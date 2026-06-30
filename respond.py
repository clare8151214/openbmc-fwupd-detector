#!/usr/bin/env python3
"""OpenBMC firmware update response / rollback helper.

This is a pre-demo response action, not a real post-flash watchdog rollback:
it blocks a suspicious staged image by never setting Activation=Activating,
deletes the staged /software/<id> object, and verifies the running Active
firmware object is unchanged.

Typical demo:
  ./trigger.sh normal
  python3 respond.py --latest-ready
  python3 respond.py status
"""
import argparse
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass

BMC_HOST = os.environ.get("BMC_HOST", "127.0.0.1")
BMC_PORT = os.environ.get("BMC_SSH_PORT", "2222")
BMC_USER = os.environ.get("BMC_USER", "root")
os.environ.setdefault("BMC_PASS", os.environ.get("BMC_PASS", "0penBmc"))

HERE = os.path.dirname(os.path.abspath(__file__))
ASKPASS = os.path.join(HERE, "_askpass.sh")

UPDATER = "xyz.openbmc_project.Software.BMC.Updater"
SOFTWARE_ROOT = "/xyz/openbmc_project/software"
ACT_IFACE = "xyz.openbmc_project.Software.Activation"
VER_IFACE = "xyz.openbmc_project.Software.Version"
PURPOSE_IFACE = "xyz.openbmc_project.Software.Version"
DELETE_IFACE = "xyz.openbmc_project.Object.Delete"
PATH_RX = re.compile(r"^/xyz/openbmc_project/software/[0-9a-fA-F]{8}$")

C = {
    "ALERT": "\033[1;31m",
    "RESPONSE": "\033[1;34m",
    "OK": "\033[1;32m",
    "INFO": "\033[36m",
    "WARN": "\033[1;33m",
    "0": "\033[0m",
}


@dataclass
class VersionObject:
    path: str
    activation: str
    version: str
    purpose: str

    @property
    def state(self) -> str:
        return self.activation.rsplit(".", 1)[-1] if self.activation else "?"

    @property
    def active(self) -> bool:
        return self.state == "Active"

    @property
    def ready(self) -> bool:
        return self.state == "Ready"

    @property
    def failed(self) -> bool:
        return self.state in ("Failed", "Invalid")


def paint(label, msg):
    return f"{C.get(label, C['INFO'])}{msg}{C['0']}"


def log(label, msg):
    print(paint(label, f"[{label}] {msg}"), flush=True)


def ssh(remote, check=True):
    cmd = [
        "setsid",
        "-w",
        "ssh",
        "-p",
        BMC_PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "PubkeyAuthentication=no",
        f"{BMC_USER}@{BMC_HOST}",
        remote,
    ]
    env = dict(
        os.environ,
        SSH_ASKPASS=ASKPASS,
        SSH_ASKPASS_REQUIRE="force",
        DISPLAY=os.environ.get("DISPLAY", ":0"),
    )
    proc = subprocess.run(
        cmd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"ssh command failed: {remote}")
    return proc.stdout


def list_objects():
    remote = rf'''
U={shlex.quote(UPDATER)}
for p in $(busctl call xyz.openbmc_project.ObjectMapper /xyz/openbmc_project/object_mapper xyz.openbmc_project.ObjectMapper GetSubTreePaths sias {shlex.quote(SOFTWARE_ROOT)} 0 0 2>/dev/null | tr " " "\n" | grep -oE "{SOFTWARE_ROOT}/[0-9a-fA-F]{{8}}" | awk '!seen[$0]++'); do
  a=$(busctl get-property "$U" "$p" {shlex.quote(ACT_IFACE)} Activation 2>/dev/null | grep -oE "Activations\.[A-Za-z]+" || true)
  v=$(busctl get-property "$U" "$p" {shlex.quote(VER_IFACE)} Version 2>/dev/null | sed -E 's/^s "//; s/"$//' || true)
  purpose=$(busctl get-property "$U" "$p" {shlex.quote(PURPOSE_IFACE)} Purpose 2>/dev/null | sed -E 's/^s "//; s/"$//' || true)
  printf '%s\t%s\t%s\t%s\n' "$p" "$a" "$v" "$purpose"
done
'''
    rows = []
    for line in ssh(remote).splitlines():
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        rows.append(VersionObject(*parts))
    return rows


def active_snapshot(objects):
    return sorted((o.path, o.activation, o.version) for o in objects if o.active)


def print_objects(objects, title="Software objects"):
    log("INFO", title)
    if not objects:
        print("  (none)")
        return
    for obj in objects:
        marker = "functional/running" if obj.active else "staged"
        print(
            f"  {obj.path}  Activation={obj.state:<8}  "
            f"Version={obj.version or '?'}  ({marker})"
        )


def validate_target(path):
    if not PATH_RX.match(path):
        raise ValueError(f"invalid software object path: {path}")
    return path


def choose_target(objects, args):
    if args.target:
        target = validate_target(args.target)
        for obj in objects:
            if obj.path == target:
                return obj
        raise RuntimeError(f"target not found on BMC: {target}")

    if args.failed:
        candidates = [o for o in objects if o.failed]
        if not candidates:
            raise RuntimeError("no Failed/Invalid software object found")
        return candidates[-1]

    if args.latest_ready:
        candidates = [o for o in objects if o.ready]
        if not candidates:
            raise RuntimeError("no Ready software object found")
        if len(candidates) > 1:
            log("WARN", f"{len(candidates)} Ready objects found; choosing the last ObjectMapper entry")
        return candidates[-1]

    raise RuntimeError("choose a target with --target, --latest-ready, or --failed")


def delete_object(path, dry_run=False):
    remote = (
        f"busctl call {shlex.quote(UPDATER)} {shlex.quote(path)} "
        f"{shlex.quote(DELETE_IFACE)} Delete"
    )
    if dry_run:
        log("INFO", f"dry-run: would run on BMC: {remote}")
        return
    ssh(remote)


def rollback(args):
    before = list_objects()
    if not before:
        raise RuntimeError("no software objects found; is the BMC ready?")

    print_objects(before, "Before response")
    functional_before = active_snapshot(before)
    if not functional_before:
        raise RuntimeError("no Active firmware object found; refusing to delete anything")

    target = choose_target(before, args)
    if target.active and not args.force:
        raise RuntimeError("target is Active; refusing to delete the running firmware without --force")

    log("RESPONSE", f"selected target: {target.path} Activation={target.state} Version={target.version or '?'}")
    log("RESPONSE", "block activation: do not set RequestedActivation/Activation to Activating")
    log("RESPONSE", f"delete staged object through {DELETE_IFACE}.Delete")
    delete_object(target.path, dry_run=args.dry_run)

    if args.dry_run:
        log("OK", "dry-run complete; no BMC state changed")
        return

    after = list_objects()
    print_objects(after, "After response")
    functional_after = active_snapshot(after)
    target_still_exists = any(o.path == target.path for o in after)

    if target_still_exists:
        raise RuntimeError(f"delete did not remove target: {target.path}")
    if functional_after != functional_before:
        raise RuntimeError("functional/running firmware changed after response; check BMC state")

    log("OK", "blocked and restored: staged object removed, functional/running firmware unchanged")


def main():
    parser = argparse.ArgumentParser(
        description="Rollback/response helper for OpenBMC staged firmware versions."
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status", help="list software objects and activation states")

    rollback_p = sub.add_parser("rollback", help="delete a suspicious non-active software object")
    rollback_p.add_argument("--target", help="exact /xyz/openbmc_project/software/<id> object to delete")
    rollback_p.add_argument("--latest-ready", action="store_true", help="delete the last Ready staged object")
    rollback_p.add_argument("--failed", action="store_true", help="delete the last Failed/Invalid object")
    rollback_p.add_argument("--dry-run", action="store_true", help="show the response without deleting")
    rollback_p.add_argument("--force", action="store_true", help="allow deleting an Active target")

    # Friendly shortcut for demo muscle memory.
    parser.add_argument("--latest-ready", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--failed", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--target", help=argparse.SUPPRESS)
    parser.add_argument("--dry-run", action="store_true", help=argparse.SUPPRESS)

    args = parser.parse_args()
    try:
        if args.command == "status":
            print_objects(list_objects())
        elif args.command == "rollback":
            rollback(args)
        elif args.latest_ready or args.failed or args.target:
            args.command = "rollback"
            args.force = False
            rollback(args)
        else:
            parser.print_help()
    except Exception as exc:
        log("ALERT", str(exc))
        sys.exit(1)


if __name__ == "__main__":
    main()
