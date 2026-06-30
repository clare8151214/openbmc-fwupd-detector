#!/usr/bin/env python3
"""OpenBMC 韌體更新 D-Bus 事件監看(第三條資料來源)

用 `busctl monitor` 訂閱 BMC 上 `xyz.openbmc_project.Software` 的 D-Bus signal,
比 journald 更權威地看到更新狀態機:
  - InterfacesAdded:新的 /software/<id> 版本物件建立 → 更新開始
  - PropertiesChanged 的 Activation 屬性:
      Ready    → 解包與簽章驗證通過(正常 baseline)
      Active   → 已啟用為 running 版本
      Failed / Invalid → 簽章或啟用失敗(異常)

與 detector.py(journald)、redfish_proxy.py(HTTP 流量)互補,構成三層資料來源。

用法:
  python3 dbus_monitor.py           # 彩色輸出
  python3 dbus_monitor.py --json    # 每筆事件一行 JSON (NDJSON),給 SIEM
"""
import os, sys, json, subprocess

BMC_HOST = os.environ.get("BMC_HOST", "127.0.0.1")
BMC_PORT = os.environ.get("BMC_SSH_PORT", "2222")
BMC_USER = os.environ.get("BMC_USER", "root")
os.environ.setdefault("BMC_PASS", os.environ.get("BMC_PASS", "0penBmc"))

HERE = os.path.dirname(os.path.abspath(__file__))
ASKPASS = os.path.join(HERE, "_askpass.sh")
JSON_MODE = "--json" in sys.argv
SOFTWARE_PATH = "/xyz/openbmc_project/software"
ACT_IFACE = "xyz.openbmc_project.Software.Activation"
VER_IFACE = "xyz.openbmc_project.Software.Version"

C = {"ALERT": "\033[1;31m", "UPDATE": "\033[1;33m", "NORMAL": "\033[1;32m",
     "INFO": "\033[36m", "0": "\033[0m"}

def info(msg):
    print(f"{C['INFO']}{msg}{C['0']}", file=(sys.stderr if JSON_MODE else sys.stdout), flush=True)

def emit(sev, rule, path="", detail=""):
    if JSON_MODE:
        print(json.dumps({"severity": sev, "rule": rule, "source": "dbus",
                          "path": path, "detail": detail}, ensure_ascii=False), flush=True)
    else:
        line = f"{C.get(sev, C['INFO'])}[{sev}] {rule}{C['0']}"
        if path:   line += f"  | {path}"
        if detail: line += f"  {detail}"
        print(line, flush=True)

def ssh_busctl_monitor():
    remote = (f"busctl --json=short monitor {ACT_IFACE.rsplit('.',1)[0]}.BMC.Updater "
              "2>/dev/null")
    cmd = ["setsid", "-w", "ssh", "-p", BMC_PORT,
           "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
           "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
           "-o", "ServerAliveInterval=15",
           f"{BMC_USER}@{BMC_HOST}", remote]
    env = dict(os.environ, SSH_ASKPASS=ASKPASS, SSH_ASKPASS_REQUIRE="force",
               DISPLAY=os.environ.get("DISPLAY", ":0"))
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            env=env, text=True, bufsize=1)

def variant(v):
    """從 busctl --json=short 的 {"type":..,"data":..} 取值。"""
    return v.get("data") if isinstance(v, dict) else v

def handle(msg):
    path = msg.get("path", "")
    if not path.startswith(SOFTWARE_PATH):
        return
    member = msg.get("member")
    data = (msg.get("payload") or {}).get("data") or []

    if member == "InterfacesAdded" and len(data) >= 2:
        obj = data[0] if isinstance(data[0], str) else path   # 新物件的實際路徑
        added = data[1] if isinstance(data[1], dict) else {}
        if VER_IFACE in added:
            ver = variant((added[VER_IFACE] or {}).get("Version", {}))
            emit("UPDATE", "新韌體版本物件建立(更新開始)", obj, f"Version={ver or '?'}")
        return

    if member == "PropertiesChanged" and len(data) >= 2 and data[0] == ACT_IFACE:
        props = data[1] if isinstance(data[1], dict) else {}
        if "Activation" in props:
            act = str(variant(props["Activation"]) or "")
            short = act.rsplit(".", 1)[-1]
            if short in ("Failed", "Invalid"):
                emit("ALERT", "更新失敗:Activation 變 " + short, path, act)
            elif short == "Ready":
                emit("NORMAL", "解包/驗章通過:Activation=Ready", path, act)
            elif short in ("Active", "Activating"):
                emit("UPDATE", f"Activation={short}", path, act)

def main():
    info(f"[dbus_monitor] 連線 {BMC_USER}@{BMC_HOST}:{BMC_PORT},訂閱 Software D-Bus signal"
         + ("(JSON/SIEM 模式)" if JSON_MODE else ""))
    proc = ssh_busctl_monitor()
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            handle(msg)
    except KeyboardInterrupt:
        info("[dbus_monitor] 結束")
    finally:
        proc.terminate()

if __name__ == "__main__":
    main()
