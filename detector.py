#!/usr/bin/env python3
"""OpenBMC 韌體更新異常偵測原型 (pre-demo)

監看 BMC 的 journald 即時串流,對韌體更新相關異常發出警告:
  - 竄改 / 格式錯誤的更新 image  → bmcweb update_service 報錯 (HTTP 500)
  - 簽章 / 驗證失敗             → software-manager / Activation 失敗
  - 重複更新                   → 視窗內多次更新請求

未授權更新 (HTTP 401) 偵測不在這裡:bmcweb 預設不把 401 寫進 journal,
需在 HTTP 流量層觀測,見 README。

用法:
  python3 detector.py              # 連預設 127.0.0.1:2222 root/0penBmc,彩色輸出
  python3 detector.py --json       # 每筆事件輸出一行 JSON (NDJSON),給 SIEM 收
  BMC_SSH_PORT=2222 python3 detector.py
"""
import os, sys, re, time, json, subprocess
from collections import deque

BMC_HOST = os.environ.get("BMC_HOST", "127.0.0.1")
BMC_PORT = os.environ.get("BMC_SSH_PORT", "2222")
BMC_USER = os.environ.get("BMC_USER", "root")
os.environ.setdefault("BMC_PASS", os.environ.get("BMC_PASS", "0penBmc"))

HERE = os.path.dirname(os.path.abspath(__file__))
ASKPASS = os.path.join(HERE, "_askpass.sh")
JSON_MODE = "--json" in sys.argv   # SIEM 用:每筆事件輸出一行 JSON (NDJSON)

# 規則: (標籤, 嚴重度, 正規式)。順序由嚴到鬆,命中第一條即分類。
RULES = [
    ("竄改/格式錯誤的更新 image", "ALERT",
     re.compile(r"update_service\.hpp|handleBMCUpdate|Invalid request descriptor", re.I)),
    ("簽章/驗證失敗", "ALERT",
     re.compile(r"(image )?verif|signature|Activation\S*\.(Failed|Invalid)", re.I)),
    ("正常更新:image 已接收解包", "NORMAL",
     re.compile(r"Untaring /tmp/images|version-software-manager", re.I)),
    ("韌體更新活動", "UPDATE",
     re.compile(r"image-updater|software-?manager|UpdateService|/xyz/openbmc_project/software/", re.I)),
]
WINDOW_S = 60          # 重複更新的觀測視窗 (秒)
REPEAT_THRESHOLD = 3   # 視窗內達此次數即視為重複更新
# 一次更新嘗試只算一次的錨點 (每個 POST 會產生多行 log,只認這條代表一次嘗試)
ATTEMPT_RX = re.compile(r"update_service\.hpp:937|error_code = Invalid request descriptor", re.I)

C = {"ALERT": "\033[1;31m", "UPDATE": "\033[1;33m", "NORMAL": "\033[1;32m",
     "REPEAT": "\033[1;35m", "INFO": "\033[36m", "0": "\033[0m"}

def color(sev, msg):
    return f"{C.get(sev, C['INFO'])}{msg}{C['0']}"

def info(msg):
    print(color("INFO", msg), file=(sys.stderr if JSON_MODE else sys.stdout), flush=True)

def emit(sev, rule, raw="", source="journald"):
    """輸出一筆偵測事件:JSON 模式給 SIEM,否則彩色給人看。"""
    if JSON_MODE:
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "severity": sev,
               "rule": rule, "source": source, "message": raw}
        print(json.dumps(rec, ensure_ascii=False), flush=True)
    else:
        print(color(sev, f"[{sev}] {rule}") + (f"  | {raw}" if raw else ""), flush=True)

def ssh_journal_stream():
    """以單一持久 SSH 連線串流 BMC 的 journalctl -f。"""
    remote = "journalctl -f -o short-iso -n 0 2>/dev/null"
    cmd = ["setsid", "-w", "ssh", "-p", BMC_PORT,
           "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
           "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
           "-o", "ServerAliveInterval=15",
           f"{BMC_USER}@{BMC_HOST}", remote]
    env = dict(os.environ, SSH_ASKPASS=ASKPASS, SSH_ASKPASS_REQUIRE="force",
               DISPLAY=os.environ.get("DISPLAY", ":0"))
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            env=env, text=True, bufsize=1)

def main():
    info(f"[detector] 連線 {BMC_USER}@{BMC_HOST}:{BMC_PORT},監看韌體更新異常"
         + ("(JSON/SIEM 模式)" if JSON_MODE else ""))
    update_events = deque()  # 更新活動的時間戳,用於重複更新偵測
    proc = ssh_journal_stream()
    try:
        for line in proc.stdout:
            line = line.rstrip("\n")
            for label, sev, rx in RULES:
                if rx.search(line):
                    now = time.time()
                    emit(sev, label, line)
                    # 重複更新偵測:每次 POST 只在錨點行計一次
                    if ATTEMPT_RX.search(line):
                        update_events.append(now)
                        while update_events and now - update_events[0] > WINDOW_S:
                            update_events.popleft()
                        if len(update_events) >= REPEAT_THRESHOLD:
                            emit("REPEAT", f"重複更新:{WINDOW_S}s 內 {len(update_events)} 次更新嘗試")
                            update_events.clear()
                    break
    except KeyboardInterrupt:
        info("[detector] 結束")
    finally:
        proc.terminate()

if __name__ == "__main__":
    main()
