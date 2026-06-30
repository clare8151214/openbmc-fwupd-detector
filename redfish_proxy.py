#!/usr/bin/env python3
"""Redfish 流量分析代理 (HTTP 層偵測,補 journald 看不到的未授權更新)

bmcweb 走 HTTPS,純 tcpdump 看不到內容也判不出 401。此代理在中間終止 TLS,
解密後檢視每個請求的 method / path / Authorization / 回應碼,對韌體更新異常報警:
  - 未授權更新:POST 更新端點但缺 Authorization 或回 401/403
  - 重複更新:更新端點 POST 在視窗內超過門檻
  - 失敗更新:更新端點回 4xx/5xx (含竄改 image 的 500)

資料流:  curl --> 本代理 127.0.0.1:2444 (解密) --> bmcweb 127.0.0.1:2443

用法:
  python3 redfish_proxy.py
  # 之後把 Redfish 請求改打 2444,例如:
  curl -sk -u root:0penBmc https://127.0.0.1:2444/redfish/v1/UpdateService
"""
import os, ssl, time, http.client, socketserver, http.server
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
LISTEN = ("127.0.0.1", int(os.environ.get("PROXY_PORT", "2444")))
UPSTREAM = ("127.0.0.1", int(os.environ.get("BMC_REDFISH_PORT", "2443")))
UPDATE_PREFIX = "/redfish/v1/UpdateService"
WINDOW_S = 60
REPEAT_THRESHOLD = 3

C = {"ALERT": "\033[1;31m", "UPDATE": "\033[1;33m",
     "REPEAT": "\033[1;35m", "INFO": "\033[36m", "0": "\033[0m"}
update_posts = deque()

class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"        # 每請求關閉,避免 keep-alive 複雜度

    def _relay(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else None
        # 轉發給 bmcweb
        ctx = ssl._create_unverified_context()
        up = http.client.HTTPSConnection(UPSTREAM[0], UPSTREAM[1], context=ctx, timeout=30)
        hdrs = {k: v for k, v in self.headers.items() if k.lower() != "host"}
        try:
            up.request(self.command, self.path, body=body, headers=hdrs)
            resp = up.getresponse()
            data = resp.read()
            status, rheaders = resp.status, resp.getheaders()
        except Exception as e:
            self.send_error(502, f"upstream error: {e}")
            return
        finally:
            up.close()
        self._inspect(status, len(body) if body else 0)
        # 回傳給 client
        self.send_response(status)
        for k, v in rheaders:
            if k.lower() in ("transfer-encoding", "connection", "content-length"):
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _inspect(self, status, body_len):
        ts = time.strftime("%H:%M:%S")
        is_update = self.path.startswith(UPDATE_PREFIX) and self.command == "POST"
        has_auth = "Authorization" in self.headers
        line = (f"{ts} {self.command} {self.path} "
                f"auth={'yes' if has_auth else 'NO'} body={body_len}B -> {status}")
        if not is_update:
            print(f"{C['INFO']}{line}{C['0']}")
            return
        now = time.time()
        update_posts.append(now)
        while update_posts and now - update_posts[0] > WINDOW_S:
            update_posts.popleft()
        if status in (401, 403) or not has_auth:
            print(f"{C['ALERT']}[ALERT] 未授權更新嘗試 | {line}{C['0']}")
        elif status >= 400:
            print(f"{C['ALERT']}[ALERT] 更新被拒/失敗 | {line}{C['0']}")
        else:
            print(f"{C['UPDATE']}[UPDATE] 更新請求 | {line}{C['0']}")
        if len(update_posts) >= REPEAT_THRESHOLD:
            print(f"{C['REPEAT']}[REPEAT] 重複更新!{WINDOW_S}s 內 {len(update_posts)} 次更新請求{C['0']}")
            update_posts.clear()

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _relay
    def log_message(self, *a):
        pass

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

def main():
    httpd = Server(LISTEN, Proxy)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(HERE, "proxy.crt"), os.path.join(HERE, "proxy.key"))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"{C['INFO']}[proxy] Redfish 流量分析代理 https://{LISTEN[0]}:{LISTEN[1]} "
          f"-> bmcweb {UPSTREAM[0]}:{UPSTREAM[1]}{C['0']}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[proxy] 結束")

if __name__ == "__main__":
    main()
