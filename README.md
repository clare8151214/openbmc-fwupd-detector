# OpenBMC 韌體更新異常偵測原型

本組專題 Security Analysis and Prototype of OpenBMC Firmware Update via Redfish 的偵測原型,在 romulus QEMU 上開發測試。

## 環境前提

QEMU 需用帶 443 轉發的方式開,Redfish 才連得到:

```bash
QB_SLIRP_OPT="-netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:2323-:23,hostfwd=tcp:127.0.0.1:2443-:443" \
  runqemu romulus nographic slirp
```

- SSH:`ssh -p 2222 root@127.0.0.1`,密碼 `0penBmc`
- Redfish:`https://127.0.0.1:2443`

## 韌體更新資料流與偵測點

```text
Redfish POST /redfish/v1/UpdateService/update   HttpPushUri
   ↓  bmcweb 收檔,寫進 /tmp/images
phosphor-image-updater / software-manager       驗證 image
   ↓  產生 D-Bus 物件 /xyz/openbmc_project/software/<id>
xyz.openbmc_project.Software.Activation          Ready→Activating→Active 或 Failed
```

實測各異常的偵測來源:

| 異常情境 | 觸發後的現象 | 偵測來源 |
| --- | --- | --- |
| 未授權更新 | HTTP 401 | bmcweb **不記** journal,需 HTTP 流量層 |
| 竄改 / 格式錯誤 image | HTTP 500,bmcweb 記 `update_service.hpp` 錯誤 | journald |
| 簽章驗證失敗 | Activation 變 Failed | journald + D-Bus |
| 重複更新 | 短時間多次更新請求 | journald 事件頻率 |

> 重要發現:bmcweb 預設只把更新「處理錯誤」寫進 journal,**不記 401 未授權**。所以未授權偵測屬於 traffic analysis 範疇,須靠封包擷取或反向代理,這也呼應投影片的 Redfish Traffic Analysis 主題。

## 兩層偵測架構

| 偵測層 | 元件 | 看得到 | 偵測 |
| --- | --- | --- | --- |
| HTTP 流量層 | `redfish_proxy.py` | method / path / Authorization / 回應碼 | 未授權、重複、被拒/失敗 |
| 內部事件層 | `detector.py` | bmcweb 與 software-manager 的 journald | 竄改/格式錯誤、簽章失敗、重複 |

兩層互補:**未授權 401** 只有流量層看得到 (bmcweb 不記 journal);**內部處理錯誤** 只有 journald 看得到。

```text
curl ──> redfish_proxy.py :2444 (TLS 終止,看明文) ──> bmcweb :2443 ──> software-manager
            │ 看 Authorization / 回應碼                          │ 寫 journald
            ↓                                                    ↓
      HTTP 層警告                                           detector.py 看 journald
```

## 元件

| 檔案 | 作用 |
| --- | --- |
| `redfish_proxy.py` | HTTP 層,TLS 終止代理,看 Authorization 與回應碼報警 |
| `detector.py` | 內部事件層,串流 BMC journald 報警 |
| `trigger.sh` | 觸發異常情境,給 demo 用,設 `RF=https://127.0.0.1:2444` 改走代理 |
| `_askpass.sh` | 提供 SSH 密碼,detector 內部用 |
| `proxy.crt` `proxy.key` | 代理的自簽憑證 |

## 跑法 pre-demo

### HTTP 流量層 demo,看未授權

視窗 A 啟動代理,視窗 B 把請求改走代理 (2444)：

```bash
# 視窗 A
cd ~/openbmc-fwupd && python3 redfish_proxy.py
# 視窗 B
cd ~/openbmc-fwupd
RF=https://127.0.0.1:2444 ./trigger.sh unauth     # 代理報 [ALERT] 未授權更新嘗試
RF=https://127.0.0.1:2444 ./trigger.sh tampered   # 代理報 [ALERT] 更新被拒/失敗 (500)
RF=https://127.0.0.1:2444 ./trigger.sh repeated   # 代理報 [REPEAT]
```

### 內部事件層 demo,看正常/竄改/重複

```bash
# 視窗 A
cd ~/openbmc-fwupd && python3 detector.py
# 視窗 B,直打 bmcweb
cd ~/openbmc-fwupd
./trigger.sh normal      # 正常更新,detector 報綠色 [NORMAL],列出 Activation=Ready 的 Version 物件
./trigger.sh tampered    # detector 報 [ALERT] 竄改/格式錯誤的更新 image
./trigger.sh repeated    # detector 報 [REPEAT]
```

`./trigger.sh info` 看更新服務現況。

> `normal` 走檔案投放(romulus 的 Redfish 更新端點壞掉,見 LEARNING 筆記步驟五)。每跑一次會在 BMC 的 tmpfs 多暫存一個版本,連跑多次後可重開 QEMU 清掉。

## 已知限制 pre-demo 範圍

- 未授權 401 已由 `redfish_proxy.py` 在 HTTP 層補上;限制是流量須改走代理 2444。正式部署可把代理擺在 bmcweb 前當反向代理。
- 純亂數 image 在 bmcweb 解析階段即被擋 (HTTP 500),尚未走到簽章驗證;要演到 Activation=Failed 需「格式合法但簽章被改」的 image,列為進階。
- 偵測規則為關鍵字與回應碼比對,正式版可改為訂閱 D-Bus `Software` signal 做結構化判斷。
- 代理用自簽憑證,client 需 `-k` 略過驗證;正式版應換正規憑證。
