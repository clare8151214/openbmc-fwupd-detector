#!/bin/bash
# 觸發韌體更新情境(正常 + 三種異常),給 detector.py 偵測 / demo 用。
# 用法: ./trigger.sh [normal|unauth|tampered|repeated|info]
# 需要另一個視窗先跑: python3 detector.py
set -u
# 預設直打 bmcweb (配 detector.py);設 RF=https://127.0.0.1:2444 改走代理 (配 redfish_proxy.py)
RF="${RF:-https://127.0.0.1:2443}"
AUTH="root:0penBmc"
EP="$RF/redfish/v1/UpdateService/update"

code() { curl -sk -o /dev/null -w "%{http_code}" "$@"; }

# --- BMC SSH(給 normal 情境的檔案投放;Redfish 更新端點在 romulus 壞掉,走原生路徑)---
HERE="$(cd "$(dirname "$0")" && pwd)"
export BMC_PASS="${BMC_PASS:-0penBmc}"
SSH_PORT="${BMC_SSH_PORT:-2222}"
IMG="${IMG:-$HOME/openbmc/build/romulus/tmp/deploy/images/romulus/obmc-phosphor-image-romulus.static.mtd.tar}"
SSH_OPTS="-p $SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no"
bmc_ssh()  { SSH_ASKPASS="$HERE/_askpass.sh" SSH_ASKPASS_REQUIRE=force setsid -w ssh $SSH_OPTS root@127.0.0.1 "$@" </dev/null 2>/dev/null; }
bmc_push() { SSH_ASKPASS="$HERE/_askpass.sh" SSH_ASKPASS_REQUIRE=force setsid -w ssh $SSH_OPTS root@127.0.0.1 "cat > $2" < "$1" 2>/dev/null; }

case "${1:-info}" in
  unauth)
    echo "[trigger] 未授權更新:不帶帳密 POST"
    echo "  HTTP = $(code -X POST -H 'Content-Type: application/octet-stream' \
                      --data-binary 'FAKE' "$EP")  (預期 401)"
    echo "  >> bmcweb 不記 401,需在 HTTP 層偵測 (見 README)"
    ;;
  tampered)
    echo "[trigger] 竄改 image:帶帳密 POST 一個壞掉的 image"
    head -c 4096 /dev/urandom > /tmp/tampered.bin
    echo "  HTTP = $(code -X POST -H 'Content-Type: application/octet-stream' \
                      -u "$AUTH" --data-binary @/tmp/tampered.bin "$EP")  (預期 500)"
    echo "  >> detector 應報「竄改/格式錯誤的更新 image」"
    ;;
  repeated)
    echo "[trigger] 重複更新:短時間連續 POST 4 次"
    for i in 1 2 3 4; do
      head -c 4096 /dev/urandom > /tmp/tampered.bin
      echo "  #$i HTTP = $(code -X POST -H 'Content-Type: application/octet-stream' \
                            -u "$AUTH" --data-binary @/tmp/tampered.bin "$EP")"
    done
    echo "  >> detector 應在數次後報 [REPEAT] 重複更新"
    ;;
  normal)
    echo "[trigger] 正常更新:把合法簽章包投放到 BMC /tmp/images(romulus 的 Redfish 更新端點壞掉,走原生路徑)"
    [ -f "$IMG" ] || { echo "  找不到 image: $IMG"; exit 1; }
    echo "  傳送 $(basename "$IMG") ..."
    bmc_push "$IMG" /tmp/images/update.tar
    echo "  等 software-manager 解包驗章..."
    sleep 4
    echo "  software 版本物件(running=Active,新上傳=Ready):"
    bmc_ssh 'U=xyz.openbmc_project.Software.BMC.Updater
      for p in $(busctl call xyz.openbmc_project.ObjectMapper /xyz/openbmc_project/object_mapper xyz.openbmc_project.ObjectMapper GetSubTreePaths sias /xyz/openbmc_project/software 0 0 2>/dev/null | tr " " "\n" | grep -oE "/xyz/openbmc_project/software/[0-9a-f]{8}" | sort -u); do
        a=$(busctl get-property $U $p xyz.openbmc_project.Software.Activation Activation 2>/dev/null | grep -oE "Activations\.[A-Za-z]+")
        v=$(busctl get-property $U $p xyz.openbmc_project.Software.Version Version 2>/dev/null | sed -E "s/^s \"//; s/\"$//")
        echo "    $p  Activation=$a  Version=$v"
      done'
    echo "  >> 合法包 → Activation=Ready、有 Version 物件,即正常 baseline"
    echo "  >> detector 會看到 phosphor-version-software-manager 的 Untaring 事件(NORMAL)"
    ;;
  info)
    echo "[trigger] 韌體更新服務現況"
    curl -sk -u "$AUTH" "$RF/redfish/v1/UpdateService" | python3 -m json.tool 2>/dev/null \
      | grep -E 'HttpPushUri|MaxImageSize|ServiceEnabled'
    ;;
  *)
    echo "用法: $0 [normal|unauth|tampered|repeated|info]"; exit 1;;
esac
