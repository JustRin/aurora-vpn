#!/usr/bin/env bash
# Список сетей РФ для veil-server: российские адреса он наружу не выпускает,
# чтобы IP сервера не увидели российские платформы, обязанные искать VPN.
# Сервер перечитывает файл сам в течение 30 секунд после обновления.
set -euo pipefail
OUT=/etc/veil/ru-cidr.txt
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
curl -fsSL --max-time 60 https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone >> "$TMP"
curl -fsSL --max-time 60 https://www.ipdeny.com/ipv6/ipaddresses/aggregated/ru-aggregated.zone >> "$TMP" || true
# Защита от пустого или обрезанного ответа: настоящий список — тысячи сетей.
if [ "$(grep -c / "$TMP")" -lt 1000 ]; then
  echo "список сетей РФ подозрительно короткий, оставляю прежний" >&2
  exit 1
fi
install -m 0644 "$TMP" "$OUT"
echo "сетей РФ: $(grep -c / "$OUT")"
