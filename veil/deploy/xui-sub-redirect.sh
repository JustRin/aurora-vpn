#!/usr/bin/env bash
# Подписка 3x-ui на её родном порту (2096) — тоже через veil-server, чтобы
# старые ссылки клиентов получали Veil, а панель трогать не пришлось.
#
# Внешние подключения к 2096 перенаправляются на Caddy (2443), он отдаёт
# /subs/* в veil-server, а тот берёт подписку у самой панели через мост на
# 127.0.0.1 — этот трафик идёт через OUTPUT и под перенаправление не попадает.
# Прямые подключения к 2443 снаружи отбрасываются: лишнего порта не видно.
#
#   xui-sub-redirect.sh up | down
set -euo pipefail
FROM="${XUI_SUB_PORT:-2096}"
TO="${CADDY_SUB_PORT:-2443}"

rule() {
  local tool="$1" action="$2"; shift 2
  if [ "$action" = up ]; then
    "$tool" -C "$@" 2>/dev/null || "$tool" -A "$@"
  else
    while "$tool" -C "$@" 2>/dev/null; do "$tool" -D "$@"; done
  fi
}

case "${1:-}" in
  up | down)
    for tool in iptables ip6tables; do
      rule "$tool" "$1" PREROUTING -t nat -p tcp --dport "$FROM" -j REDIRECT --to-ports "$TO"
      rule "$tool" "$1" INPUT -p tcp --dport "$TO" -m conntrack ! --ctstate DNAT -j DROP
    done
    ;;
  *)
    echo "использование: $0 up|down" >&2
    exit 2
    ;;
esac
