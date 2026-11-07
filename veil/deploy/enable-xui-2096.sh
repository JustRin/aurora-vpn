#!/usr/bin/env bash
# Старые ссылки на подписку 3x-ui (https://ДОМЕН:2096/subs/<subId>) — тоже с
# Veil. Панель не трогается: внешний 2096 перенаправляется на Caddy (2443),
# тот пропускает /subs/* через veil-server, остальное отдаёт панели как было.
#
# Рядом должны лежать xui-sub-redirect.sh и veil-sub-2096.service. На сервере
# от root:
#   bash enable-xui-2096.sh ДОМЕН
# Откат: systemctl disable --now veil-sub-2096
set -euo pipefail
DOMAIN="${1:?нужен домен: bash enable-xui-2096.sh example.com}"
[ "$(id -u)" = 0 ] || { echo "запускать от root" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
LISTEN="$(grep -o '"listen": *"[^"]*"' /etc/veil/config.json | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
grep -q '"subscription"' /etc/veil/config.json || { echo "в /etc/veil/config.json нет раздела subscription" >&2; exit 1; }

if ! grep -q "^$DOMAIN:2443 {" /etc/caddy/Caddyfile; then
  cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak-$(date +%Y%m%d-%H%M%S)"
  cat >> /etc/caddy/Caddyfile <<CADDY

# Подписка 3x-ui на родном порту 2096: iptables перенаправляет его сюда
# (veil-sub-2096), /subs/* идёт через veil-server, остальное — в панель как было.
$DOMAIN:2443 {
	tls {
		curves x25519 secp256r1 secp384r1
	}
	@subs path /subs/*
	handle @subs {
		reverse_proxy h2c://$LISTEN
	}
	handle {
		reverse_proxy https://127.0.0.1:2096 {
			header_up Host $DOMAIN
			transport http {
				tls_insecure_skip_verify
				tls_server_name $DOMAIN
			}
		}
	}
}
CADDY
fi
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
systemctl reload caddy

install -m 0755 "$HERE/xui-sub-redirect.sh" /usr/local/sbin/veil-sub-2096
install -m 0644 "$HERE/veil-sub-2096.service" /etc/systemd/system/veil-sub-2096.service
systemctl daemon-reload
systemctl enable --now veil-sub-2096 >/dev/null
systemctl restart veil-sub-2096

echo "перенаправление: $(systemctl is-active veil-sub-2096)"
iptables -t nat -S PREROUTING | grep -- "--dport 2096" || echo "ВНИМАНИЕ: правила нет"
echo "Проверка (должно быть veil в списке):"
SUB="$(python3 -c 'import json;print(next(iter(json.load(open("/var/lib/veil/subs.json"))["subs"]),""))' 2>/dev/null || true)"
if [ -n "$SUB" ]; then
  curl -s --max-time 10 -A "Aurora-VPN/0.1 (sing-box)" --resolve "$DOMAIN:2096:127.0.0.1" "https://$DOMAIN:2096/subs/$SUB" >/dev/null || true
  echo "  снаружи: curl -A 'Aurora-VPN/0.1 (sing-box)' https://$DOMAIN:2096/subs/<subId> | base64 -d"
fi
