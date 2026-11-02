#!/usr/bin/env bash
# Установка Veil на сервер: veil-server за Caddy, который держит сайт и TLS.
#
#   ./install.sh --domain example.com [--site ./site] [--install-caddy] [--xui]
#
# --xui: рядом 3x-ui, и его подписки (https://127.0.0.1:2096/subs/) должны
# приходить клиентам с Veil внутри: https://ДОМЕН/subs/<subId>.
#
# Рядом со скриптом должны лежать veil-server (сборка под x86_64-linux-musl)
# и veil.service. Повторный запуск безопасен: конфиг с паролями не трогается.
set -euo pipefail

DOMAIN=""
SITE=""
INSTALL_CADDY=0
XUI=0
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --site) SITE="$2"; shift 2 ;;
    --install-caddy) INSTALL_CADDY=1; shift ;;
    --xui) XUI=1; shift ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done
[ -n "$DOMAIN" ] || { echo "нужен --domain" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "запускать от root" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
SITE_DIR="/var/www/$DOMAIN"

# ---- veil-server
install -m 0755 "$HERE/veil-server" /usr/local/bin/veil-server
id veil >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin veil
install -d -m 0750 -o root -g veil /etc/veil
if [ ! -f /etc/veil/config.json ]; then
  INIT_FLAGS=""
  [ "$XUI" = 1 ] && INIT_FLAGS="--xui"
  ( umask 027; /usr/local/bin/veil-server init --host "$DOMAIN" $INIT_FLAGS > /etc/veil/config.json )
fi
chown root:veil /etc/veil/config.json
chmod 0640 /etc/veil/config.json
VPATH="$(grep -o '"path": *"[^"]*"' /etc/veil/config.json | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
LISTEN="$(grep -o '"listen": *"[^"]*"' /etc/veil/config.json | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"

# Сети РФ: veil-server их наружу не выпускает (см. ru-cidr-update.sh),
# список обновляется раз в неделю.
install -m 0755 "$HERE/ru-cidr-update.sh" /usr/local/bin/veil-ru-cidr-update
ln -sf /usr/local/bin/veil-ru-cidr-update /etc/cron.weekly/veil-ru-cidr-update
/usr/local/bin/veil-ru-cidr-update || echo "ВНИМАНИЕ: список сетей РФ не скачан — российское режется только по доменам" >&2

install -m 0644 "$HERE/veil.service" /etc/systemd/system/veil.service
systemctl daemon-reload
systemctl enable veil >/dev/null
systemctl restart veil

# ---- сайт: без него сервер — голый TLS, который выдаёт себя первой же пробой
install -d -m 0755 "$SITE_DIR"
if [ -n "$SITE" ]; then
  cp -r "$SITE"/. "$SITE_DIR"/
fi
if [ -z "$(ls -A "$SITE_DIR")" ]; then
  echo "ВНИМАНИЕ: $SITE_DIR пуст. Положите туда настоящий сайт (--site ./папка): пустой домен на 443 подозрителен." >&2
fi

# ---- Caddy: сертификат Let's Encrypt, h2, сайт и путь туннеля
if ! command -v caddy >/dev/null; then
  if [ "$INSTALL_CADDY" = 1 ]; then
    apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' |
      gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update
    apt-get install -y caddy
  else
    echo "Caddy не установлен: запустите с --install-caddy или настройте nginx по nginx.conf.example" >&2
    exit 1
  fi
fi

SUBS_ROUTE=""
BRIDGE=""
if [ "$XUI" = 1 ]; then
  SUBS_ROUTE="$(cat <<ROUTE
	# Подписки 3x-ui с Veil внутри: veil-server дописывает ссылку (subs.rs).
	@subs path /subs/*
	handle @subs {
		reverse_proxy h2c://$LISTEN {
			@missing status 404
			handle_response @missing {
				method GET
				rewrite * /404.html
				file_server {
					status 404
				}
			}
		}
	}
ROUTE
)"
  BRIDGE="$(cat <<ROUTE
# Мост к подписке 3x-ui на TLS: veil-server забирает её здесь по HTTP.
http://:2097 {
	bind 127.0.0.1
	reverse_proxy https://127.0.0.1:2096 {
		header_up Host $DOMAIN
		transport http {
			tls_insecure_skip_verify
			tls_server_name $DOMAIN
		}
	}
}
ROUTE
)"
fi

if [ -f /etc/caddy/Caddyfile ] && ! grep -q "veil-server" /etc/caddy/Caddyfile; then
  cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak-$(date +%Y%m%d-%H%M%S)"
fi
cat > /etc/caddy/Caddyfile <<CADDY
# Без HTTP/3: иначе браузеры шли бы к сайту по UDP, а клиенты Veil — по TCP,
# и туннель выделялся бы на фоне посетителей. В РФ QUIC к зарубежным адресам
# всё равно режут, обычный сайт там — это h2 поверх TCP.
{
	servers {
		protocols h1 h2
	}
}

# Сайт $DOMAIN и туннель veil-server на пути, известном только клиентам.
$DOMAIN {
	root * $SITE_DIR

	# Клиент Veil объявляет X25519MLKEM768 без ключа (отпечаток как у Chrome,
	# hello в одном сегменте). Сервер, предпочитающий ML-KEM, ответил бы HRR.
	tls {
		curves x25519 secp256r1 secp384r1
	}

	header {
		Strict-Transport-Security "max-age=63072000; includeSubDomains"
		X-Content-Type-Options "nosniff"
		X-Frame-Options "SAMEORIGIN"
		Referrer-Policy "strict-origin-when-cross-origin"
	}

$SUBS_ROUTE

	@veil path $VPATH
	handle @veil {
		reverse_proxy h2c://$LISTEN {
			# Поток туннеля нельзя копить в буфере.
			flush_interval -1
			# Без жетона — та же страница 404, что на любой чужой адрес.
			@missing status 404
			handle_response @missing {
				# POST на чужой адрес у сайта — тоже 404 со страницей, не 405.
				method GET
				rewrite * /404.html
				file_server {
					status 404
				}
			}
		}
	}

	handle {
		encode zstd gzip
		file_server
	}

	handle_errors {
		@notfound expression {err.status_code} == 404
		handle @notfound {
			rewrite * /404.html
			file_server
		}
	}
}
$BRIDGE
CADDY
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
systemctl reload caddy || systemctl restart caddy

# ---- итог
echo
echo "veil-server: $(systemctl is-active veil), путь $VPATH, слушает $LISTEN"
echo "Ссылка администратора:"
/usr/local/bin/veil-server link -c /etc/veil/config.json --host "$DOMAIN" admin
echo
echo "Друзей добавлять так (сервер перечитает конфиг за 30 с, перезапуск не нужен):"
echo "  veil-server adduser -c /etc/veil/config.json --host $DOMAIN имя"
echo
echo "Порты, открытые наружу (должны остаться только 22, 80, 443):"
ss -tlnH | awk '{print $4}' | grep -vE '^(127\.|\[::1\]|\[::ffff:127)' | sort -u | tr '\n' ' '
echo
