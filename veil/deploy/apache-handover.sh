#!/usr/bin/env bash
# Отдать 80 и 443 от Apache к Caddy, когда Apache уже держит сайт на этом
# сервере (так было на NL). Остальные порты Apache не трогаются. Копия
# /etc/apache2 и скрипт отката кладутся рядом:
#
#   bash apache-handover.sh            перевести
#   bash /root/veil/rollback-apache.sh вернуть как было
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "запускать от root" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP="$HERE/apache2.bak-$TS"

cp -a /etc/apache2 "$BACKUP"
cat > "$HERE/rollback-apache.sh" <<ROLLBACK
#!/usr/bin/env bash
# Вернуть Apache на 80 и 443 (копия от $TS) и остановить Caddy.
set -e
systemctl stop caddy 2>/dev/null || true
systemctl disable caddy 2>/dev/null || true
rm -rf /etc/apache2
cp -a "$BACKUP" /etc/apache2
systemctl restart apache2
echo "Apache снова на 80/443"
ROLLBACK
chmod +x "$HERE/rollback-apache.sh"

# Listen 80 и Listen 443 закомментировать; прочие (например, 1230) остаются.
sed -i -E 's/^([[:space:]]*)Listen[[:space:]]+(80|443)([[:space:]].*)?$/\1# Caddy: Listen \2\3/' /etc/apache2/ports.conf
# Хосты на 80/443 без Listen не нужны, но и не мешают — выключаем для ясности.
for site in /etc/apache2/sites-enabled/*.conf; do
  if grep -qE '<VirtualHost[^>]*:(80|443)>' "$site"; then
    a2dissite -q "$(basename "$site" .conf)"
  fi
done
apache2ctl configtest
systemctl restart apache2
echo "Apache слушает теперь:"
ss -tlnpH | grep apache2 | awk '{print $4}' | sort -u
echo "Откат: bash $HERE/rollback-apache.sh"
