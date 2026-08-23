<div align="center">

<img src="docs/assets/logo.png" width="96" alt="">

# Aurora VPN

**Открытый VPN-клиент для VLESS, VMess, Trojan, Shadowsocks, Hysteria2 и TUIC.**<br>
Режим TUN, раздельное туннелирование по приложениям и маршрутизация по правилам — Windows, Android, Linux и macOS.

[![Релиз](https://img.shields.io/github/v/release/JustRin/aurora-vpn?style=flat-square&color=7c3aed&label=%D1%80%D0%B5%D0%BB%D0%B8%D0%B7)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Загрузки](https://img.shields.io/github/downloads/JustRin/aurora-vpn/total?style=flat-square&color=7c3aed&label=%D0%B7%D0%B0%D0%B3%D1%80%D1%83%D0%B7%D0%BA%D0%B8)](https://github.com/JustRin/aurora-vpn/releases)
[![Лицензия](https://img.shields.io/badge/%D0%BB%D0%B8%D1%86%D0%B5%D0%BD%D0%B7%D0%B8%D1%8F-MIT-7c3aed?style=flat-square)](LICENSE)
[![Ядро](https://img.shields.io/badge/%D1%8F%D0%B4%D1%80%D0%BE-sing--box%20%2B%20Xray-22d3ee?style=flat-square)](docs/architecture.ru.md)
[![Сайт](https://img.shields.io/badge/%D1%81%D0%B0%D0%B9%D1%82-aurora--vpn-1f2937?style=flat-square)](https://justrin.github.io/aurora-vpn/)

[English](README.md) · **Русский**

<img src="docs/screenshots/dashboard.png" width="840" alt="Aurora VPN — обзор">

</div>

## Загрузка

[![Windows](https://img.shields.io/badge/Windows-%D1%83%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D1%89%D0%B8%D0%BA_x64-0078d4?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Android](https://img.shields.io/badge/Android-APK-3ddc84?style=for-the-badge&logo=android&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Linux](https://img.shields.io/badge/Linux-AppImage_·_deb_·_rpm-e95420?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![macOS](https://img.shields.io/badge/macOS-Apple_Silicon_·_Intel-000000?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)

Все сборки и контрольные суммы — на [странице релизов](https://github.com/JustRin/aurora-vpn/releases/latest). На Windows приложение обновляется оттуда само.

<details>
<summary><b>Windows пишет «Windows защитила ваш компьютер»</b></summary>

<br>

Сборки пока не подписаны сертификатом кода, поэтому SmartScreen предупреждает о неизвестном издателе. Это отсутствие подписи, а не находка антивируса: **«Подробнее» → «Выполнить в любом случае»**.

Проект подал заявку в [SignPath Foundation](https://signpath.org) (бесплатная подпись для open source); CI уже готов подписывать релизы, как только заявку одобрят.

</details>

## Возможности

| | |
|---|---|
| **Протоколы** | VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC |
| **Шифрование** | REALITY с uTLS-отпечатком, TLS, VLESS Encryption (ML-KEM-768) |
| **Транспорты** | TCP, WebSocket, gRPC, HTTP/2, HTTPUpgrade, XHTTP |
| **Импорт** | ссылки `vless://` и другие, подписки 3x-ui / Marzban, фоновое автообновление |
| **Статус тарифа** | остаток дней и трафика прямо с панели |
| **Режимы туннеля** | TUN на всю систему или системный прокси — без прав администратора |
| **Раздельный туннель** | по приложениям: *только выбранные через VPN* или *выбранные мимо VPN* |
| **Маршрутизация** | гео-наборы RU/CN, блокировка рекламы, свои списки доменов и подсетей |
| **Переключение** | сервер и режим «по правилам»/«всё через VPN» меняются на лету, без перезапуска ядра |
| **Автозапуск** | обычный или с правами администратора через планировщик — без UAC при каждом входе |
| **Диагностика** | живой журнал ядра, замер задержки, просмотр итогового конфига |
| **Оформление** | 6 палитр и режим «как в системе», русский и английский |

## Скриншоты

| | |
|:--:|:--:|
| <img src="docs/screenshots/servers.png" alt="Серверы"><br>**Серверы** | <img src="docs/screenshots/routing.png" alt="Маршрутизация"><br>**Маршрутизация** |
| <img src="docs/screenshots/split.png" alt="Раздельный туннель"><br>**Раздельный туннель** | <img src="docs/screenshots/settings.png" alt="Настройки"><br>**Настройки** |

## Быстрый старт

1. **Установите** сборку под свою систему и запустите её.
2. **Добавьте серверы** — вставьте ссылку `vless://` / `vmess://` / … или адрес подписки из панели. Импорт разбирает всё разом, а неподдерживаемые ссылки отклоняет с объяснением, вместо того чтобы они молча сломались позже.
3. **Подключитесь.** Режим TUN уводит в туннель всю систему и требует прав администратора — приложение предложит перезапуск через UAC. Системный прокси работает и без них.

## Документация

- **[Как это устроено](docs/architecture.ru.md)** — два движка, порядок правил маршрутизации, раздельный туннель и DNS, автозапуск, Android/libbox.
- **[Сборка из исходников](docs/architecture.ru.md#сборка-из-исходников)** — требования и команды для каждой платформы.

<details>
<summary><b>Если что-то не работает</b></summary>

<br>

**Ядро сразу умирает после «Подключение…»** — откройте **«Журнал»**. Конфигурация проверяется через `sing-box check` до запуска, поэтому ошибка будет с конкретной причиной.

**Нет интернета в режиме TUN** — проверьте, не остался ли включённым системный прокси от другого клиента, и попробуйте выключить **«Строгую маршрутизацию»** (она конфликтует с VirtualBox, WSL и некоторыми античитами).

**Запущен другой VPN-клиент** — два адаптера TUN не уживаются. Hiddify и всё, что построено на sing-box, берут тот же адрес `172.19.0.1` и тот же маршрут по умолчанию; проигравший остаётся «подключённым» без трафика. Второй клиент нужно закрыть полностью: адаптер живёт, пока жив процесс.

**Сайт не открывается только в туннеле** — включите Fake-IP либо добавьте домен в **«всегда напрямую»**.

**Задержка показывается как «н/д»** — при отключённом ядре измеряется TCP-рукопожатие до сервера, поэтому «н/д» означает недоступный порт. При активном подключении замер идёт через прокси и учитывает реальный маршрут.

**Не видно остатка подписки** — панель не прислала заголовок `subscription-userinfo`. В 3x-ui он есть только у подписок; у серверов, добавленных отдельной ссылкой, статуса тарифа не существует в принципе.

</details>

## На чём построено

[sing-box](https://github.com/SagerNet/sing-box) · [Xray-core](https://github.com/XTLS/Xray-core) · [Wintun](https://www.wintun.net/) · [Slint](https://slint.dev) · [Tauri](https://tauri.app)

## Лицензия

[MIT](LICENSE) © JustRin
