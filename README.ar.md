<div align="center">

<img src="docs/assets/logo.png" width="96" alt="">

# Aurora VPN

<p dir="rtl"><b>عميل VPN مفتوح المصدر يدعم VLESS وVMess وTrojan وShadowsocks وHysteria2 وTUIC.</b><br>
وضع TUN، وتقسيم النفق لكل تطبيق على حدة، والتوجيه بالقواعد — على Windows وAndroid وLinux وmacOS.</p>

[![Release](https://img.shields.io/github/v/release/JustRin/aurora-vpn?style=flat-square&color=7c3aed&label=release)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/JustRin/aurora-vpn/total?style=flat-square&color=7c3aed)](https://github.com/JustRin/aurora-vpn/releases)
[![License](https://img.shields.io/badge/license-MIT-7c3aed?style=flat-square)](LICENSE)
[![Core](https://img.shields.io/badge/core-sing--box%20%2B%20Xray-22d3ee?style=flat-square)](docs/architecture.md)
[![Site](https://img.shields.io/badge/site-aurora--vpn-1f2937?style=flat-square)](https://justrin.github.io/aurora-vpn/)

[English](README.md) · [Русский](README.ru.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · **العربية** · [Português](README.pt.md)

<img src="docs/screenshots/dashboard.png" width="840" alt="Aurora VPN — نظرة عامة">

</div>

<div dir="rtl">

## التنزيل

<div align="center">

[![Windows](https://img.shields.io/badge/Windows-x64_installer-0078d4?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Android](https://img.shields.io/badge/Android-APK-3ddc84?style=for-the-badge&logo=android&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Linux](https://img.shields.io/badge/Linux-AppImage_·_deb_·_rpm-e95420?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![macOS](https://img.shields.io/badge/macOS-Apple_Silicon_·_Intel-000000?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)

</div>

كل النسخ ومجاميعها الاختبارية موجودة في [صفحة الإصدارات](https://github.com/JustRin/aurora-vpn/releases/latest). على Windows يحدّث التطبيق نفسه من هناك.

<details>
<summary><b>يقول Windows: «حماية الكمبيوتر بواسطة Windows»</b></summary>

<br>

النسخ غير موقّعة بشهادة توقيع برمجي بعد، ولذلك يحذّر SmartScreen من ناشر مجهول — هذا نقص في التوقيع، وليس اكتشافًا لبرنامج ضار. اضغط **«مزيد من المعلومات» ← «تشغيل على أي حال»**.

قدّم المشروع طلبًا إلى [SignPath Foundation](https://signpath.org) (توقيع برمجي مجاني للمشاريع مفتوحة المصدر)، وخط التكامل المستمر جاهز بالفعل لتوقيع الإصدارات فور الموافقة على الطلب.

</details>

## المزايا

| | |
|---|---|
| **البروتوكولات** | VLESS، VMess، Trojan، Shadowsocks، Hysteria2، TUIC |
| **الأمان** | REALITY ببصمات uTLS، وTLS، وVLESS Encryption (ML-KEM-768) |
| **طبقات النقل** | TCP، WebSocket، gRPC، HTTP/2، HTTPUpgrade، XHTTP |
| **الاستيراد** | روابط `vless://` وأخواتها، واشتراكات 3x-ui / Marzban، وتحديث تلقائي في الخلفية |
| **حالة الباقة** | الأيام والبيانات المتبقية، تُقرأ مباشرة من اللوحة |
| **أوضاع النفق** | TUN لكامل النظام، أو وكيل نظام لا يحتاج صلاحيات المسؤول |
| **تقسيم النفق** | لكل تطبيق — *هذه فقط عبر VPN* أو *كل شيء ما عدا هذه* |
| **التوجيه** | مجموعات قواعد جغرافية RU/CN، وحجب الإعلانات، وقوائم نطاقات وشبكات فرعية خاصة بك |
| **التبديل** | الخادم ووضع «القواعد / كل شيء عبر VPN» يتغيّران فورًا دون إعادة تشغيل النواة |
| **الموازن** | احتياطي، أو الأسرع مع حدّ تبديل، أو بالتناوب — يقرّر التطبيق لا urltest في النواة، فلا تتأرجح الخوادم متقاربة الزمن |
| **البدء التلقائي** | عادي، أو بصلاحيات مرتفعة عبر «برنامج جدولة المهام» — دون نافذة UAC عند كل تسجيل دخول |
| **التشخيص** | سجل حي للنواة، وقياس زمن الاستجابة، وعارض للإعداد المُولَّد |
| **المظهر** | ٦ لوحات ألوان إضافة إلى *اتّباع النظام*، وعدة لغات للواجهة |
| **Android** | ودجات الشاشة الرئيسية — زر، حالة مع السرعة، بطاقة كاملة ببيانات الجلسة ووقتها — وبلاطة في الإعدادات السريعة؛ اتصال دون فتح التطبيق |

## لقطات الشاشة

| | |
|:--:|:--:|
| <img src="docs/screenshots/servers.png" alt="الخوادم"><br>**الخوادم** | <img src="docs/screenshots/routing.png" alt="التوجيه"><br>**التوجيه** |
| <img src="docs/screenshots/split.png" alt="تقسيم النفق"><br>**تقسيم النفق** | <img src="docs/screenshots/settings.png" alt="الإعدادات"><br>**الإعدادات** |

## البدء

1. **ثبّت** النسخة المناسبة لنظامك وشغّلها.
2. **أضف الخوادم** — الصق رابط `vless://` أو `vmess://` أو غيرهما، أو عنوان اشتراك من لوحتك. يُستورد كل شيء دفعة واحدة، والروابط غير المدعومة تُرفض مع ذكر السبب بدل أن تتعطّل بصمت لاحقًا.
3. **اتّصل.** وضع TUN يوجّه النظام بأكمله ويحتاج صلاحيات المسؤول — ويعرض التطبيق إعادة تشغيل بنقرة واحدة عبر UAC. أما وضع وكيل النظام فيعمل دونها.

## التوثيق

- **[كيف يعمل](docs/architecture.md)** (بالإنجليزية) — بنية المحرّكين، وترتيب قواعد التوجيه، وتقسيم النفق وDNS، والبدء التلقائي، وAndroid/libbox.
- **[البناء من المصدر](docs/architecture.md#building-from-source)** (بالإنجليزية) — المتطلبات والأوامر لكل نظام.

<details>
<summary><b>شيء ما لا يعمل</b></summary>

<br>

**النواة تتوقف مباشرة بعد «جارٍ الاتصال…»** — افتح **السجل**. يُتحقَّق من الإعداد بأمر `sing-box check` قبل التشغيل، لذا يأتي الفشل دائمًا بسبب محدّد.

**لا إنترنت في وضع TUN** — تأكد من أن عميلًا آخر لم يترك وكيل نظام مفعّلًا، وجرّب إيقاف *التوجيه الصارم* (فهو يتعارض مع VirtualBox وWSL وبعض أنظمة مكافحة الغش).

**عميل VPN آخر قيد التشغيل** — محوّلا TUN لا يتعايشان. فـ Hiddify وكل ما يقوم على sing-box يطالب بالعنوان `172.19.0.1` نفسه وبالمسار الافتراضي نفسه، والخاسر يبقى «متصلًا» بلا حركة بيانات. أغلق العميل الآخر تمامًا — فمحوّله يبقى حيًّا ما بقيت عمليته حية.

**موقع بعينه يفشل داخل النفق فقط** — فعّل Fake-IP، أو أضف النطاق إلى *الاتصال المباشر دائمًا*.

**زمن الاستجابة يظهر «n/a»** — عند إيقاف النواة يُقاس تصافح TCP مع الخادم، لذا تعني «n/a» أن المنفذ غير قابل للوصول. وأثناء الاتصال يمرّ القياس عبر الوكيل ويعكس المسار الحقيقي.

**لا تظهر حالة الاشتراك** — لم ترسل اللوحة ترويسة `subscription-userinfo`. في 3x-ui توجد هذه الترويسة للاشتراكات فقط، ولا توجد أبدًا للخوادم المضافة برابط مفرد.

</details>

## مبني على

[sing-box](https://github.com/SagerNet/sing-box) · [Xray-core](https://github.com/XTLS/Xray-core) · [Wintun](https://www.wintun.net/) · [Slint](https://slint.dev) · [Tauri](https://tauri.app)

## الرخصة

[MIT](LICENSE) © JustRin

</div>
