# CTI Radar — لوحة ثغرات وأخبار الأمن السيبراني

**المشروع يعمل دون Telegram.** موقع ويب عربي متجاوب للجوال والكمبيوتر، يجمع المعلومات تلقائياً عبر GitHub Actions، وينشرها إلى GitHub Pages. لا تحتاج إبقاء جهازك مفتوحاً بعد الإعداد.

## أهم المميزات

- متابعة **CISA KEV** (ثغرات مؤكدة الاستغلال)، **NIST NVD**، تحديثات **Apple** و **Saudi CERT**، ومصادر الأخبار مثل BleepingComputer، The Hacker News، Citizen Lab، Project Zero، VulnCheck Research، Exploit-DB.
- محاولة الوصول إلى **CISA Advisories**؛ وإذا رفضت الخدمة اتصالات GitHub، يحاول المجمّع الرجوع إلى ملفات **CISA CSAF IT/OT** الرسمية كبديل **جزئي**، وليس بديلاً كاملاً عن جميع إعلانات CISA.
- تتبع **CVE وSeverity وExploitation وEPSS (إذا توفر)**، روابط المصادر، وتوصيات SOC عامة مرتبطة بنوع الثغرة.
- **تجميع النتائج ذات CVE نفسه في بطاقة واحدة** بدلاً من تكرار إشعارات المصادر، مع الاحتفاظ بروابط متعددة.
- بحث، فلاتر، ترتيب، Apple/iOS، وحفظ العناصر في متصفحك.
- حفظ آخر **30 يوماً** من النتائج، وإظهار آخر وقت تحديث وحالة المصادر المتعطلة.
- تحديث المصادر تقريباً **كل ساعة** عبر GitHub Actions، والصفحة المفتوحة تعيد قراءة التحديث كل **5 دقائق**.
- إشعارات المتصفح **فقط عندما تكون اللوحة مفتوحة ومسموحاً لها بالإشعار** في متصفح يدعم Notification API. **لا توجد إشعارات Push موثوقة عندما يكون الموقع مغلقاً.**

## مهم قبل البدء — GitHub Pages وخصوصية البيانات

بحسب توثيق GitHub، حساب **GitHub Free** يسمح بـ Pages في **Public Repository**. إذا كنت على GitHub Pro أو خطة أخرى تدعم Pages لمستودع Private فقد تستطيع استخدامه. **موقع GitHub Pages المنشور عام حتى عندما يكون المستودع Private**؛ لذا لا تعرض بيانات عملاء أو أسرار أو IOCs داخلية أو API Tokens في ملفات الموقع. المشروع يحفظ الأخبار العامة فقط.

**أنصحك بإنشاء Repository جديد** اسمه `CTI-Radar-Dashboard` وعدم خلطه بمستودع Telegram القديم. لا تحذف مستودع Telegram حتى تتأكد أن الموقع الجديد يعمل.

## الطريقة الأسهل لتشغيله عبر GitHub (بدون تشغيل الكمبيوتر)

1. حمّل `CTI_Radar_Dashboard.zip` وفك الضغط على Windows.
2. افتح https://github.com/new وأنشئ مستودعاً **Public** جديداً باسم `CTI-Radar-Dashboard`، دون إضافة README عند إنشائه.
3. ارفع **محتويات المجلد المستخرج** إلى **جذر** المستودع (ليس ملف ZIP). تأكد من وجود الملفات التالية في أماكنها:

   ```text
   collect.py
   sources.py
   requirements.txt
   site/index.html
   site/assets/app.js
   site/assets/style.css
   site/data/feed.json
   tests/test_dashboard.py
   .github/workflows/cti-dashboard.yml
   ```

   **مهم:** GitHub Web Upload قد يضع الملفات المخفية في غير مسارها. تأكد من ظهور `.github/workflows/cti-dashboard.yml`.
4. من المستودع افتح **Settings → Pages**. تحت **Build and deployment** اجعل **Source = GitHub Actions**.
5. افتح **Settings → Actions → General**، وتحقق من السماح لتشغيل Workflows، وأن **Workflow permissions = Read and write permissions** إذا كانت إعدادات المؤسسة تمنع ذلك. الملف نفسه يطلب `contents: write` و `pages: write` و `id-token: write`.
6. افتح **Actions → CTI RADAR - Collect and Publish → Run workflow**، واختر فرع `main`.
7. افتح سجل الـWorkflow وتأكد من نجاح **Run tests → Collect CTI sources → Persist archive → Deploy dashboard**. بعد نجاح النشر ستجد رابط الموقع في **Settings → Pages** أو في صفحة تشغيل Actions. غالباً يكون على نمط:

   `https://YOUR_USERNAME.github.io/CTI-Radar-Dashboard/`

   هذا **مثال لنمط الرابط**؛ لا يعتبر موقعك منشوراً حتى ترى نجاح Deploy.
8. بعدها يعمل Schedule تقريباً كل ساعة حتى عندما يكون جهازك مقفلاً. قد يؤخر GitHub بعض التشغيلات أو يسقطها، ولا توجد ضمانة لوقت لحظي.

### أول تشغيل

تظهر البيانات الحقيقية بعد أول تشغيل ناجح. إذا ظهر "بانتظار أول تقرير"، راجع **Actions**. لا تضف بيانات تجريبية إلى ملف `site/data/feed.json` لأن هذا الملف هو الأرشيف الفعلي.

### لا تعدّل ملف الأرشيف دون حاجة

`site/data/feed.json` يحتوي تاريخ العناصر والمصادر. لا تحذفه أو تستبدله بملف فارغ؛ المجمّع يتوقف إذا وجد حالة مفقودة أو تالفة بدلاً من مسح بياناتك. عملية GitHub Actions تحفظه تلقائياً مع كل تحديث.

## تشغيل نسخة محلية على Windows (مع ملاحظة أن التحديث التلقائي من GitHub لا يحتاجه)

افتح PowerShell داخل المجلد:

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python collect.py --check
python -m http.server 8000 -d site
```

ثم افتح http://localhost:8000 . سيفتح الموقع دون أخبار حقيقية قبل أول جمع ناجح. إذا أردت جمع المصادر **محلياً**، نفّذ `python collect.py` مع اتصال إنترنت فعّال، وسيحدّث `site/data/feed.json`.

## المصادر الاختيارية

للحصول على بيانات إضافية من NVD/OpenCVE/VulnCheck يمكن إضافة GitHub Actions Secrets اختيارية:

- `NVD_API_KEY`
- `OPENCVE_TOKEN`
- `VULNCHECK_API_TOKEN`

**لا تحتاج أي مفتاح لتشغيل الإصدار الأساسي**. لا تضع Secret في `site/` أو ملفات HTML/JavaScript أو داخل GitHub commits.

## هل الموقع يرسل إشعارات مثل Telegram؟

**ليس بنفس الطريقة.** يجمع ويعرض تلقائياً ويظل متاحاً باستمرار، لكن الإشعارات الفورية خارج المتصفح تتطلب نظام Push/Email مستقل. زر «إشعارات المتصفح» يعمل فقط عند دعم المتصفح وفتح اللوحة؛ لا تدّعِ أنه يقدم تنبيهات مغلقة التطبيق على iPhone.

## معالجة المشاكل

| المشكلة | الإجراء |
|---|---|
| فشل `Collect CTI sources` | افتح Logs، راجع المصدر الذي فشل وبيانات الشبكة؛ إذا فشلت كل المصادر تُحفظ بيانات التقرير القديم |
| GitHub Pages غير متوفر | تأكد أن المستودع Public على GitHub Free وأن Source = GitHub Actions |
| صفحة `404` | راجع نجاح Deploy والفرع وإعداد Pages وانتظر انتشار الموقع |
| بعض مصادر RSS ترجع `403` | متوقع أحياناً؛ تظهر في Failed Sources وتستمر بقية المصادر |
| مشاكل `NVD 429` | أضف `NVD_API_KEY` اختياريًا واحترم حدود المعدل |
| بيانات قديمة | تحقق من آخر Schedule run؛ الجدولة ليست خدمة فورية مضمونة |
| تغييرات لا تظهر | اضغط تحديث داخل الموقع؛ صفحة الويب تطلب Feed بـ `cache: no-store` |
| `git push` فشل | تحقق من GitHub workflow permissions وBranch Protection |

## حدود التحقق

تم اختبار Python Unit Tests ومنطق دمج المصادر والحماية من فقد الأرشيف، وفحص JavaScript syntax، وفحص إعدادات الموقع محلياً. لم يُنشر المشروع فعلياً على حسابك، ولم تُجرَ عملية جمع حي لجميع المصادر من بيئة GitHub الخاصة بك حتى الآن. يجب التحقق من التشغيل الأول.
