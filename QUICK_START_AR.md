# تشغيل CTI RADAR خلال 5 خطوات

1. حمّل ملف ZIP وفك ضغطه.
2. أنشئ **Public GitHub Repository** جديد باسم `CTI-Radar-Dashboard`. **لا تستخدم مستودع Telegram القديم**.
3. ارفع محتويات المشروع بما فيها مجلد `.github/workflows` إلى جذر المستودع.
4. افتح `Settings → Pages → Build and deployment → Source = GitHub Actions`.
5. افتح `Actions → CTI RADAR - Collect and Publish → Run workflow`، وبعد نجاح **Deploy dashboard** افتح رابط **Settings → Pages**.

الموقع بعد النشر يجمع الأخبار تقريباً كل ساعة دون تشغيل جهازك. على حساب GitHub Free، الاستضافة تتطلب مستودعاً عاماً. بيانات الموقع عامة؛ لا ترفع فيه أي معلومات داخلية أو رموز وصول.

**أوقف البوت القديم إن لم تعد تريده:** ادخل مستودع Telegram القديم → Actions → اختر Workflow القديم → قائمة `...` → `Disable workflow`. لا تحذف Telegram القديم قبل التحقق من أول جمع بيانات للموقع.

**الفرق في التنبيهات:** اللوحة تعرض أخباراً جديدة تلقائياً، وزر إشعارات المتصفح ينبه عندما تكون الصفحة مفتوحة فقط. لا توجد إشعارات Push إلى الهاتف وهو مغلق.

للتفاصيل واستكشاف الأعطال راجع `README_AR.md`.
