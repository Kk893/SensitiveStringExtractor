# SensitiveStringExtractor
कैसे चलाएँ

सिस्टम पर Python 3 इंस्टॉल होना चाहिए (कोई external लाइब्रेरी की ज़रूरत नहीं)

फाइल सेव करने के बाद डबल-क्लिक करें या टर्मिनल/कमांड प्रॉम्प्ट में चलाएँ:

python SensitiveStringExtractor.py


“Browse…” से अपना build/output फ़ोल्डर चुनें (जिसमें .html/.css/.js हैं) → “Scan”.

फीचर्स

JS: single/double/backtick string literals निकालता है (template literals में ${…} वाले skip).

HTML: टेक्स्ट नोड्स और common attributes (href/src/content/action/value/data*) निकालता है।

CSS: url(...), content:"..." और quoted strings.

Sensitive detection: AWS/Google/Stripe/Slack/Twilio keys, JWT, private key blocks, secret-like URL params, emails, IPv4 आदि।

GUI में severity रंग-कोडेड, कॉपी selected, CSV export, severity फ़िल्टर।

अगर आप चाहें तो मैं इसमें extra checks (जैसे custom regexes, phone/ Aadhaar patterns, env-style KEY=VALUE grep, min-length thresholds) भी जोड़ दूँ या ZIP फ़ाइल इनपुट सपोर्ट कर दूँ।
