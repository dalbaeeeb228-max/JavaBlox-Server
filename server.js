// server.js — JavaBlox Server
// Ключи и токены: заполни своими
const express = require('express');
const crypto = require('crypto');
const http = require('http');
const path = require('path');
const fsSync = require('fs');

const app = express();
const PORT = process.env.PORT || 8080;

// ==== СЕКРЕТЫ (заполни своими) ====
const ADMIN_PASSWORD = '';                    // <-- свой пароль админа
const ALLSTORE_SECRET = '';                   // <-- свой секрет AllStore
const PM_SECRET = '';                         // <-- свой секрет для профилей

// ==== АДРЕСА (не менять) ====
const ALLSTORE_HOST = 'alldevicestore.ru';
const ALLSTORE_LOGIN_PATH = '/api/v3/auth/login';

// ==== производные значения ====
const ADMIN_KEY_HASH = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest('hex');

const ALLSTORE_KEY = crypto.createHash('sha256').update(ALLSTORE_SECRET).digest();
const ALLSTORE_IV  = crypto.createHash('md5').update(ALLSTORE_SECRET).digest();

const PM_KEY = crypto.createHash('sha256').update(PM_SECRET).digest();
const PM_IV  = crypto.createHash('md5').update(PM_SECRET).digest();

// ==== шифрование/дешифрование ====
function encAes(text, key, iv) {
    const c = crypto.createCipheriv('aes-256-cbc', key, iv);
    return c.update(text, 'utf8', 'hex') + c.final('hex');
}
function decAes(enc, key, iv) {
    const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
    return d.update(enc, 'hex', 'utf8') + d.final('utf8');
}
function encUrl(t) { return encAes(t, ALLSTORE_KEY, ALLSTORE_IV); }
function decUrl(e) { return decAes(e, ALLSTORE_KEY, ALLSTORE_IV); }

// производные эндпоинты (шифруются на лету)
const ALLSTORE_HOST_ENC = encUrl(ALLSTORE_HOST);
const ALLSTORE_LOGIN_PATH_ENC = encUrl(ALLSTORE_LOGIN_PATH);

// ==== пути ====
const BANS_DIR = path.join(__dirname, 'bans');
const FRIENDS_DIR = path.join(__dirname, 'friends');
const PROFILES_DIR = path.join(__dirname, 'profiles');
const USER_PLACES_DIR = path.join(__dirname, 'user_places');
const USER_PLACES_FILE = path.join(USER_PLACES_DIR, 'places.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');

for (const d of [BANS_DIR, FRIENDS_DIR, PROFILES_DIR, USER_PLACES_DIR]) {
    try { fsSync.mkdirSync(d, { recursive: true }); } catch (e) {}
}
if (!fsSync.existsSync(USER_PLACES_FILE)) fsSync.writeFileSync(USER_PLACES_FILE, '[]', 'utf-8');

// ==== middleware ====
app.use((req, res, next) => {
    req.setTimeout(30000);
    res.setTimeout(30000);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    next();
});
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.json({ limit: '10mb' }));
app.use((req, res, next) => {
    const url = req.url.toLowerCase();
    if (url.includes('..') || url.includes('~') || url.includes('\\')) return res.status(403).send('ERROR|Доступ запрещён');
    const forbidden = ['.js', '.json', '.log', '.env', '.git', '.md', '.sql', '.bak'];
    for (const ext of forbidden) if (url.endsWith(ext)) return res.status(403).send('ERROR|Доступ запрещён');
    next();
});
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

// ==== in-memory ====
const players = new Map();
const chatMessages = new Map();
const soundEvents = new Map();
const sessions = new Map();
const chatRateLimits = new Map();
const joinRateLimits = new Map();
const bannedPlayers = new Map();
const bannedIds = new Map();
const suspiciousActions = new Map();

let nextChatId = 1;
let nextSoundId = 1;

const PLAYER_TIMEOUT = 30000;
const MAX_CHAT_MESSAGES = 30;
const MAX_SOUND_EVENTS = 10;
const CHAT_MESSAGE_TIMEOUT = 2 * 60 * 1000;
const SOUND_EVENT_TIMEOUT = 10 * 1000;
const MAX_CHAT_RATE = 5;
const MAX_JOIN_RATE = 50;
const SUSPICIOUS_PACKET_THRESHOLD = 20;
const BAN_DURATION = 7 * 24 * 60 * 60 * 1000;

// ==== sessions ====
function saveSessions() { try { fsSync.writeFileSync(SESSIONS_FILE, JSON.stringify([...sessions.entries()], null, 2), 'utf-8'); } catch (e) {} }
function loadSessions() {
    try {
        if (fsSync.existsSync(SESSIONS_FILE)) {
            const data = JSON.parse(fsSync.readFileSync(SESSIONS_FILE, 'utf-8'));
            for (const [k, s] of data) {
                if (typeof s.skin !== 'number') s.skin = 0;
                sessions.set(k, s);
            }
        }
    } catch (e) {}
}
function createSession(k, d) { sessions.set(k, d); saveSessions(); }
loadSessions();

// ==== профили ====
function profileFile(u) { return path.join(PROFILES_DIR, u + '.json'); }
function saveAllStoreProfile(u, user) {
    try {
        const enc = encAes(JSON.stringify(user), PM_KEY, PM_IV);
        fsSync.writeFileSync(profileFile(u), 'ENC:' + enc, 'utf-8');
    } catch (e) {}
}
function loadAllStoreProfile(u) {
    try {
        const f = profileFile(u);
        if (fsSync.existsSync(f)) {
            const c = fsSync.readFileSync(f, 'utf-8');
            if (c.indexOf('ENC:') === 0) {
                return JSON.parse(decAes(c.substring(4), PM_KEY, PM_IV));
            }
        }
    } catch (e) {}
    return null;
}

// ==== друзья ====
function friendsFile(u) { return path.join(FRIENDS_DIR, u + '.json'); }
function loadFriends(u) {
    try {
        const f = friendsFile(u);
        if (fsSync.existsSync(f)) return JSON.parse(fsSync.readFileSync(f, 'utf-8'));
    } catch (e) {}
    return { friends: [], incoming: [], outgoing: [] };
}
function saveFriends(u, d) { try { fsSync.writeFileSync(friendsFile(u), JSON.stringify(d, null, 2), 'utf-8'); } catch (e) {} }

// ==== плейсы ====
function loadUserPlaces() {
    try {
        const data = JSON.parse(fsSync.readFileSync(USER_PLACES_FILE, 'utf-8'));
        return Array.isArray(data) ? data : [];
    } catch (e) { return []; }
}
function saveUserPlaces(list) { try { fsSync.writeFileSync(USER_PLACES_FILE, JSON.stringify(list, null, 2), 'utf-8'); } catch (e) {} }
function findUserPlace(id) { return loadUserPlaces().find(p => p.id === id) || null; }
function userPlaceMapPath(id) { return path.join(USER_PLACES_DIR, id + '.txt'); }

// ==== утилиты ====
function sanitizeString(s, max) { if (typeof s !== 'string') return ''; return s.substring(0, max || 100).replace(/[<>]/g, ''); }
function isValidPlaceId(id) { return /^[a-zA-Z0-9_\-]+$/.test(id); }
function isValidJavabloxId(id) { return /^javablox_id[a-f0-9]{6}$/.test(id) || /^javablox_id\d{3,12}$/.test(id); }

function getSessionByKey(k) { if (!k || typeof k !== 'string' || k.length !== 32) return null; return sessions.get(k) || null; }
function getUsernameByKey(k) { const s = getSessionByKey(k); if (!s) return null; s.lastActivity = Date.now(); return s.username; }
function generateGuestName() { let n; do { n = 'Guest' + Math.floor(100000 + Math.random() * 900000); } while ([...sessions.values()].some(s => s.username === n)); return n; }
function generateJavabloxId() { let id; do { id = 'javablox_id' + Math.floor(1000 + Math.random() * 9000000); } while ([...sessions.values()].some(s => s.javabloxId === id)); return id; }
function generateJavabloxIdFromId(aid) { return 'javablox_id' + crypto.createHash('md5').update(String(aid)).digest('hex').substring(0, 6); }

// ==== баны ====
function saveBanData() {
    try {
        fsSync.writeFileSync(path.join(BANS_DIR, 'bans.json'), JSON.stringify({
            players: [...bannedPlayers.entries()], ids: [...bannedIds.entries()]
        }, null, 2), 'utf-8');
    } catch (e) {}
}
function loadBanData() {
    try {
        const f = path.join(BANS_DIR, 'bans.json');
        if (fsSync.existsSync(f)) {
            const d = JSON.parse(fsSync.readFileSync(f, 'utf-8'));
            if (d.players) for (const [k, v] of d.players) bannedPlayers.set(k, v);
            if (d.ids) for (const [k, v] of d.ids) bannedIds.set(k, v);
        }
    } catch (e) {}
}
loadBanData();

function isBanned(u, jid) {
    const now = Date.now();
    if (bannedPlayers.has(u)) { const b = bannedPlayers.get(u); if (now < b.expiresAt) return b; bannedPlayers.delete(u); }
    if (bannedIds.has(jid)) { const b = bannedIds.get(jid); if (now < b.expiresAt) return b; bannedIds.delete(jid); }
    return null;
}
function banPlayer(u, jid, reason) {
    const now = Date.now();
    const info = { reason, bannedAt: now, expiresAt: now + BAN_DURATION, username: u, javabloxId: jid };
    bannedPlayers.set(u, info); bannedIds.set(jid, info);
    for (const [k, s] of sessions.entries()) if (s.username === u) sessions.delete(k);
    saveSessions();
    for (const [p, pl] of players.entries()) { pl.delete(u); if (pl.size === 0) players.delete(p); }
    chatRateLimits.delete(u); joinRateLimits.delete(u); saveBanData();
}
function addSuspiciousAction(u, jid, action) {
    const c = (suspiciousActions.get(u) || 0) + 1;
    suspiciousActions.set(u, c);
    if (c >= SUSPICIOUS_PACKET_THRESHOLD) { banPlayer(u, jid, 'Suspicious: ' + action); suspiciousActions.set(u, 0); return true; }
    return false;
}
function checkChatRate(u) {
    const now = Date.now();
    const r = chatRateLimits.get(u) || { count: 0, lastReset: now };
    if (now - r.lastReset > 1000) { r.count = 0; r.lastReset = now; }
    r.count++; chatRateLimits.set(u, r); return r.count <= MAX_CHAT_RATE;
}
function checkJoinRate(u) {
    const now = Date.now();
    const r = joinRateLimits.get(u) || { count: 0, lastReset: now };
    if (now - r.lastReset > 1000) { r.count = 0; r.lastReset = now; }
    r.count++; joinRateLimits.set(u, r); return r.count <= MAX_JOIN_RATE;
}

// ==== уборка ====
setInterval(() => {
    const now = Date.now();
    for (const [p, pl] of players) {
        for (const [u, pd] of pl) if (now - pd.lastSeen > PLAYER_TIMEOUT) pl.delete(u);
        if (pl.size === 0) players.delete(p);
    }
}, 10000);
setInterval(() => {
    const now = Date.now();
    for (const [p, m] of chatMessages) {
        const f = m.filter(x => now - x.createdAt < CHAT_MESSAGE_TIMEOUT);
        chatMessages.set(p, f);
        if (f.length === 0) chatMessages.delete(p);
    }
}, 15000);
setInterval(() => {
    const now = Date.now();
    for (const [p, s] of soundEvents) {
        const f = s.filter(x => now - x.createdAt < SOUND_EVENT_TIMEOUT);
        soundEvents.set(p, f);
        if (f.length === 0) soundEvents.delete(p);
    }
}, 5000);

// ==== ответ в стиле Java ====
const sendJavaResponse = (res, text) => {
    const safeText = text != null ? String(text) : '';
    const buf = Buffer.from(safeText, 'utf-8');
    res.writeHead(200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Length': buf.length,
        'Connection': 'close',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
    });
    res.end(buf);
};

// ==== авторизация AllStore ====
function allStoreLogin(username, password, callback) {
    // если секрет пустой — AllStore отключён
    if (!ALLSTORE_SECRET || ALLSTORE_SECRET.length === 0) return callback(null);

    const postData = JSON.stringify({ username, password, client_name: 'JavaBlox' });
    const hostname = decUrl(ALLSTORE_HOST_ENC);
    const loginPath = decUrl(ALLSTORE_LOGIN_PATH_ENC);
    const options = {
        hostname, port: 80, path: loginPath, method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
            'Accept': 'application/json',
            'User-Agent': 'JavaBlox-Client/1.0'
        }
    };
    const req = http.request(options, (r) => {
        let body = '';
        r.on('data', c => body += c);
        r.on('end', () => {
            try {
                const j = JSON.parse(body);
                if (j.status !== 'ok' || !j.data || !j.data.user) return callback(null);
                callback(j.data);
            } catch (e) { callback(null); }
        });
    });
    req.on('error', () => callback(null));
    req.setTimeout(10000, () => { req.abort(); callback(null); });
    req.write(postData); req.end();
}

// ================= СПИСОК ПЛЕЙСОВ =================
app.get('/places', (req, res) => {
    try {
        const entries = [];
        for (const p of loadUserPlaces()) {
            if ((p.mode || '').toLowerCase() !== 'sandbox') continue;
            entries.push(`${p.id}|${p.name}|${p.mode}|${p.owner || ''}`);
        }
        if (entries.length === 0) return sendJavaResponse(res, 'ERROR|Нет плейсов');
        return sendJavaResponse(res, 'OK|' + entries.join(';'));
    } catch (e) {
        return sendJavaResponse(res, 'ERROR|Ошибка чтения');
    }
});

// ================= СОЗДАНИЕ / УДАЛЕНИЕ =================
app.post('/create_place', (req, res) => {
    const data = { ...req.query, ...req.body };
    const key  = data.key || '';
    const name = sanitizeString((data.name || '').trim(), 32);

    if (!name || name.length < 3) return sendJavaResponse(res, 'ERROR|Название от 3 символов');
    if (!/^[A-Za-z0-9_а-яА-ЯЁё\- ]+$/.test(name)) return sendJavaResponse(res, 'ERROR|Недопустимые символы');

    const session = getSessionByKey(key);
    if (!session) return sendJavaResponse(res, 'ERROR|Не авторизован');
    if (session.isGuest) return sendJavaResponse(res, 'ERROR|Только для AllStore');
    if (!session.username) return sendJavaResponse(res, 'ERROR|Нет имени');

    let id = name.toLowerCase().replace(/[^a-z0-9а-яё]+/g, '_').slice(0, 24);
    if (id.length === 0) id = 'place';

    const list = loadUserPlaces();
    let base = id, n = 1;
    while (list.some(p => p.id === id)) { id = base + '_' + n; n++; }

    list.push({ id, name, mode: 'sandbox', owner: session.username, createdAt: Date.now() });
    saveUserPlaces(list);

    try { fsSync.writeFileSync(userPlaceMapPath(id), 'MODE=SANDBOX\nSPAWN=100,100\n', 'utf-8'); } catch (e) {}

    return sendJavaResponse(res, 'OK|' + id);
});

app.post('/delete_place', (req, res) => {
    const data = { ...req.query, ...req.body };
    const key = data.key || '';
    const id  = sanitizeString((data.id || '').trim(), 50);

    const session = getSessionByKey(key);
    if (!session) return sendJavaResponse(res, 'ERROR|Не авторизован');

    const list = loadUserPlaces();
    const idx = list.findIndex(p => p.id === id);
    if (idx < 0) return sendJavaResponse(res, 'ERROR|Плейс не найден');
    if (list[idx].owner !== session.username) return sendJavaResponse(res, 'ERROR|Это не ваш плейс');

    list.splice(idx, 1);
    saveUserPlaces(list);
    try { fsSync.unlinkSync(userPlaceMapPath(id)); } catch (e) {}
    return sendJavaResponse(res, 'OK');
});

// ================= КАРТА =================
app.get('/place_map', (req, res) => {
    const id = sanitizeString(String(req.query.place || ''), 50);
    if (!id || !isValidPlaceId(id)) return sendJavaResponse(res, 'ERROR|Неверный плейс');

    const p = userPlaceMapPath(id);
    if (!fsSync.existsSync(p)) {
        const tpl = 'MODE=SANDBOX\nSPAWN=100,100\n';
        try { fsSync.writeFileSync(p, tpl, 'utf-8'); } catch (e) {}
        return sendJavaResponse(res, tpl);
    }
    try { return sendJavaResponse(res, fsSync.readFileSync(p, 'utf-8')); }
    catch (e) { return sendJavaResponse(res, 'ERROR|Ошибка чтения'); }
});

app.post('/place_map_save', (req, res) => {
    const data = { ...req.query, ...req.body };
    const key  = data.key || '';
    const id   = sanitizeString((data.place || '').trim(), 50);
    const body = typeof data.map === 'string' ? data.map : '';

    const session = getSessionByKey(key);
    if (!session) return sendJavaResponse(res, 'ERROR|Не авторизован');

    const place = findUserPlace(id);
    if (!place) return sendJavaResponse(res, 'ERROR|Плейс не найден');
    if (place.owner !== session.username) return sendJavaResponse(res, 'ERROR|Это не ваш плейс');
    if (body.length > 500000) return sendJavaResponse(res, 'ERROR|Слишком большой файл');

    const lines = body.split('\n').filter(l => /^(MODE|SPAWN|BLOCK)=/.test(l.trim()));
    try { fsSync.writeFileSync(userPlaceMapPath(id), lines.join('\n') + '\n', 'utf-8'); }
    catch (e) { return sendJavaResponse(res, 'ERROR|Ошибка записи'); }
    return sendJavaResponse(res, 'OK');
});

// ================= СКИН =================
app.post('/skin_set', (req, res) => {
    const data = { ...req.query, ...req.body };
    const session = getSessionByKey(data.key);
    if (!session) return sendJavaResponse(res, 'ERROR|Не авторизован');

    const s = parseInt(data.skin);
    if (isNaN(s) || s < 0 || s > 63) return sendJavaResponse(res, 'ERROR|Неверный скин');

    session.skin = s;
    saveSessions();
    return sendJavaResponse(res, 'OK');
});

// ================= AUTH =================
app.all('/auth', (req, res) => {
    const data = { ...req.query, ...req.body };
    const action = data.action;

    if (action === 'restore_guest' || action === 'guest') {
        let username = sanitizeString(data.username || '', 15);
        let javabloxId = sanitizeString(data.javablox_id || '', 30);
        const session = sanitizeString(data.session || '', 32);

        if (session && sessions.has(session)) {
            const e = sessions.get(session);
            if (isBanned(e.username, e.javabloxId)) return sendJavaResponse(res, 'ERROR|Вы забанены');
            return sendJavaResponse(res, `SUCCESS|${session}|${e.username}|${e.javabloxId}`);
        }
        if (action === 'restore_guest' && username.length >= 3 && isValidJavabloxId(javabloxId)) {
            if (isBanned(username, javabloxId)) return sendJavaResponse(res, 'ERROR|Вы забанены');
            const k = crypto.randomBytes(16).toString('hex');
            createSession(k, { username, javabloxId, skin: 0, createdAt: Date.now(), lastActivity: Date.now(), isGuest: true });
            return sendJavaResponse(res, `SUCCESS|${k}|${username}|${javabloxId}`);
        }
        if (username.length < 3) username = generateGuestName();
        if (!isValidJavabloxId(javabloxId)) javabloxId = generateJavabloxId();
        if (isBanned(username, javabloxId)) return sendJavaResponse(res, 'ERROR|Вы забанены');
        const k = crypto.randomBytes(16).toString('hex');
        createSession(k, { username, javabloxId, skin: 0, createdAt: Date.now(), lastActivity: Date.now(), isGuest: true });
        return sendJavaResponse(res, `SUCCESS|${k}|${username}|${javabloxId}`);
    }

    if (action === 'restore_allstore') {
        const username = sanitizeString(data.username || '', 15);
        const javabloxId = sanitizeString(data.javablox_id || '', 30);
        const session = sanitizeString(data.session || '', 32);

        if (session && sessions.has(session)) {
            const e = sessions.get(session);
            if (isBanned(e.username, e.javabloxId)) return sendJavaResponse(res, 'ERROR|Вы забанены');
            return sendJavaResponse(res, `SUCCESS|${session}|${e.username}|${e.javabloxId}`);
        }
        if (username.length >= 3 && isValidJavabloxId(javabloxId)) {
            if (isBanned(username, javabloxId)) return sendJavaResponse(res, 'ERROR|Вы забанены');
            const saved = loadAllStoreProfile(username);
            const k = crypto.randomBytes(16).toString('hex');
            createSession(k, { username, javabloxId, skin: 0, allstoreUser: saved, createdAt: Date.now(), lastActivity: Date.now(), isGuest: false });
            return sendJavaResponse(res, `SUCCESS|${k}|${username}|${javabloxId}`);
        }
        return sendJavaResponse(res, 'ERROR|Сессия истекла');
    }

    if (action === 'allstore') {
        const user = sanitizeString(data.allstore_user || '', 30);
        const pass = data.allstore_pass || '';
        if (!user || !pass) return sendJavaResponse(res, 'ERROR|Введи ник и пароль');

        allStoreLogin(user, pass, (authData) => {
            if (!authData || !authData.user) return sendJavaResponse(res, 'ERROR|AllStore недоступен');
            const u = authData.user;
            const username = sanitizeString(u.username || user, 15);
            if (username.length < 3) return sendJavaResponse(res, 'ERROR|Неверный ник AllStore');
            const javabloxId = generateJavabloxIdFromId(u.id || '');
            if (isBanned(username, javabloxId)) return sendJavaResponse(res, 'ERROR|Вы забанены');
            saveAllStoreProfile(username, u);
            const k = crypto.randomBytes(16).toString('hex');
            createSession(k, { username, javabloxId, skin: 0, allstoreId: u.id || '', allstoreUser: u, createdAt: Date.now(), lastActivity: Date.now(), isGuest: false });
            return sendJavaResponse(res, `SUCCESS|${k}|${username}|${javabloxId}`);
        });
        return;
    }

    sendJavaResponse(res, 'ERROR|Неизвестное действие');
});

// ================= ПРОФИЛЬ =================
app.all('/profile', (req, res) => {
    const data = { ...req.query, ...req.body };
    const session = getSessionByKey(data.key);
    if (!session) return sendJavaResponse(res, 'ERROR|Не авторизован');
    if (session.isGuest) return sendJavaResponse(res, 'ERROR|Только для AllStore');

    let user = session.allstoreUser || loadAllStoreProfile(session.username);
    if (user) session.allstoreUser = user;
    if (!user) return sendJavaResponse(res, 'ERROR|Профиль не загружен');

    let r = 'OK|';
    r += 'Ник: ' + (user.username || '—') + ';';
    r += 'ID: ' + (user.id ? user.id.substring(0, 8) + '...' : '—') + ';';
    r += 'Роль: ' + (user.role_label || user.role || '—') + ';';
    r += 'Рейтинг: ' + (user.rating || 0) + ';';
    r += 'Страна: ' + (user.country || '—') + ';';
    r += 'О себе: ' + (user.description || '—') + ';';
    return sendJavaResponse(res, r);
});

app.all('/player_profile', (req, res) => {
    const data = { ...req.query, ...req.body };
    const session = getSessionByKey(data.key);
    if (!session) return sendJavaResponse(res, 'ERROR|Не авторизован');

    const target = sanitizeString(data.target || '', 30);
    if (!target) return sendJavaResponse(res, 'ERROR|Неверный ник');

    let ts = null;
    for (const s of sessions.values()) if (s.username === target) { ts = s; break; }
    if (!ts) return sendJavaResponse(res, 'ERROR|Игрок не в сети');

    let r = 'OK|';
    r += 'Ник: ' + target + ';';
    r += 'ID: ' + (ts.javabloxId || '—') + ';';
    r += 'Тип аккаунта: ' + (ts.isGuest ? 'Гость' : 'AllStore') + ';';

    if (!ts.isGuest) {
        let user = ts.allstoreUser || loadAllStoreProfile(target);
        if (user) {
            if (user.role_label || user.role) r += 'Роль: ' + (user.role_label || user.role) + ';';
            if (user.rating) r += 'Рейтинг: ' + user.rating + ';';
            if (user.country) r += 'Страна: ' + user.country + ';';
            if (user.description) r += 'О себе: ' + user.description + ';';
        }
    }
    let place = null;
    for (const [p, pl] of players.entries()) if (pl.has(target)) { place = p; break; }
    if (place) r += 'Играет в: ' + place + ';';

    return sendJavaResponse(res, r);
});

app.all('/players_online', (req, res) => {
    const data = { ...req.query, ...req.body };
    const session = getSessionByKey(data.key);
    if (!session) return sendJavaResponse(res, 'ERROR|Не авторизован');

    const me = session.username;
    const friends = loadFriends(me).friends || [];
    const all = new Set();
    for (const pl of players.values()) for (const name of pl.keys()) if (name !== me) all.add(name);

    const entries = [];
    for (const name of all) entries.push(name + ',' + (friends.indexOf(name) !== -1 ? '1' : '0'));
    return sendJavaResponse(res, 'OK|' + entries.join(';'));
});

// ================= ДРУЗЬЯ =================
app.all('/friends/send', (req, res) => {
    const data = { ...req.query, ...req.body };
    const session = getSessionByKey(data.key);
    if (!session) return sendJavaResponse(res, 'ERROR|Не авторизован');
    if (session.isGuest) return sendJavaResponse(res, 'ERROR|Друзья только для AllStore');

    const target = sanitizeString(data.target || '', 30);
    if (target.length < 3) return sendJavaResponse(res, 'ERROR|Неверный ник');
    if (target === session.username) return sendJavaResponse(res, 'ERROR|Это вы');

    let ts = null;
    for (const s of sessions.values()) if (s.username === target) { ts = s; break; }
    if (!ts) return sendJavaResponse(res, 'ERROR|Игрок не в сети');

    const my = loadFriends(session.username);
    const td = loadFriends(target);
    if (my.friends.indexOf(target) !== -1) return sendJavaResponse(res, 'ERROR|Уже в друзьях');
    if (td.incoming.indexOf(session.username) !== -1) return sendJavaResponse(res, 'ERROR|Заявка уже отправлена');

    td.incoming.push(session.username); saveFriends(target, td);
    my.outgoing.push(target); saveFriends(session.username, my);
    return sendJavaResponse(res, 'OK');
});
app.all('/friends/accept', (req, res) => {
    const data = { ...req.query, ...req.body };
    const session = getSessionByKey(data.key);
    if (!session) return sendJavaResponse(res, 'ERROR|Не авторизован');

    const from = sanitizeString(data.from || '', 30);
    if (from.length < 3) return sendJavaResponse(res, 'ERROR|Неверный ник');

    const my = loadFriends(session.username);
    const fd = loadFriends(from);
    const idx = my.incoming.indexOf(from);
    if (idx === -1) return sendJavaResponse(res, 'ERROR|Заявка не найдена');
    my.incoming.splice(idx, 1);
    if (my.friends.indexOf(from) === -1) my.friends.push(from);
    saveFriends(session.username, my);

    const oi = fd.outgoing.indexOf(session.username);
    if (oi !== -1) fd.outgoing.splice(oi, 1);
    if (fd.friends.indexOf(session.username) === -1) fd.friends.push(session.username);
    saveFriends(from, fd);
    return sendJavaResponse(res, 'OK');
});
app.all('/friends/reject', (req, res) => {
    const data = { ...req.query, ...req.body };
    const session = getSessionByKey(data.key);
    if (!session) return sendJavaResponse(res, 'ERROR|Не авторизован');

    const from = sanitizeString(data.from || '', 30);
    const my = loadFriends(session.username);
    const fd = loadFriends(from);
    const idx = my.incoming.indexOf(from);
    if (idx !== -1) my.incoming.splice(idx, 1);
    saveFriends(session.username, my);
    const oi = fd.outgoing.indexOf(session.username);
    if (oi !== -1) fd.outgoing.splice(oi, 1);
    saveFriends(from, fd);
    return sendJavaResponse(res, 'OK');
});
app.all('/friends/remove', (req, res) => {
    const data = { ...req.query, ...req.body };
    const session = getSessionByKey(data.key);
    if (!session) return sendJavaResponse(res, 'ERROR|Не авторизован');

    const target = sanitizeString(data.target || '', 30);
    const my = loadFriends(session.username);
    const td = loadFriends(target);
    let idx = my.friends.indexOf(target); if (idx !== -1) my.friends.splice(idx, 1);
    saveFriends(session.username, my);
    idx = td.friends.indexOf(session.username); if (idx !== -1) td.friends.splice(idx, 1);
    saveFriends(target, td);
    return sendJavaResponse(res, 'OK');
});
app.all('/friends/list', (req, res) => {
    const data = { ...req.query, ...req.body };
    const session = getSessionByKey(data.key);
    if (!session) return sendJavaResponse(res, 'ERROR|Не авторизован');
    if (session.isGuest) return sendJavaResponse(res, 'ERROR|Друзья только для AllStore');

    const my = loadFriends(session.username);
    let r = 'OK|';
    r += (my.friends || []).join(',') + '|';
    r += (my.incoming || []).join(',') + '|';
    r += (my.outgoing || []).join(',');
    return sendJavaResponse(res, r);
});

// ================= ИГРА =================
app.all('/join', (req, res) => {
    const data = { ...req.query, ...req.body };
    const place = sanitizeString(data.place || 'main', 50);
    if (!isValidPlaceId(place)) return sendJavaResponse(res, 'ERROR|Неверный плейс');

    const username = getUsernameByKey(data.key);
    if (!username) return sendJavaResponse(res, 'ERROR|Не авторизован');
    const session = sessions.get(data.key);
    const javabloxId = session ? session.javabloxId : '';

    if (isBanned(username, javabloxId)) return sendJavaResponse(res, 'ERROR|Вы забанены');
    if (!checkJoinRate(username)) { addSuspiciousAction(username, javabloxId, 'Join flood'); return sendJavaResponse(res, 'ERROR|Слишком часто'); }

    const x = Math.round(Math.max(0, Math.min(100000, parseFloat(data.x) || 0)));
    const y = Math.round(Math.max(0, Math.min(100000, parseFloat(data.y) || 0)));
    const dir = Math.min(3, Math.max(0, parseInt(data.dir) || 0));
    const moving = parseInt(data.moving) === 1 ? 1 : 0;
    const jumping = 0;

    if (!players.has(place)) players.set(place, new Map());
    const pl = players.get(place);
    pl.set(username, { x, y, dir, moving, jumping, lastSeen: Date.now() });

    const friends = loadFriends(username).friends || [];
    const others = [];
    const now = Date.now();
    for (const [name, pData] of pl.entries()) {
        if (now - pData.lastSeen > PLAYER_TIMEOUT) continue;
        if (name !== username) {
            const isFriend = friends.indexOf(name) !== -1 ? 1 : 0;
            let otherSkin = 0;
            for (const s of sessions.values()) if (s.username === name) { otherSkin = s.skin || 0; break; }
            others.push(`${name},${pData.x},${pData.y},${pData.dir},${pData.moving},${pData.jumping},${isFriend},${otherSkin}`);
        }
    }
    return sendJavaResponse(res, `OK|${others.join(';')}`);
});

app.all('/chat', (req, res) => {
    const data = { ...req.query, ...req.body };
    const { action, key } = data;
    const place = sanitizeString(data.place || 'main', 50);
    if (!isValidPlaceId(place)) return sendJavaResponse(res, 'ERROR|Неверный плейс');
    if (!chatMessages.has(place)) chatMessages.set(place, []);
    const pc = chatMessages.get(place);

    if (action === 'send') {
        const username = getUsernameByKey(key);
        if (!username) return sendJavaResponse(res, 'ERROR|Не авторизован');
        const session = sessions.get(key);
        const jid = session ? session.javabloxId : '';
        if (isBanned(username, jid)) return sendJavaResponse(res, 'ERROR|Вы забанены');
        if (!checkChatRate(username)) { addSuspiciousAction(username, jid, 'Chat spam'); return sendJavaResponse(res, 'ERROR|Слишком часто'); }
        const m = sanitizeString(data.message || '', 100);
        if (!m) return sendJavaResponse(res, 'ERROR|Пустое');

        pc.push({ id: ++nextChatId, username, text: m, createdAt: Date.now() });
        if (pc.length > MAX_CHAT_MESSAGES) pc.shift();
        return sendJavaResponse(res, 'OK');
    }
    if (action === 'get') {
        const lastId = parseInt(data.last_id) || 0;
        const nm = pc.filter(msg => msg.id > lastId);
        if (nm.length === 0) return sendJavaResponse(res, 'OK|');
        return sendJavaResponse(res, nm.slice(-10).map(msg => `${msg.id}|${msg.username}|${msg.text}`).join('\n'));
    }
    sendJavaResponse(res, 'OK|');
});

app.all('/sound', (req, res) => {
    const data = { ...req.query, ...req.body };
    const { action, key } = data;
    const place = sanitizeString(data.place || 'main', 50);
    if (!isValidPlaceId(place)) return sendJavaResponse(res, 'ERROR|Неверный плейс');
    if (!soundEvents.has(place)) soundEvents.set(place, []);
    const ps = soundEvents.get(place);

    if (action === 'send') {
        const username = getUsernameByKey(key);
        if (!username) return sendJavaResponse(res, 'ERROR|Не авторизован');
        const session = sessions.get(key);
        const jid = session ? session.javabloxId : '';
        if (isBanned(username, jid)) return sendJavaResponse(res, 'ERROR|Вы забанены');
        const sound = sanitizeString(data.sound || '', 20);
        if (!sound) return sendJavaResponse(res, 'ERROR|Неверный звук');
        ps.push({ id: ++nextSoundId, username, sound, createdAt: Date.now() });
        if (ps.length > MAX_SOUND_EVENTS) ps.shift();
        return sendJavaResponse(res, 'OK');
    }
    if (action === 'get') {
        const lastId = parseInt(data.last_id) || 0;
        const ns = ps.filter(s => s.id > lastId);
        if (ns.length === 0) return sendJavaResponse(res, 'OK|');
        return sendJavaResponse(res, ns.map(s => `${s.id}|${s.username}|${s.sound}`).join('\n'));
    }
    sendJavaResponse(res, 'OK|');
});

app.use((req, res) => sendJavaResponse(res, 'ERROR|404'));

app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});