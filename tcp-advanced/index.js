/**
 * index.js
 * Advanced TCP Ping Detection System — Unique Semi-Supervised Learning Edition
 * IT Project 700 - Richfield Graduate Institute of Technology
 *
 * UNIQUE FEATURES:
 *  1. Geographic Behaviour Learning
 *  2. Time Based Personality Profiling
 *  3. Connection Rhythm Detection
 *  4. IP DNA Fingerprinting
 *  5. Trust Network
 *
 * NEW FEATURE:
 *  6. IP Website Access Control — blocked IPs cannot access the aviation website
 *
 * NEW FEATURE:
 *  7. Real Website Proxy Monitor — proxy any real website through TCP detection
 *
 * NEW FEATURE:
 *  8. Ghost IP Detection — detects IP-hopping evasion and links ghost IPs together
 */

const net      = require('net');
const http     = require('http');
const https    = require('https');
const express  = require('express');
const socketIO = require('socket.io');
const mongoose = require('mongoose');
const path     = require('path');
const geoip    = require('geoip-lite');
const kmeans   = require('ml-kmeans');
const crypto   = require('crypto');
const url      = require('url');

// ── Country code → full name lookup ───────────────────────────────────────
const COUNTRY_NAMES = {
    AF:'Afghanistan',AL:'Albania',DZ:'Algeria',AD:'Andorra',AO:'Angola',AG:'Antigua and Barbuda',
    AR:'Argentina',AM:'Armenia',AU:'Australia',AT:'Austria',AZ:'Azerbaijan',BS:'Bahamas',BH:'Bahrain',
    BD:'Bangladesh',BB:'Barbados',BY:'Belarus',BE:'Belgium',BZ:'Belize',BJ:'Benin',BT:'Bhutan',
    BO:'Bolivia',BA:'Bosnia and Herzegovina',BW:'Botswana',BR:'Brazil',BN:'Brunei',BG:'Bulgaria',
    BF:'Burkina Faso',BI:'Burundi',CV:'Cape Verde',KH:'Cambodia',CM:'Cameroon',CA:'Canada',
    CF:'Central African Republic',TD:'Chad',CL:'Chile',CN:'China',CO:'Colombia',KM:'Comoros',
    CG:'Congo',CD:'Congo (DRC)',CR:'Costa Rica',HR:'Croatia',CU:'Cuba',CY:'Cyprus',CZ:'Czech Republic',
    DK:'Denmark',DJ:'Djibouti',DM:'Dominica',DO:'Dominican Republic',EC:'Ecuador',EG:'Egypt',
    SV:'El Salvador',GQ:'Equatorial Guinea',ER:'Eritrea',EE:'Estonia',SZ:'Eswatini',ET:'Ethiopia',
    FJ:'Fiji',FI:'Finland',FR:'France',GA:'Gabon',GM:'Gambia',GE:'Georgia',DE:'Germany',GH:'Ghana',
    GR:'Greece',GD:'Grenada',GT:'Guatemala',GN:'Guinea',GW:'Guinea-Bissau',GY:'Guyana',HT:'Haiti',
    HN:'Honduras',HU:'Hungary',IS:'Iceland',IN:'India',ID:'Indonesia',IR:'Iran',IQ:'Iraq',IE:'Ireland',
    IL:'Israel',IT:'Italy',JM:'Jamaica',JP:'Japan',JO:'Jordan',KZ:'Kazakhstan',KE:'Kenya',KI:'Kiribati',
    KP:'North Korea',KR:'South Korea',KW:'Kuwait',KG:'Kyrgyzstan',LA:'Laos',LV:'Latvia',LB:'Lebanon',
    LS:'Lesotho',LR:'Liberia',LY:'Libya',LI:'Liechtenstein',LT:'Lithuania',LU:'Luxembourg',
    MG:'Madagascar',MW:'Malawi',MY:'Malaysia',MV:'Maldives',ML:'Mali',MT:'Malta',MH:'Marshall Islands',
    MR:'Mauritania',MU:'Mauritius',MX:'Mexico',FM:'Micronesia',MD:'Moldova',MC:'Monaco',MN:'Mongolia',
    ME:'Montenegro',MA:'Morocco',MZ:'Mozambique',MM:'Myanmar',NA:'Namibia',NR:'Nauru',NP:'Nepal',
    NL:'Netherlands',NZ:'New Zealand',NI:'Nicaragua',NE:'Niger',NG:'Nigeria',NO:'Norway',OM:'Oman',
    PK:'Pakistan',PW:'Palau',PA:'Panama',PG:'Papua New Guinea',PY:'Paraguay',PE:'Peru',PH:'Philippines',
    PL:'Poland',PT:'Portugal',QA:'Qatar',RO:'Romania',RU:'Russia',RW:'Rwanda',KN:'Saint Kitts and Nevis',
    LC:'Saint Lucia',VC:'Saint Vincent and the Grenadines',WS:'Samoa',SM:'San Marino',
    ST:'Sao Tome and Principe',SA:'Saudi Arabia',SN:'Senegal',RS:'Serbia',SC:'Seychelles',
    SL:'Sierra Leone',SG:'Singapore',SK:'Slovakia',SI:'Slovenia',SB:'Solomon Islands',SO:'Somalia',
    ZA:'South Africa',SS:'South Sudan',ES:'Spain',LK:'Sri Lanka',SD:'Sudan',SR:'Suriname',SE:'Sweden',
    CH:'Switzerland',SY:'Syria',TW:'Taiwan',TJ:'Tajikistan',TZ:'Tanzania',TH:'Thailand',TL:'Timor-Leste',
    TG:'Togo',TO:'Tonga',TT:'Trinidad and Tobago',TN:'Tunisia',TR:'Turkey',TM:'Turkmenistan',
    TV:'Tuvalu',UG:'Uganda',UA:'Ukraine',AE:'United Arab Emirates',GB:'United Kingdom',
    US:'United States',UY:'Uruguay',UZ:'Uzbekistan',VU:'Vanuatu',VE:'Venezuela',VN:'Vietnam',
    YE:'Yemen',ZM:'Zambia',ZW:'Zimbabwe'
};
function countryName(code) {
    if (!code || code === 'Unknown') return 'Unknown';
    return COUNTRY_NAMES[code] || code;
}

// ── Admin Credentials (in-memory cache, seeded from DB on startup) ──────────
let ADMIN_USERS = Object.create(null);   // { username: hashedPassword }
// Master reset code — can be overridden with the TCP_RESET_CODE environment variable.
// It is printed in the server console on startup (NOT shown on the public reset page).
const MASTER_RESET_CODE = process.env.TCP_RESET_CODE || 'RICHFIELD-RESET-2026';
const SESSION_TIMEOUT_MS = 8 * 60 * 60 * 1000; // 8 hours inactivity

// Make sure the default Super Admin "admin" exists. If it is missing (first start, or the
// database was cleared in MongoDB Compass) it is created with a RANDOM password that is
// printed once in this console — there is no fixed default password anywhere.
async function ensureDefaultAdmin() {
    const defaultAdmin = await AdminUser.findOne({ username: 'admin' });
    if (!defaultAdmin) {
        const initialPassword = crypto.randomBytes(9).toString('base64url');   // 12 random characters
        const created = await AdminUser.create({
            username  : 'admin',
            password  : await hashPassword(initialPassword),
            role      : 'superadmin',
            createdBy : 'system'
        });
        ADMIN_USERS['admin'] = created.password;
        console.log('==============================================================');
        console.log('[ADMIN] Super Admin account created');
        console.log(`[ADMIN]   Username: admin`);
        console.log(`[ADMIN]   Password: ${initialPassword}`);
        console.log('[ADMIN] This password is shown ONCE. Log in and change it in the Admin tab.');
        console.log('==============================================================');
        return created;
    }
    if (defaultAdmin.role !== 'superadmin') {
        defaultAdmin.role = 'superadmin';
        await defaultAdmin.save();
        console.log('[ADMIN] "admin" account restored to Super Admin');
    }
    // Older versions created "admin" with a published default password — warn until it is changed
    if (await verifyPassword('richfield2026', defaultAdmin.password)) {
        console.warn('[ADMIN] WARNING: "admin" still uses the old default password. Change it in the Admin tab now.');
    }
    return defaultAdmin;
}

// Find an admin by username, ignoring extra spaces and upper/lower case
// (phone keyboards often type "Admin" or add a space after the word)
async function findAdminByName(name) {
    if (typeof name !== 'string') return null;
    const clean = name.trim();
    if (!clean) return null;
    const exact = await AdminUser.findOne({ username: clean });
    if (exact) return exact;
    const escaped = clean.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return AdminUser.findOne({ username: { $regex: `^${escaped}$`, $options: 'i' } });
}

// ── Password hashing ───────────────────────────────────────────────────────
// Passwords are hashed with scrypt, a slow, memory-hard algorithm recommended by the
// OWASP Password Storage Cheat Sheet (minimum N=2^17, r=8, p=1). Each password gets its
// own random 16-byte salt. Stored format:  scrypt$N$r$p$salt(base64)$hash(base64)
// (Earlier versions used a fast salted SHA-256 hash. Those hashes still verify, and are
// upgraded to scrypt automatically the next time that admin logs in.)
const SCRYPT = { N: 2 ** 17, r: 8, p: 1, keyLen: 64, maxmem: 256 * 1024 * 1024 };

function scryptAsync(password, salt, keyLen, N, r, p) {
    return new Promise((resolve, reject) => {
        crypto.scrypt(password, salt, keyLen, { N, r, p, maxmem: SCRYPT.maxmem },
            (err, key) => err ? reject(err) : resolve(key));
    });
}

async function hashPassword(password) {
    const salt = crypto.randomBytes(16);
    const key  = await scryptAsync(password, salt, SCRYPT.keyLen, SCRYPT.N, SCRYPT.r, SCRYPT.p);
    return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

function legacySha256(password) {
    return crypto.createHash('sha256').update(password + 'tcp_salt_2026').digest('hex');
}

// Constant-time comparison so the response time does not leak how much of a hash matched
async function verifyPassword(password, stored) {
    if (typeof password !== 'string' || typeof stored !== 'string') return false;
    if (stored.startsWith('scrypt$')) {
        const [, N, r, p, saltB64, hashB64] = stored.split('$');
        const expected = Buffer.from(hashB64 || '', 'base64');
        if (!expected.length) return false;
        const key = await scryptAsync(password, Buffer.from(saltB64 || '', 'base64'), expected.length, Number(N), Number(r), Number(p));
        return crypto.timingSafeEqual(key, expected);
    }
    const legacy = Buffer.from(legacySha256(password));
    const saved  = Buffer.from(stored);
    return legacy.length === saved.length && crypto.timingSafeEqual(legacy, saved);
}

function needsRehash(stored) {
    return typeof stored !== 'string' || !stored.startsWith(`scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$`);
}

// ── Session Store (in-memory) ──────────────────────────────────────────────
const sessions = {};

function createSession(username, role) {
    const token = crypto.randomBytes(32).toString('hex');
    sessions[token] = { username, role: role || 'admin', lastActive: Date.now() };
    return token;
}

function getSession(token) {
    if (!token || !sessions[token]) return null;
    const session = sessions[token];
    if (Date.now() - session.lastActive > SESSION_TIMEOUT_MS) {
        delete sessions[token];
        return null;
    }
    session.lastActive = Date.now();
    return session;
}

function destroySession(token) {
    delete sessions[token];
}

function requireAuth(req, res, next) {
    const token = req.headers['x-auth-token'] || req.query.token;
    const session = getSession(token);
    if (!session) return res.status(401).json({ error: 'Unauthorized' });
    req.session = session;
    next();
}

function requireSuperAdmin(req, res, next) {
    const token = req.headers['x-auth-token'] || req.query.token;
    const session = getSession(token);
    if (!session) return res.status(401).json({ error: 'Unauthorized' });
    if (session.role !== 'superadmin') return res.status(403).json({ error: 'Super Admin access required' });
    req.session = session;
    next();
}

// ── Configuration ──────────────────────────────────────────────────────────
const CONFIG = {
    HTTP_PORT               : 3000,
    TCP_PORT                : 9000,
    WEBSITE_PORT            : 8080,   // Aviation website port
    PROXY_PORT              : 8082,   // Real website proxy port
    SUSPICIOUS_LIMIT        : 10,
    MALICIOUS_LIMIT         : 12,
    WINDOW_MS               : 60000,
    BLOCK_DURATION_MS       : null,     // null = permanent: an IP stays blocked until an admin unblocks it
                                        // (set a number of ms, e.g. 86400000 = 24 h, to make blocks expire)
    REPUTATION_START        : 50,  // neutral start — IPs must earn trust
    REPUTATION_MAX          : 100,
    REPUTATION_MIN          : 0,
    REPUTATION_NORMAL_UP    : 2,   // slow trust build — takes consistent good behaviour
    REPUTATION_SUSPICIOUS   : -8,  // meaningful penalty per suspicious ping
    REPUTATION_MALICIOUS    : -20, // heavy penalty per malicious ping — score drops fast
    TRUSTED_SCORE           : 80,
    BLOCK_SCORE             : 20,  // auto-block when score drops to 20
    LEARNING_INTERVAL_MS    : 300000,
    CLUSTER_COUNT           : 3,
    MIN_HUMAN_PAUSE_MS      : 500,
    RHYTHM_WINDOW           : 10,
    DNA_MATCH_THRESHOLD     : 0.85,
    TRUST_BOOST             : 10,
    TRUST_SIMILARITY        : 0.80,
    // Ghost IP Detection settings
    GHOST_IP_WINDOW_MS      : 600000,  // 10 minutes — window to detect IP hopping
    GHOST_IP_THRESHOLD      : 3,       // 3+ IPs in the window = ghost IP cluster
    GHOST_IP_BLOCK_ALL      : true,    // block ALL IPs in a ghost cluster when detected
};

// ── Safety net: never let one unexpected error silently stop the whole system ──
process.on('unhandledRejection', (err) => {
    console.error('[ERROR] Unhandled promise rejection:', err && err.stack ? err.stack : err);
});
process.on('uncaughtException', (err) => {
    console.error('[ERROR] Uncaught exception (system keeps running):', err && err.stack ? err.stack : err);
});
process.on('SIGINT', () => {
    console.log('\n[STOP] Server stopped by Ctrl+C / terminal closed.');
    process.exit(0);
});

// MongoDB connection status messages, so you can see if the database goes away
mongoose.connection.on('disconnected', () => console.error('[MONGODB] Disconnected — is MongoDB still running? Retrying…'));
mongoose.connection.on('reconnected',  () => console.log('[MONGODB] Reconnected'));

// ── Connect to MongoDB ─────────────────────────────────────────────────────
mongoose.connect('mongodb://127.0.0.1:27017/tcp_detection')
    .then(async () => {
        console.log('Connected to MongoDB');

        // ── Seed default admin if no admins exist ──────────────────────────
        // Make sure the default Super Admin account always exists. If "admin" was deleted
        // (or the database only has other accounts), it is recreated so you can never be
        // locked out of the dashboard.
        await ensureDefaultAdmin();
        // Load all admins into memory
        const admins = await AdminUser.find();
        ADMIN_USERS = Object.create(null);
        admins.forEach(a => { ADMIN_USERS[a.username] = a.password; });
        console.log(`[ADMIN] Loaded ${admins.length} admin account(s)`);
        console.log(`[ADMIN] Master password-reset code: ${MASTER_RESET_CODE}`);

        // Blocks created by older versions expired after 24 hours — make the ones that are
        // still active permanent, so they stay until an admin unblocks them
        if (!CONFIG.BLOCK_DURATION_MS) {
            const upd = await BlockedIP.updateMany(
                { expiresAt: { $gt: new Date(), $lt: PERMANENT_BLOCK_DATE } },
                { $set: { expiresAt: PERMANENT_BLOCK_DATE } });
            if (upd.modifiedCount) console.log(`[BLOCK] ${upd.modifiedCount} existing block(s) made permanent`);
        }

        initLearning();
        // Reload BLOCKED ghost clusters from DB into the in-memory tracker so they survive
        // restarts. Only the signal that actually created the cluster is restored (the
        // clusterId is the hash of that signal key), and the cluster is marked "confirmed"
        // so any new IP that matches the same signal is caught immediately.
        try {
            const savedClusters = await GhostCluster.find({ status: 'BLOCKED' });
            for (const c of savedClusters) {
                const candidates = [`fp:${c.fingerprint}`, `sn:${c.subnet}`];
                const key = candidates.find(k => ghostClusterIdFor(k) === c.clusterId);
                if (!key) continue;
                const tracker = getGhostTracker(key);
                tracker.confirmed = true;
                c.ips.forEach(ip => tracker.ips.set(ip, Date.now()));
            }
            if (savedClusters.length > 0)
                console.log(`[GHOST] Restored ${savedClusters.length} ghost clusters from DB`);
        } catch (e) { console.error('[GHOST] restore error:', e.message); }
    })
    .catch(err => {
        console.error('MongoDB connection error:', err.message);
        console.error('Is MongoDB running on 127.0.0.1:27017? Start it and then restart this system — logins will not work until it connects.');
    });

// ══════════════════════════════════════════════════════════════════════════
// MONGODB SCHEMAS
// ══════════════════════════════════════════════════════════════════════════

const pingSchema = new mongoose.Schema({
    ip               : { type: String, required: true },
    port             : { type: Number, required: true },
    time             : { type: Date,   default: Date.now },
    classification   : { type: String, default: 'NORMAL' },
    blocked          : { type: Boolean, default: false },
    reputationScore  : { type: Number, default: 50 },
    anomalyScore     : { type: Number, default: 0 },
    cluster          : { type: Number, default: 0 },
    country          : { type: String, default: 'Unknown' },
    city             : { type: String, default: 'Unknown' },
    geoRisk          : { type: String, default: 'NORMAL' },
    rhythmScore      : { type: Number, default: 0 },
    isBot            : { type: Boolean, default: false },
    dnaFingerprint   : { type: String, default: '' },
    dnaMatch         : { type: String, default: 'NEW' },
    trustNetworkBoost: { type: Number, default: 0 }
});
// Indexes keep the dashboard counts and live feed fast as the collection grows
pingSchema.index({ time: -1 });
pingSchema.index({ classification: 1 });
pingSchema.index({ isBot: 1 });
pingSchema.index({ ip: 1, time: -1 });
const Ping = mongoose.model('Ping', pingSchema);

const alertSchema = new mongoose.Schema({
    ip      : { type: String, required: true },
    type    : { type: String, required: true },
    message : { type: String, required: true },
    time    : { type: Date, default: Date.now },
    read    : { type: Boolean, default: false }
});
const Alert = mongoose.model('Alert', alertSchema);

const blockedSchema = new mongoose.Schema({
    ip        : { type: String, required: true, unique: true },
    reason    : { type: String, required: true },
    blockedAt : { type: Date, default: Date.now },
    expiresAt : { type: Date, required: true }
});
const BlockedIP = mongoose.model('BlockedIP', blockedSchema);

const reputationSchema = new mongoose.Schema({
    ip               : { type: String, required: true, unique: true },
    score            : { type: Number, default: 50 },
    totalPings       : { type: Number, default: 0 },
    normalPings      : { type: Number, default: 0 },
    suspiciousPings  : { type: Number, default: 0 },
    maliciousPings   : { type: Number, default: 0 },
    firstSeen        : { type: Date, default: Date.now },
    lastSeen         : { type: Date, default: Date.now },
    trusted          : { type: Boolean, default: false },
    cluster          : { type: Number, default: 0 },
    country          : { type: String, default: 'Unknown' },
    city             : { type: String, default: 'Unknown' },
    visitHours       : { type: [Number], default: [] },
    avgRhythm        : { type: Number, default: 0 },
    dnaFingerprint   : { type: String, default: '' },
    trustNetworkScore: { type: Number, default: 0 }
});
const IPReputation = mongoose.model('IPReputation', reputationSchema);

const patternSchema = new mongoose.Schema({
    hour        : { type: Number, required: true, unique: true },
    avgPings    : { type: Number, default: 0 },
    maxPings    : { type: Number, default: 0 },
    sampleCount : { type: Number, default: 0 },
    threshold   : { type: Number, default: 10 },
    topCountries: { type: [String], default: [] }
});
const TrafficPattern = mongoose.model('TrafficPattern', patternSchema);

const geoSchema = new mongoose.Schema({
    country     : { type: String, required: true, unique: true },
    visitCount  : { type: Number, default: 0 },
    normalCount : { type: Number, default: 0 },
    riskScore   : { type: Number, default: 50 },
    trusted     : { type: Boolean, default: false },
    firstSeen   : { type: Date, default: Date.now },
    lastSeen    : { type: Date, default: Date.now }
});
const GeoPattern = mongoose.model('GeoPattern', geoSchema);

const dnaSchema = new mongoose.Schema({
    fingerprint : { type: String, required: true, unique: true },
    ip          : { type: String, required: true },
    label       : { type: String, default: 'UNKNOWN' },
    matchCount  : { type: Number, default: 1 },
    firstSeen   : { type: Date, default: Date.now },
    lastSeen    : { type: Date, default: Date.now }
});
const DNAFingerprint = mongoose.model('DNAFingerprint', dnaSchema);

// ══════════════════════════════════════════════════════════════════════════
// NEW FEATURE 8: GHOST IP DETECTION SCHEMA
// Tracks clusters of IPs that belong to the same evading entity
// ══════════════════════════════════════════════════════════════════════════
const ghostClusterSchema = new mongoose.Schema({
    clusterId    : { type: String, required: true, unique: true }, // shared fingerprint/subnet key
    ips          : { type: [String], default: [] },                // all IPs in this cluster
    fingerprint  : { type: String, default: '' },                  // browser/user-agent fingerprint
    subnet       : { type: String, default: '' },                  // /24 subnet (e.g. 192.168.1)
    country      : { type: String, default: 'Unknown' },
    firstSeen    : { type: Date, default: Date.now },
    lastSeen     : { type: Date, default: Date.now },
    ipCount      : { type: Number, default: 1 },
    status       : { type: String, default: 'ACTIVE' },           // ACTIVE | BLOCKED
    blockedAt    : { type: Date, default: null },
    reason       : { type: String, default: '' }
});
const GhostCluster = mongoose.model('GhostCluster', ghostClusterSchema);

// ── Admin User Schema ──────────────────────────────────────────────────────
const adminSchema = new mongoose.Schema({
    username    : { type: String, required: true, unique: true },
    password    : { type: String, required: true },   // SHA-256 hash
    role        : { type: String, default: 'admin' }, // 'superadmin' | 'admin'
    createdAt   : { type: Date, default: Date.now },
    createdBy   : { type: String, default: 'system' },
    lastLogin   : { type: Date, default: null }
});
const AdminUser = mongoose.model('AdminUser', adminSchema);

// ── Backup Log Schema ──────────────────────────────────────────────────────
const backupLogSchema = new mongoose.Schema({
    filename    : { type: String, required: true },
    createdAt   : { type: Date, default: Date.now },
    createdBy   : { type: String, default: 'admin' },
    collections : { type: [String], default: [] },
    sizeBytes   : { type: Number, default: 0 }
});
const BackupLog = mongoose.model('BackupLog', backupLogSchema);

// ══════════════════════════════════════════════════════════════════════════
// IN-MEMORY STATE
// ══════════════════════════════════════════════════════════════════════════
const connectionTracker  = {};
const rhythmTracker      = {};
let   selfLearningThreshold = CONFIG.SUSPICIOUS_LIMIT;
let   clusterData           = [];
let   knownGeoPatterns      = {};

// Ghost IP: in-memory tracker maps fingerprint/subnet key →
//   { ips: Map<ip, lastSeenMs>, confirmed: boolean }
// "confirmed" = a ghost cluster already exists for this key, so any new matching IP joins it.
const ghostTracker = {};

function getGhostTracker(key) {
    if (!ghostTracker[key]) ghostTracker[key] = { ips: new Map(), confirmed: false };
    return ghostTracker[key];
}

function ghostClusterIdFor(signalKey) {
    return crypto.createHash('md5').update(signalKey).digest('hex').slice(0, 12);
}

const LOCALHOST_IPS = ['127.0.0.1', '::1', '::ffff:127.0.0.1'];

// ── Helpers ────────────────────────────────────────────────────────────────
function normalizeIP(ip) {
    if (!ip) return 'unknown';
    ip = String(ip).split(',')[0].trim();
    if (ip.startsWith('::ffff:')) ip = ip.slice(7);
    if (ip === '::1') ip = '127.0.0.1';
    return ip;
}

// Work out the client IP for an HTTP request. x-forwarded-for is honoured (the test
// scripts use it to simulate external visitors) but ONLY if it is a real IP address —
// otherwise anyone could inject HTML/script into the dashboard through that header.
function getClientIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        const candidate = normalizeIP(forwarded);
        if (net.isIP(candidate)) return candidate;
    }
    return normalizeIP(req.socket.remoteAddress);
}

// Escape text before putting it into server-generated HTML
function escapeHtml(value) {
    return String(value == null ? '' : value)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Static assets (images, CSS, JS, fonts...) should not count as separate "visits"
const STATIC_ASSET_RE = /\.(css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3|wav|json|xml|txt)$/i;
function isPageRequest(req) {
    const accept = req.headers['accept'] || '';
    if (accept.includes('text/html')) return true;
    const pathname = (req.path || req.url || '').split('?')[0];
    return !STATIC_ASSET_RE.test(pathname);
}

// Extract /24 subnet from an IP (e.g. "192.168.1.5" → "192.168.1")
function getSubnet(ip) {
    const parts = ip.split('.');
    if (parts.length === 4) return parts.slice(0, 3).join('.');
    return ip; // IPv6 or unknown — use as-is
}

// Build a lightweight browser fingerprint from HTTP request headers
// (user-agent + accept-language + common header set)
function buildBrowserFingerprint(req) {
    const ua   = (req.headers['user-agent']       || '').toLowerCase();
    const lang = (req.headers['accept-language']  || '').split(',')[0].trim().toLowerCase();
    const enc  = (req.headers['accept-encoding']  || '').toLowerCase();
    // Hash to a short hex string so we don't store the full UA in every record
    return crypto.createHash('md5').update(`${ua}|${lang}|${enc}`).digest('hex').slice(0, 16);
}

// ── Per-key lock ───────────────────────────────────────────────────────────
// Several visits can be processed at the same time. Without this, two visits that
// read-modify-save the SAME document (e.g. the traffic pattern for this hour, one
// IP's reputation, one ghost cluster) clash and Mongoose throws a VersionError or
// a duplicate-key error — and that visit is lost. Work on the same key is queued.
const _locks = new Map();
function withLock(key, fn) {
    const prev = _locks.get(key) || Promise.resolve();
    const run  = prev.catch(() => {}).then(fn);
    const tail = run.catch(() => {});
    _locks.set(key, tail);
    tail.then(() => { if (_locks.get(key) === tail) _locks.delete(key); });
    return run;
}

function findOrCreate(Model, filter, defaults) {
    return Model.findOneAndUpdate(filter, { $setOnInsert: defaults }, { upsert: true, new: true });
}

// ══════════════════════════════════════════════════════════════════════════
// EXPRESS + SOCKET.IO — DASHBOARD
// ══════════════════════════════════════════════════════════════════════════
const app    = express();
const server = http.createServer(app);
const io     = socketIO(server);

// Only logged-in admins may receive live dashboard events
io.use((socket, next) => {
    const token = (socket.handshake.auth && socket.handshake.auth.token) || socket.handshake.query.token;
    if (getSession(token)) return next();
    next(new Error('Unauthorized'));
});

// Large limit so that restoring a backup (which can be several MB) does not fail
app.use(express.json({ limit: '50mb' }));

// ── Login page (unprotected) ───────────────────────────────────────────────
app.get('/login', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin Login — TCP Ping Detection System</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #0d1117; display: flex; align-items: center; justify-content: center; min-height: 100vh; font-family: 'Segoe UI', sans-serif; }
  .login-box { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 40px; width: 100%; max-width: 400px; }
  .logo { text-align: center; margin-bottom: 30px; }
  .logo h1 { color: #58a6ff; font-size: 20px; font-weight: 700; }
  .logo p { color: #8b949e; font-size: 13px; margin-top: 6px; }
  label { display: block; color: #c9d1d9; font-size: 14px; margin-bottom: 6px; }
  input { width: 100%; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 10px 14px; color: #c9d1d9; font-size: 14px; margin-bottom: 16px; outline: none; }
  input:focus { border-color: #58a6ff; }
  button { width: 100%; background: #1f6feb; color: #fff; border: none; border-radius: 6px; padding: 12px; font-size: 15px; font-weight: 600; cursor: pointer; }
  button:hover { background: #388bfd; }
  .error { color: #f85149; font-size: 13px; text-align: center; margin-top: 12px; display: none; }
  .shield { font-size: 40px; margin-bottom: 10px; }
</style>
</head>
<body>
<div class="login-box">
  <div class="logo">
    <div class="shield">🛡️</div>
    <h1>TCP Ping Detection System</h1>
    <p>IT Project 700 — Richfield | Admin Access</p>
  </div>
  <label>Username</label>
  <input type="text" id="username" placeholder="Enter username" autocapitalize="none" autocorrect="off" autocomplete="username" spellcheck="false" />
  <label>Password</label>
  <input type="password" id="password" placeholder="Enter password" autocapitalize="none" autocorrect="off" autocomplete="current-password" spellcheck="false" onkeydown="if(event.key==='Enter')login()" />
  <button onclick="login()">Sign In</button>
  <div class="error" id="error">Invalid username or password.</div>
  <div style="text-align:center;margin-top:16px;">
    <a href="/reset-password" style="color:#58a6ff;font-size:13px;text-decoration:none;">Forgot password?</a>
  </div>
</div>
<script>
async function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const res = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) });
  const data = await res.json();
  if (data.token) {
    localStorage.setItem('adminToken', data.token);
    window.location.href = '/';
  } else {
    document.getElementById('error').style.display = 'block';
  }
}
</script>
</body>
</html>`);
});

// ── Password Reset Page (unprotected — for locked-out admins) ──────────────
app.get('/reset-password', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Reset Password — TCP Ping Detection System</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #0d1117; display: flex; align-items: center; justify-content: center; min-height: 100vh; font-family: 'Segoe UI', sans-serif; }
  .box { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 40px; width: 100%; max-width: 400px; }
  .logo { text-align: center; margin-bottom: 28px; }
  .logo h1 { color: #f0883e; font-size: 20px; font-weight: 700; }
  .logo p { color: #8b949e; font-size: 13px; margin-top: 6px; }
  label { display: block; color: #c9d1d9; font-size: 14px; margin-bottom: 6px; }
  input { width: 100%; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 10px 14px; color: #c9d1d9; font-size: 14px; margin-bottom: 16px; outline: none; }
  input:focus { border-color: #f0883e; }
  button { width: 100%; background: #b45309; color: #fff; border: none; border-radius: 6px; padding: 12px; font-size: 15px; font-weight: 600; cursor: pointer; }
  button:hover { background: #d97706; }
  .msg { font-size: 13px; text-align: center; margin-top: 12px; display: none; }
  .success { color: #3fb950; }
  .error { color: #f85149; }
  .hint { background: #21262d; border: 1px solid #30363d; border-radius: 8px; padding: 12px 16px; color: #8b949e; font-size: 12px; margin-bottom: 20px; line-height: 1.6; }
</style>
</head>
<body>
<div class="box">
  <div class="logo">
    <div style="font-size:36px;margin-bottom:8px;">🔑</div>
    <h1>Password Reset</h1>
    <p>TCP Ping Detection System</p>
  </div>
  <div class="hint">Use the master reset code to set a new password.<br>The reset code is shown in the server console when the system starts.</div>
  <label>Username</label>
  <input type="text" id="username" placeholder="Admin username" autocapitalize="none" autocorrect="off" autocomplete="username" spellcheck="false" />
  <label>New Password</label>
  <input type="password" id="newPassword" placeholder="New password (min 6 chars)" autocapitalize="none" autocorrect="off" autocomplete="new-password" spellcheck="false" />
  <label>Master Reset Code</label>
  <input type="text" id="resetCode" placeholder="Enter reset code" autocapitalize="characters" autocorrect="off" spellcheck="false" />
  <button onclick="resetPassword()">Reset Password</button>
  <div class="msg success" id="success">✅ Password reset! <a href="/login" style="color:#58a6ff;">Sign in</a></div>
  <div class="msg error" id="error"></div>
  <div style="text-align:center;margin-top:16px;">
    <a href="/login" style="color:#58a6ff;font-size:13px;text-decoration:none;">← Back to Login</a>
  </div>
</div>
<script>
async function resetPassword() {
  const username    = document.getElementById('username').value.trim();
  const newPassword = document.getElementById('newPassword').value;
  const resetCode   = document.getElementById('resetCode').value.trim();
  document.getElementById('success').style.display = 'none';
  document.getElementById('error').style.display   = 'none';
  if (!username || !newPassword || !resetCode) {
    document.getElementById('error').textContent = 'All fields are required.';
    document.getElementById('error').style.display = 'block'; return;
  }
  const res  = await fetch('/api/reset-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, newPassword, resetCode }) });
  const data = await res.json();
  if (data.success) {
    document.getElementById('success').style.display = 'block';
  } else {
    document.getElementById('error').textContent = data.error || 'Reset failed.';
    document.getElementById('error').style.display = 'block';
  }
}
</script>
</body>
</html>`);
});

// ── Login API ──────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body || {};
        if (typeof username !== 'string' || typeof password !== 'string') {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        // The database is the source of truth (it may have been cleared or edited in
        // MongoDB Compass while the server was running). The default "admin" account is
        // recreated automatically (with a new random password) if it has been deleted.
        let adminDoc = await findAdminByName(username);
        if (!adminDoc && username.trim().toLowerCase() === 'admin') adminDoc = await ensureDefaultAdmin();
        if (adminDoc) ADMIN_USERS[adminDoc.username] = adminDoc.password;
        if (adminDoc && await verifyPassword(password, adminDoc.password)) {
            // Upgrade an old SHA-256 hash to scrypt now that we know the password
            if (needsRehash(adminDoc.password)) {
                adminDoc.password = await hashPassword(password);
                await adminDoc.save();
                ADMIN_USERS[adminDoc.username] = adminDoc.password;
                console.log(`[ADMIN] Password hash for "${adminDoc.username}" upgraded to scrypt`);
            }
            const name  = adminDoc.username;           // the account's real spelling
            const token = createSession(name, adminDoc.role);
            await AdminUser.findOneAndUpdate({ username: name }, { lastLogin: new Date() });
            res.json({ token, username: name, role: adminDoc.role });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (err) {
        console.error('Login error:', err.message);
        res.status(500).json({ error: 'Login unavailable — is MongoDB running?' });
    }
});

// ── Logout API ─────────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (token) destroySession(token);
    res.json({ success: true });
});

// ── Session check API ──────────────────────────────────────────────────────
app.get('/api/session', (req, res) => {
    const token = req.headers['x-auth-token'];
    const session = getSession(token);
    if (session) res.json({ valid: true, username: session.username, role: session.role });
    else res.status(401).json({ valid: false });
});

// ── Serve dashboard (protected — auth checked client-side) ─────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ══════════════════════════════════════════════════════════════════════════
// NEW FEATURE: AVIATION WEBSITE WITH IP BLOCKING
// ══════════════════════════════════════════════════════════════════════════
const websiteApp    = express();
const websiteServer = http.createServer(websiteApp);

websiteApp.use(async (req, res, next) => {
    const ip = getClientIP(req);

    // Only local visitors are registered through a TCP ping. Visitors forwarded by the
    // proxy (port 8082) were already analysed there with their real IP — pinging again
    // would count each of those visits a second time against 127.0.0.1.
    if (req.method === 'GET' && req.path === '/' && LOCALHOST_IPS.includes(ip)) {
        const socket = new net.Socket();
        socket.setTimeout(2000);
        socket.connect(CONFIG.TCP_PORT, '127.0.0.1', () => { socket.destroy(); });
        socket.on('error',   () => {});
        socket.on('timeout', () => { socket.destroy(); });
    }

    let blocked;
    try {
        blocked = await BlockedIP.findOne({ ip, expiresAt: { $gt: new Date() } });
    } catch (err) {
        console.error('Block check failed:', err.message);
        return next();
    }

    if (blocked) {
        res.status(403).send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                <title>403 Forbidden — SkyForce Aviation</title>
                <style>
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    body {
                        font-family     : 'Segoe UI', sans-serif;
                        background      : #0f1117;
                        color           : #e2e8f0;
                        min-height      : 100vh;
                        display         : flex;
                        align-items     : center;
                        justify-content : center;
                    }
                    .blocked-box {
                        background    : #1a1d27;
                        border        : 1px solid #ef4444;
                        border-radius : 16px;
                        padding       : 48px;
                        max-width     : 540px;
                        text-align    : center;
                        box-shadow    : 0 0 40px rgba(239,68,68,0.2);
                    }
                    .error-code {
                        font-size     : 80px;
                        font-weight   : 900;
                        color         : #ef4444;
                        line-height   : 1;
                        margin-bottom : 8px;
                        letter-spacing: -2px;
                    }
                    .error-label {
                        font-size     : 14px;
                        letter-spacing: 4px;
                        text-transform: uppercase;
                        color         : #ef4444;
                        margin-bottom : 24px;
                    }
                    .blocked-icon  { font-size: 48px; margin-bottom: 20px; }
                    .blocked-title { font-size: 22px; font-weight: 700; color: #fff; margin-bottom: 12px; }
                    .blocked-sub   { font-size: 14px; color: #8892a4; margin-bottom: 24px; line-height: 1.7; }
                    .blocked-ip {
                        font-family   : 'Consolas', monospace;
                        background    : #21253a;
                        padding       : 10px 20px;
                        border-radius : 8px;
                        color         : #ef4444;
                        font-size     : 15px;
                        margin-bottom : 16px;
                        display       : inline-block;
                        border        : 1px solid rgba(239,68,68,0.3);
                    }
                    .blocked-reason {
                        font-size     : 13px;
                        color         : #8892a4;
                        background    : #21253a;
                        padding       : 12px 16px;
                        border-radius : 8px;
                        margin-bottom : 24px;
                        border-left   : 3px solid #ef4444;
                        text-align    : left;
                    }
                    .blocked-info {
                        font-size     : 13px;
                        color         : #f59e0b;
                        background    : rgba(245,158,11,0.1);
                        border        : 1px solid rgba(245,158,11,0.3);
                        padding       : 12px 16px;
                        border-radius : 8px;
                        margin-bottom : 24px;
                        line-height   : 1.6;
                    }
                    .divider {
                        border        : none;
                        border-top    : 1px solid #2e3350;
                        margin        : 24px 0;
                    }
                    .blocked-footer {
                        font-size     : 11px;
                        color         : #4a5280;
                    }
                </style>
            </head>
            <body>
                <div class="blocked-box">
                    <div class="error-code">403</div>
                    <div class="error-label">Forbidden</div>
                    <div class="blocked-icon">🚫</div>
                    <div class="blocked-title">Access Denied</div>
                    <p class="blocked-sub">
                        Your IP address has been blocked from accessing
                        SkyForce Aviation. This block was triggered by our TCP
                        security system detecting malicious or suspicious activity.
                    </p>
                    <div class="blocked-ip">${escapeHtml(ip)}</div>
                    <div class="blocked-reason">
                        <strong>Reason:</strong> ${escapeHtml(blocked.reason)}
                    </div>
                    <div class="blocked-info">
                        ⚠️ Your access will only be restored once an administrator
                        manually unblocks your IP address from the TCP security dashboard.
                        Refreshing this page will not restore your access.
                    </div>
                    <hr class="divider" />
                    <div class="blocked-footer">
                        SkyForce Aviation — TCP Ping Detection Security System<br>
                        IT Project 700 &nbsp;|&nbsp; Richfield Graduate Institute of Technology &nbsp;|&nbsp; 2026
                    </div>
                </div>
            </body>
            </html>
        `);
        return;
    }

    next();
});

websiteApp.use(express.static(path.join(__dirname, '..', 'aviation-test-site', 'public')));
websiteApp.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'aviation-test-site', 'public', 'index.html'));
});

// ══════════════════════════════════════════════════════════════════════════
// NEW FEATURE 7: REAL WEBSITE PROXY MONITOR
// ══════════════════════════════════════════════════════════════════════════

let monitoredURL = 'http://example.com';

app.get('/api/proxy-url', requireAuth, (req, res) => {
    res.json({ url: monitoredURL });
});

app.post('/api/proxy-url', requireAuth, (req, res) => {
    let newURL = (typeof req.body.url === 'string' ? req.body.url : '').trim();
    if (!newURL) return res.status(400).json({ error: 'URL required' });
    if (!/^https?:\/\//i.test(newURL)) {
        newURL = 'https://' + newURL;
    }
    try {
        const parsed = new URL(newURL);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('bad protocol');
        monitoredURL = parsed.href;
        io.emit('proxy-url-changed', { url: monitoredURL });
        console.log(`🌐 Monitored URL changed to: ${monitoredURL}`);
        res.json({ success: true, url: monitoredURL });
    } catch (e) {
        res.status(400).json({ error: 'Invalid URL' });
    }
});

const proxyApp    = express();
const proxyServer = http.createServer(proxyApp);

proxyApp.use(async (req, res) => {
    const arrivedAt = Date.now();
    // Prefer x-forwarded-for (set by test scripts and real proxies) over the raw socket address
    const clientIP = getClientIP(req);

    // Only page requests count as a "visit". Images, CSS, JS and fonts are ignored,
    // otherwise one normal page view (with 20+ assets) would look like an attack.
    const isMainRequest = isPageRequest(req);
    const isLocal       = LOCALHOST_IPS.includes(clientIP);
    // Local visitors are registered through a TCP ping (they show as 127.0.0.1).
    // External visitors are analysed directly below with their real IP — sending them
    // through the TCP ping as well would count every visit twice against 127.0.0.1.
    if (isMainRequest && isLocal) {
        const tcpSocket = new net.Socket();
        tcpSocket.setTimeout(2000);
        tcpSocket.connect(CONFIG.TCP_PORT, '127.0.0.1', () => { tcpSocket.destroy(); });
        tcpSocket.on('error',   () => {});
        tcpSocket.on('timeout', () => { tcpSocket.destroy(); });
    }

    let blocked;
    try {
        blocked = isLocal ? null :
            await BlockedIP.findOne({ ip: clientIP, expiresAt: { $gt: new Date() } });
    } catch (e) {
        blocked = null;
    }

    // Full detection (ghost IP, geo, rhythm, DNA, trust, reputation) runs here with the
    // real external IP — the TCP socket to 127.0.0.1:9000 always looks like localhost.
    // Already-blocked IPs are turned away without analysis (same as the TCP listener),
    // so a stray request from a blocked IP can't re-block it just after an admin unblocks it.
    if (isMainRequest && !isLocal && !blocked) {
        const browserFp = buildBrowserFingerprint(req);
        console.log(`[GHOST-PROXY] hit: IP=${clientIP} method=${req.method} fp=${browserFp}`);
        processVisit(clientIP, CONFIG.PROXY_PORT, browserFp, 'PROXY', arrivedAt)
            .catch(e => console.error('[PROXY-PING] error:', e.message));
    }

    if (blocked) {
        if (isMainRequest) {
            recordBlockedAttempt(clientIP, CONFIG.PROXY_PORT, 'PROXY', arrivedAt)
                .catch(e => console.error('[BLOCKED-ATTEMPT] error:', e.message));
        }
        return res.status(403).send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>403 Forbidden — TCP Monitor Proxy</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e2e8f0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
.box { background: #1a1d27; border: 1px solid #ef4444; border-radius: 16px; padding: 48px; max-width: 540px; text-align: center; box-shadow: 0 0 40px rgba(239,68,68,0.2); }
.code { font-size: 80px; font-weight: 900; color: #ef4444; line-height: 1; margin-bottom: 8px; }
.label { font-size: 14px; letter-spacing: 4px; text-transform: uppercase; color: #ef4444; margin-bottom: 24px; }
.icon { font-size: 48px; margin-bottom: 20px; }
h2 { font-size: 22px; font-weight: 700; color: #fff; margin-bottom: 12px; }
p { font-size: 14px; color: #8892a4; margin-bottom: 16px; line-height: 1.7; }
.ip { font-family: monospace; background: #21253a; padding: 10px 20px; border-radius: 8px; color: #ef4444; font-size: 15px; display: inline-block; border: 1px solid rgba(239,68,68,0.3); }
footer { margin-top: 24px; font-size: 11px; color: #4a5280; border-top: 1px solid #2e3350; padding-top: 16px; }
</style>
</head>
<body>
<div class="box">
  <div class="code">403</div>
  <div class="label">Forbidden</div>
  <div class="icon">🚫</div>
  <h2>Access Denied — Proxy Blocked</h2>
  <p>Your IP address has been blocked by the TCP security system. You cannot access the monitored website through this proxy.</p>
  <div class="ip">${escapeHtml(clientIP)}</div>
  <footer>TCP Ping Detection System — IT Project 700 | Richfield Graduate Institute of Technology | 2026</footer>
</div>
</body>
</html>`);
    }

    const banner = `<div id="tcp-monitor-bar" style="position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#1a1d27;border-bottom:2px solid #58a6ff;padding:9px 18px;font-family:'Segoe UI',sans-serif;font-size:13px;color:#c9d1d9;display:flex;align-items:center;gap:12px;box-shadow:0 2px 12px rgba(0,0,0,0.5);">
<span style="color:#58a6ff;font-weight:700;">&#x1F6E1;&#xFE0F; TCP Monitor</span>
<span style="color:#555;">|</span>
<span>Monitoring: <strong style="color:#58a6ff">${escapeHtml(monitoredURL.replace(/^https?:\/\//, '').replace(/\/$/, ''))}</strong></span>
<span style="color:#555;">|</span>
<span style="color:#3fb950;display:flex;align-items:center;gap:5px;"><span style="width:8px;height:8px;background:#3fb950;border-radius:50%;display:inline-block;animation:tcppulse 1.5s infinite;"></span>Live</span>
<span style="color:#555;">|</span>
<span style="color:#8b949e;">IP: ${escapeHtml(clientIP)}</span>
<a href="http://localhost:3000" target="_blank" style="margin-left:auto;color:#58a6ff;text-decoration:none;font-size:12px;background:rgba(88,166,255,0.1);padding:4px 12px;border-radius:4px;border:1px solid rgba(88,166,255,0.3);">Open Dashboard &#x2197;</a>
</div>
<div style="height:44px;"></div>
<style>@keyframes tcppulse{0%,100%{opacity:1}50%{opacity:0.3}}</style>`;

    let target;
    try { target = new URL(monitoredURL); } catch(e) { return res.status(500).send('Invalid monitored URL'); }

    const isHTTPS = target.protocol === 'https:';
    const lib     = isHTTPS ? https : http;
    const options = {
        hostname          : target.hostname,
        port              : target.port || (isHTTPS ? 443 : 80),
        path              : (req.url === '/' && (target.pathname || '/') !== '/') ? (target.pathname + (target.search || '')) : req.url,
        method            : req.method,
        headers           : { ...req.headers, host: target.host, 'x-forwarded-for': clientIP, 'accept-encoding': 'identity' },
        timeout           : 10000,
        rejectUnauthorized: false
    };
    delete options.headers['connection'];
    delete options.headers['upgrade'];
    delete options.headers['proxy-connection'];

    const proxyReq = lib.request(options, (proxyRes) => {
        const ct = proxyRes.headers['content-type'] || '';
        const filteredHeaders = { ...proxyRes.headers };
        delete filteredHeaders['content-security-policy'];
        delete filteredHeaders['x-frame-options'];
        delete filteredHeaders['content-encoding'];
        delete filteredHeaders['transfer-encoding'];

        // Keep redirects inside the proxy (e.g. http → https or /path → /path/),
        // otherwise the browser leaves the proxy and detection stops.
        if (filteredHeaders['location']) {
            try {
                const loc = new URL(filteredHeaders['location'], target);
                if (loc.hostname === target.hostname) {
                    if (loc.protocol !== target.protocol) {
                        // Site redirected http ↔ https — follow it for future requests
                        monitoredURL = `${loc.protocol}//${loc.host}${target.pathname}${target.search}`;
                        io.emit('proxy-url-changed', { url: monitoredURL });
                    }
                    filteredHeaders['location'] = loc.pathname + loc.search + loc.hash;
                }
            } catch (_) { /* leave location header unchanged */ }
        }

        if (ct.includes('text/html')) {
            // The body is modified (banner injected), so the original length is no longer valid
            delete filteredHeaders['content-length'];
            res.writeHead(proxyRes.statusCode, { ...filteredHeaders, 'content-type': 'text/html; charset=utf-8' });
            let body = '';
            proxyRes.setEncoding('utf8');
            proxyRes.on('data', chunk => { body += chunk; });
            proxyRes.on('end', () => {
                if (/<body[^>]*>/i.test(body)) {
                    body = body.replace(/<body([^>]*)>/i, (m, attrs) => `<body${attrs}>${banner}`);
                } else {
                    body = banner + body;
                }
                res.end(body);
            });
        } else {
            res.writeHead(proxyRes.statusCode, filteredHeaders);
            proxyRes.pipe(res);
        }
    });

    proxyReq.on('error', (err) => {
        if (res.headersSent) return res.destroy();
        if (!res.headersSent) res.status(502).send(`<h1>502 Bad Gateway</h1><p>Could not reach ${escapeHtml(monitoredURL)}: ${escapeHtml(err.message)}</p>`);
    });
    proxyReq.on('timeout', () => {
        proxyReq.destroy();
        if (!res.headersSent) res.status(504).send(`<h1>504 Timeout</h1><p>${escapeHtml(monitoredURL)} did not respond in time.</p>`);
    });

    if (req.method !== 'GET' && req.method !== 'HEAD') { req.pipe(proxyReq); } else { proxyReq.end(); }
});

proxyServer.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`Port ${CONFIG.PROXY_PORT} is already in use.`);
    } else {
        console.error('Proxy server error:', err.message);
    }
});

proxyServer.listen(CONFIG.PROXY_PORT, () => {
    console.log(`🌐 Real website proxy running at http://localhost:${CONFIG.PROXY_PORT}`);
    console.log(`   Currently monitoring: ${monitoredURL}`);
    console.log(`   Change the monitored URL from the Web Monitor tab on the dashboard`);
});

// ══════════════════════════════════════════════════════════════════════════
// API ENDPOINTS
// ══════════════════════════════════════════════════════════════════════════

app.get('/api/pings', requireAuth, async (req, res) => {
    try {
        const pings = await Ping.find().sort({ time: -1 }).limit(100);
        res.json(pings);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/alerts', requireAuth, async (req, res) => {
    try {
        const alerts = await Alert.find().sort({ time: -1 }).limit(50);
        res.json(alerts);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/alerts/:id/read', requireAuth, async (req, res) => {
    try {
        await Alert.findByIdAndUpdate(req.params.id, { read: true });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/blocked', requireAuth, async (req, res) => {
    try {
        const now     = new Date();
        const blocked = await BlockedIP.find({ expiresAt: { $gt: now } });
        res.json(blocked);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/blocked/:ip', requireAuth, async (req, res) => {
    try {
        await unblockIP(req.params.ip);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/reputations', requireAuth, async (req, res) => {
    try {
        const reps = await IPReputation.find().sort({ score: 1 }).limit(50);
        res.json(reps);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/patterns', requireAuth, async (req, res) => {
    try {
        const patterns = await TrafficPattern.find().sort({ hour: 1 });
        res.json(patterns);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/geo', requireAuth, async (req, res) => {
    try {
        const geo = await GeoPattern.find().sort({ visitCount: -1 });
        res.json(geo);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/dna', requireAuth, async (req, res) => {
    try {
        const dna = await DNAFingerprint.find().sort({ matchCount: -1 }).limit(50);
        res.json(dna);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Ghost IP Detection API endpoints ──────────────────────────────────────
app.get('/api/ghost-clusters', requireAuth, async (req, res) => {
    try {
        const clusters = await GhostCluster.find().sort({ lastSeen: -1 }).limit(100);
        res.json(clusters);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Manually unblock all IPs in a ghost cluster
app.delete('/api/ghost-clusters/:clusterId', requireAuth, async (req, res) => {
    try {
        const cluster = await GhostCluster.findOne({ clusterId: req.params.clusterId });
        if (!cluster) return res.status(404).json({ error: 'Cluster not found' });
        // Remove all IP blocks for this cluster
        for (const ip of cluster.ips) {
            await unblockIP(ip);
        }
        // Forget the in-memory signal so the same IPs are not instantly re-detected
        for (const key of [`fp:${cluster.fingerprint}`, `sn:${cluster.subnet}`]) {
            if (ghostClusterIdFor(key) === cluster.clusterId) delete ghostTracker[key];
        }
        cluster.status = 'ACTIVE';
        cluster.blockedAt = null;
        await cluster.save();
        res.json({ success: true, unblockedIPs: cluster.ips });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Reports API ───────────────────────────────────────────────────────────
app.get('/api/report', requireAuth, async (req, res) => {
    try {
        const now     = new Date();
        const last24h = new Date(now - 86400000);
        const last7d  = new Date(now - 7 * 86400000);
        const [blockedIPs, ghostClusters, recentPings, alerts, reputations, geoPatterns, trafficPatterns] = await Promise.all([
            BlockedIP.find({ expiresAt: { $gt: now } }).sort({ blockedAt: -1 }),
            GhostCluster.find().sort({ lastSeen: -1 }),
            Ping.find().sort({ time: -1 }).limit(50),
            Alert.find().sort({ time: -1 }).limit(50),
            IPReputation.find().sort({ score: 1 }).limit(30),
            GeoPattern.find().sort({ visitCount: -1 }),
            TrafficPattern.find().sort({ hour: 1 })
        ]);
        const [baseStats, pingsLast7d] = await Promise.all([
            getStats(),
            Ping.countDocuments({ time: { $gte: last7d } })
        ]);
        const stats = { ...baseStats, pingsLast7d };
        res.json({ generatedAt: now.toLocaleString('en-ZA'), stats, blockedIPs, ghostClusters, recentPings, alerts, reputations, geoPatterns, trafficPatterns });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/stats', requireAuth, async (req, res) => {
    try {
        res.json(await getStats());
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Health / resource usage (used by test-performance.js) ─────────────────
// cpuMicros is cumulative CPU time used by this Node.js process; the test script
// samples it twice and divides by the elapsed time to get CPU %.
app.get('/api/health', requireAuth, (req, res) => {
    const cpu = process.cpuUsage();
    const mem = process.memoryUsage();
    res.json({
        uptimeSeconds : Math.round(process.uptime()),
        cpuMicros     : cpu.user + cpu.system,
        rssMB         : +(mem.rss / 1048576).toFixed(1),
        heapUsedMB    : +(mem.heapUsed / 1048576).toFixed(1),
        sampledAt     : Date.now()
    });
});

// ══════════════════════════════════════════════════════════════════════════
// ADMIN MANAGEMENT APIs
// ══════════════════════════════════════════════════════════════════════════

// List all admins
app.get('/api/admins', requireAuth, async (req, res) => {
    try {
        const admins = await AdminUser.find({}, { password: 0 }).sort({ createdAt: 1 });
        res.json(admins);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Add a new admin
app.post('/api/admins', requireAuth, async (req, res) => {
    try {
        const { username, password } = req.body;
        const role = req.body.role || 'admin';
        if (typeof username !== 'string' || typeof password !== 'string' || !username || !password)
            return res.status(400).json({ error: 'Username and password required' });
        if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username))
            return res.status(400).json({ error: 'Username must be 3–32 characters: letters, numbers, . _ -' });
        if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
        if (!['admin', 'superadmin'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
        if (role === 'superadmin' && req.session.role !== 'superadmin')
            return res.status(403).json({ error: 'Only a Super Admin can create another Super Admin' });
        if (await AdminUser.findOne({ username })) return res.status(400).json({ error: 'Username already exists' });
        const newAdmin = await AdminUser.create({
            username,
            password  : await hashPassword(password),
            role,
            createdBy : req.session.username
        });
        ADMIN_USERS[username] = newAdmin.password;
        res.json({ success: true, username: newAdmin.username, role: newAdmin.role });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Delete an admin (cannot delete yourself) — SUPER ADMIN ONLY
app.delete('/api/admins/:username', requireSuperAdmin, async (req, res) => {
    try {
        const target = req.params.username;
        if (target === req.session.username) return res.status(400).json({ error: 'Cannot delete your own account' });
        if (!(await AdminUser.findOne({ username: target }))) return res.status(404).json({ error: 'Admin not found' });
        const adminCount = await AdminUser.countDocuments();
        if (adminCount <= 1) return res.status(400).json({ error: 'Cannot delete the last admin account' });
        await AdminUser.deleteOne({ username: target });
        delete ADMIN_USERS[target];
        // Destroy any active sessions for that user
        for (const [tok, sess] of Object.entries(sessions)) {
            if (sess.username === target) delete sessions[tok];
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Change password for any admin — SUPER ADMIN ONLY
app.post('/api/admins/:username/password', requireSuperAdmin, async (req, res) => {
    try {
        const { newPassword } = req.body;
        if (typeof newPassword !== 'string' || newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
        const hashed = await hashPassword(newPassword);
        const updated = await AdminUser.findOneAndUpdate({ username: req.params.username }, { password: hashed });
        if (!updated) return res.status(404).json({ error: `Admin "${req.params.username}" not found` });
        ADMIN_USERS[req.params.username] = hashed;
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Password reset using master reset code (no auth required — for locked-out admins)
app.post('/api/reset-password', async (req, res) => {
    try {
        const { username, newPassword, resetCode } = req.body;
        if (resetCode !== MASTER_RESET_CODE) return res.status(403).json({ error: 'Invalid reset code' });
        if (typeof username !== 'string' || typeof newPassword !== 'string' || !username || newPassword.length < 6) return res.status(400).json({ error: 'Username and password (min 6 chars) required' });
        let admin = await findAdminByName(username);
        if (!admin && username.trim().toLowerCase() === 'admin') admin = await ensureDefaultAdmin();
        if (!admin) return res.status(404).json({ error: 'Admin not found' });
        const hashed = await hashPassword(newPassword);
        admin.password = hashed;
        await admin.save();
        ADMIN_USERS[admin.username] = hashed;
        res.json({ success: true, message: 'Password reset successfully' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════════════════
// BACKUP & RESTORE APIs
// ══════════════════════════════════════════════════════════════════════════

// Create a full database backup (JSON export)
app.post('/api/backup', requireAuth, async (req, res) => {
    try {
        const [pings, alerts, blocked, reputations, patterns, geo, dna, ghosts] = await Promise.all([
            Ping.find().lean(),
            Alert.find().lean(),
            BlockedIP.find().lean(),
            IPReputation.find().lean(),
            TrafficPattern.find().lean(),
            GeoPattern.find().lean(),
            DNAFingerprint.find().lean(),
            GhostCluster.find().lean()
        ]);

        const backup = {
            version    : '1.0',
            createdAt  : new Date().toISOString(),
            createdBy  : req.session.username,
            system     : 'TCP Ping Detection System — Richfield IT Project 700',
            collections: { pings, alerts, blocked, reputations, patterns, geo, dna, ghosts }
        };

        const json      = JSON.stringify(backup, null, 2);
        const bytes     = Buffer.byteLength(json, 'utf8');
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        const filename  = `tcp_backup_${timestamp}.json`;

        // Log the backup
        await BackupLog.create({
            filename,
            createdBy  : req.session.username,
            collections: ['pings','alerts','blocked','reputations','patterns','geo','dna','ghosts'],
            sizeBytes  : bytes
        });

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.send(json);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// List backup history
app.get('/api/backup/history', requireAuth, async (req, res) => {
    try {
        const logs = await BackupLog.find().sort({ createdAt: -1 }).limit(20);
        res.json(logs);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Restore from backup JSON — SUPER ADMIN ONLY
app.post('/api/restore', requireSuperAdmin, async (req, res) => {
    try {
        const { backup } = req.body;
        if (!backup || !backup.collections) return res.status(400).json({ error: 'Invalid backup format' });
        let restored = 0;
        const cols = backup.collections;

        let failed = 0;
        const upsertAll = async (Model, records, key) => {
            for (const r of (Array.isArray(records) ? records : [])) {
                try {
                    if (!r || r[key] === undefined) { failed++; continue; }
                    const filter = { [key]: r[key] };
                    // _id can't be changed on an existing document, so only keep it when
                    // it is the lookup key — otherwise the update fails for existing records.
                    const update = { ...r };
                    delete update.__v;
                    if (key !== '_id') delete update._id;
                    await Model.findOneAndUpdate(filter, update, { upsert: true, new: true });
                    restored++;
                } catch (e) { failed++; }
            }
        };

        await upsertAll(Ping,         cols.pings,       '_id');
        await upsertAll(Alert,        cols.alerts,      '_id');
        await upsertAll(BlockedIP,    cols.blocked,     'ip');
        await upsertAll(IPReputation, cols.reputations, 'ip');
        await upsertAll(TrafficPattern, cols.patterns,  'hour');
        await upsertAll(GeoPattern,   cols.geo,         'country');
        await upsertAll(DNAFingerprint, cols.dna,       'fingerprint');
        await upsertAll(GhostCluster, cols.ghosts,      'clusterId');

        res.json({ success: true, restored, failed });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/learning', requireAuth, async (req, res) => {
    try {
        const reputations = await IPReputation.find().sort({ score: -1 });
        const patterns    = await TrafficPattern.find().sort({ hour: 1 });
        const geo         = await GeoPattern.find().sort({ visitCount: -1 });
        const dna         = await DNAFingerprint.find().sort({ matchCount: -1 }).limit(20);
        res.json({ reputations, patterns, geo, dna, currentThreshold: selfLearningThreshold, clusterCount: CONFIG.CLUSTER_COUNT, totalIPs: reputations.length, trustedIPs: reputations.filter(r => r.trusted).length, clusters: clusterData });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════════════════
// ALL UNIQUE FEATURES (unchanged from previous version)
// ══════════════════════════════════════════════════════════════════════════

async function analyzeGeography(ip) {
    const geo     = geoip.lookup(ip);
    const country = countryName(geo ? geo.country : 'Unknown');
    const city    = geo ? (geo.city || 'Unknown') : 'Unknown';
    return withLock(`geo:${country}`, () => _analyzeGeography(country, city));
}
async function _analyzeGeography(country, city) {
    const geoPattern = await findOrCreate(GeoPattern, { country }, { visitCount: 0, riskScore: 50 });
    geoPattern.visitCount++;
    geoPattern.lastSeen = new Date();
    if (geoPattern.visitCount > 10 && geoPattern.normalCount > geoPattern.visitCount * 0.8) { geoPattern.trusted = true; geoPattern.riskScore = 10; }
    await geoPattern.save();
    let geoRisk = 'NORMAL';
    if (!geoPattern.trusted && geoPattern.visitCount < 3) geoRisk = 'SUSPICIOUS';
    if (geoPattern.riskScore > 70) geoRisk = 'MALICIOUS';
    knownGeoPatterns[country] = geoRisk;
    return { country, city, geoRisk, geoPattern };
}

async function analyzeTimePersonality(ip) {
    const currentHour = new Date().getHours();
    const rep         = await IPReputation.findOne({ ip });
    if (!rep || rep.visitHours.length < 5) return { timeRisk: 0, unusualTime: false };
    const hourCounts  = {};
    rep.visitHours.forEach(h => { hourCounts[h] = (hourCounts[h] || 0) + 1; });
    const totalVisits = rep.visitHours.length;
    const thisHourPct = (hourCounts[currentHour] || 0) / totalVisits;
    const unusualTime = thisHourPct < 0.05;
    const timeRisk    = unusualTime ? Math.round((1 - thisHourPct) * 100) : 0;
    return { timeRisk, unusualTime };
}

// `now` = when the visit ARRIVED (not when it was processed), so a busy server
// doesn't make a fast bot look like a slow human
function analyzeConnectionRhythm(ip, now = Date.now()) {
    if (!rhythmTracker[ip]) rhythmTracker[ip] = { timestamps: [], pauses: [] };
    const tracker = rhythmTracker[ip];
    if (tracker.timestamps.length > 0) {
        const pause = Math.max(0, now - tracker.timestamps[tracker.timestamps.length - 1]);
        tracker.pauses.push(pause);
        if (tracker.pauses.length > CONFIG.RHYTHM_WINDOW) tracker.pauses.shift();
    }
    tracker.timestamps.push(now);
    // Only the most recent timestamp is needed to measure the next pause — keep the
    // list short so memory doesn't grow forever on a long-running server
    if (tracker.timestamps.length > CONFIG.RHYTHM_WINDOW) tracker.timestamps.shift();
    if (tracker.pauses.length < 5) return { rhythmScore: 0, isBot: false };
    const avgPause      = tracker.pauses.reduce((a,b) => a+b, 0) / tracker.pauses.length;
    const variance      = tracker.pauses.reduce((a,b) => a + Math.pow(b - avgPause, 2), 0) / tracker.pauses.length;
    const stdDev        = Math.sqrt(variance);
    const tooFast       = avgPause < CONFIG.MIN_HUMAN_PAUSE_MS;
    const tooConsistent = stdDev < 50 && tracker.pauses.length >= 5;
    const isBot         = tooFast || tooConsistent;
    const rhythmScore   = Math.min(100, Math.round((tooFast ? 50 : 0) + (tooConsistent ? Math.max(0, 50 - stdDev) : 0)));
    return { rhythmScore, isBot, avgPause: Math.round(avgPause), stdDev: Math.round(stdDev) };
}

async function analyzeDNAFingerprint(ip, count, reputationScore, currentHour, rhythmScore, country) {
    const hourBucket   = Math.floor(currentHour / 4);
    const countBucket  = Math.min(5, Math.floor(count / 2));
    const repBucket    = Math.floor(reputationScore / 20);
    const rhythmBucket = Math.floor(rhythmScore / 25);
    const fingerprint  = `${hourBucket}-${countBucket}-${repBucket}-${rhythmBucket}-${country}`;
    const existing = await withLock(`dna:${fingerprint}`, () => DNAFingerprint.findOneAndUpdate(
        { fingerprint },
        { $inc: { matchCount: 1 }, $set: { lastSeen: new Date() }, $setOnInsert: { ip, label: 'UNKNOWN' } },
        { upsert: true, new: false }
    ));
    const dnaMatch = existing ? existing.label : 'NEW';
    return { fingerprint, dnaMatch };
}

async function analyzeTrustNetwork(ip, count, currentHour, country) {
    const trustedIPs = await IPReputation.find({ trusted: true });
    if (trustedIPs.length === 0) return { trustBoost: 0, trustMatch: null };
    let bestMatch = null; let bestScore = 0;
    for (const trusted of trustedIPs) {
        if (trusted.ip === ip) continue;
        let similarity = 0;
        if (trusted.country === country) similarity += 0.3;
        if (trusted.visitHours.length > 0 && new Set(trusted.visitHours).has(currentHour)) similarity += 0.3;
        const freqSimilarity = 1 - Math.min(1, Math.abs(count - (trusted.totalPings / 10)) / 10);
        similarity += freqSimilarity * 0.4;
        if (similarity > bestScore) { bestScore = similarity; bestMatch = trusted.ip; }
    }
    let trustBoost = 0;
    if (bestScore >= CONFIG.TRUST_SIMILARITY) trustBoost = Math.round(CONFIG.TRUST_BOOST * bestScore);
    return { trustBoost, trustMatch: bestMatch };
}

function trackConnection(ip, now = Date.now()) {
    if (!connectionTracker[ip]) connectionTracker[ip] = [];
    connectionTracker[ip] = connectionTracker[ip].filter(t => now - t < CONFIG.WINDOW_MS);
    connectionTracker[ip].push(now);
    return connectionTracker[ip].length;
}

function classify(count, reputationScore, isBot, geoRisk, unusualTime, rhythmScore) {
    // Bots are always suspicious/malicious regardless of reputation
    if (isBot) return count >= CONFIG.MALICIOUS_LIMIT ? 'MALICIOUS' : 'SUSPICIOUS';

    // Known malicious geo — always MALICIOUS
    if (geoRisk === 'MALICIOUS') return 'MALICIOUS';

    // Reputation gives leniency on the COUNT threshold only — not immunity.
    // Trusted IPs (80+) get 2× the threshold before flagging.
    // Good IPs (60+) get 1.5× the threshold.
    // Unknown/low IPs use the raw threshold.
    let multiplier = 1;
    if (reputationScore >= CONFIG.TRUSTED_SCORE) multiplier = 2;
    else if (reputationScore >= 60)              multiplier = 1.5;

    const suspiciousAt = Math.ceil(selfLearningThreshold * multiplier);
    const maliciousAt  = Math.ceil(selfLearningThreshold * multiplier * 1.5);

    if (geoRisk === 'SUSPICIOUS' && count >= suspiciousAt) return 'SUSPICIOUS';
    if (unusualTime && count >= suspiciousAt)              return 'SUSPICIOUS';
    if (count >= maliciousAt)  return 'MALICIOUS';
    if (count >= suspiciousAt) return 'SUSPICIOUS';
    return 'NORMAL';
}

async function getReputation(ip) {
    return withLock(`repc:${ip}`, () => findOrCreate(IPReputation, { ip }, { score: CONFIG.REPUTATION_START }));
}

function updateReputation(...args) {
    return withLock(`rep:${args[0]}`, () => _updateReputation(...args));
}
async function _updateReputation(ip, classification, country, city, currentHour, avgRhythm, fingerprint, trustBoost, startedAt) {
    const rep = await getReputation(ip);
    // A visit that began before an admin unblocked this IP must not undo the unblock
    const stale = startedAt !== undefined && wasUnblockedSince(ip, startedAt);
    let scoreDelta = 0;
    if (classification === 'NORMAL') { scoreDelta = CONFIG.REPUTATION_NORMAL_UP + trustBoost; rep.normalPings++; }
    else if (classification === 'SUSPICIOUS') { scoreDelta = CONFIG.REPUTATION_SUSPICIOUS; rep.suspiciousPings++; }
    else if (classification === 'MALICIOUS') { scoreDelta = CONFIG.REPUTATION_MALICIOUS; rep.maliciousPings++; }
    if (stale) scoreDelta = 0;
    rep.score = Math.max(CONFIG.REPUTATION_MIN, Math.min(CONFIG.REPUTATION_MAX, rep.score + scoreDelta));
    // A blocked IP never gains reputation (e.g. the visit that triggered a ghost-cluster block)
    if (!stale && rep.score > CONFIG.BLOCK_SCORE && await isBlocked(ip)) rep.score = CONFIG.BLOCK_SCORE;
    rep.totalPings++; rep.lastSeen = new Date(); rep.trusted = rep.score >= CONFIG.TRUSTED_SCORE;
    rep.country = country; rep.city = city; rep.avgRhythm = avgRhythm || rep.avgRhythm;
    rep.dnaFingerprint = fingerprint; rep.trustNetworkScore = trustBoost;
    rep.visitHours.push(currentHour);
    if (rep.visitHours.length > 100) rep.visitHours.shift();
    await rep.save();
    if (rep.score <= CONFIG.BLOCK_SCORE && !stale) await blockIP(ip, `Reputation score too low: ${rep.score}/100`, startedAt);
    return rep;
}

async function calculateAnomalyScore(ip, count) {
    const currentHour = new Date().getHours();
    const pattern     = await TrafficPattern.findOne({ hour: currentHour });
    if (!pattern || pattern.sampleCount < 5) return 0;
    const deviation    = count - pattern.avgPings;
    const maxDeviation = pattern.maxPings - pattern.avgPings || 1;
    return Math.min(100, Math.max(0, Math.round((deviation / maxDeviation) * 100)));
}

function updateTrafficPattern(count, country) {
    return withLock(`tp:${new Date().getHours()}`, () => _updateTrafficPattern(count, country));
}
async function _updateTrafficPattern(count, country) {
    const hour    = new Date().getHours();
    const pattern = await findOrCreate(TrafficPattern, { hour }, { sampleCount: 0 });
    pattern.sampleCount++;
    pattern.avgPings  = Math.round(((pattern.avgPings * (pattern.sampleCount-1)) + count) / pattern.sampleCount);
    pattern.maxPings  = Math.max(pattern.maxPings, count);
    pattern.threshold = Math.round(pattern.avgPings * 1.5) || CONFIG.SUSPICIOUS_LIMIT;
    if (country && country !== 'Unknown' && !pattern.topCountries.includes(country)) {
        pattern.topCountries.push(country);
        if (pattern.topCountries.length > 5) pattern.topCountries.shift();
    }
    await pattern.save();
}

async function runClustering() {
    try {
        const reps = await IPReputation.find();
        if (reps.length < CONFIG.CLUSTER_COUNT) return;
        const data   = reps.map(r => [r.score/100, r.normalPings/(r.totalPings||1), r.suspiciousPings/(r.totalPings||1), r.maliciousPings/(r.totalPings||1)]);
        const result = kmeans(data, CONFIG.CLUSTER_COUNT, {});

        // k-means numbers its clusters in random order, so cluster "0" is not necessarily
        // the good one. Rank the clusters by average reputation score (highest first) and
        // relabel them so that 0 = TRUSTED/normal, 1 = SUSPICIOUS, 2 = MALICIOUS.
        const sums = {}, counts = {};
        result.clusters.forEach((c, i) => { sums[c] = (sums[c] || 0) + reps[i].score; counts[c] = (counts[c] || 0) + 1; });
        const ranked = Object.keys(sums).map(Number).sort((a, b) => (sums[b] / counts[b]) - (sums[a] / counts[a]));
        const remap  = {};
        ranked.forEach((c, rank) => { remap[c] = Math.min(rank, 2); });
        const labels = result.clusters.map(c => remap[c]);
        clusterData  = labels;

        for (let i = 0; i < reps.length; i++) {
            await IPReputation.findByIdAndUpdate(reps[i]._id, { cluster: labels[i] });
            if (reps[i].dnaFingerprint) {
                const label = labels[i] === 0 ? 'TRUSTED' : labels[i] === 1 ? 'SUSPICIOUS' : 'MALICIOUS';
                await DNAFingerprint.findOneAndUpdate({ fingerprint: reps[i].dnaFingerprint }, { label });
            }
        }
        console.log('Clustering updated');
        io.emit('clustering-updated', { clusters: labels });
    } catch (err) { console.error('Clustering error:', err.message); }
}

async function updateSelfLearningThreshold() {
    const currentHour = new Date().getHours();
    const pattern     = await TrafficPattern.findOne({ hour: currentHour });
    if (pattern && pattern.sampleCount >= 5) {
        selfLearningThreshold = Math.max(CONFIG.SUSPICIOUS_LIMIT, Math.round(pattern.avgPings * 1.5));
        io.emit('threshold-updated', { threshold: selfLearningThreshold });
    }
}

// Blocks are permanent unless CONFIG.BLOCK_DURATION_MS is set
const PERMANENT_BLOCK_DATE = new Date('9999-12-31T23:59:59Z');
function blockExpiryDate() {
    return CONFIG.BLOCK_DURATION_MS ? new Date(Date.now() + CONFIG.BLOCK_DURATION_MS) : PERMANENT_BLOCK_DATE;
}

async function isBlocked(ip) {
    const now     = new Date();
    const blocked = await BlockedIP.findOne({ ip, expiresAt: { $gt: now } });
    return blocked !== null;
}

// Block and unblock for the same IP take turns (per-IP lock). `startedAt` = when the visit
// that caused this block arrived — if an admin unblocked the IP after that, the block is dropped.
function blockIP(ip, reason, startedAt) {
    return withLock(`block:${ip}`, async () => {
        if (startedAt !== undefined && wasUnblockedSince(ip, startedAt)) return;
        await _blockIP(ip, reason);
    });
}
async function _blockIP(ip, reason) {
    const expiresAt = blockExpiryDate();
    await BlockedIP.findOneAndUpdate({ ip }, { ip, reason, blockedAt: new Date(), expiresAt }, { upsert: true });
    // A blocked IP can't keep a good reputation (e.g. one blocked as part of a ghost
    // cluster) — drop it to the block level so the score matches its status
    await IPReputation.updateOne({ ip, score: { $gt: CONFIG.BLOCK_SCORE } },
        { $set: { score: CONFIG.BLOCK_SCORE, trusted: false } });
    console.log(`IP BLOCKED: ${ip} — ${reason}`);
    console.log(`IP ${ip} will now be redirected to blocked page on the aviation website`);
    io.emit('ip-blocked', { ip, reason, expiresAt });
}

// Manually unblock an IP. Its reputation is reset to the neutral starting score and its
// short-term counters are cleared — otherwise an IP that was blocked for a low score
// (e.g. 0/100) would be blocked again on its very next visit.
// When each IP was last manually unblocked (used to ignore visits already in progress)
const unblockedAt = {};
function wasUnblockedSince(ip, time) { return (unblockedAt[ip] || 0) >= time; }

async function unblockIP(ip) {
    unblockedAt[ip] = Date.now();
    delete connectionTracker[ip];
    delete rhythmTracker[ip];
    await withLock(`block:${ip}`, async () => {
        await BlockedIP.deleteOne({ ip });
        await IPReputation.updateOne({ ip }, { $set: { score: CONFIG.REPUTATION_START, trusted: false } });
    });
    console.log(`IP UNBLOCKED: ${ip} (reputation reset to ${CONFIG.REPUTATION_START})`);
    io.emit('ip-unblocked', { ip });
}

// A blocked IP that keeps trying is recorded as MALICIOUS (blocked = true) so the attack
// stays visible on the dashboard. It does NOT go through the learning pipeline again,
// so it can't affect reputation, counters or blocking.
async function recordBlockedAttempt(ip, port, source, arrivedAt = Date.now()) {
    const geo     = geoip.lookup(ip);
    const country = countryName(geo ? geo.country : 'Unknown');
    const city    = geo ? (geo.city || 'Unknown') : 'Unknown';
    // Each new attempt from a blocked IP is a malicious ping and lowers its reputation
    // (skipped if an admin unblocked the IP after this attempt arrived)
    const rep = await withLock(`rep:${ip}`, async () => {
        const r = await getReputation(ip);
        if (!wasUnblockedSince(ip, arrivedAt)) {
            r.score = Math.max(CONFIG.REPUTATION_MIN, Math.min(r.score, CONFIG.BLOCK_SCORE) + CONFIG.REPUTATION_MALICIOUS);
            r.trusted = false;
            r.maliciousPings++;
            r.totalPings++;
            r.lastSeen = new Date();
            r.country = country; r.city = city;
            await r.save();
        }
        return r;
    });
    const ping    = new Ping({
        ip, port, classification: 'MALICIOUS', blocked: true,
        reputationScore: rep ? rep.score : 0,
        cluster        : rep ? rep.cluster : 0,
        country, city,
        dnaMatch       : 'BLOCKED'
    });
    await ping.save();
    console.log(`[${source}] [MALICIOUS] ${ip} | blocked IP tried again — rejected`);
    io.emit('new-ping', { id: ping._id, ip: ping.ip, port: ping.port, time: ping.time.toLocaleString('en-ZA'), classification: ping.classification, reputationScore: ping.reputationScore, anomalyScore: 0, cluster: ping.cluster, country: ping.country, city: ping.city, geoRisk: ping.geoRisk, rhythmScore: 0, isBot: false, dnaMatch: ping.dnaMatch, trustNetworkBoost: 0, blocked: true });
    scheduleStatsUpdate();
}

async function createAlert(ip, type, message) {
    const alert = new Alert({ ip, type, message });
    await alert.save();
    io.emit('new-alert', { id: alert._id, ip: alert.ip, type: alert.type, message: alert.message, time: alert.time.toLocaleString('en-ZA'), read: false });
}

async function getStats() {
    const now     = new Date();
    const last24h = new Date(now - 86400000);
    // All counts run in parallel (they used to run one after another)
    const [totalPings, pingsLast24h, normalCount, suspiciousCount, maliciousCount, blockedCount,
           unreadAlerts, trustedIPs, botCount, uniqueCountries, dnaFingerprints, ghostClusters] = await Promise.all([
        Ping.countDocuments(),
        Ping.countDocuments({ time: { $gte: last24h } }),
        Ping.countDocuments({ classification: 'NORMAL' }),
        Ping.countDocuments({ classification: 'SUSPICIOUS' }),
        Ping.countDocuments({ classification: 'MALICIOUS' }),
        BlockedIP.countDocuments({ expiresAt: { $gt: now } }),
        Alert.countDocuments({ read: false }),
        IPReputation.countDocuments({ trusted: true }),
        Ping.countDocuments({ isBot: true }),
        GeoPattern.countDocuments(),
        DNAFingerprint.countDocuments(),
        GhostCluster.countDocuments()
    ]);
    return { totalPings, pingsLast24h, normalCount, suspiciousCount, maliciousCount, blockedCount,
             unreadAlerts, trustedIPs, botCount, uniqueCountries, dnaFingerprints, ghostClusters,
             currentThreshold: selfLearningThreshold };
}

// Push fresh dashboard numbers at most once per second. Previously the full set of
// counts ran after EVERY visit, which slowed the whole system down during a flood.
let _statsTimer = null;
function scheduleStatsUpdate() {
    if (_statsTimer) return;
    _statsTimer = setTimeout(async () => {
        _statsTimer = null;
        try { io.emit('stats-update', await getStats()); }
        catch (err) { console.error('Stats update error:', err.message); }
    }, 1000);
}

// ══════════════════════════════════════════════════════════════════════════
// NEW FEATURE 8: GHOST IP DETECTION
//
// How it works:
//  - Every connection carries two "link keys": its browser fingerprint AND its
//    /24 subnet.  These are the signals that tie different IPs to the same
//    human even when they keep changing IP addresses.
//  - In-memory ghostTracker maps each key → { ips: Map<ip, lastSeen>, confirmed }.
//    IPs not seen within GHOST_IP_WINDOW_MS are pruned on every check, so only
//    genuine hopping inside the window forms a NEW cluster.
//  - Once a cluster is confirmed, any further IP with the same key joins it and is
//    blocked straight away. Alerts are only raised when a cluster gains new IPs.
//  - When the same key is seen from 3+ DIFFERENT IPs within the window, a
//    Ghost IP Cluster is created in MongoDB.
//  - If CONFIG.GHOST_IP_BLOCK_ALL is true, EVERY IP in the cluster gets
//    blocked immediately, including any future ones that match the same key.
//  - The cluster is saved to MongoDB so the dashboard can show it.
//  - A GHOST_IP alert is fired and emitted live via Socket.io.
// ══════════════════════════════════════════════════════════════════════════

async function detectGhostIP(ip, browserFingerprint, country) {
    // Localhost is never flagged as a ghost IP
    if (LOCALHOST_IPS.includes(ip)) return { isGhost: false };

    const subnet = getSubnet(ip);
    const now    = Date.now();

    // We check two separate signals and use whichever one fires first
    const signals = [
        { key: `fp:${browserFingerprint}`, label: 'browser fingerprint', value: browserFingerprint },
        { key: `sn:${subnet}`,             label: 'subnet',              value: subnet }
    ];

    for (const signal of signals) {
        const tracker = getGhostTracker(signal.key);

        // Record this IP, then forget IPs not seen within the detection window
        // (unless a cluster is already confirmed for this signal — then we keep them all)
        tracker.ips.set(ip, now);
        if (!tracker.confirmed) {
            for (const [seenIP, seenAt] of tracker.ips) {
                if (now - seenAt > CONFIG.GHOST_IP_WINDOW_MS) tracker.ips.delete(seenIP);
            }
        }

        // Ghost IP = same signal from 3+ different IPs within the window
        // (or any new IP matching a signal that is already a confirmed ghost cluster)
        if (!tracker.confirmed && tracker.ips.size < CONFIG.GHOST_IP_THRESHOLD) continue;

        const clusterIPs = Array.from(tracker.ips.keys());
        const clusterId  = ghostClusterIdFor(signal.key);
        return withLock(`ghost:${clusterId}`, () => recordGhostCluster(ip, signal, tracker, clusterIPs, clusterId, browserFingerprint, subnet, country));
    }

    return { isGhost: false, clusterId: null };
}

async function recordGhostCluster(ip, signal, tracker, clusterIPs, clusterId, browserFingerprint, subnet, country) {
    {
        clusterIPs = Array.from(tracker.ips.keys()); // refresh — other visits may have added IPs while we waited
        let   newIPs     = clusterIPs;

        // Upsert cluster record in MongoDB
        const existing = await GhostCluster.findOne({ clusterId });
        if (existing) {
            newIPs = clusterIPs.filter(x => !existing.ips.includes(x));
            const wasBlocked = existing.status === 'BLOCKED';
            existing.ips      = [...existing.ips, ...newIPs];
            existing.ipCount  = existing.ips.length;
            existing.lastSeen = new Date();
            existing.status   = 'BLOCKED';
            if (!existing.blockedAt) existing.blockedAt = new Date();
            await existing.save();
            // Re-detected after an admin dismissed it — treat every IP as new again
            if (!wasBlocked) newIPs = clusterIPs;
        } else {
            await GhostCluster.create({
                clusterId,
                ips        : clusterIPs,
                fingerprint: browserFingerprint,
                subnet,
                country,
                ipCount    : clusterIPs.length,
                status     : 'BLOCKED',
                blockedAt  : new Date(),
                reason     : `IP hopping detected via ${signal.label} — ${clusterIPs.length} IPs in ${CONFIG.GHOST_IP_WINDOW_MS / 60000} min`
            });
            console.log(`👻 GHOST IP CLUSTER detected [${signal.label}]: ${clusterIPs.join(', ')}`);
        }
        tracker.confirmed = true;

        // Nothing new in this cluster — it is already blocked, so don't spam alerts
        if (newIPs.length === 0) return { isGhost: true, clusterId, isNew: false };

        // Block the IPs in the cluster if the setting is enabled
        if (CONFIG.GHOST_IP_BLOCK_ALL) {
            for (const ghostIP of newIPs) {
                if (!LOCALHOST_IPS.includes(ghostIP)) {
                    await blockIP(ghostIP, `Ghost IP cluster — IP hopping via ${signal.label}`);
                }
            }
        }

        // Fire alert
        const msg = `👻 GHOST IP detected: ${clusterIPs.length} IPs linked by ${signal.label} (${signal.value}) — cluster ${clusterId}`;
        await createAlert(ip, 'GHOST_IP', msg);

        // Emit real-time update to dashboard
        io.emit('ghost-ip-detected', {
            clusterId,
            ips        : clusterIPs,
            signal     : signal.label,
            fingerprint: browserFingerprint,
            subnet,
            country,
            ipCount    : clusterIPs.length,
            isNew      : !existing,
            time       : new Date().toLocaleString('en-ZA')
        });

        return { isGhost: true, clusterId, isNew: true }; // one detection is enough — don't double-alert
    }
}

function initLearning() {
    setInterval(async () => {
        try {
            await runClustering();
            await updateSelfLearningThreshold();
            const stats = await getStats();
            io.emit('stats-update', stats);
        } catch (err) { console.error('Learning cycle error:', err.message); }
    }, CONFIG.LEARNING_INTERVAL_MS);

    setInterval(async () => {
        try {
            const result = await BlockedIP.deleteMany({ expiresAt: { $lt: new Date() } });
            if (result.deletedCount > 0) console.log(`Cleaned up ${result.deletedCount} expired blocks`);
        } catch (err) { console.error('Block cleanup error:', err.message); }
    }, CONFIG.LEARNING_INTERVAL_MS);

    console.log('All unique semi-supervised learning features initialised');
    console.log('Features: Geographic Learning, Time Personality, Rhythm Detection, DNA Fingerprinting, Trust Network');
    console.log('NEW: IP Website Access Control — blocked IPs cannot access the aviation website');
    console.log('NEW: Real Website Proxy Monitor — proxy any website through TCP detection on port 8082');
    console.log('NEW: Ghost IP Detection — detects IP-hopping evasion and blocks entire clusters');
}

// ══════════════════════════════════════════════════════════════════════════
// TCP LISTENER
// ══════════════════════════════════════════════════════════════════════════
const tcpServer = net.createServer(async (socket) => {
    socket.on('error', () => {});
    try {
        await handleConnection(socket);
    } catch (err) {
        console.error('Connection handling error:', err.message);
        socket.destroy();
    }
});

async function handleConnection(socket) {
    const arrivedAt   = Date.now();   // recorded before any waiting, so an unblock that
                                      // happens while this connection is queued still wins
    const ip          = normalizeIP(socket.remoteAddress);
    const port        = socket.remotePort    || 0;
    const currentHour = new Date().getHours();

    if (await isBlocked(ip)) {
        console.log(`Blocked IP: ${ip}`);
        socket.destroy();
        await recordBlockedAttempt(ip, port, 'TCP', arrivedAt);
        return;
    }

    // TCP connections don't carry HTTP headers, so we use subnet + hour as the fingerprint
    const tcpFingerprint = crypto.createHash('md5')
        .update(`${getSubnet(ip)}|${currentHour}`)
        .digest('hex').slice(0, 16);

    await processVisit(ip, port, tcpFingerprint, 'TCP', arrivedAt);
    socket.end();
}

// ── Shared detection pipeline (used by the TCP listener AND the website proxy) ──
async function processVisit(ip, port, fingerprint, source, arrivedAt) {
    const startedAt   = arrivedAt || Date.now();
    const currentHour = new Date().getHours();

    const [rep, geoResult, timeResult] = await Promise.all([
        getReputation(ip),
        analyzeGeography(ip),
        analyzeTimePersonality(ip)
    ]);

    // ── Ghost IP detection (subnet + fingerprint) ──────────────────────────
    const ghostResult = await detectGhostIP(ip, fingerprint, geoResult.country);
    if (ghostResult.isGhost && ghostResult.isNew) {
        console.log(`👻 Ghost IP confirmed: ${ip} — cluster ${ghostResult.clusterId}`);
    }

    // A visit that was already queued when an admin unblocked this IP must not refill
    // the freshly-reset counters — otherwise the next real visit looks like a flood.
    const queuedBeforeUnblock = wasUnblockedSince(ip, startedAt);
    const count        = queuedBeforeUnblock ? 1 : trackConnection(ip, startedAt);
    const rhythmResult = queuedBeforeUnblock ? { rhythmScore: 0, isBot: false } : analyzeConnectionRhythm(ip, startedAt);
    const anomalyScore = await calculateAnomalyScore(ip, count);
    const dnaResult    = await analyzeDNAFingerprint(ip, count, rep.score, currentHour, rhythmResult.rhythmScore, geoResult.country);
    const trustResult  = await analyzeTrustNetwork(ip, count, currentHour, geoResult.country);

    const classification = classify(count, rep.score + trustResult.trustBoost, rhythmResult.isBot, geoResult.geoRisk, timeResult.unusualTime, rhythmResult.rhythmScore);

    await updateTrafficPattern(count, geoResult.country);

    // Geographic learning: count normal visits per country so countries can become trusted
    if (classification === 'NORMAL') {
        await GeoPattern.updateOne({ country: geoResult.country }, { $inc: { normalCount: 1 } });
    }

    // Update reputation FIRST so the ping is saved/emitted with the NEW score
    const updatedRep = await updateReputation(ip, classification, geoResult.country, geoResult.city, currentHour, rhythmResult.avgPause, dnaResult.fingerprint, trustResult.trustBoost, startedAt);

    const ping = new Ping({
        ip, port, classification, blocked: false,
        reputationScore  : updatedRep.score,
        anomalyScore,
        cluster          : updatedRep.cluster,
        country          : geoResult.country,
        city             : geoResult.city,
        geoRisk          : geoResult.geoRisk,
        rhythmScore      : rhythmResult.rhythmScore,
        isBot            : rhythmResult.isBot,
        dnaFingerprint   : dnaResult.fingerprint,
        dnaMatch         : dnaResult.dnaMatch,
        trustNetworkBoost: trustResult.trustBoost
    });

    try {
        await ping.save();
        console.log(`[${source}] [${classification}] ${ip} | Geo:${geoResult.country} | Bot:${rhythmResult.isBot} | DNA:${dnaResult.dnaMatch} | Trust:+${trustResult.trustBoost} | Ghost:${ghostResult.isGhost}`);
        io.emit('new-ping', { id: ping._id, ip: ping.ip, port: ping.port, time: ping.time.toLocaleString('en-ZA'), classification: ping.classification, reputationScore: ping.reputationScore, anomalyScore: ping.anomalyScore, cluster: ping.cluster, country: ping.country, city: ping.city, geoRisk: ping.geoRisk, rhythmScore: ping.rhythmScore, isBot: ping.isBot, dnaMatch: ping.dnaMatch, trustNetworkBoost: ping.trustNetworkBoost });
        scheduleStatsUpdate();
    } catch (err) { console.error('Failed to save ping:', err.message); }

    if (classification === 'SUSPICIOUS') {
        let reason = `Suspicious activity from ${ip}`;
        if (rhythmResult.isBot)      reason += ' — BOT DETECTED';
        if (timeResult.unusualTime)  reason += ' — UNUSUAL TIME';
        if (geoResult.geoRisk !== 'NORMAL') reason += ` — GEO RISK (${geoResult.country})`;
        if (ghostResult.isGhost)     reason += ` — GHOST IP CLUSTER ${ghostResult.clusterId}`;
        await createAlert(ip, 'SUSPICIOUS', reason);
    }

    if (classification === 'MALICIOUS') {
        let reason = `Malicious activity from ${ip} (${geoResult.country})`;
        if (rhythmResult.isBot) reason += ' — BOT CONFIRMED';
        if (ghostResult.isGhost) reason += ` — GHOST IP CLUSTER ${ghostResult.clusterId}`;
        reason += '. IP blocked from website.';
        await createAlert(ip, 'MALICIOUS', reason);
        await blockIP(ip, `Malicious: ${count} connections/min from ${geoResult.country}`, startedAt);
    }

    return classification;
}

tcpServer.on('error', (err) => {
    if (err.code === 'EADDRINUSE') { console.error(`Port ${CONFIG.TCP_PORT} is already in use.`); }
    else { console.error('TCP Error:', err.message); }
});

// ── Start all servers ──────────────────────────────────────────────────────
tcpServer.listen(CONFIG.TCP_PORT, () => {
    console.log(`TCP listener running on port ${CONFIG.TCP_PORT}`);
});

server.listen(CONFIG.HTTP_PORT, () => {
    console.log(`Dashboard running at http://localhost:${CONFIG.HTTP_PORT}`);
});

websiteServer.on('error', (err) => {
    if (err.code === 'EADDRINUSE') { console.error(`Port ${CONFIG.WEBSITE_PORT} is already in use — is aviation-test-site running separately? Stop it; this system already serves the website.`); }
    else { console.error('Website server error:', err.message); }
});
websiteServer.listen(CONFIG.WEBSITE_PORT, () => {
    console.log(`Aviation website running at http://localhost:${CONFIG.WEBSITE_PORT}`);
    console.log(`Blocked IPs will see a blocked page instead of the website`);
});