// ════════════════════════════════════════════════════════════════════════════
//  TCP Ping Detection System — FULL SYSTEM TEST
//  IT Project 700 — Richfield
//
//  Tests every feature and prints PASS / FAIL for each check:
//    1. Login & security          6. Bot detection + auto-block
//    2. Aviation website (8080)   7. Ghost IP detection + dismiss
//    3. Website proxy (8082)      8. TCP listener — localhost block/unblock
//    4. Normal traffic + geo      9. Reports, backup & restore
//    5. Unblock                  10. Admin accounts & roles
//
//  HOW TO RUN (with the system already running via "npm start"):
//      node test-all.js            ← normal test: NOTHING is ever unblocked —
//                                    every IP the test blocks stays blocked
//      node test-all.js --full     ← also tests the Unblock and Dismiss buttons and
//                                    a TCP flood from your own computer (127.0.0.1).
//                                    In this mode the test unblocks what it checks.
//  If you changed the admin password:
//      PowerShell:      $env:TCP_ADMIN_PASS="yourpassword"; node test-all.js
//      Command Prompt:  set TCP_ADMIN_PASS=yourpassword && node test-all.js
//
//  Every run uses fresh random IP addresses, so you can run it as often as you
//  like. Blocked IPs stay blocked (unblock them yourself on the dashboard). The
//  temporary admin account is removed and the Web Monitor URL is put back.
// ════════════════════════════════════════════════════════════════════════════

const http = require('http');
const net  = require('net');

const ADMIN_USER = process.env.TCP_ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.TCP_ADMIN_PASS || 'richfield2026';
const RUN_ID     = Math.random().toString(36).slice(2, 7);   // makes every run unique
const FULL       = process.argv.includes('--full');           // also test unblock / dismiss / localhost flood

let passed = 0, failed = 0;
const failures = [];

// ── Helpers ────────────────────────────────────────────────────────────────
const sleep = ms => new Promise(r => setTimeout(r, ms));
const rand  = (a, b) => a + Math.floor(Math.random() * (b - a + 1));

function check(name, ok, detail) {
    if (ok) { passed++; console.log(`   ✅ PASS  ${name}`); }
    else    { failed++; failures.push(name); console.log(`   ❌ FAIL  ${name}${detail ? '  →  ' + detail : ''}`); }
}

function section(title) { console.log(`\n── ${title} ${'─'.repeat(Math.max(0, 60 - title.length))}`); }

function request(port, path, { method = 'GET', headers = {}, body = null, token = null } = {}) {
    return new Promise((resolve) => {
        const data = body ? JSON.stringify(body) : null;
        const h = { ...headers };
        if (data)  { h['Content-Type'] = 'application/json'; h['Content-Length'] = Buffer.byteLength(data); }
        if (token) h['x-auth-token'] = token;
        const req = http.request({ hostname: '127.0.0.1', port, path, method, headers: h }, (res) => {
            let text = '';
            res.setEncoding('utf8');
            res.on('data', c => { text += c; });
            res.on('end', () => {
                let json = null; try { json = JSON.parse(text); } catch (_) {}
                resolve({ status: res.statusCode, text, json, headers: res.headers });
            });
        });
        req.on('error', (e) => resolve({ status: 0, text: e.message, json: null }));
        req.setTimeout(15000, () => { req.destroy(); resolve({ status: 0, text: 'timeout', json: null }); });
        if (data) req.write(data);
        req.end();
    });
}

const api = (path, opts = {}) => request(3000, path, opts);

// A "visitor" browsing the proxy from a given IP with its own browser identity
function visit(ip, ua, path = '/') {
    return request(8082, path, { headers: {
        'x-forwarded-for': ip,
        'User-Agent'     : ua,
        'Accept'         : 'text/html,application/xhtml+xml,*/*;q=0.8',
        'Accept-Language': 'en-ZA,en;q=0.9'
    }});
}

// Wait until a condition is true (the server analyses visits in the background)
async function waitFor(fn, timeoutMs = 8000) {
    const end = Date.now() + timeoutMs;
    while (Date.now() < end) {
        try { if (await fn()) return true; } catch (_) {}
        await sleep(400);
    }
    return false;
}

function tcpPing() {
    return new Promise((resolve) => {
        const s = net.connect(9000, '127.0.0.1');
        s.on('connect', () => { s.end(); resolve(true); });
        s.on('error', () => resolve(false));
        s.setTimeout(3000, () => { s.destroy(); resolve(false); });
    });
}

// Random public IPs in ranges from different regions (fresh last two octets each run)
const COUNTRY_PREFIXES = [
    ['41.13'], ['8.8'], ['185.220'], ['212.58'], ['200.195'], ['103.86'], ['202.12'], ['196.201']
];
// Pick a random address in the range that the GeoIP database actually knows
let geoip = null; try { geoip = require('geoip-lite'); } catch (_) {}
function freshIP(prefix) {
    for (let i = 0; i < 50; i++) {
        const ip = `${prefix}.${rand(1, 254)}.${rand(1, 254)}`;
        if (!geoip) return ip;
        const g = geoip.lookup(ip);
        if (g && g.country) return ip;
    }
    return `${prefix}.${rand(1, 254)}.${rand(1, 254)}`;
}

// ════════════════════════════════════════════════════════════════════════════
(async () => {
    console.log('═'.repeat(64));
    console.log('  TCP Ping Detection System — FULL SYSTEM TEST   (run ' + RUN_ID + ')');
    console.log('═'.repeat(64));

    // ── 0. Is the system running? ───────────────────────────────────────────
    const up = await api('/login');
    if (up.status !== 200) {
        console.log('\n❌ The system is not running on http://localhost:3000');
        console.log('   Start it first:  cd tcp-advanced  then  npm start\n');
        process.exit(1);
    }

    let token = null;
    let originalURL = null;
    const blockedByTest = new Set();
    const ghostClustersByTest = [];
    const evidenceIPs = [];

    try {
        // ── 1. LOGIN & SECURITY ─────────────────────────────────────────────
        section('1. Login & security');
        const bad = await api('/api/login', { method: 'POST', body: { username: ADMIN_USER, password: 'wrong-password' } });
        check('Wrong password is rejected', bad.status === 401, `got HTTP ${bad.status}`);

        const login = await api('/api/login', { method: 'POST', body: { username: ADMIN_USER, password: ADMIN_PASS } });
        token = login.json && login.json.token;
        check('Admin can log in', !!token, login.json && login.json.error ? login.json.error : `HTTP ${login.status} — check TCP_ADMIN_PASS / is MongoDB running?`);
        if (!token) throw new Error('Cannot continue without logging in');

        for (const p of ['/api/stats', '/api/pings', '/api/blocked', '/api/report', '/api/proxy-url']) {
            const r = await api(p);
            check(`${p} is protected without login`, r.status === 401, `got HTTP ${r.status}`);
        }
        let allOk = true;
        for (const p of ['/api/stats', '/api/pings', '/api/alerts', '/api/blocked', '/api/reputations', '/api/patterns',
                         '/api/geo', '/api/dna', '/api/ghost-clusters', '/api/report', '/api/learning', '/api/admins']) {
            const r = await api(p, { token });
            if (r.status !== 200) { allOk = false; check(`${p} works when logged in`, false, `HTTP ${r.status}`); }
        }
        if (allOk) check('All 12 dashboard APIs work when logged in', true);

        const reset = await api('/reset-password');
        check('Reset page does not reveal the master reset code', reset.status === 200 && !reset.text.includes('RICHFIELD-RESET-2026'));

        const dash = await request(3000, '/');
        check('Dashboard page loads', dash.status === 200 && dash.text.includes('TCP Ping Detection'));

        const statsBefore = (await api('/api/stats', { token })).json;

        // ── 2. AVIATION WEBSITE ─────────────────────────────────────────────
        section('2. Aviation website (port 8080)');
        const site = await request(8080, '/', { headers: { Accept: 'text/html' } });
        check('Aviation website loads', site.status === 200 && site.text.includes('SkyForce'), `HTTP ${site.status}`);
        const css = await request(8080, '/css/style.css');
        check('Website CSS loads', css.status === 200);
        const js = await request(8080, '/js/site.js');
        check('Website JavaScript loads', js.status === 200);

        // ── 3. WEBSITE PROXY ────────────────────────────────────────────────
        section('3. Website proxy (port 8082)');
        originalURL = (await api('/api/proxy-url', { token })).json.url;
        const setURL = await api('/api/proxy-url', { method: 'POST', token, body: { url: 'http://localhost:8080' } });
        check('Monitored URL can be changed (pointed at the aviation site)', setURL.json && setURL.json.success);
        const badURL = await api('/api/proxy-url', { method: 'POST', token, body: { url: 'javascript:alert(1)' } });
        check('Invalid monitored URL is rejected', badURL.status === 400, `HTTP ${badURL.status}`);

        const proxIP = freshIP('41.13');
        const prox = await visit(proxIP, `ProxyCheck/${RUN_ID}`);
        check('Proxy shows the monitored website', prox.status === 200 && prox.text.includes('SkyForce'), `HTTP ${prox.status}`);
        check('Proxy injects the TCP Monitor banner', prox.text.includes('tcp-monitor-bar'));
        const xss = await request(8082, '/', { headers: { 'x-forwarded-for': '<script>alert(1)</script>', Accept: 'text/html' } });
        check('Fake IP header cannot inject script into the page', !xss.text.includes('<script>alert(1)</script>'));

        // Assets must NOT count as visits
        await sleep(1500);
        const before = (await api('/api/pings', { token })).json.filter(p => p.ip === proxIP).length;
        for (const a of ['/css/style.css', '/js/site.js', '/favicon.ico']) await request(8082, a, { headers: { 'x-forwarded-for': proxIP } });
        await sleep(1500);
        const after = (await api('/api/pings', { token })).json.filter(p => p.ip === proxIP).length;
        check('Images/CSS/JS are not counted as extra visits', before === 1 && after === 1, `page visits=${before}, after assets=${after}`);

        // ── 4. NORMAL TRAFFIC + GEOGRAPHY ───────────────────────────────────
        section('4. Normal traffic & geographic learning');
        const normalIPs = COUNTRY_PREFIXES.map(([prefix, country], i) => ({ ip: freshIP(prefix), country, ua: `NormalUser-${i}/${RUN_ID}` }));
        for (const v of normalIPs) { await visit(v.ip, v.ua); await sleep(700); }
        const gotAll = await waitFor(async () => {
            const pings = (await api('/api/pings', { token })).json;
            return normalIPs.every(v => pings.some(p => p.ip === v.ip));
        });
        const pings = (await api('/api/pings', { token })).json;
        check(`All ${normalIPs.length} visitors appear in the live feed`, gotAll);
        const normalOk = normalIPs.every(v => { const p = pings.find(x => x.ip === v.ip); return p && p.classification === 'NORMAL'; });
        check('Normal visitors are classified NORMAL', normalOk);
        const geoOk = normalIPs.filter(v => { const p = pings.find(x => x.ip === v.ip); return p && p.country && p.country !== 'Unknown'; }).length;
        check('Country detected for every visitor (GeoIP)', geoOk === normalIPs.length, `${geoOk}/${normalIPs.length} had a country`);
        const geo = (await api('/api/geo', { token })).json;
        check('Geography table is populated', Array.isArray(geo) && geo.length >= 5, `${geo.length} countries`);
        const reps = (await api('/api/reputations', { token })).json;
        check('Reputation scores are being tracked', reps.length > 0);
        const dna = (await api('/api/dna', { token })).json;
        check('DNA fingerprints are being recorded', dna.length > 0);

        // ── 6 (run before 5). BOT DETECTION ─────────────────────────────────
        section('5. Bot detection & automatic blocking');
        const botIP = freshIP('77.88');   // Russia
        console.log(`   … sending 18 rapid requests from ${botIP}`);
        for (let i = 0; i < 18; i++) { await visit(botIP, `AttackBot/${RUN_ID}`); await sleep(120); }
        const botBlocked = await waitFor(async () => (await api('/api/blocked', { token })).json.some(b => b.ip === botIP), 10000);
        blockedByTest.add(botIP);
        const botPings = (await api('/api/pings', { token })).json.filter(p => p.ip === botIP);
        check('Rapid visitor is flagged as a BOT', botPings.some(p => p.isBot));
        check('Rapid visitor is classified SUSPICIOUS', botPings.some(p => p.classification === 'SUSPICIOUS'));
        check('Attacking IP is automatically blocked', botBlocked);
        const botBlock = (await api('/api/blocked', { token })).json.find(b => b.ip === botIP);
        check('Block reason is recorded', !!(botBlock && botBlock.reason), botBlock ? '' : 'no block record');
        const alertRaised = await waitFor(async () => (await api('/api/alerts', { token })).json
            .some(a => a.ip === botIP && (a.type === 'MALICIOUS' || a.type === 'SUSPICIOUS')), 15000);
        check('Alerts were raised for the attack', alertRaised);
        const blockedPage = await visit(botIP, `AttackBot/${RUN_ID}`);
        check('Blocked IP gets the 403 Access Denied page', blockedPage.status === 403 && blockedPage.text.includes('Access Denied'));
        const maliciousLogged = await waitFor(async () => (await api('/api/pings', { token })).json
            .some(p => p.ip === botIP && p.classification === 'MALICIOUS' && p.blocked));
        check('Blocked attacker trying again is recorded as MALICIOUS', maliciousLogged);

        // ── 5. UNBLOCK ──────────────────────────────────────────────────────
        section('6. Manual unblock');
        if (!FULL) console.log('   (skipped — blocked IPs stay blocked. Run "node test-all.js --full" to test the Unblock button)');
        if (FULL) {
        const unb = await api(`/api/blocked/${encodeURIComponent(botIP)}`, { method: 'DELETE', token });
        check('Admin can unblock an IP', unb.json && unb.json.success);
        await sleep(2000);
        const again = await visit(botIP, `CalmUser/${RUN_ID}`);
        check('Unblocked IP can access the website again', again.status === 200, `HTTP ${again.status}`);
        await sleep(2000);
        const stillUnblocked = !(await api('/api/blocked', { token })).json.some(b => b.ip === botIP);
        check('Unblocked IP stays unblocked on its next visit', stillUnblocked);
        if (stillUnblocked) blockedByTest.delete(botIP);
        } else {
            evidenceIPs.push(botIP);
        }

        // ── 7. GHOST IP DETECTION ───────────────────────────────────────────
        section('7. Ghost IP detection (IP hopping)');
        const ghostUA  = `GhostHopper/${RUN_ID}`;
        const ghostIPs = [freshIP('91.100'), freshIP('83.160'), freshIP('62.241')];
        console.log(`   … same browser hopping between ${ghostIPs.join(', ')}`);
        for (const ip of ghostIPs) { await visit(ip, ghostUA); await sleep(800); }
        let cluster = null;
        await waitFor(async () => {
            const cl = (await api('/api/ghost-clusters', { token })).json;
            cluster = cl.find(c => ghostIPs.every(ip => c.ips.includes(ip)));
            return !!cluster;
        }, 10000);
        check('Ghost IP cluster is detected', !!cluster);
        if (cluster) ghostClustersByTest.push(cluster.clusterId);
        const blockedNow = (await api('/api/blocked', { token })).json.map(b => b.ip);
        ghostIPs.forEach(ip => blockedByTest.add(ip));
        check('All IPs in the ghost cluster are blocked', ghostIPs.every(ip => blockedNow.includes(ip)));
        const ghostAlert = (await api('/api/alerts', { token })).json.some(a => a.type === 'GHOST_IP' && ghostIPs.includes(a.ip));
        check('GHOST_IP alert is raised', ghostAlert);

        // 4th IP with the same browser should join the existing cluster immediately
        const fourth = freshIP('94.140');
        await visit(fourth, ghostUA);
        blockedByTest.add(fourth);
        const joined = await waitFor(async () => (await api('/api/blocked', { token })).json.some(b => b.ip === fourth));
        check('A new IP with the same fingerprint joins the cluster and is blocked', joined);

        if (!FULL) evidenceIPs.push(...ghostIPs, fourth);
        if (cluster && FULL) {
            const dismiss = await api(`/api/ghost-clusters/${cluster.clusterId}`, { method: 'DELETE', token });
            check('Admin can dismiss a ghost cluster', dismiss.json && dismiss.json.success);
            const nowBlocked = (await api('/api/blocked', { token })).json.map(b => b.ip);
            check('Dismissing the cluster unblocks all its IPs', [...ghostIPs, fourth].every(ip => !nowBlocked.includes(ip)));
            [...ghostIPs, fourth].forEach(ip => blockedByTest.delete(ip));
        }

        // ── 8. TCP LISTENER (localhost) ─────────────────────────────────────
        if (!FULL) {
        section('8. TCP listener (port 9000)');
        const okTcp = await tcpPing();
        check('TCP listener accepts connections', okTcp);
        console.log('   (localhost flood skipped — it would block your own computer. Run with --full to test it)');
        } else {
        section('8. TCP listener (port 9000) — localhost flood');
        // Unblock localhost first in case a previous test left it blocked
        await api('/api/blocked/127.0.0.1', { method: 'DELETE', token });
        await sleep(500);
        console.log('   … sending 20 rapid TCP connections from 127.0.0.1');
        let connected = 0;
        for (let i = 0; i < 20; i++) { if (await tcpPing()) connected++; await sleep(100); }
        check('TCP listener accepts connections', connected > 0, `${connected}/20 connected`);
        const lhBlocked = await waitFor(async () => (await api('/api/blocked', { token })).json.some(b => b.ip === '127.0.0.1'), 10000);
        blockedByTest.add('127.0.0.1');
        check('TCP flood from localhost is detected and blocked', lhBlocked);
        const site403 = await request(8080, '/');
        check('Blocked localhost sees the 403 page on the aviation website', site403.status === 403);
        // Let the server finish processing the flood before unblocking (like an admin would)
        console.log('   … waiting for the flood to finish processing');
        let lastCount = -1;
        for (let i = 0; i < 30; i++) {
            const n = (await api('/api/stats', { token })).json.totalPings;
            if (n === lastCount) break;
            lastCount = n; await sleep(1500);
        }
        await api('/api/blocked/127.0.0.1', { method: 'DELETE', token });
        blockedByTest.delete('127.0.0.1');
        await sleep(500);
        const site200 = await request(8080, '/');
        check('After unblock, the aviation website works again', site200.status === 200);
        }

        // ── 9. REPORTS, BACKUP & RESTORE ────────────────────────────────────
        section('9. Reports, backup & restore');
        const report = await api('/api/report', { token });
        check('Report data is generated', report.status === 200 && report.json && report.json.stats && Array.isArray(report.json.geoPatterns),
              `HTTP ${report.status} ${String(report.text).slice(0, 120)}`);
        const learning = await api('/api/learning', { token });
        check('Learning / clustering data is available', learning.status === 200 && typeof learning.json.currentThreshold === 'number');
        const backup = await api('/api/backup', { method: 'POST', token });
        const bk = backup.json;
        check('Backup is created', backup.status === 200 && bk && bk.collections && Array.isArray(bk.collections.pings),
              `HTTP ${backup.status}`);
        if (bk && bk.collections) {
            // Restore only a small part of the backup (safe — records are merged, not duplicated)
            const small = { ...bk, collections: { geo: bk.collections.geo, patterns: bk.collections.patterns, alerts: bk.collections.alerts.slice(0, 20) } };
            const restore = await api('/api/restore', { method: 'POST', token, body: { backup: small } });
            check('Backup can be restored', restore.json && restore.json.success && restore.json.failed === 0,
                  JSON.stringify(restore.json));
        }
        const history = await api('/api/backup/history', { token });
        check('Backup history is recorded', history.status === 200 && history.json.length > 0);

        // ── 10. ADMIN ACCOUNTS ──────────────────────────────────────────────
        section('10. Admin accounts & roles');
        const tmpUser = `test_${RUN_ID}`;
        const add = await api('/api/admins', { method: 'POST', token, body: { username: tmpUser, password: 'testpass1', role: 'admin' } });
        check('Super Admin can add an admin', add.json && add.json.success, add.json && add.json.error);
        const tmpLogin = await api('/api/login', { method: 'POST', body: { username: tmpUser, password: 'testpass1' } });
        const tmpToken = tmpLogin.json && tmpLogin.json.token;
        check('New admin can log in', !!tmpToken);
        if (tmpToken) {
            const esc = await api('/api/admins', { method: 'POST', token: tmpToken, body: { username: `x_${RUN_ID}`, password: 'xxxxxx1', role: 'superadmin' } });
            check('Normal admin cannot create a Super Admin', esc.status === 403, `HTTP ${esc.status}`);
            const del = await api(`/api/admins/${ADMIN_USER}`, { method: 'DELETE', token: tmpToken });
            check('Normal admin cannot delete accounts', del.status === 403, `HTTP ${del.status}`);
        }
        const ghostPw = await api('/api/admins/nobody_' + RUN_ID + '/password', { method: 'POST', token, body: { newPassword: 'abcdef' } });
        check('Changing password of a non-existent admin is refused', ghostPw.status === 404, `HTTP ${ghostPw.status}`);
        const rm = await api(`/api/admins/${tmpUser}`, { method: 'DELETE', token });
        check('Super Admin can remove an admin', rm.json && rm.json.success, rm.json && rm.json.error);

        // ── 11. ATTACKS LEFT ON THE DASHBOARD ───────────────────────────────
        section('11. Attacks left on the dashboard (stay blocked)');
        const attacker = freshIP('5.188');      // bot attacker that keeps attacking after being blocked
        console.log(`   … bot attack from ${attacker}`);
        for (let i = 0; i < 18; i++) { await visit(attacker, `PersistentBot/${RUN_ID}`); await sleep(120); }
        await waitFor(async () => (await api('/api/blocked', { token })).json.some(b => b.ip === attacker), 10000);
        for (let i = 0; i < 3; i++) { await visit(attacker, `PersistentBot/${RUN_ID}`); await sleep(300); }   // keeps trying
        evidenceIPs.push(attacker);

        const hopUA  = `IPHopper/${RUN_ID}`;
        const hopIPs = [freshIP('91.200'), freshIP('46.4'), freshIP('109.70')];
        console.log(`   … IP-hopping attacker using ${hopIPs.join(', ')}`);
        for (const ip of hopIPs) { await visit(ip, hopUA); await sleep(800); }
        let hopCluster = null;
        await waitFor(async () => {
            hopCluster = (await api('/api/ghost-clusters', { token })).json.find(c => hopIPs.every(ip => c.ips.includes(ip)));
            return !!hopCluster;
        }, 10000);
        evidenceIPs.push(...hopIPs);
        await sleep(1500);

        const blockedList = (await api('/api/blocked', { token })).json.map(b => b.ip);
        check('Bot attacker is still blocked', blockedList.includes(attacker));
        check('Ghost cluster IPs are still blocked', hopIPs.every(ip => blockedList.includes(ip)));
        check('Ghost cluster shows as BLOCKED', !!(hopCluster && hopCluster.status === 'BLOCKED'));
        const atkMalicious = await waitFor(async () => (await api('/api/pings', { token })).json
            .some(p => p.ip === attacker && p.classification === 'MALICIOUS'), 20000);
        check('Bot attacker\'s repeat attempts are MALICIOUS', atkMalicious);

        // ── SUMMARY STATS ───────────────────────────────────────────────────
        await sleep(1200);   // dashboard numbers refresh once per second
        const s = (await api('/api/stats', { token })).json;
        section('Dashboard numbers after the test');
        console.log(`   Total pings ${statsBefore.totalPings} → ${s.totalPings}   |  Suspicious ${s.suspiciousCount}  |  Malicious ${s.maliciousCount}`);
        console.log(`   Bots ${s.botCount}  |  Countries ${s.uniqueCountries}  |  Ghost clusters ${s.ghostClusters}  |  Blocked now ${s.blockedCount}`);
        check('Dashboard totals increased', s.totalPings > statsBefore.totalPings);
        check('Dashboard shows MALICIOUS traffic', s.maliciousCount > statsBefore.maliciousCount);
        check('Dashboard shows blocked IPs', s.blockedCount >= evidenceIPs.length, `blocked now: ${s.blockedCount}`);
        const finalBlocked = (await api('/api/blocked', { token })).json.map(b => b.ip);
        const missing = evidenceIPs.filter(ip => !finalBlocked.includes(ip));
        check(`Every IP blocked during this test is still blocked (${evidenceIPs.length})`, missing.length === 0, `not blocked: ${missing.join(', ')}`);
        console.log(`\n   Blocked by this test — they STAY blocked (unblock them yourself on the dashboard):`);
        evidenceIPs.forEach(ip => console.log(`   • ${ip}`));

    } catch (err) {
        console.log(`\n❌ Test stopped early: ${err.message}`);
        failed++;
    } finally {
        // ── CLEAN-UP ────────────────────────────────────────────────────────
        if (token) {
            // Normal mode: nothing is unblocked — every blocked IP stays blocked.
            // --full mode: unblock what the Unblock/Dismiss/localhost checks blocked
            // (never the attackers left on purpose), so your own computer works again.
            if (FULL) {
                blockedByTest.add('127.0.0.1');
                for (const ip of blockedByTest) {
                    if (!evidenceIPs.includes(ip)) await api(`/api/blocked/${encodeURIComponent(ip)}`, { method: 'DELETE', token });
                }
            }
            if (originalURL) await api('/api/proxy-url', { method: 'POST', token, body: { url: originalURL } });
        }
    }

    console.log('\n' + '═'.repeat(64));
    console.log(`  RESULT:  ${passed} passed,  ${failed} failed`);
    if (failures.length) { console.log('  Failed checks:'); failures.forEach(f => console.log('   • ' + f)); }
    else console.log('  🎉 Everything works!');
    console.log('═'.repeat(64) + '\n');
    process.exit(failed ? 1 : 0);
})();
