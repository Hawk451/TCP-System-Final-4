// ════════════════════════════════════════════════════════════════════════════
//  TCP Ping Detection System — FULL TRAFFIC SIMULATION
//  IT Project 700 — Richfield
//
//  Simulates every kind of visitor so EVERY counter on the dashboard moves:
//    • Normal visitors from many countries      → Normal, Countries, DNA Prints
//    • Loyal visitors who come back regularly   → Trusted IPs (reputation 80+)
//    • A human who refreshes far too often      → Suspicious
//    • A bot attack that keeps going when blocked → Bots, Suspicious, Blocked, Malicious
//    • An attacker hopping between IP addresses → Ghost Clusters, Blocked, Alerts
//
//  HOW TO RUN (with the system already running via "npm start"):
//      node test-simulate.js
//  If you changed the admin password:
//      PowerShell:      $env:TCP_ADMIN_PASS="yourpassword"; node test-simulate.js
//      Command Prompt:  set TCP_ADMIN_PASS=yourpassword && node test-simulate.js
//
//  Takes about 2½ minutes (building trust has to be slow on purpose — fast
//  visits look like an attack). Uses fresh random IPs every run. Nothing is
//  unblocked: every IP the simulation blocks stays blocked.
// ════════════════════════════════════════════════════════════════════════════

const http = require('http');

const ADMIN_USER = process.env.TCP_ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.TCP_ADMIN_PASS || 'richfield2026';
const RUN_ID     = Math.random().toString(36).slice(2, 7);

const sleep = ms => new Promise(r => setTimeout(r, ms));
const rand  = (a, b) => a + Math.floor(Math.random() * (b - a + 1));

let geoip = null; try { geoip = require('geoip-lite'); } catch (_) {}
// Random public IP in a range the GeoIP database knows (so a country is shown)
function freshIP(prefix) {
    for (let i = 0; i < 50; i++) {
        const ip = `${prefix}.${rand(1, 254)}.${rand(1, 254)}`;
        if (!geoip || (geoip.lookup(ip) || {}).country) return ip;
    }
    return `${prefix}.${rand(1, 254)}.${rand(1, 254)}`;
}

// Address ranges in many different countries
const PREFIXES = ['41.13', '196.25', '8.8', '24.53', '185.220', '212.58', '212.27', '200.195',
                  '189.40', '103.86', '202.12', '203.2', '117.18', '77.88', '1.180', '196.201',
                  '185.93', '200.23', '190.220', '194.25', '62.4', '80.12', '151.101', '109.70'];

function request(port, path, { method = 'GET', headers = {}, body = null, token = null } = {}) {
    return new Promise((resolve) => {
        const data = body ? JSON.stringify(body) : null;
        const h = { ...headers };
        if (data)  { h['Content-Type'] = 'application/json'; h['Content-Length'] = Buffer.byteLength(data); }
        if (token) h['x-auth-token'] = token;
        const req = http.request({ hostname: '127.0.0.1', port, path, method, headers: h }, (res) => {
            let text = ''; res.setEncoding('utf8');
            res.on('data', c => { text += c; });
            res.on('end', () => { let json = null; try { json = JSON.parse(text); } catch (_) {} resolve({ status: res.statusCode, json }); });
        });
        req.on('error', () => resolve({ status: 0, json: null }));
        req.setTimeout(15000, () => { req.destroy(); resolve({ status: 0, json: null }); });
        if (data) req.write(data);
        req.end();
    });
}
const api = (path, opts = {}) => request(3000, path, opts);

let visits = 0;
function visit(ip, ua) {
    visits++;
    return request(8082, '/', { headers: {
        'x-forwarded-for': ip, 'User-Agent': ua,
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8', 'Accept-Language': 'en-ZA,en;q=0.9'
    }});
}

let passed = 0, failed = 0;
function check(name, ok, detail) {
    if (ok) { passed++; console.log(`   ✅ PASS  ${name}`); }
    else    { failed++; console.log(`   ❌ FAIL  ${name}${detail ? '  →  ' + detail : ''}`); }
}

// ── Visitor types ──────────────────────────────────────────────────────────
async function normalVisitors(n) {
    for (let i = 0; i < n; i++) {
        await visit(freshIP(PREFIXES[i % PREFIXES.length]), `Mozilla/5.0 Visitor-${i}/${RUN_ID}`);
        await sleep(300);
    }
}

async function loyalVisitors(ips) {
    // 16 visits each, every 6.5–9.5 s at irregular times (like a real person) →
    // reputation climbs 50 → 80+ without looking like a flood or a too-regular bot
    for (let round = 0; round < 16; round++) {
        for (const v of ips) await visit(v.ip, v.ua);
        process.stdout.write(`\r   … trusted visitors: round ${round + 1}/16   `);
        await sleep(rand(6500, 9500));
    }
    process.stdout.write('\n');
}

async function overeagerHuman(ip) {
    // 16 visits about once a second, irregular timing → too many visits, but clearly a human
    for (let i = 0; i < 16; i++) { await visit(ip, `Mozilla/5.0 Refresher/${RUN_ID}`); await sleep(rand(700, 1300)); }
}

async function botAttack(ip) {
    for (let i = 0; i < 18; i++) { await visit(ip, `AttackBot/${RUN_ID}`); await sleep(120); }
    await sleep(3000);
    for (let i = 0; i < 4; i++) { await visit(ip, `AttackBot/${RUN_ID}`); await sleep(400); }   // keeps trying while blocked
}

async function ipHopper(ips) {
    for (const ip of ips) { await visit(ip, `IPHopper/${RUN_ID}`); await sleep(800); }
}

// ════════════════════════════════════════════════════════════════════════════
(async () => {
    console.log('═'.repeat(64));
    console.log('  TCP Ping Detection — FULL TRAFFIC SIMULATION   (run ' + RUN_ID + ')');
    console.log('═'.repeat(64));

    const login = await api('/api/login', { method: 'POST', body: { username: ADMIN_USER, password: ADMIN_PASS } });
    const token = login.json && login.json.token;
    if (!token) {
        console.log(login.status === 0
            ? '\n❌ The system is not running — start it first with "npm start"\n'
            : '\n❌ Could not log in — check TCP_ADMIN_USER / TCP_ADMIN_PASS\n');
        process.exit(1);
    }

    // Point the website proxy at the local aviation site so every visit works offline
    const originalURL = ((await api('/api/proxy-url', { token })).json || {}).url;
    await api('/api/proxy-url', { method: 'POST', token, body: { url: 'http://localhost:8080' } });

    const before = (await api('/api/stats', { token })).json;

    const loyal    = [0, 1, 2].map(i => ({ ip: freshIP(['41.13', '196.25', '105.27'][i]), ua: `Mozilla/5.0 Loyal-${i}/${RUN_ID}` }));
    const eager    = freshIP('102.65');
    const bot      = freshIP('5.188');
    const hoppers  = [freshIP('91.200'), freshIP('46.4'), freshIP('95.85')];

    console.log('\n  Visitors in this run:');
    console.log(`   • 40 normal visitors from ${PREFIXES.length} address ranges`);
    console.log(`   • 3 loyal visitors (become TRUSTED):  ${loyal.map(v => v.ip).join(', ')}`);
    console.log(`   • 1 human refreshing too often (SUSPICIOUS): ${eager}`);
    console.log(`   • 1 bot attack (BOT → BLOCKED → MALICIOUS): ${bot}`);
    console.log(`   • 1 attacker hopping IPs (GHOST CLUSTER):   ${hoppers.join(', ')}\n`);

    // Loyal visitors run in the background the whole time (they need ~2½ minutes)
    const loyalDone = loyalVisitors(loyal);

    console.log('   … normal visitors');        await normalVisitors(40);
    console.log('   … human refreshing too often'); await overeagerHuman(eager);
    console.log('   … bot attack');              await botAttack(bot);
    console.log('   … IP-hopping attacker');     await ipHopper(hoppers);
    await loyalDone;

    console.log('   … waiting for the system to finish processing');
    await sleep(5000);

    // ── RESULTS ─────────────────────────────────────────────────────────────
    const after   = (await api('/api/stats', { token })).json;
    const pings   = (await api('/api/pings', { token })).json || [];
    const blocked = ((await api('/api/blocked', { token })).json || []).map(b => b.ip);
    const reps    = ((await api('/api/learning', { token })).json || {}).reputations || [];
    const ghosts  = (await api('/api/ghost-clusters', { token })).json || [];
    const repOf   = ip => (reps.find(r => r.ip === ip) || {});
    const d = k => after[k] - before[k];

    console.log('\n── Dashboard counters (before → after) ' + '─'.repeat(25));
    const rows = [['Total pings','totalPings'],['Normal','normalCount'],['Suspicious','suspiciousCount'],
                  ['Malicious','maliciousCount'],['Blocked IPs','blockedCount'],['Trusted IPs','trustedIPs'],
                  ['Bots detected','botCount'],['Countries','uniqueCountries'],['DNA prints','dnaFingerprints'],
                  ['Ghost clusters','ghostClusters'],['Unread alerts','unreadAlerts']];
    for (const [label, k] of rows) console.log(`   ${label.padEnd(15)} ${String(before[k]).padStart(5)} → ${String(after[k]).padEnd(6)} (+${d(k)})`);

    console.log('\n── Checks ' + '─'.repeat(54));
    check('Every visit was recorded', d('totalPings') >= visits - 2, `${d('totalPings')} recorded of ${visits} sent`);
    check('Normal traffic counted', d('normalCount') >= 40);
    check('Countries detected', after.uniqueCountries >= 10, `${after.uniqueCountries} countries`);
    check('DNA fingerprints recorded', d('dnaFingerprints') > 0 || after.dnaFingerprints > 0);
    check('Loyal visitors became TRUSTED (reputation 80+)', loyal.every(v => repOf(v.ip).trusted),
          loyal.map(v => `${v.ip}=${repOf(v.ip).score}`).join(', '));
    check('Trusted IPs counter went up', d('trustedIPs') >= 3, `+${d('trustedIPs')}`);
    const eagerPings = pings.filter(p => p.ip === eager);
    check('Over-eager human flagged SUSPICIOUS', eagerPings.some(p => p.classification === 'SUSPICIOUS'));
    check('…but NOT mistaken for a bot', !eagerPings.some(p => p.isBot));
    const botPings = pings.filter(p => p.ip === bot);
    check('Bot attack detected as a BOT', botPings.some(p => p.isBot));
    check('Bot attacker was blocked', blocked.includes(bot));
    check('Bot reputation dropped into the red', (repOf(bot).score ?? 100) <= 20, `score ${repOf(bot).score}`);
    check('Blocked bot trying again counted as MALICIOUS', botPings.some(p => p.classification === 'MALICIOUS' && p.blocked));
    const cluster = ghosts.find(c => hoppers.every(ip => c.ips.includes(ip)));
    check('IP-hopping attacker found as a GHOST CLUSTER', !!cluster);
    check('All hopping IPs blocked', hoppers.every(ip => blocked.includes(ip)));
    check('Suspicious counter went up',   d('suspiciousCount') > 0);
    check('Malicious counter went up',    d('maliciousCount') > 0);
    check('Bots counter went up',         d('botCount') > 0);
    check('Blocked IPs counter went up',  d('blockedCount') >= 4, `+${d('blockedCount')}`);
    check('Ghost clusters counter went up', d('ghostClusters') > 0);
    check('Alerts were raised',           d('unreadAlerts') > 0);

    if (originalURL) await api('/api/proxy-url', { method: 'POST', token, body: { url: originalURL } });

    console.log('\n' + '═'.repeat(64));
    console.log(`  RESULT:  ${passed} passed,  ${failed} failed`);
    console.log(failed ? '  Some checks failed — see above.' : '  🎉 Every part of the dashboard was exercised!');
    console.log(`  Blocked by this run (they stay blocked): ${[bot, ...hoppers].join(', ')}`);
    console.log('═'.repeat(64) + '\n');
    process.exit(failed ? 1 : 0);
})();
