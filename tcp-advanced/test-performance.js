// ════════════════════════════════════════════════════════════════════════════
//  TCP Ping Detection System — PERFORMANCE TEST
//  IT Project 700 — Richfield
//
//  Measures the Phase 1 success criteria that the functional tests do not cover:
//    1. Logging accuracy      — % of visits that are detected and saved as pings   (target ≥ 95%)
//    2. Alert delivery time   — time from the triggering visit until its alert is
//                               visible to the dashboard                         (target ≤ 5 s in ≥ 95%)
//    3. CPU overhead          — CPU used by the system under normal traffic      (target < 5%)
//    4. Memory consumption    — resident memory of the Node.js process           (target < 50 MB)
//    5. Proxy overhead        — extra page response time added by monitoring (RQ3 baseline)
//
//  HOW TO RUN (with the system already running via "npm start", and no other traffic):
//      node test-performance.js
//  Log in details: set TCP_ADMIN_USER / TCP_ADMIN_PASS if you are not using admin / your password
//      PowerShell:      $env:TCP_ADMIN_PASS="yourpassword"; node test-performance.js
//      Command Prompt:  set TCP_ADMIN_PASS=yourpassword && node test-performance.js
//
//  The results are printed as a table and also saved to performance-results.json.
//  NOTE: the alert-time test deliberately triggers bot detection from 20 random test IPs,
//  so those test IPs will appear as blocked on the dashboard afterwards.
// ════════════════════════════════════════════════════════════════════════════

const http = require('http');
const fs   = require('fs');

const ADMIN_USER = process.env.TCP_ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.TCP_ADMIN_PASS || '';
const NORMAL_VISITS = 200;   // visits used for logging accuracy, CPU and memory
const ALERT_TRIALS  = 20;    // separate bot bursts used to time alert delivery
const LATENCY_SAMPLES = 30;  // page loads timed directly and through the proxy

const sleep = ms => new Promise(r => setTimeout(r, ms));
const rand  = (a, b) => a + Math.floor(Math.random() * (b - a + 1));
const RUN   = Math.random().toString(36).slice(2, 7);

function request(port, path, { method = 'GET', headers = {}, body = null, token = null } = {}) {
    return new Promise((resolve) => {
        const data = body ? JSON.stringify(body) : null;
        const h = { ...headers };
        if (data)  { h['Content-Type'] = 'application/json'; h['Content-Length'] = Buffer.byteLength(data); }
        if (token) h['x-auth-token'] = token;
        const started = process.hrtime.bigint();
        const req = http.request({ hostname: '127.0.0.1', port, path, method, headers: h }, (res) => {
            let text = '';
            res.setEncoding('utf8');
            res.on('data', c => { text += c; });
            res.on('end', () => {
                let json = null; try { json = JSON.parse(text); } catch (_) {}
                const ms = Number(process.hrtime.bigint() - started) / 1e6;
                resolve({ status: res.statusCode, json, ms });
            });
        });
        req.on('error', () => resolve({ status: 0, json: null, ms: 0 }));
        req.setTimeout(20000, () => { req.destroy(); resolve({ status: 0, json: null, ms: 0 }); });
        if (data) req.write(data);
        req.end();
    });
}

// Every simulated visitor gets its own IP, /24 subnet and browser identity so the
// ghost-IP detector does not link them together.
function uniqueVisitor() {
    const ip = `${rand(11, 99)}.${rand(1, 254)}.${rand(1, 254)}.${rand(1, 254)}`;
    const ua = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) PerfTest/${RUN}-${Math.random().toString(36).slice(2, 10)}`;
    return { ip, ua };
}
function visit(port, v) {
    return request(port, '/', { headers: {
        'x-forwarded-for': v.ip, 'User-Agent': v.ua,
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8', 'Accept-Language': 'en-ZA,en;q=0.9'
    }});
}

const pct = (arr, p) => { const s = [...arr].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.ceil(p / 100 * s.length) - 1)]; };
const avg = arr => arr.reduce((a, b) => a + b, 0) / arr.length;

(async () => {
    console.log('═'.repeat(64));
    console.log(`  TCP Ping Detection System — PERFORMANCE TEST   (run ${RUN})`);
    console.log('═'.repeat(64));

    if (!ADMIN_PASS) {
        console.log('\n❌ Set your admin password first, e.g. in PowerShell:');
        console.log('   $env:TCP_ADMIN_PASS="yourpassword"; node test-performance.js\n');
        process.exit(1);
    }
    const login = await request(3000, '/api/login', { method: 'POST', body: { username: ADMIN_USER, password: ADMIN_PASS } });
    if (!login.json || !login.json.token) { console.log('\n❌ Could not log in — is the system running and is the password right?\n'); process.exit(1); }
    const token = login.json.token;
    const api = (path, opts = {}) => request(3000, path, { ...opts, token });

    // Point the proxy at the local aviation website for the duration of the test
    const before = await api('/api/proxy-url');
    const originalURL = before.json && before.json.url;
    await api('/api/proxy-url', { method: 'POST', body: { url: 'http://localhost:8080' } });

    const results = { run: RUN, date: new Date().toISOString() };
    try {
        // ── 1. Idle baseline ────────────────────────────────────────────────
        console.log('\n1. Idle baseline (10 s)…');
        const h0 = (await api('/api/health')).json;
        await sleep(10000);
        const h1 = (await api('/api/health')).json;
        const idleCpu = (h1.cpuMicros - h0.cpuMicros) / 1000 / (h1.sampledAt - h0.sampledAt) * 100;
        results.idle = { cpuPercent: +idleCpu.toFixed(2), rssMB: h1.rssMB };

        // ── 2. Normal traffic: logging accuracy, CPU and memory ─────────────
        console.log(`2. Normal traffic: ${NORMAL_VISITS} visits at about 10 per second…`);
        const statsBefore = (await api('/api/stats')).json;
        const s0 = (await api('/api/health')).json;
        let peakRss = s0.rssMB;
        const sampler = setInterval(async () => {
            const h = (await api('/api/health')).json; if (h && h.rssMB > peakRss) peakRss = h.rssMB;
        }, 1000);
        let okResponses = 0;
        for (let i = 0; i < NORMAL_VISITS; i++) {
            const r = await visit(8082, uniqueVisitor());
            if (r.status === 200) okResponses++;
            await sleep(100);
        }
        await sleep(3000);                       // let background analysis finish
        clearInterval(sampler);
        const s1 = (await api('/api/health')).json;
        const statsAfter = (await api('/api/stats')).json;
        const logged = statsAfter.totalPings - statsBefore.totalPings;
        const loadCpu = (s1.cpuMicros - s0.cpuMicros) / 1000 / (s1.sampledAt - s0.sampledAt) * 100;
        results.normalTraffic = {
            visitsSent: NORMAL_VISITS, pagesServed: okResponses, pingsLogged: logged,
            loggingAccuracyPercent: +(logged / NORMAL_VISITS * 100).toFixed(1),
            cpuPercent: +loadCpu.toFixed(2), peakRssMB: peakRss
        };

        // ── 3. Alert delivery time ──────────────────────────────────────────
        console.log(`3. Alert delivery: ${ALERT_TRIALS} bot bursts…`);
        const delays = [];
        for (let t = 0; t < ALERT_TRIALS; t++) {
            const bot = uniqueVisitor();
            const sends = [];
            for (let i = 0; i < 8; i++) { sends.push(Date.now()); visit(8082, bot); await sleep(40); }
            let seenAt = null, alertTime = null;
            const deadline = Date.now() + 15000;
            while (Date.now() < deadline) {
                const list = (await api('/api/alerts')).json || [];
                const a = list.find(x => x.ip === bot.ip);
                if (a) { seenAt = Date.now(); alertTime = new Date(a.time).getTime(); break; }
                await sleep(100);
            }
            if (seenAt) {
                // the visit that triggered the alert = the last one sent before the alert was created
                const trigger = sends.filter(s => s <= alertTime).pop() || sends[0];
                delays.push(seenAt - trigger);
            } else delays.push(Infinity);
            process.stdout.write(`\r   trial ${t + 1}/${ALERT_TRIALS}`);
            await sleep(300);
        }
        console.log('');
        const delivered = delays.filter(Number.isFinite);
        results.alertDelivery = {
            trials: ALERT_TRIALS, alertsReceived: delivered.length,
            withinFiveSecondsPercent: +(delays.filter(d => d <= 5000).length / ALERT_TRIALS * 100).toFixed(1),
            medianMs: delivered.length ? Math.round(pct(delivered, 50)) : null,
            p95Ms: delivered.length ? Math.round(pct(delivered, 95)) : null,
            maxMs: delivered.length ? Math.round(Math.max(...delivered)) : null
        };

        // ── 4. Page response time: direct vs through the monitoring proxy ───
        console.log(`4. Page response time: ${LATENCY_SAMPLES} direct vs ${LATENCY_SAMPLES} monitored…`);
        const direct = [], monitored = [];
        for (let i = 0; i < LATENCY_SAMPLES; i++) {
            direct.push((await request(8080, '/css/style.css')).ms);           // static file: no TCP ping
            monitored.push((await visit(8082, uniqueVisitor())).ms);
            await sleep(150);
        }
        results.pageResponse = {
            directMedianMs: +pct(direct, 50).toFixed(1),
            monitoredMedianMs: +pct(monitored, 50).toFixed(1),
            addedMedianMs: +(pct(monitored, 50) - pct(direct, 50)).toFixed(1),
            monitoredAvgMs: +avg(monitored).toFixed(1)
        };
    } finally {
        if (originalURL) await api('/api/proxy-url', { method: 'POST', body: { url: originalURL } });
    }

    // ── Report ──────────────────────────────────────────────────────────────
    const n = results.normalTraffic, a = results.alertDelivery, p = results.pageResponse;
    const row = (name, value, target, ok) => console.log(`  ${name.padEnd(34)} ${String(value).padEnd(16)} ${target.padEnd(14)} ${ok ? 'MET' : 'NOT MET'}`);
    console.log('\n' + '═'.repeat(64));
    console.log('  RESULTS');
    console.log('═'.repeat(64));
    console.log(`  ${'Measure'.padEnd(34)} ${'Result'.padEnd(16)} ${'Target'.padEnd(14)} Status`);
    row('Logging accuracy', `${n.loggingAccuracyPercent}%`, '>= 95%', n.loggingAccuracyPercent >= 95);
    row('Alerts delivered within 5 s', `${a.withinFiveSecondsPercent}%`, '>= 95%', a.withinFiveSecondsPercent >= 95);
    row('Alert delivery (median / p95)', `${a.medianMs} / ${a.p95Ms} ms`, '<= 5000 ms', a.p95Ms !== null && a.p95Ms <= 5000);
    row('CPU under normal traffic', `${n.cpuPercent}%`, '< 5%', n.cpuPercent < 5);
    row('Peak memory (RSS)', `${n.peakRssMB} MB`, '< 50 MB', n.peakRssMB < 50);
    console.log(`  ${'Idle CPU / memory'.padEnd(34)} ${results.idle.cpuPercent}% / ${results.idle.rssMB} MB`);
    console.log(`  ${'Page time direct / monitored'.padEnd(34)} ${p.directMedianMs} / ${p.monitoredMedianMs} ms (median)`);
    console.log('  CPU % is the share of ONE processor core used by the Node.js process.');
    console.log('═'.repeat(64));
    fs.writeFileSync('performance-results.json', JSON.stringify(results, null, 2));
    console.log('  Saved to performance-results.json\n');
})();
