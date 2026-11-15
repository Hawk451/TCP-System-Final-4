// TCP Ping Detection System — 100 User Simulation
// Simulates 100 people from different countries visiting the proxy

const http = require('http');

// Step 1: Set the proxy to monitor the local aviation website
function setProxyURL() {
    return new Promise((resolve) => {
        const body = JSON.stringify({ url: 'http://localhost:8080' });
        const req = http.request({
            hostname: 'localhost',
            port: 3000,
            path: '/api/proxy-url',
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
        }, (res) => {
            res.on('data', () => {});
            res.on('end', () => {
                console.log('  ✅ Proxy set to monitor http://localhost:8080');
                resolve();
            });
        });
        req.on('error', () => { console.log('  ⚠️  Could not set proxy URL — continuing anyway'); resolve(); });
        req.write(body);
        req.end();
    });
}
const crypto = require('crypto');

// Real public IPs from different countries
const ipPools = [
    // United States
    '8.8.8.8', '8.8.4.4', '208.67.222.222', '198.41.0.4', '4.2.2.1',
    // South Africa
    '41.13.64.1', '196.25.1.1', '41.0.96.1', '196.11.240.1', '41.185.8.1',
    // Germany
    '185.220.101.1', '194.25.0.1', '217.0.0.1', '195.71.35.1', '80.237.0.1',
    // United Kingdom
    '212.58.244.1', '193.113.0.1', '195.99.66.1', '194.168.4.100', '80.169.0.1',
    // France
    '212.27.48.10', '195.101.0.1', '217.108.0.1', '194.2.0.1', '80.10.0.1',
    // Brazil
    '200.195.136.1', '189.40.0.1', '201.0.0.1', '186.192.0.1', '177.0.0.1',
    // Singapore
    '103.86.96.1', '202.166.127.1', '203.116.0.1', '118.201.0.1', '175.41.0.1',
    // Australia
    '203.2.218.1', '139.130.4.5', '203.0.178.1', '192.189.54.1', '124.168.0.1',
    // India
    '117.18.232.1', '202.54.0.1', '203.94.0.1', '115.112.0.1', '59.144.0.1',
    // Japan
    '202.12.27.33', '203.178.128.1', '210.130.0.1', '133.205.0.1', '150.70.0.1',
    // Russia
    '77.88.8.8', '195.208.0.1', '213.180.193.1', '217.69.139.1', '194.190.0.1',
    // China
    '1.180.0.1', '58.14.0.1', '110.242.68.1', '180.76.76.76', '114.114.114.114',
    // Canada
    '24.53.192.1', '70.28.0.1', '206.108.0.1', '209.212.0.1', '64.26.0.1',
    // Netherlands
    '195.169.0.1', '194.109.6.66', '213.154.0.1', '80.100.0.1', '62.163.0.1',
    // Nigeria
    '196.201.208.1', '41.203.64.1', '197.255.0.1', '196.216.0.1', '105.112.0.1',
    // Kenya
    '196.201.216.1', '41.90.64.1', '197.136.0.1', '105.163.0.1', '196.207.0.1',
    // UAE
    '185.93.0.1', '194.170.0.1', '213.42.0.1', '82.149.0.1', '78.100.0.1',
    // Mexico
    '200.23.0.1', '187.188.0.1', '201.131.0.1', '189.203.0.1', '148.243.0.1',
    // Argentina
    '200.49.0.1', '190.220.0.1', '181.13.0.1', '200.3.0.1', '170.51.0.1',
    // Unknown/suspicious IPs
    '1.2.3.4', '5.6.7.8', '9.10.11.12', '13.14.15.16', '17.18.19.20',
];

const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    // Bot-like agents (will trigger bot detection)
    'python-requests/2.31.0',
    'curl/7.88.1',
    'Go-http-client/1.1',
];

const languages = ['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'fr-FR,fr;q=0.9', 'de-DE,de;q=0.9', 'zh-CN,zh;q=0.9', 'ja-JP,ja;q=0.9', 'pt-BR,pt;q=0.9', 'ar-SA,ar;q=0.9'];

let completed = 0;
let failed = 0;
const total = 100;

function sendVisit(index) {
    return new Promise((resolve) => {
        const ip = ipPools[index % ipPools.length];
        const ua = userAgents[Math.floor(Math.random() * userAgents.length)];
        const lang = languages[Math.floor(Math.random() * languages.length)];

        const options = {
            hostname: 'localhost',
            port: 8082,
            path: '/',
            method: 'GET',
            headers: {
                'x-forwarded-for': ip,
                'User-Agent': ua,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': lang,
                'Accept-Encoding': 'gzip, deflate',
            }
        };

        const req = http.request(options, (res) => {
            res.on('data', () => {});
            res.on('end', () => {
                completed++;
                process.stdout.write(`\r  Progress: ${completed + failed}/${total} | ✅ ${completed} ok | ❌ ${failed} failed`);
                resolve();
            });
        });

        req.on('error', () => {
            failed++;
            process.stdout.write(`\r  Progress: ${completed + failed}/${total} | ✅ ${completed} ok | ❌ ${failed} failed`);
            resolve();
        });

        req.setTimeout(5000, () => {
            req.destroy();
            failed++;
            resolve();
        });

        req.end();
    });
}

// Trusted IPs — these send enough normal requests to reach score 80+ (TRUSTED)
// Starting at 50, +2 per normal ping → need 15+ visits each
const trustedIPs = [
    '8.8.8.8',        // United States (Google DNS)
    '41.13.64.1',     // South Africa
    '203.2.218.1',    // Australia
    '194.25.0.1',     // Germany
    '212.58.244.1',   // United Kingdom
];

function sendTrustedVisit(ip) {
    return new Promise((resolve) => {
        const options = {
            hostname: 'localhost',
            port: 8082,
            path: '/',
            method: 'GET',
            headers: {
                'x-forwarded-for': ip,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
            }
        };
        const req = http.request(options, (res) => {
            res.on('data', () => {});
            res.on('end', () => { completed++; resolve(); });
        });
        req.on('error', () => { failed++; resolve(); });
        req.setTimeout(5000, () => { req.destroy(); failed++; resolve(); });
        req.end();
    });
}

async function runSimulation() {
    console.log('='.repeat(55));
    console.log('  TCP Ping Detection — 100 User Simulation');
    console.log('='.repeat(55));
    console.log(`  Simulating 100 visitors from 20 countries`);
    console.log(`  Mix of normal users, bots, suspicious + trusted IPs`);
    console.log('='.repeat(55));
    console.log('');

    // First set the proxy to point to the local aviation website
    await setProxyURL();
    console.log('');

    // Phase 1: Build trusted IPs — send 18 normal visits each (score 50 + 36 = 86 → TRUSTED)
    console.log('  Phase 1: Building trusted IP reputations...');
    for (const ip of trustedIPs) {
        for (let visit = 0; visit < 18; visit++) {
            await sendTrustedVisit(ip);
            await new Promise(r => setTimeout(r, 120)); // small gap so rhythm detection sees normal human pace
        }
        process.stdout.write(`\r  Progress: ${completed + failed} sent | ✅ ${completed} ok | ❌ ${failed} failed`);
    }
    console.log(`\n  ✔ Trusted IPs seeded (${trustedIPs.length} IPs × 18 visits)\n`);

    // Phase 2: Normal 100-visitor simulation
    console.log('  Phase 2: 100-visitor mixed simulation...');
    for (let batch = 0; batch < 10; batch++) {
        const promises = [];
        for (let i = 0; i < 10; i++) {
            promises.push(sendVisit(batch * 10 + i));
        }
        await Promise.all(promises);
        // Small delay between batches so the dashboard can keep up
        await new Promise(r => setTimeout(r, 500));
    }

    console.log('\n');
    console.log('='.repeat(55));
    console.log('  Simulation complete!');
    console.log(`  ✅ ${completed} successful  ❌ ${failed} failed`);
    console.log('');
    console.log('  Check your dashboard for:');
    console.log('  • Reputation tab — trusted IPs showing TRUSTED badge');
    console.log('  • Geography tab  — countries populated');
    console.log('  • Ghost Clusters — IP hopping detected');
    console.log('  • Blocked IPs    — suspicious IPs blocked');
    console.log('  • Alerts         — new alerts fired');
    console.log('='.repeat(55));
}

runSimulation();
