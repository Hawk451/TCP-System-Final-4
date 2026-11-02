// TCP Ping Detection System — Geo Test Script
// Sends requests with real public IPs via x-forwarded-for to populate country/city data

const http = require('http');

const testIPs = [
    { ip: '8.8.8.8',         label: 'United States (Google)' },
    { ip: '41.13.64.1',      label: 'South Africa' },
    { ip: '185.220.101.1',   label: 'Germany' },
    { ip: '103.86.96.1',     label: 'Singapore' },
    { ip: '200.195.136.1',   label: 'Brazil' },
];

const PROXY_URL = 'http://localhost:8082';

function sendRequest(ip, label, index) {
    return new Promise((resolve) => {
        const options = {
            hostname: 'localhost',
            port: 8082,
            path: '/',
            method: 'GET',
            headers: {
                'x-forwarded-for': ip,
                'User-Agent': `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36`,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
            }
        };

        const req = http.request(options, (res) => {
            res.on('data', () => {});
            res.on('end', () => {
                console.log(`[${index + 1}/${testIPs.length}] ✅ ${label} (${ip}) — HTTP ${res.statusCode}`);
                resolve();
            });
        });

        req.on('error', (e) => {
            console.log(`[${index + 1}/${testIPs.length}] ❌ ${label} (${ip}) — Error: ${e.message}`);
            resolve();
        });

        req.setTimeout(5000, () => {
            console.log(`[${index + 1}/${testIPs.length}] ⏱️  ${label} (${ip}) — Timeout`);
            req.destroy();
            resolve();
        });

        req.end();
    });
}

async function runTest() {
    console.log('='.repeat(55));
    console.log('  TCP Ping Detection — Geo IP Test');
    console.log('='.repeat(55));
    console.log(`  Target: ${PROXY_URL}`);
    console.log(`  Simulating ${testIPs.length} IPs from different countries`);
    console.log('='.repeat(55));
    console.log('');

    for (let i = 0; i < testIPs.length; i++) {
        const { ip, label } = testIPs[i];
        await sendRequest(ip, label, i);
        await new Promise(r => setTimeout(r, 800)); // small delay between requests
    }

    console.log('');
    console.log('='.repeat(55));
    console.log('  Done! Check MongoDB / dashboard for geo data.');
    console.log('  Look for country and city fields in the Pings');
    console.log('  collection and the Geographic Patterns section.');
    console.log('='.repeat(55));
}

runTest();
