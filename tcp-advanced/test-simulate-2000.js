// TCP Ping Detection System — 2000 User Simulation
// Directly calls the dashboard API to simulate real pings with real IPs/countries

const http = require('http');
const net  = require('net');

// Ghost clusters are sent as a dedicated pre-phase (Phase 0) BEFORE the main simulation.
// Each cluster = 4+ IPs from the same /24 subnet, all using the same User-Agent + language.
// This triggers BOTH signals in detectGhostIP:
//   1. fp:<fingerprint> fires once 3 IPs with the same UA hit → one cluster record
//   2. sn:<subnet>      fires once 3 IPs from the same /24 hit  → another cluster record
// Result: each ghost group creates UP TO 2 cluster records → 6 groups × 2 = up to 12 clusters.

const ipPools = [
    { ip: '8.8.8.8',          country: 'US', label: 'United States'  },
    { ip: '8.8.4.4',          country: 'US', label: 'United States'  },
    { ip: '208.67.222.222',   country: 'US', label: 'United States'  },
    { ip: '41.13.64.1',       country: 'ZA', label: 'South Africa'   },
    { ip: '196.25.1.1',       country: 'ZA', label: 'South Africa'   },
    { ip: '41.0.96.1',        country: 'ZA', label: 'South Africa'   },
    { ip: '185.220.101.1',    country: 'DE', label: 'Germany'        },
    { ip: '194.25.0.1',       country: 'DE', label: 'Germany'        },
    { ip: '212.58.244.1',     country: 'GB', label: 'United Kingdom' },
    { ip: '193.113.0.1',      country: 'GB', label: 'United Kingdom' },
    { ip: '212.27.48.10',     country: 'FR', label: 'France'         },
    { ip: '195.101.0.1',      country: 'FR', label: 'France'         },
    { ip: '200.195.136.1',    country: 'BR', label: 'Brazil'         },
    { ip: '189.40.0.1',       country: 'BR', label: 'Brazil'         },
    { ip: '103.86.96.1',      country: 'SG', label: 'Singapore'      },
    { ip: '202.166.127.1',    country: 'SG', label: 'Singapore'      },
    { ip: '203.2.218.1',      country: 'AU', label: 'Australia'      },
    { ip: '139.130.4.5',      country: 'AU', label: 'Australia'      },
    { ip: '117.18.232.1',     country: 'IN', label: 'India'          },
    { ip: '202.54.0.1',       country: 'IN', label: 'India'          },
    { ip: '202.12.27.33',     country: 'JP', label: 'Japan'          },
    { ip: '203.178.128.1',    country: 'JP', label: 'Japan'          },
    { ip: '77.88.8.8',        country: 'RU', label: 'Russia'         },
    { ip: '195.208.0.1',      country: 'RU', label: 'Russia'         },
    { ip: '1.180.0.1',        country: 'CN', label: 'China'          },
    { ip: '58.14.0.1',        country: 'CN', label: 'China'          },
    { ip: '24.53.192.1',      country: 'CA', label: 'Canada'         },
    { ip: '70.28.0.1',        country: 'CA', label: 'Canada'         },
    { ip: '196.201.208.1',    country: 'NG', label: 'Nigeria'        },
    { ip: '41.203.64.1',      country: 'NG', label: 'Nigeria'        },
    { ip: '196.201.216.1',    country: 'KE', label: 'Kenya'          },
    { ip: '41.90.64.1',       country: 'KE', label: 'Kenya'          },
    { ip: '185.93.0.1',       country: 'AE', label: 'UAE'            },
    { ip: '194.170.0.1',      country: 'AE', label: 'UAE'            },
    { ip: '200.23.0.1',       country: 'MX', label: 'Mexico'         },
    { ip: '187.188.0.1',      country: 'MX', label: 'Mexico'         },
    { ip: '200.49.0.1',       country: 'AR', label: 'Argentina'      },
    { ip: '190.220.0.1',      country: 'AR', label: 'Argentina'      },
];

// Trusted IPs — clean, slow, real-browser traffic that will build up to 80+ reputation
const trustedIPs = [
    { ip: '146.64.16.1',   label: 'ZA Clean'  },   // South Africa
    { ip: '41.185.24.1',   label: 'ZA Clean'  },   // South Africa
    { ip: '152.111.0.1',   label: 'ZA Clean'  },   // South Africa
    { ip: '196.22.242.1',  label: 'ZA Clean'  },   // South Africa
    { ip: '105.27.0.1',    label: 'ZA Clean'  },   // South Africa
];

const cleanAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36',
    'python-requests/2.31.0',
    'curl/7.88.1',
];

const languages = ['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'fr-FR,fr;q=0.9', 'de-DE,de;q=0.9', 'zh-CN,zh;q=0.9'];

// Ghost clusters — each group shares:
//   • the same /24 subnet  → triggers the subnet signal (sn:<subnet>)
//   • the same User-Agent  → triggers the fingerprint signal (fp:<hash>)
// Both signals fire independently, so each group creates 2 cluster records in the DB.
// 20 groups × 2 = up to 40 ghost clusters visible on the dashboard.
const ghostGroups = [
    { label:'Ghost-A',  ua:'GhostBot/1.0 (Subnet-A; rv:1.0)',   lang:'zh-CN,zh;q=0.9',  ips:['1.2.3.10','1.2.3.11','1.2.3.12','1.2.3.13'] },
    { label:'Ghost-B',  ua:'GhostBot/2.0 (Subnet-B; rv:2.0)',   lang:'ru-RU,ru;q=0.9',  ips:['5.6.7.20','5.6.7.21','5.6.7.22','5.6.7.23'] },
    { label:'Ghost-C',  ua:'GhostBot/3.0 (Subnet-C; rv:3.0)',   lang:'ar-SA,ar;q=0.9',  ips:['9.8.7.30','9.8.7.31','9.8.7.32','9.8.7.33'] },
    { label:'Ghost-D',  ua:'GhostBot/4.0 (Subnet-D; rv:4.0)',   lang:'ko-KR,ko;q=0.9',  ips:['172.16.99.40','172.16.99.41','172.16.99.42','172.16.99.43'] },
    { label:'Ghost-E',  ua:'GhostBot/5.0 (Subnet-E; rv:5.0)',   lang:'ja-JP,ja;q=0.9',  ips:['10.20.30.50','10.20.30.51','10.20.30.52','10.20.30.53'] },
    { label:'Ghost-F',  ua:'GhostBot/6.0 (Subnet-F; rv:6.0)',   lang:'tr-TR,tr;q=0.9',  ips:['45.90.180.60','45.90.180.61','45.90.180.62','45.90.180.63'] },
    { label:'Ghost-G',  ua:'GhostBot/7.0 (Subnet-G; rv:7.0)',   lang:'hi-IN,hi;q=0.9',  ips:['110.10.20.70','110.10.20.71','110.10.20.72','110.10.20.73'] },
    { label:'Ghost-H',  ua:'GhostBot/8.0 (Subnet-H; rv:8.0)',   lang:'pt-BR,pt;q=0.9',  ips:['187.50.60.80','187.50.60.81','187.50.60.82','187.50.60.83'] },
    { label:'Ghost-I',  ua:'GhostBot/9.0 (Subnet-I; rv:9.0)',   lang:'es-MX,es;q=0.9',  ips:['201.10.20.90','201.10.20.91','201.10.20.92','201.10.20.93'] },
    { label:'Ghost-J',  ua:'GhostBot/10.0 (Subnet-J; rv:10.0)', lang:'de-DE,de;q=0.9',  ips:['83.160.10.100','83.160.10.101','83.160.10.102','83.160.10.103'] },
    { label:'Ghost-K',  ua:'GhostBot/11.0 (Subnet-K; rv:11.0)', lang:'fr-FR,fr;q=0.9',  ips:['90.70.10.110','90.70.10.111','90.70.10.112','90.70.10.113'] },
    { label:'Ghost-L',  ua:'GhostBot/12.0 (Subnet-L; rv:12.0)', lang:'pl-PL,pl;q=0.9',  ips:['91.100.20.120','91.100.20.121','91.100.20.122','91.100.20.123'] },
    { label:'Ghost-M',  ua:'GhostBot/13.0 (Subnet-M; rv:13.0)', lang:'nl-NL,nl;q=0.9',  ips:['82.150.30.130','82.150.30.131','82.150.30.132','82.150.30.133'] },
    { label:'Ghost-N',  ua:'GhostBot/14.0 (Subnet-N; rv:14.0)', lang:'sv-SE,sv;q=0.9',  ips:['94.140.40.140','94.140.40.141','94.140.40.142','94.140.40.143'] },
    { label:'Ghost-O',  ua:'GhostBot/15.0 (Subnet-O; rv:15.0)', lang:'cs-CZ,cs;q=0.9',  ips:['78.130.50.150','78.130.50.151','78.130.50.152','78.130.50.153'] },
    { label:'Ghost-P',  ua:'GhostBot/16.0 (Subnet-P; rv:16.0)', lang:'ro-RO,ro;q=0.9',  ips:['79.115.60.160','79.115.60.161','79.115.60.162','79.115.60.163'] },
    { label:'Ghost-Q',  ua:'GhostBot/17.0 (Subnet-Q; rv:17.0)', lang:'hu-HU,hu;q=0.9',  ips:['84.2.70.170','84.2.70.171','84.2.70.172','84.2.70.173'] },
    { label:'Ghost-R',  ua:'GhostBot/18.0 (Subnet-R; rv:18.0)', lang:'el-GR,el;q=0.9',  ips:['80.100.80.180','80.100.80.181','80.100.80.182','80.100.80.183'] },
    { label:'Ghost-S',  ua:'GhostBot/19.0 (Subnet-S; rv:19.0)', lang:'uk-UA,uk;q=0.9',  ips:['93.175.90.190','93.175.90.191','93.175.90.192','93.175.90.193'] },
    { label:'Ghost-T',  ua:'GhostBot/20.0 (Subnet-T; rv:20.0)', lang:'fi-FI,fi;q=0.9',  ips:['62.241.100.200','62.241.100.201','62.241.100.202','62.241.100.203'] },
];

let completed = 0;
let failed = 0;
const total = 100;

// Send request to proxy with x-forwarded-for so the real IP goes through geo + ghost detection
function sendVisit(index) {
    return new Promise((resolve) => {
        const entry = ipPools[index % ipPools.length];
        const ua    = userAgents[Math.floor(Math.random() * userAgents.length)];
        const lang  = languages[Math.floor(Math.random() * languages.length)];

        const req = http.request({
            hostname: 'localhost',
            port: 8082,
            path: '/',
            method: 'GET',
            headers: {
                'x-forwarded-for': entry.ip,
                'User-Agent': ua,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': lang,
                'Accept-Encoding': 'identity',
            }
        }, (res) => {
            res.resume();
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

        req.setTimeout(8000, () => { req.destroy(); failed++; resolve(); });
        req.end();
    });
}

// Send a ghost visit — same UA/lang as the rest of the group so the fingerprint signal fires
function sendGhostVisit(ip, ua, lang) {
    return new Promise((resolve) => {
        const req = http.request({
            hostname: 'localhost',
            port: 8082,
            path: '/',
            method: 'GET',
            headers: {
                'x-forwarded-for' : ip,
                'User-Agent'      : ua,
                'Accept'          : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language' : lang,
                'Accept-Encoding' : 'identity',
            }
        }, (res) => { res.resume(); res.on('end', resolve); });
        req.on('error', resolve);
        req.setTimeout(8000, () => { req.destroy(); resolve(); });
        req.end();
    });
}

// Send a clean trusted visit — slow, real browser headers, no bot signals
function sendTrustedVisit(ip) {
    return new Promise((resolve) => {
        const req = http.request({
            hostname: 'localhost',
            port: 8082,
            path: '/',
            method: 'GET',
            headers: {
                'x-forwarded-for'  : ip,
                'User-Agent'       : cleanAgent,
                'Accept'           : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language'  : 'en-ZA,en;q=0.9',
                'Accept-Encoding'  : 'identity',
                'Cache-Control'    : 'no-cache',
                'Connection'       : 'keep-alive',
            }
        }, (res) => { res.resume(); res.on('end', resolve); });
        req.on('error', resolve);
        req.setTimeout(8000, () => { req.destroy(); resolve(); });
        req.end();
    });
}

// Set proxy to point at a real public site so requests actually complete
function setProxyURL(url) {
    return new Promise((resolve) => {
        const body = JSON.stringify({ url });
        const req = http.request({
            hostname: 'localhost', port: 3000, path: '/api/proxy-url', method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
        }, (res) => { res.resume(); res.on('end', resolve); });
        req.on('error', resolve);
        req.write(body); req.end();
    });
}

async function runSimulation() {
    console.log('='.repeat(55));
    console.log('  TCP Ping Detection — 100 User Simulation');
    console.log('='.repeat(55));
    console.log(`  Phase 0: Ghost clusters — 20 groups × 4 IPs = up to 40 clusters`);
    console.log(`  Phase 1: 100 clean visits (200ms gaps) → build Trusted IPs`);
    console.log(`  Phase 2: 100 visitors from 20 countries`);
    console.log(`  Mix of normal users, bots, suspicious + trusted IPs`);
    console.log('='.repeat(55));
    console.log('');

    // Point proxy at example.com (lightweight, always up)
    await setProxyURL('http://example.com');
    console.log('  ✅ Proxy pointed at http://example.com');
    console.log('');

    // Phase 0 — Ghost IP clusters
    // Each group: 4 IPs hit the proxy with the same UA.
    // After the 3rd IP hits, detectGhostIP fires for BOTH the fingerprint key and subnet key.
    // We send each IP 3 times to make sure all 4 are registered before the window expires.
    console.log('  Phase 0: Firing ghost IP clusters...');
    for (const group of ghostGroups) {
        process.stdout.write(`\r  Cluster ${group.label}: sending 4 IPs...`);
        // Round 1: all 4 IPs — triggers both fp and subnet signals on the 3rd IP
        for (const ip of group.ips) {
            await sendGhostVisit(ip, group.ua, group.lang);
            await new Promise(r => setTimeout(r, 200));
        }
        // Round 2: send again so the tracker has multiple timestamps and the cluster is solid
        for (const ip of group.ips) {
            await sendGhostVisit(ip, group.ua, group.lang);
            await new Promise(r => setTimeout(r, 200));
        }
        await new Promise(r => setTimeout(r, 500)); // small gap between groups
    }
    console.log('\n  ✅ Ghost clusters fired — check dashboard Ghost Clusters counter');
    console.log('');

    // Phase 1 — Pre-seed trusted IPs with 20 clean visits each (100 total)
    // Each visit = +5 reputation → 20 visits = +100 from 65 → capped at 100. Trusted after 3 visits.
    console.log('  Phase 1: Building trusted IP reputation (100 clean visits, 200ms spacing)...');
    for (let round = 0; round < 20; round++) {
        for (const t of trustedIPs) {
            await sendTrustedVisit(t.ip);
            await new Promise(r => setTimeout(r, 200)); // same 200ms gap as rest of simulation
        }
        if ((round + 1) % 5 === 0) process.stdout.write(`\r  Phase 1: round ${round+1}/20`);
    }
    console.log('\n  ✅ Trusted IPs seeded — reputation building done');
    console.log('');

    // Phase 2 — Main 2000 user simulation
    console.log('  Phase 2: Running 2000 user simulation...');
    for (let i = 0; i < total; i++) {
        await sendVisit(i);
        // Every 5 requests pause slightly to let MongoDB and Socket.io keep up
        if ((i + 1) % 5 === 0) await new Promise(r => setTimeout(r, 50));
    }

    console.log('\n');
    console.log('='.repeat(55));
    console.log('  Simulation complete!');
    console.log(`  ✅ ${completed} successful  ❌ ${failed} failed`);
    console.log('');
    console.log('  Check your dashboard for:');
    console.log('  • Live Feed      — real IPs and countries');
    console.log('  • Geography tab  — 20+ countries populated');
    console.log('  • Ghost Clusters — 20 groups × 2 signals = up to 40 clusters');
    console.log('  • Trusted IPs    — 5 ZA IPs should show as trusted');
    console.log('  • Blocked IPs    — suspicious IPs blocked');
    console.log('  • Alerts         — suspicious/malicious alerts');
    console.log('  • Reports tab    — full data ready to print');
    console.log('='.repeat(55));
}

runSimulation();
