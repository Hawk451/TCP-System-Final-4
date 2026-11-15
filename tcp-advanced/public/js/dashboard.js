'use strict';
const state = { pings:[], alerts:[], blocked:[], reps:[], patterns:[], geo:[], dna:[], filter:'', maxPings:200 };
const $ = id => document.getElementById(id);

// ── Authenticated fetch — every dashboard API now requires the admin token ──
function authHeaders(extra) {
    return Object.assign({ 'x-auth-token': localStorage.getItem('adminToken') || '' }, extra || {});
}
async function api(url, opts) {
    opts = opts || {};
    const res = await fetch(url, Object.assign({}, opts, { headers: authHeaders(opts.headers) }));
    if (res.status === 401) {
        localStorage.removeItem('adminToken');
        window.location.href = '/login';
        throw new Error('Session expired');
    }
    return res;
}

// ── Socket.io with auto-reconnect ──────────────────────────────────────────
const socket = io({
    auth               : cb => cb({ token: localStorage.getItem('adminToken') || '' }),
    reconnection       : true,
    reconnectionAttempts: Infinity,   // keep trying forever
    reconnectionDelay  : 1000,        // start at 1 s
    reconnectionDelayMax: 5000,       // cap at 5 s
    timeout            : 10000,
    transports         : ['websocket','polling']  // websocket first, polling fallback
});

// Track last update time so we can detect a "stuck" socket
let _lastUpdate = Date.now();
function _touch() { _lastUpdate = Date.now(); }

socket.on('connect', () => {
    $('statusDot').className = 'status-dot connected';
    $('statusText').textContent = 'Connected — All 5 Unique SSL Features Active';
    _touch();
    // Re-fetch everything when we (re)connect so we never miss data
    loadAll();
});
socket.on('disconnect', () => {
    $('statusDot').className = 'status-dot disconnected';
    $('statusText').textContent = 'Reconnecting…';
});
socket.on('connect_error', () => {
    if (!localStorage.getItem('adminToken')) { window.location.href = '/login'; return; }
    $('statusDot').className = 'status-dot disconnected';
    $('statusText').textContent = 'Reconnecting…';
});
socket.on('new-ping', p => {
    _touch();
    state.pings.unshift(p);
    if (state.pings.length > state.maxPings) state.pings.pop();
    renderPings(true);
});
socket.on('stats-update',      s  => { _touch(); renderStats(s); renderBreakdown(s); });
socket.on('new-alert',         a  => { _touch(); state.alerts.unshift(a); renderAlerts(); showBanner(a); });
socket.on('ip-blocked',        () => { _touch(); loadBlocked(); });
socket.on('ip-unblocked',      d  => { _touch(); state.blocked=state.blocked.filter(b=>b.ip!==d.ip); renderBlocked(); });
socket.on('threshold-updated', d  => { _touch(); $('statThreshold').textContent=d.threshold; $('learnThreshold').textContent=d.threshold; $('learnMalicious').textContent=Math.ceil(d.threshold*1.5); });
socket.on('clustering-updated',() => { _touch(); loadLearning(); });

// ── Polling fallback — keeps dashboard alive even when socket is stuck ─────
// Runs every 5 s. If the socket is connected it only polls stats (lightweight).
// If the socket is disconnected OR hasn't pushed an update for 15 s, it also
// refreshes the live feed so you never have to reload the page manually.
setInterval(async () => {
    const socketOk = socket.connected && (Date.now() - _lastUpdate < 15000);
    try {
        // Always refresh stats
        const sr = await api('/api/stats');
        if (sr.ok) { const s = await sr.json(); renderStats(s); renderBreakdown(s); }

        // Refresh live feed only when socket seems stuck
        if (!socketOk) {
            const pr = await api('/api/pings');
            if (pr.ok) {
                const pings = await pr.json();
                state.pings = pings.map(p => ({ ...p, time: new Date(p.time).toLocaleString('en-ZA') }));
                renderPings();
            }
        }
    } catch (e) { /* silently ignore — next tick will retry */ }
}, 5000);

async function loadAll() {
    try {
        const [pr,ar,br,sr,rr,ptr,gr,dr] = await Promise.all([
            api('/api/pings'),api('/api/alerts'),api('/api/blocked'),api('/api/stats'),
            api('/api/reputations'),api('/api/patterns'),api('/api/geo'),api('/api/dna')
        ]);
        state.pings    = (await pr.json()).map(p=>({...p,time:new Date(p.time).toLocaleString('en-ZA')}));
        state.alerts   = (await ar.json()).map(a=>({...a,time:new Date(a.time).toLocaleString('en-ZA')}));
        state.blocked  = await br.json();
        state.reps     = await rr.json();
        state.patterns = await ptr.json();
        state.geo      = await gr.json();
        state.dna      = await dr.json();
        const stats    = await sr.json();
        renderPings(); renderAlerts(); renderBlocked(); renderReputation();
        renderPatterns(); renderGeo(); renderDNA(); renderStats(stats); renderBreakdown(stats); renderClusters();
    } catch(err) { console.error(err); }
}

async function loadBlocked() { const r=await api('/api/blocked'); state.blocked=await r.json(); renderBlocked(); }
async function loadLearning() {
    const r=await api('/api/learning'); const d=await r.json();
    state.reps=d.reputations; state.patterns=d.patterns; state.geo=d.geo; state.dna=d.dna;
    renderReputation(); renderPatterns(); renderGeo(); renderDNA(); renderClusters();
}

function renderPings(highlightFirst) {
    const tbody=$('pingTable');
    let pings=state.filter?state.pings.filter(p=>p.classification===state.filter):state.pings;
    if(!pings.length){tbody.innerHTML='<tr><td colspan="9" class="empty">No pings yet.</td></tr>';return;}
    tbody.innerHTML=pings.map((p,i)=>{
        const rc=p.reputationScore>=80?'#22c55e':p.reputationScore>=50?'#3b82f6':p.reputationScore>=20?'#f59e0b':'#ef4444';
        const botBadge=p.isBot?'<span class="badge badge--BOT">BOT</span>':'<span style="color:#8892a4">—</span>';
        const dnaBadge=`<span class="badge badge--${p.dnaMatch==='TRUSTED'?'TRUSTED':p.dnaMatch==='BLOCKED'?'MALICIOUS':p.dnaMatch==='UNKNOWN'||p.dnaMatch==='NEW'?'UNKNOWN':'SUSPICIOUS'}">${p.dnaMatch||'NEW'}</span>`;
        const trustColor=p.trustNetworkBoost>0?'#22c55e':'#8892a4';
        return `<tr class="${highlightFirst&&i===0?'new-row':''}">
            <td>${pings.length-i}</td><td>${esc(p.ip)}</td><td>${p.time}</td>
            <td><span class="badge badge--${p.classification}">${p.classification}</span></td>
            <td>${esc(p.country||'?')} ${p.geoRisk!=='NORMAL'?'⚠️':''}</td>
            <td><span style="color:${rc};font-weight:600">${p.reputationScore}/100</span>
                <div class="rep-bar"><div class="rep-bar__fill" style="width:${p.reputationScore}%;background:${rc}"></div></div></td>
            <td>${botBadge}</td><td>${dnaBadge}</td>
            <td style="color:${trustColor}">${p.trustNetworkBoost>0?'+'+p.trustNetworkBoost:'—'}</td>
        </tr>`;
    }).join('');
}

function renderStats(s) {
    $('statTotal').textContent     =s.totalPings      ||0;
    $('statNormal').textContent    =s.normalCount     ||0;
    $('statSuspicious').textContent=s.suspiciousCount ||0;
    $('statMalicious').textContent =s.maliciousCount  ||0;
    $('statBlocked').textContent   =s.blockedCount    ||0;
    $('statTrusted').textContent   =s.trustedIPs      ||0;
    $('statBots').textContent      =s.botCount        ||0;
    $('statCountries').textContent =s.uniqueCountries ||0;
    $('statDNA').textContent       =s.dnaFingerprints ||0;
    $('statThreshold').textContent =s.currentThreshold||10;
    $('statGhostClusters').textContent=s.ghostClusters||0;
    $('learnThreshold').textContent=s.currentThreshold||10;
    $('learnMalicious').textContent=Math.ceil((s.currentThreshold||10)*1.5);
}

function renderBreakdown(s) {
    const total=(s.normalCount||0)+(s.suspiciousCount||0)+(s.maliciousCount||0)||1;
    $('bdNormal').textContent       =s.normalCount    ||0;
    $('bdSuspicious').textContent   =s.suspiciousCount||0;
    $('bdMalicious').textContent    =s.maliciousCount ||0;
    $('bdNormalBar').style.width    =Math.round(((s.normalCount    ||0)/total)*100)+'%';
    $('bdSuspiciousBar').style.width=Math.round(((s.suspiciousCount||0)/total)*100)+'%';
    $('bdMaliciousBar').style.width =Math.round(((s.maliciousCount ||0)/total)*100)+'%';
}

function renderAlerts() {
    const list=$('alertList');
    if(!state.alerts.length){list.innerHTML='<p class="empty">No alerts yet.</p>';return;}
    list.innerHTML=state.alerts.map(a=>`
        <div class="alert-item alert-item--${a.type} ${a.read?'read':''}">
            <div class="alert-item__type">${a.type}</div>
            <div class="alert-item__msg">${esc(a.message)}</div>
            <div class="alert-item__meta">${esc(a.ip)} · ${a.time}
                ${!a.read?`<a href="#" onclick="markRead('${a._id||a.id}');return false;" style="color:#3b82f6;margin-left:6px">Mark read</a>`:''}
            </div>
        </div>`).join('');
}

function renderBlocked() {
    const list=$('blockedList');
    if(!state.blocked.length){list.innerHTML='<p class="empty">No blocked IPs.</p>';return;}
    list.innerHTML=state.blocked.map(b=>`
        <div class="blocked-item">
            <div><div class="blocked-item__ip">${esc(b.ip)}</div><div class="blocked-item__reason">${esc(b.reason)}</div></div>
            <button class="blocked-item__unblock" onclick="unblockIP('${b.ip}')">Unblock</button>
        </div>`).join('');
}

function renderReputation() {
    const tbody=$('reputationTable');
    if(!state.reps.length){tbody.innerHTML='<tr><td colspan="10" class="empty">No data yet.</td></tr>';return;}
    tbody.innerHTML=state.reps.map(r=>{
        const rc=r.score>=80?'#22c55e':r.score>=50?'#3b82f6':r.score>=20?'#f59e0b':'#ef4444';
        const badge=r.trusted?'<span class="badge badge--TRUSTED">TRUSTED</span>':r.score<=20?'<span class="badge badge--MALICIOUS">RISKY</span>':'<span class="badge badge--NORMAL">NORMAL</span>';
        return `<tr>
            <td>${esc(r.ip)}</td>
            <td><span style="color:${rc};font-weight:700">${r.score}/100</span>
                <div class="rep-bar"><div class="rep-bar__fill" style="width:${r.score}%;background:${rc}"></div></div></td>
            <td>${badge}</td><td>${esc(r.country||'?')}</td><td>${r.totalPings}</td>
            <td style="color:#22c55e">${r.normalPings}</td>
            <td style="color:#f59e0b">${r.suspiciousPings}</td>
            <td style="color:#ef4444">${r.maliciousPings}</td>
            <td style="color:#22c55e">${r.trustNetworkScore>0?'+'+r.trustNetworkScore:'—'}</td>
            <td>${new Date(r.lastSeen).toLocaleString('en-ZA')}</td>
        </tr>`;
    }).join('');
}

function renderGeo() {
    const tbody=$('geoTable');
    if(!state.geo.length){tbody.innerHTML='<tr><td colspan="6" class="empty">Learning geography...</td></tr>';return;}
    tbody.innerHTML=state.geo.map(g=>{
        const badge=g.trusted?'<span class="badge badge--TRUSTED">TRUSTED</span>':g.riskScore>70?'<span class="badge badge--MALICIOUS">HIGH RISK</span>':'<span class="badge badge--UNKNOWN">LEARNING</span>';
        return `<tr>
            <td style="font-weight:600">${esc(g.country)}</td><td>${g.visitCount}</td>
            <td>${g.riskScore}/100</td><td>${badge}</td>
            <td>${new Date(g.firstSeen).toLocaleString('en-ZA')}</td>
            <td>${new Date(g.lastSeen).toLocaleString('en-ZA')}</td>
        </tr>`;
    }).join('');
}

function renderDNA() {
    const tbody=$('dnaTable');
    if(!state.dna.length){tbody.innerHTML='<tr><td colspan="6" class="empty">Building fingerprints...</td></tr>';return;}
    tbody.innerHTML=state.dna.map(d=>{
        const badge=`<span class="badge badge--${d.label==='TRUSTED'?'TRUSTED':d.label==='MALICIOUS'?'MALICIOUS':'UNKNOWN'}">${d.label}</span>`;
        return `<tr>
            <td style="font-family:'Consolas',monospace;font-size:11px">${esc(d.fingerprint)}</td>
            <td>${esc(d.ip)}</td><td>${badge}</td><td style="color:#3b82f6;font-weight:600">${d.matchCount}</td>
            <td>${new Date(d.firstSeen).toLocaleString('en-ZA')}</td>
            <td>${new Date(d.lastSeen).toLocaleString('en-ZA')}</td>
        </tr>`;
    }).join('');
}

function renderPatterns() {
    const tbody=$('patternTable');
    if(!state.patterns.length){tbody.innerHTML='<tr><td colspan="6" class="empty">Learning...</td></tr>';return;}
    tbody.innerHTML=state.patterns.map(p=>`<tr>
        <td>${String(p.hour).padStart(2,'0')}:00</td><td>${p.avgPings}</td><td>${p.maxPings}</td>
        <td style="color:#3b82f6;font-weight:600">${p.threshold}</td>
        <td style="font-size:10px">${(p.topCountries||[]).join(', ')||'—'}</td><td>${p.sampleCount}</td>
    </tr>`).join('');
}

function renderClusters() {
    const counts=[0,0,0];
    state.reps.forEach(r=>{if(r.cluster>=0&&r.cluster<=2)counts[r.cluster]++;});
    const total=counts.reduce((a,b)=>a+b,0)||1;
    $('clusterNormal').textContent       =counts[0];
    $('clusterSuspicious').textContent   =counts[1];
    $('clusterMalicious').textContent    =counts[2];
    $('clusterNormalBar').style.width    =Math.round((counts[0]/total)*100)+'%';
    $('clusterSuspiciousBar').style.width=Math.round((counts[1]/total)*100)+'%';
    $('clusterMaliciousBar').style.width =Math.round((counts[2]/total)*100)+'%';
}

async function markRead(id) {
    await api(`/api/alerts/${id}/read`,{method:'POST'});
    const a=state.alerts.find(a=>(a._id||a.id)===id);
    if(a)a.read=true; renderAlerts();
}
async function markAllRead() {
    for(const a of state.alerts){if(!a.read){await api(`/api/alerts/${a._id||a.id}/read`,{method:'POST'});a.read=true;}}
    renderAlerts();
}
async function unblockIP(ip) {
    await api(`/api/blocked/${encodeURIComponent(ip)}`,{method:'DELETE'});
    state.blocked=state.blocked.filter(b=>b.ip!==ip); renderBlocked();
}
function applyFilter(){state.filter=$('filterClass').value;renderPings();}
function showTab(name,btn){
    document.querySelectorAll('.tab-content').forEach(t=>{t.classList.remove('active');t.classList.add('hidden');});
    document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
    $('tab-'+name).classList.remove('hidden'); $('tab-'+name).classList.add('active'); btn.classList.add('active');
    if(name==='reputation'||name==='geo'||name==='dna'||name==='learning') loadLearning();
}
let _bannerTimer=null;
function showBanner(alert) {
    const banner=$('alertBanner');
    const type=String(alert.type||'ALERT');
    const message=String(alert.message||'');
    $('alertBannerIcon').textContent=type==='MALICIOUS'?'🚨':type==='GHOST_IP'?'👻':'⚠️';
    $('alertBannerText').textContent=`${type}: ${message.slice(0,100)}`;
    banner.className=`alert-banner ${type==='MALICIOUS'?'malicious':'suspicious'}`;
    clearTimeout(_bannerTimer);
    _bannerTimer=setTimeout(()=>banner.classList.add('hidden'),8000);
}
function closeBanner(){$('alertBanner').classList.add('hidden');}
function esc(str){if(str===undefined||str===null)return'';return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}

window.applyFilter=applyFilter;window.markRead=markRead;window.markAllRead=markAllRead;
window.unblockIP=unblockIP;window.api=api;window.authHeaders=authHeaders;window.closeBanner=closeBanner;window.showTab=showTab;

loadAll();
