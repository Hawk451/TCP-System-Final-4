/**
 * server.js
 * SkyForce Aviation — Test Website Server
 * 
 * Runs on port 8080 so it doesn't clash with:
 *   - TCP Ping Detection dashboard (port 3000)
 *   - TCP listener (port 9000)
 * 
 * Every time a browser loads a page on this site, it makes a TCP connection
 * which the TCP Ping Detection System on port 9000 will detect and log.
 * 
 * HOW TO TEST:
 *   1. Start the TCP Ping Detection System first (npm start in that folder)
 *   2. Start this site (npm start in this folder)
 *   3. Open http://localhost:8080 in your browser
 *   4. Watch http://localhost:3000 — you will see events appear live
 */

'use strict';

const express = require('express');
const net     = require('net');
const path    = require('path');
const app     = express();

const PORT          = 8080;
const TCP_MONITOR_PORT = 9000;   // Must match CONFIG.TCP_PORT in tcp-advanced/index.js

// ── Every page request also pings the TCP monitor ─────────────────────────────
// This simulates what would happen on a real server where the monitor runs
// alongside the web application. It must run BEFORE express.static, otherwise
// the home page (index.html) is served by the static handler and never pinged.
app.use((req, res, next) => {
    // Only page loads count — not the CSS/JS/image files the page pulls in
    if (req.method !== 'GET' || /\.[a-z0-9]+$/i.test(req.path)) return next();
    // Send a TCP ping to the detection system so it registers the visit
    const socket = new net.Socket();
    socket.setTimeout(2000);
    socket.connect(TCP_MONITOR_PORT, '127.0.0.1', () => {
        socket.destroy();
    });
    socket.on('error', () => { /* detection system may not be running yet */ });
    socket.on('timeout', () => { socket.destroy(); });
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ── Serve all pages ───────────────────────────────────────────────────────────
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const server = app.listen(PORT, () => {
    console.log(`\n✈  SkyForce Aviation website running at: http://localhost:${PORT}`);
    console.log(`📡 TCP pings being sent to monitor port: ${TCP_MONITOR_PORT}`);
    console.log(`\n   Open http://localhost:${PORT} in your browser`);
    console.log(`   Then check http://localhost:3000 to see events appear live\n`);
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use — tcp-advanced already serves this website on port ${PORT}, so you don't need to run this server as well.`);
    } else {
        console.error('Server error:', err.message);
    }
});
