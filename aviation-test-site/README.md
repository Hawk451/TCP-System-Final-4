# SkyForce Aviation — Test Website
**Used to test the TCP Ping Detection System — IT Project 700**

---

## How to Run

### Step 1 — Start the TCP Ping Detection System
```
cd tcp-advanced
npm install
npm start
```
Dashboard will be at: http://localhost:3000

### Step 2 — Open the aviation website
`tcp-advanced` already serves this website (with IP blocking) on port 8080,
so you do **not** need to run `npm start` in this folder. Running both at once
causes a port 8080 conflict.

Website will be at: http://localhost:8080

### Step 3 — Test the TCP detection
1. Open the aviation website: **http://localhost:8080**
2. Open the TCP monitor dashboard in another tab: **http://localhost:3000**
3. Browse around the aviation website — click different sections
4. Watch events appear **live** on the TCP monitor dashboard

---

## How TCP Detection Works With This Site

Every time a page is loaded on this site, the server sends a TCP connection
to the monitor on port 9000. This triggers the detection system and you will
see events classified as NORMAL traffic on the dashboard.

To test SUSPICIOUS traffic detection:
- Rapidly refresh the aviation website page many times (10+ times quickly)
- The classifier will escalate from NORMAL → SUSPICIOUS → MALICIOUS

---

## Ports Used

| Service | Port |
|---|---|
| TCP Monitor Dashboard | 3000 |
| TCP Listener (detection) | 9000 |
| Aviation Test Website | 8080 |

---

*SkyForce Aviation is a fictional company created for academic testing purposes only.*
*IT Project 700 — Richfield Graduate Institute of Technology — 2026*
