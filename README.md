# TCP Ping Detection System (IT Project 700)

A Node.js, Express, MongoDB and Socket.io system that monitors incoming connections to a website, classifies them as normal, suspicious or malicious, blocks bad IP addresses and shows everything on a live admin dashboard.

Student project for Richfield Graduate Institute of Technology.

## Folders

- `tcp-advanced/` – the detection system: TCP listener (port 9000), admin dashboard and REST API (port 3000), website proxy and web monitor.
- `aviation-test-site/` – the SkyForce Aviation demo website that the system protects (port 8080).

## Requirements

- Node.js 18 or higher
- MongoDB running on `localhost:27017`

## Run it

```
cd tcp-advanced
npm install
node index.js
```

Open http://localhost:3000. On the first start the system creates a Super Admin account called `admin` with a random password and prints that password once in the console. Log in, open the Admin tab and change it.

The demo site can be started separately with `cd aviation-test-site`, `npm install`, `node server.js`.

## Tests

```
cd tcp-advanced
node test-all.js
```
