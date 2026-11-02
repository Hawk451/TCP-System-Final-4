const http = require('http');

const ips = ['1.2.3.4', '5.6.7.8', '9.10.11.12'];

ips.forEach((ip, i) => {
    setTimeout(() => {
        const r = http.request({
            hostname: 'localhost',
            port: 8082,
            path: '/',
            headers: {
                'x-forwarded-for': ip,
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'text/html'
            }
        });
        r.on('error', () => {});
        r.end();
        console.log('Sent request from', ip);
    }, i * 2000);
});
