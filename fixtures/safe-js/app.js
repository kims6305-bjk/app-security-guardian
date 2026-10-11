const http = require('http');
http.createServer((req, res) => { res.setHeader('Content-Type','text/plain'); res.end('ok'); }).listen(3000, '127.0.0.1');
