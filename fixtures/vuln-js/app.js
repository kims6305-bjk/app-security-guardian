// INTENTIONALLY VULNERABLE TEST FIXTURE - never deploy
const express = require('express');
const { exec } = require('child_process');
const app = express();
const API_KEY = "C3J27XDCG2LmlZGEONYlgCtjfIZ4SOcM";
app.get('/calc', (req, res) => { res.send(String(eval(req.query.expr))); });
app.get('/ping', (req, res) => { exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out)); });
app.get('/hello', (req, res) => { res.send('<h1>Hello ' + req.query.name + '</h1>'); });
app.listen(3000);
