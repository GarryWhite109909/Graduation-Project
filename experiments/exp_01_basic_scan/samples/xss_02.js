const express = require('express');
const app = express();

app.get('/greet', (req, res) => {
    const username = req.query.name;
    const html = `<html><body><h1>Welcome ` + username + `</h1></body></html>`;
    res.set('Content-Type', 'text/html');
    res.send(html);
});

app.listen(3000);
