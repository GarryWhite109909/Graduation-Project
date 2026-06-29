const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/dns-lookup', (req, res) => {
    const domain = req.query.domain;
    exec(`nslookup ${domain}`, (err, stdout, stderr) => {
        if (err) {
            res.status(500).send(stderr);
            return;
        }
        res.send(stdout);
    });
});

app.listen(3000);
