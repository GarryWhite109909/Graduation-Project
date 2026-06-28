// 样本: 命令注入 - Node.js child_process.exec
// 期望: 检测到命令注入（用户输入拼接到 exec 命令字符串中）
const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/dns-lookup', (req, res) => {
    const domain = req.query.domain;
    // 漏洞：exec 使用 shell，用户输入直接拼接
    exec(`nslookup ${domain}`, (err, stdout, stderr) => {
        if (err) {
            res.status(500).send(stderr);
            return;
        }
        res.send(stdout);
    });
});

app.listen(3000);
