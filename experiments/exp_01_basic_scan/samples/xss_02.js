// 样本: XSS - Node.js Express 直接返回用户输入
// 期望: 检测到反射型 XSS（用户输入未转义直接写入响应 HTML）
const express = require('express');
const app = express();

app.get('/greet', (req, res) => {
    const username = req.query.name;
    // 漏洞：直接将用户输入拼接到 HTML 字符串返回
    const html = `<html><body><h1>Welcome ` + username + `</h1></body></html>`;
    res.set('Content-Type', 'text/html');
    res.send(html);
});

app.listen(3000);
