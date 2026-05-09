// dummy-server/server.js
const https = require('https');
const express = require('express');
const selfsigned = require('selfsigned');

const app = express();
app.use(express.json());

app.post('/api/login', (req, res) => {
    console.log('[SERVER] Received credentials:', req.body);

    // Trả về session token — App sẽ lưu token này vào SharedPreferences
    // Đây là điểm mấu chốt của Scenario 2: nếu storage không mã hóa,
    // attacker đọc file SharedPreferences sẽ lấy được token này
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret_session_12345';
    res.json({
        status: 'ok',
        message: 'Login received',
        token: token,
        user: req.body.username
    });
});

// Endpoint kiểm tra token hợp lệ (dùng cho demo Scenario 2)
app.get('/api/profile', (req, res) => {
    const authHeader = req.headers['authorization'];
    console.log('[SERVER] Auth header:', authHeader);
    if (authHeader && authHeader.startsWith('Bearer ')) {
        res.json({ status: 'ok', user: 'admin', role: 'superuser' });
    } else {
        res.status(401).json({ status: 'error', message: 'Unauthorized' });
    }
});

// Tạo self-signed certificate tự động
const attrs = [{ name: 'commonName', value: 'localhost' }];
const pems = selfsigned.generate(attrs, { days: 365 });

const options = {
    key:  pems.private,
    cert: pems.cert,
};

https.createServer(options, app).listen(3000, '0.0.0.0', () => {
    console.log('[SERVER] HTTPS Listening on port 3000');
});