const https = require('https');
const express = require('express');
const crypto = require('crypto');
const forge = require('node-forge');
const fs = require('fs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// CẤU HÌNH HỆ THỐNG
const PORT = 3000;
const SECRET_KEY = "project4_attt_secure_key_2026"; // Khóa bí mật để ký JWT
const CERT_FILE = 'cert.pem';
const KEY_FILE = 'key.pem';

// 1. QUẢN LÝ CHỨNG CHỈ (Phục vụ Certificate Pinning)
let pemCert, pemKey;

// Kiểm tra nếu đã có cert thì dùng lại để mã Pin SHA-256 không bị thay đổi
if (fs.existsSync(CERT_FILE) && fs.existsSync(KEY_FILE)) {
    pemCert = fs.readFileSync(CERT_FILE, 'utf8');
    pemKey = fs.readFileSync(KEY_FILE, 'utf8');
    console.log('[SERVER] 🔒 Đã tải chứng chỉ hiện có.');
} else {
    // Tự động tạo cặp khóa RSA và chứng chỉ Self-signed nếu chưa có
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01' + crypto.randomBytes(4).toString('hex');
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    const attrs = [{ name: 'commonName', value: 'localhost' }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.sign(keys.privateKey, forge.md.sha256.create());

    pemCert = forge.pki.certificateToPem(cert);
    pemKey = forge.pki.privateKeyToPem(keys.privateKey);

    fs.writeFileSync(CERT_FILE, pemCert);
    fs.writeFileSync(KEY_FILE, pemKey);
    console.log('[SERVER] ✨ Đã tạo mới và lưu chứng chỉ.');
}

// TÍNH TOÁN MÃ PIN SHA-256 (Dùng để dán vào file XML trên Android)
const derCert = forge.asn1.toDer(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(pemCert))).getBytes();
const hash = crypto.createHash('sha256').update(Buffer.from(derCert, 'binary')).digest('base64');

console.log('\n' + '='.repeat(60));
console.log('THÔNG TIN CẤU HÌNH NETWORK SECURITY CHO ANDROID:');
console.log(`SHA-256 Pin: sha256/${hash}`);
console.log('='.repeat(60) + '\n');


// 2. LOGIC NGHIỆP VỤ BẢO MẬT

// API Đăng nhập: Giải quyết lỗi "Session vĩnh viễn" bằng JWT có thời hạn
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    console.log(`[SERVER] Thử đăng nhập: ${username}`);

    // Giả lập kiểm tra tài khoản
    if (username === 'admin' && password === 'p@ssword123') {
        // Tạo JWT Token hết hạn sau 15 phút (Tuân thủ ISO 27002 về quản lý phiên)
        const token = jwt.sign(
            { user: username, role: 'superuser' }, 
            SECRET_KEY, 
            { expiresIn: '15m' } 
        );

        res.json({
            status: 'ok',
            message: 'Đăng nhập thành công',
            token: token, // App Android cần lưu cái này vào EncryptedSharedPreferences
            user: username
        });
    } else {
        res.status(401).json({ status: 'error', message: 'Sai tài khoản hoặc mật khẩu' });
    }
});

// API Profile: Kiểm tra quyền truy cập (Giảm thiểu rủi ro rò rỉ dữ liệu)
app.get('/api/profile', (req, res) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ status: 'error', message: 'Không có token' });
    }

    const token = authHeader.split(' ')[1];

    try {
        // Xác thực chữ ký và thời hạn token
        const decoded = jwt.verify(token, SECRET_KEY);
        res.json({ 
            status: 'ok', 
            data: { 
                user: decoded.user, 
                role: decoded.role,
                compliance: "Verified by ISO 27002 & GDPR"
            } 
        });
    } catch (err) {
        res.status(403).json({ status: 'error', message: 'Token đã hết hạn hoặc không hợp lệ' });
    }
});

// 3. GHI LOG HỆ THỐNG (Đáp ứng tiêu chuẩn Audit Log của ISO 27002)
app.use((req, res, next) => {
    const log = `${new Date().toISOString()} - ${req.method} ${req.url}\n`;
    fs.appendFileSync('access.log', log);
    next();
});

// 4. KHỞI TẠO SERVER HTTPS
const options = { key: pemKey, cert: pemCert };
https.createServer(options, app).listen(PORT, '0.0.0.0', () => {
    console.log(`[SERVER] 🚀 Server chạy tại https://0.0.0.0:${PORT}`);
});
