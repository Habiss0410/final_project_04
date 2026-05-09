"""
04_security_audit.py — Tổng hợp Security Audit Report

Script này tổng hợp toàn bộ kết quả demo thành một báo cáo
có cấu trúc, ánh xạ sang các tiêu chuẩn quốc tế.

Cách chạy:
    python python-tools/04_security_audit.py
    → Sinh file: reports/final_report.html
"""

import datetime
from pathlib import Path
from utils.logger import print_banner, log_info, log_success


# ──────────────────────────────────────────────
# Dữ liệu cấu trúc — Findings & Compliance
# ──────────────────────────────────────────────

FINDINGS = [
    {
        "id":          "VULN-001",
        "title":       "M3: Insecure Communication — User-installed CA Accepted",
        "severity":    "CRITICAL",
        "description": (
            "App chấp nhận User-added CA certificates, cho phép kẻ tấn công "
            "thực hiện MITM qua chứng chỉ giả (Burp Suite CA). "
            "Toàn bộ HTTPS traffic có thể bị đọc dưới dạng plaintext."
        ),
        "evidence":    "Burp Suite capture được POST /api/login với username/password rõ.",
        "fix":         "Áp dụng Network Security Config chỉ tin tưởng System CAs.",
        "owasp":       "OWASP Mobile Top 10 - M3: Insecure Communication",
        "iso":         "ISO/IEC 27002:2022 — 8.24, 8.26",
        "gdpr":        "GDPR Article 32 — Security of processing (Data in transit)",
    },
    {
        "id":          "VULN-002",
        "title":       "M9: Insecure Data Storage — SharedPreferences Không Mã Hóa",
        "severity":    "HIGH",
        "description": (
            "App lưu session token và credentials vào SharedPreferences dạng "
            "plaintext XML. Trên thiết bị root hoặc emulator, kẻ tấn công dùng "
            "ADB shell đọc trực tiếp file /data/data/<package>/shared_prefs/ "
            "mà không cần bẻ khóa hay can thiệp network."
        ),
        "evidence":    "ADB shell đọc được auth_token và username dạng plaintext từ app_prefs.xml.",
        "fix":         "Dùng EncryptedSharedPreferences (AES-256-GCM) + Root Detection + Android Keystore.",
        "owasp":       "OWASP Mobile Top 10 - M9: Insecure Data Storage",
        "iso":         "ISO/IEC 27002:2022 — 8.24, 8.10",
        "gdpr":        "GDPR Article 32 — Security of processing (Data at rest)",
    },
]

RISK_MATRIX = {
    "Threat":        "MITM attack (network) + ADB Storage Extraction (local device).",
    "Vulnerability": "App không kiểm tra nguồn gốc chứng chỉ TLS; credentials lưu plaintext.",
    "Likelihood":    "HIGH — Cả hai attack đều thực hiện bằng free tools (Burp Suite, ADB).",
    "Impact":        "CRITICAL — Lộ toàn bộ Authentication Credentials ở cả 2 lớp.",
    "Risk Level":    "CRITICAL",
}


def generate_html_report(output_path: str) -> None:
    """Sinh báo cáo HTML có thể in / nộp giảng viên."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = ""
    for f in FINDINGS:
        severity_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c"}.get(f["severity"], "#666")
        rows += f"""
        <tr>
          <td><code>{f['id']}</code></td>
          <td>{f['title']}</td>
          <td style="color:{severity_color};font-weight:bold">{f['severity']}</td>
          <td>{f['owasp']}</td>
          <td>{f['iso']}</td>
          <td>{f['gdpr']}</td>
          <td>{f['fix']}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <title>Security Audit Report — Project 4</title>
  <style>
    body     {{ font-family: 'Segoe UI', sans-serif; max-width: 960px;
                margin: 40px auto; color: #1e293b; line-height: 1.6; }}
    h1       {{ color: #0f172a; border-bottom: 3px solid #dc2626; padding-bottom: 8px; }}
    h2       {{ color: #1d4ed8; margin-top: 36px; }}
    table    {{ width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 14px; }}
    th       {{ background: #1e293b; color: white; padding: 10px; text-align: left; }}
    td       {{ padding: 9px 10px; border-bottom: 1px solid #e2e8f0; }}
    tr:hover {{ background: #f8fafc; }}
    .badge   {{ display:inline-block; padding:2px 8px; border-radius:4px;
                background:#dc2626; color:white; font-size:12px; }}
    .meta    {{ color:#64748b; font-size:14px; }}
    .box     {{ background:#f1f5f9; border-left:4px solid #1d4ed8;
                padding:12px 16px; margin:12px 0; border-radius:0 8px 8px 0; }}
  </style>
</head>
<body>
  <h1>🔐 Security Audit Report</h1>
  <p class="meta">Project 4 — Android MITM Lab &nbsp;|&nbsp; Generated: {now}</p>

  <h2>1. Executive Summary</h2>
  <div class="box">
    Demo này chứng minh <strong>2 lỗ hổng bảo mật nghiêm trọng</strong> trên ứng dụng Android,
    bao gồm cả lớp Network và lớp Storage — tương ứng với yêu cầu bảo vệ
    <em>Data in transit</em> và <em>Data at rest</em> theo GDPR Article 32.<br><br>
    <strong>Scenario 1 — MITM Attack (VULN-001):</strong> App chấp nhận User-installed CA →
    Burp Suite intercept credentials qua HTTPS giả mạo → Fix: Network Security Config.<br><br>
    <strong>Scenario 2 — Storage Attack (VULN-002):</strong> App lưu token plaintext trong
    SharedPreferences → ADB shell đọc trực tiếp trên thiết bị root →
    Fix: EncryptedSharedPreferences + Root Detection.
  </div>

  <h2>2. Risk Assessment</h2>
  <table>
    <tr><th>Yếu tố</th><th>Mô tả</th></tr>
    {''.join(f"<tr><td><strong>{k}</strong></td><td>{v}</td></tr>" for k,v in RISK_MATRIX.items())}
  </table>

  <h2>3. Vulnerability Findings & Compliance Mapping</h2>
  <table>
    <tr>
      <th>ID</th><th>Lỗ hổng</th><th>Severity</th>
      <th>OWASP</th><th>ISO/IEC 27002</th><th>GDPR</th><th>Giải pháp</th>
    </tr>
    {rows}
  </table>

  <h2>4. Remediation</h2>

  <h3 style="color:#1d4ed8">4.1 Scenario 1 — Network Security Config</h3>
  <div class="box">
    Áp dụng file <code>res/xml/network_security_config.xml</code> với thuộc tính
    <code>cleartextTrafficPermitted="false"</code> và chỉ tin tưởng
    <code>&lt;certificates src="system"/&gt;</code>. Kết quả:
    App ném <code>SSLHandshakeException</code> và từ chối gửi data khi
    phát hiện chứng chỉ không thuộc System CA store.
  </div>

  <h3 style="color:#1d4ed8">4.2 Scenario 2 — EncryptedSharedPreferences + Root Detection</h3>
  <div class="box">
    Thay thế <code>SharedPreferences</code> bằng <code>EncryptedSharedPreferences</code>
    (AndroidX Security, AES-256-GCM). Keys được quản lý bởi Android Keystore —
    không thể đọc được kể cả khi có quyền root. Bổ sung thêm Root Detection:
    App tự động thoát (<code>finish()</code>) khi phát hiện thiết bị bị root,
    ngăn chặn hoàn toàn vector tấn công qua ADB shell.
  </div>

  <h2>5. Attack Surface Comparison</h2>
  <table>
    <tr>
      <th>Tiêu chí</th>
      <th>Scenario 1 — MITM</th>
      <th>Scenario 2 — Storage</th>
    </tr>
    <tr><td>Attack vector</td><td>Network (Wi-Fi proxy)</td><td>Local device (ADB shell)</td></tr>
    <tr><td>Tool sử dụng</td><td>Burp Suite Community</td><td>ADB (Android SDK)</td></tr>
    <tr><td>Dữ liệu bị lộ</td><td>Credentials in transit</td><td>Token/credentials at rest</td></tr>
    <tr><td>OWASP</td><td>M3: Insecure Communication</td><td>M9: Insecure Data Storage</td></tr>
    <tr><td>Giải pháp</td><td>Network Security Config</td><td>EncryptedSharedPreferences</td></tr>
    <tr><td>GDPR coverage</td><td>Data in transit (Art.32)</td><td>Data at rest (Art.32)</td></tr>
  </table>

  <h2>6. References</h2>
  <ul>
    <li>OWASP Mobile Security Testing Guide (MSTG) 2024</li>
    <li>OWASP Mobile Top 10 — M3: Insecure Communication, M9: Insecure Data Storage</li>
    <li>ISO/IEC 27002:2022 Information Security Controls (8.24, 8.26, 8.10)</li>
    <li>GDPR Regulation (EU) 2016/679 — Article 32</li>
    <li>Android Developer Docs: Network Security Configuration</li>
    <li>Android Developer Docs: EncryptedSharedPreferences</li>
    <li>Android Keystore System Documentation</li>
  </ul>
</body>
</html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    log_success(f"Báo cáo đã được lưu: {output_path}")


def main():
    print_banner("SECURITY AUDIT REPORT — Project 4")
    output = "reports/final_report.html"
    log_info(f"Đang sinh báo cáo → {output}")
    generate_html_report(output)
    log_success("Xong! Mở file HTML trong trình duyệt để xem báo cáo.")


if __name__ == "__main__":
    main()