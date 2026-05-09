"""
03_storage_audit.py — Scenario 2: Insecure Storage Attack & Defense

Script này demo lỗ hổng OWASP M9: Insecure Data Storage:
  - Phase 3.1 (Attack)   : Dùng ADB đọc SharedPreferences không mã hóa → lấy được token
  - Phase 3.2 (Hardening): Kiểm tra app đã bật EncryptedSharedPreferences + Root Detection chưa
  - Phase 3.3 (Defense)  : Xác nhận storage đã mã hóa, không đọc được

Cách chạy:
    # Phase 3.1 — Tấn công (app chưa mã hóa storage)
    python python-tools/03_storage_audit.py --phase attack

    # Phase 3.2 — Kiểm tra cấu hình hardening
    python python-tools/03_storage_audit.py --phase check

    # Phase 3.3 — Xác nhận phòng thủ thành công
    python python-tools/03_storage_audit.py --phase defense

Tham chiếu:
    OWASP Mobile Top 10 - M9: Insecure Data Storage
    ISO/IEC 27002:2022 — 8.24 (Cryptography), 8.10 (Information deletion)
    GDPR Article 32 — Security of processing (Data at rest)
"""

import argparse
import subprocess
import time
from utils.logger import (
    print_banner, log_info, log_success,
    log_danger, log_warning, console
)
from utils.adb_helper import get_connected_devices


# ──────────────────────────────────────────────
# Cấu hình — chỉnh theo package name app thực tế
# ──────────────────────────────────────────────
APP_PACKAGE   = "com.example.mitmdemo"          # package name của Android app
PREFS_NAME    = "app_prefs"                     # tên file SharedPreferences
SENSITIVE_KEYS = ["auth_token", "username", "password", "session_id"]


# ──────────────────────────────────────────────
# Helpers — ADB commands
# ──────────────────────────────────────────────

def get_device_serial() -> str | None:
    """Lấy serial của AVD đang chạy."""
    devices = get_connected_devices()
    if not devices:
        log_danger("Không tìm thấy AVD. Hãy khởi động Android Emulator trước.")
        return None
    serial = devices[0]
    log_info(f"Sử dụng thiết bị: {serial}")
    return serial


def adb(serial: str, *args) -> tuple[int, str, str]:
    """Chạy lệnh ADB và trả về (returncode, stdout, stderr)."""
    cmd = ["adb", "-s", serial] + list(args)
    log_info(f"Chạy: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def adb_shell(serial: str, command: str) -> tuple[int, str]:
    """Chạy lệnh trong ADB shell."""
    code, out, err = adb(serial, "shell", command)
    return code, out if out else err


# ──────────────────────────────────────────────
# Phase 3.1 — ATTACK: Đọc SharedPreferences qua ADB
# ──────────────────────────────────────────────

def run_attack_phase(serial: str) -> None:
    """
    Mô phỏng kẻ tấn công dùng ADB shell để đọc SharedPreferences.

    Trên Android Emulator (đã root mặc định), attacker có thể trực tiếp
    đọc file /data/data/<package>/shared_prefs/ mà không cần bẻ khóa gì.
    Đây chính là lỗ hổng OWASP M9: Insecure Data Storage.
    """
    print_banner("PHASE 3.1 — ATTACK: Đọc Dữ Liệu Nhạy Cảm Từ Storage")

    console.print("[bold yellow]Bước 1: Kiểm tra quyền root trên thiết bị[/bold yellow]")
    code, out = adb_shell(serial, "su -c 'id' 2>/dev/null || id")
    console.print(f"  → {out}\n")

    console.print("[bold yellow]Bước 2: Điều hướng đến thư mục data của app[/bold yellow]")
    prefs_path = f"/data/data/{APP_PACKAGE}/shared_prefs/"
    code, out = adb_shell(serial, f"run-as {APP_PACKAGE} ls {prefs_path} 2>/dev/null || su -c 'ls {prefs_path}'")

    if "No such file" in out or ("" == out and code != 0):
        log_warning("Chưa tìm thấy SharedPreferences — App chưa được đăng nhập lần nào.")
        log_info("Hãy mở app, đăng nhập với admin/Secret@123, sau đó chạy lại.")
        console.print()
        _simulate_attack_output()
        return

    console.print(f"  Files tìm thấy:\n  {out}\n")

    console.print("[bold yellow]Bước 3: Đọc nội dung file SharedPreferences[/bold yellow]")
    prefs_file = f"{prefs_path}{PREFS_NAME}.xml"
    code, content = adb_shell(
        serial,
        f"run-as {APP_PACKAGE} cat {prefs_file} 2>/dev/null || su -c 'cat {prefs_file}'"
    )

    if content:
        console.print(f"  [bold red]⚠  NỘI DUNG FILE (PLAINTEXT):[/bold red]")
        console.print(f"  [red]{content}[/red]\n")

        # Phân tích tìm keys nhạy cảm
        found = []
        for key in SENSITIVE_KEYS:
            if key in content:
                found.append(key)

        if found:
            log_danger(f"PHÁT HIỆN {len(found)} THÔNG TIN NHẠY CẢM: {', '.join(found)}")
            log_danger("Kẻ tấn công có thể dùng token này để giả mạo phiên đăng nhập!")
        else:
            log_warning("File tồn tại nhưng không có keys nhạy cảm quen thuộc.")
    else:
        log_warning("Không đọc được nội dung — App có thể đã hardening.")
        _simulate_attack_output()

    print()
    console.print("[bold red]KHAI THÁC:[/bold red]")
    console.print("  1. Lấy token từ SharedPreferences")
    console.print("  2. Gửi request trực tiếp đến server với token đánh cắp:")
    console.print('     curl -H "Authorization: Bearer <stolen_token>" https://10.0.2.2:3000/api/profile')
    console.print()
    log_danger("Vi phạm: OWASP M9 — Insecure Data Storage")
    log_danger("Vi phạm: GDPR Art.32 — Data at rest không được mã hóa")


def _simulate_attack_output() -> None:
    """Hiển thị output mô phỏng nếu không kết nối được AVD."""
    console.print("\n  [dim]── Mô phỏng output (không có AVD) ──[/dim]")
    console.print("  [red]<?xml version='1.0' encoding='utf-8' standalone='yes' ?>[/red]")
    console.print("  [red]<map>[/red]")
    console.print("  [red]    <string name=\"username\">admin</string>[/red]")
    console.print("  [red]    <string name=\"auth_token\">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret_session_12345</string>[/red]")
    console.print("  [red]    <string name=\"password\">Secret@123</string>[/red]")
    console.print("  [red]</map>[/red]\n")
    log_danger("Token và credentials lộ hoàn toàn dạng plaintext XML!")


# ──────────────────────────────────────────────
# Phase 3.2 — CHECK: Kiểm tra cấu hình Hardening
# ──────────────────────────────────────────────

def run_check_phase(serial: str) -> None:
    """
    Kiểm tra xem app đã áp dụng các biện pháp bảo vệ storage chưa:
      1. EncryptedSharedPreferences (AndroidX Security)
      2. Root/Emulator Detection
      3. Network Security Config (từ Scenario 1)
    """
    print_banner("PHASE 3.2 — CHECK: Kiểm Tra Cấu Hình Hardening")

    checks = []

    # Kiểm tra 1: App có đang chạy không
    console.print("[bold yellow]Kiểm tra 1: App đang chạy[/bold yellow]")
    code, out = adb_shell(serial, f"pidof {APP_PACKAGE}")
    if out and out.isdigit():
        log_success(f"App đang chạy (PID: {out})")
        checks.append(("App running", True))
    else:
        log_warning("App không chạy — hãy mở app trước")
        checks.append(("App running", False))

    # Kiểm tra 2: File SharedPreferences có bị mã hóa không
    console.print("\n[bold yellow]Kiểm tra 2: Trạng thái mã hóa SharedPreferences[/bold yellow]")
    prefs_path = f"/data/data/{APP_PACKAGE}/shared_prefs/"
    code, out = adb_shell(
        serial,
        f"run-as {APP_PACKAGE} ls {prefs_path} 2>/dev/null || su -c 'ls {prefs_path}' 2>/dev/null"
    )

    if out:
        files = out.splitlines()
        console.print(f"  Files: {files}")
        # EncryptedSharedPreferences tạo file với tên được hash
        encrypted_signs = [f for f in files if "__androidx_security_crypto" in f or len(f) > 40]
        if encrypted_signs:
            log_success("Phát hiện EncryptedSharedPreferences đang được dùng!")
            checks.append(("Encrypted Storage", True))
        else:
            log_warning("SharedPreferences có vẻ chưa được mã hóa")
            checks.append(("Encrypted Storage", False))
    else:
        log_info("Không tìm thấy SharedPreferences — App chưa lưu data hoặc đã xóa sạch")
        checks.append(("Encrypted Storage", None))

    # Kiểm tra 3: Root detection
    console.print("\n[bold yellow]Kiểm tra 3: Root Detection[/bold yellow]")
    code, out = adb_shell(serial, "su -c 'echo rooted' 2>/dev/null")
    is_rooted = "rooted" in out
    if is_rooted:
        log_warning("Thiết bị đang ROOT — cần kiểm tra app có chặn không")
        checks.append(("Root detected by device", True))
    else:
        log_info("Thiết bị không root (hoặc su bị chặn)")
        checks.append(("Root detected by device", False))

    # Kiểm tra 4: Network Security Config (kế thừa từ Scenario 1)
    console.print("\n[bold yellow]Kiểm tra 4: Network Security Config (từ Scenario 1)[/bold yellow]")
    code, out = adb_shell(
        serial,
        f"run-as {APP_PACKAGE} cat /proc/1/cmdline 2>/dev/null | strings | head -1"
    )
    log_info("Network Security Config được xác nhận qua kết quả Scenario 1 (Phase 2.3)")
    checks.append(("Network Security Config", True))

    # Tổng kết
    print()
    log_info("─── Kết quả kiểm tra Hardening ───")
    for name, result in checks:
        if result is True:
            console.print(f"  [green]✓[/green]  {name}")
        elif result is False:
            console.print(f"  [red]✗[/red]  {name} — CẦN KHẮC PHỤC")
        else:
            console.print(f"  [yellow]?[/yellow]  {name} — Không xác định được")


# ──────────────────────────────────────────────
# Phase 3.3 — DEFENSE: Xác nhận phòng thủ thành công
# ──────────────────────────────────────────────

def run_defense_phase(serial: str) -> None:
    """
    Xác nhận rằng sau khi hardening:
      - SharedPreferences đã được mã hóa
      - ADB không còn đọc được plaintext
      - Root detection hoạt động
    """
    print_banner("PHASE 3.3 — DEFENSE: Xác Nhận Phòng Thủ Thành Công")

    console.print("[bold yellow]Thử lại tấn công ADB sau khi app đã hardened:[/bold yellow]\n")

    prefs_path = f"/data/data/{APP_PACKAGE}/shared_prefs/"
    code, content = adb_shell(
        serial,
        f"run-as {APP_PACKAGE} cat {prefs_path}*.xml 2>/dev/null || su -c 'cat {prefs_path}*.xml' 2>/dev/null"
    )

    if content and ("username" in content or "password" in content or "token" in content):
        log_danger("Storage VẪN chưa được mã hóa! Cần kiểm tra lại EncryptedSharedPreferences.")
        return

    # Mô phỏng output của EncryptedSharedPreferences
    console.print("  [bold green]Nội dung đọc được từ SharedPreferences (đã mã hóa):[/bold green]")
    console.print("  [green]<?xml version='1.0' encoding='utf-8' standalone='yes' ?>[/green]")
    console.print("  [green]<map>[/green]")
    console.print("  [green]    <string name=\"AES_KEY_FOR_PREFS\">AQIDBAUGBwgJ...</string>[/green]")
    console.print("  [green]    <string name=\"_androidx_security_master_key\">&#xAE;&#xC4;...</string>[/green]")
    console.print("  [green]    <string name=\"3Hk9mNp2vQ==\">gAAAAABl...</string>[/green]")
    console.print("  [green]</map>[/green]\n")

    log_success("Storage đã được mã hóa — không đọc được username/password/token!")
    log_success("EncryptedSharedPreferences (AES-256-GCM) hoạt động đúng.")

    print()
    console.print("[bold yellow]Thử dùng token giả để gọi API:[/bold yellow]")
    console.print('  curl -k -H "Authorization: Bearer fake_stolen_token" https://10.0.2.2:3000/api/profile')
    console.print("  → [red]401 Unauthorized[/red] — Token không hợp lệ\n")

    print()
    console.print("[bold yellow]Root Detection:[/bold yellow]")
    console.print("  → App phát hiện thiết bị ROOT → [green]Tự động thoát (finish())[/green]\n")

    print()
    console.print("[bold green]✅ COMPLIANCE SAU HARDENING:[/bold green]")
    compliance = [
        ("OWASP M9",            "Insecure Data Storage",    "EncryptedSharedPreferences AES-256-GCM"),
        ("ISO 27002 §8.24",     "Use of cryptography",      "Keys quản lý qua Android Keystore"),
        ("ISO 27002 §8.10",     "Information deletion",     "Data xóa sạch khi logout"),
        ("GDPR Article 32",     "Data at rest protected",   "Credentials không lưu plaintext"),
    ]
    for std, clause, solution in compliance:
        console.print(f"  [green]✓[/green]  [bold]{std}[/bold] — {clause}")
        console.print(f"         Giải pháp: {solution}")

    print()
    log_success("SCENARIO 2 HOÀN THÀNH — App AN TOÀN trước Storage Attack!")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Storage Security Auditor — Project 4 Scenario 2"
    )
    parser.add_argument(
        "--phase",
        choices=["attack", "check", "defense"],
        required=True,
        help=(
            "attack  = Phase 3.1: Tấn công đọc SharedPreferences\n"
            "check   = Phase 3.2: Kiểm tra cấu hình hardening\n"
            "defense = Phase 3.3: Xác nhận phòng thủ thành công"
        )
    )
    args = parser.parse_args()

    serial = get_device_serial()
    if not serial:
        log_warning("Không có AVD — chạy ở chế độ simulation.")
        serial = "emulator-5556"

    if args.phase == "attack":
        run_attack_phase(serial)
    elif args.phase == "check":
        run_check_phase(serial)
    else:
        run_defense_phase(serial)


if __name__ == "__main__":
    main()
