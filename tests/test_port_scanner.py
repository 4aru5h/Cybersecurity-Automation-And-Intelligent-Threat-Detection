import socket
import sys
import threading
import time
from pathlib import Path
import pytest

# Ensure module directory is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "01-python-security-automation-ml"))

from port_scanner import (
    parse_port_specification,
    sanitize_banner,
    scan_single_port,
    scan_target,
    format_scan_table,
)


def test_parse_port_specification_single():
    assert parse_port_specification("80") == [80]
    assert parse_port_specification("443") == [443]


def test_parse_port_specification_range():
    assert parse_port_specification("20-25") == [20, 21, 22, 23, 24, 25]


def test_parse_port_specification_comma_list():
    assert parse_port_specification("80, 443, 8080") == [80, 443, 8080]


def test_parse_port_specification_mixed():
    assert parse_port_specification("22, 80-82, 443") == [22, 80, 81, 82, 443]


def test_parse_port_specification_deduplication():
    assert parse_port_specification("80, 80, 80-82") == [80, 81, 82]


def test_parse_port_specification_invalid():
    with pytest.raises(ValueError):
        parse_port_specification("")

    with pytest.raises(ValueError):
        parse_port_specification("100-50")  # Inverted range

    with pytest.raises(ValueError):
        parse_port_specification("0")  # Out of bounds

    with pytest.raises(ValueError):
        parse_port_specification("70000")  # Out of bounds

    with pytest.raises(ValueError):
        parse_port_specification("abc")


def test_sanitize_banner():
    assert sanitize_banner("SSH-2.0-OpenSSH_8.9\r\n") == "SSH-2.0-OpenSSH_8.9"
    assert sanitize_banner("\x00\x01Binary\x02") == "Binary"
    assert sanitize_banner("") == "No banner retrieved"


def test_scan_single_port_against_local_listener():
    # Start a dummy TCP server on an ephemeral port
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_port = server_sock.getsockname()[1]
    server_sock.listen(1)

    def handle_client():
        try:
            conn, _ = server_sock.accept()
            conn.sendall(b"TestBanner 1.0\r\n")
            conn.close()
        except OSError:
            pass

    server_thread = threading.Thread(target=handle_client, daemon=True)
    server_thread.start()

    time.sleep(0.05)
    res = scan_single_port("127.0.0.1", server_port, timeout=1.0)
    server_sock.close()

    assert res is not None
    port, state, banner = res
    assert port == server_port
    assert state == "OPEN"
    assert "TestBanner" in banner


def test_scan_single_port_closed():
    # Attempt connecting to an unlikely port on loopback
    res = scan_single_port("127.0.0.1", 59999, timeout=0.2)
    assert res is None


def test_scan_target_invalid_host():
    with pytest.raises(ValueError, match="Unable to resolve host"):
        scan_target("nonexistent.invalid.local.hostname.test", [80], timeout=0.1)


def test_format_scan_table():
    output = format_scan_table("127.0.0.1", "127.0.0.1", [(80, "OPEN", "Apache/2.4")])
    assert "127.0.0.1" in output
    assert "80" in output
    assert "Apache/2.4" in output
