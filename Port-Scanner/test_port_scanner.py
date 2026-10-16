import json
import pytest
import port_scanner


def test_parse_ports_ranges_and_lists():
    assert port_scanner.parse_ports("20-22,80,443-444") == [20, 21, 22, 80, 443, 444]


def test_parse_ports_sorts_and_removes_duplicates():
    assert port_scanner.parse_ports("80,22,80,21-22") == [21, 22, 80]


@pytest.mark.parametrize("spec", ["0", "65536", "80-65536"])
def test_parse_ports_rejects_invalid_ports(spec):
    with pytest.raises(ValueError):
        port_scanner.parse_ports(spec)


def test_parse_ports_rejects_non_numeric_values():
    with pytest.raises(ValueError):
        port_scanner.parse_ports("abc")


def test_detect_service_tcp_and_udp():
    assert port_scanner.detect_service(80, "tcp") == "http"
    assert port_scanner.detect_service(53, "udp") == "domain"


def test_build_report_is_valid_json():
    report = json.loads(port_scanner.build_report([
        (22, "ssh", "TCP"),
        (80, "http", "TCP"),
    ]))
    assert report == [
        {"port": 22, "service": "ssh", "protocol": "TCP"},
        {"port": 80, "service": "http", "protocol": "TCP"},
    ]


def test_build_report_empty_list():
    assert json.loads(port_scanner.build_report([])) == []
