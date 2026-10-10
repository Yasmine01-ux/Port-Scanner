import json

import port_scanner


def test_parse_ports_ranges_and_lists():
    ports = port_scanner.parse_ports("20-22,80,443-444")
    assert ports == [20, 21, 22, 80, 443, 444]


def test_detect_service_tcp_and_udp():
    assert port_scanner.detect_service(80, "tcp") == "http"
    assert port_scanner.detect_service(53, "udp") == "domain"


def test_build_report_json():
    report = port_scanner.build_report([
        (22, "ssh", "TCP"),
        (80, "http", "TCP")
    ])
    assert json.loads(report)[0]["port"] == 22
    assert json.loads(report)[1]["service"] == "http"
