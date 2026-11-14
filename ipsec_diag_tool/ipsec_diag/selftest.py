# -*- coding: utf-8 -*-
"""轻量自检：不依赖 pytest，直接 python -m ipsec_diag --selftest 运行。"""
from __future__ import annotations

from .config_parser import (detect_format, normalize_id, normalize_network,
                            parse_duration, parse_suite, parse_swanctl,
                            parse_ipsec_conf, parse_proposals)
from .log_parser import classify, estimate_skew, parse_log, LINE_RE
from .static_check import _suite_intersection, _nets_overlap, _ids_compatible
from .samples import generate_samples
import tempfile
import os

FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILS.append(name)


def run_selftest() -> int:
    # ---- 时长解析
    check("duration 3h", parse_duration("3h") == 10800)
    check("duration 45m", parse_duration("45m") == 2700)
    check("duration bare", parse_duration("3600") == 3600)
    check("duration 1d12h", parse_duration("1d12h") == 129600)

    # ---- 子网/ID 规范化
    check("net host -> /32", normalize_network("10.0.0.1") == "10.0.0.1/32")
    check("net cidr", normalize_network("10.0.0.0/24") == "10.0.0.0/24")
    check("id fqdn", normalize_id("hq.example.com") == "fqdn:hq.example.com")
    check("id typed", normalize_id("ipv4:1.2.3.4") == "ipv4:1.2.3.4")
    check("id ip fallback", normalize_id("1.2.3.4") == "ipv4:1.2.3.4")

    # ---- 提议解析与别名归一
    a = parse_suite("aes256-sha256-modp2048", "ike")
    check("suite encr", a.encr == "aes_cbc_256")
    check("suite prf", a.prf == "prf_sha256")
    check("suite dh", a.dh == "dh14")
    b = parse_suite("AES_256/SHA2_256/MODP_2048".replace("/", "-"), "ike")
    check("suite alias equal", (b.encr, b.prf, b.dh) == (a.encr, a.prf, a.dh))
    gcm = parse_suite("aes128gcm16-prfsha256-ecp256", "ike")
    check("aead integ", gcm.encr == "aes_gcm_128" and "内置" in (gcm.integ or ""))

    # ---- 提议交集
    p1 = parse_proposals("aes256-sha256-modp2048, aes128-sha256-modp2048", "ike")
    p2 = parse_proposals("aes128-sha256-modp2048", "ike")
    hits, _ = _suite_intersection(p1, p2, "ike")
    check("proposal intersection hits", len(hits) == 1)
    p3 = parse_proposals("aes192-sha384-ecp384", "ike")
    hits2, reasons = _suite_intersection(p1, p3, "ike")
    check("proposal intersection empty", not hits2 and bool(reasons))

    # ---- swanctl 花括号解析（含注释/引号/等号）
    swan = '''
    # outer comment
    connections {
        c1 {
            version = 2
            local_addrs = 1.2.3.4
            dpd { delay = 30s; timeout = 150s }
            local { id = "fqdn:a.example.com"; auth = psk }
            children { net { local_ts = 10.0.0.0/8; esp_proposals = aes256-sha256 } }
        }
    }'''
    check("format detect swanctl", detect_format(swan) == "swanctl")
    root = parse_swanctl(swan)
    c1 = root["connections"]["c1"]
    check("swan nested dpd", c1["dpd"]["delay"] == "30s")
    check("swan quoted id", c1["local"]["id"] == "fqdn:a.example.com")
    check("swan children", c1["children"]["net"]["local_ts"] == "10.0.0.0/8")

    # ---- ipsec.conf 解析
    legacy = """config setup
conn hq
    keyexchange=ikev2
    left=1.2.3.4
    leftsubnet=10.0.0.0/24
    authby=secret
    ike=aes256-sha256-modp2048!
"""
    check("format detect legacy", detect_format(legacy) == "ipsec.conf")
    secs = parse_ipsec_conf(legacy)
    check("legacy conn parsed", secs["conn hq"]["authby"] == "secret")
    check("legacy strict marker", parse_suite(secs["conn hq"]["ike"].rstrip("!"), "ike").encr == "aes_cbc_256")

    # ---- 子网重叠 / ID 比较
    check("nets overlap", _nets_overlap(["10.0.0.0/16"], ["10.0.1.0/24"])[0])
    check("nets disjoint", not _nets_overlap(["10.0.0.0/24"], ["192.168.0.0/24"])[0])
    st, _ = _ids_compatible("fqdn:a.com", "fqdn:b.com")
    check("id mismatch status", st == "mismatch")
    st2, _ = _ids_compatible("fqdn:a.com", "fqdn:a.com")
    check("id match status", st2 == "ok")

    # ---- 日志行格式（syslog + ISO + 毫秒）
    line1 = "Nov  8 10:23:14 hq charon[1024]: 12[IKE] sending IKE_SA_INIT request 0 [ SA KE No ]"
    line2 = "2026-11-08T10:23:14.123 7[NET] received packet from 1.2.3.4"
    m1, m2 = LINE_RE.match(line1), LINE_RE.match(line2)
    check("log syslog line", bool(m1) and m1.group("thread") == "12")
    check("log iso line", bool(m2) and m2.group("sub") == "NET")
    et, d = classify("sending IKE_SA_INIT request 0 [ SA KE No ]")
    check("classify ike_init", et == "ike_init" and d == "out")
    et2, _ = classify("received N(NO_PROPOSAL_CHOSEN) notify")
    check("classify no_proposal", et2 == "no_proposal")
    et3, _ = classify("detected CHILD_SA rekey collision")
    check("classify collision", et3 == "collision")

    # ---- 端到端：生成样例并解析，检查关键结论存在
    with tempfile.TemporaryDirectory() as td:
        generate_samples(td)
        s1_log = os.path.join(td, "s1-ike-proposal-mismatch", "local", "charon.log")
        evs = parse_log(s1_log, "local", 2026)
        check("sample s1 events", len(evs) >= 6)
        check("sample s1 no_proposal seen", any(e.etype == "no_proposal" for e in evs))
        s7_local = parse_log(os.path.join(td, "s7-rekey-collision", "local", "charon.log"), "local", 2026)
        s7_remote = parse_log(os.path.join(td, "s7-rekey-collision", "remote", "charon.log"), "remote", 2026)
        skew, pairs = estimate_skew(s7_local + s7_remote)
        check("skew estimated ~1.2s", skew is not None and abs(skew - 1.2) < 0.5,
              f"got {skew} pairs={pairs}")
        check("collision events parsed",
              any(e.etype == "collision" for e in s7_local + s7_remote))
        s6 = parse_log(os.path.join(td, "s6-dpd-nat-timeout", "local", "charon.log"), "local", 2026)
        check("syslog-year parsed", len(s6) >= 5 and any(e.etype == "dpd" for e in s6))

    print()
    if FAILS:
        print(f"自检失败 {len(FAILS)} 项：{FAILS}")
        return 1
    print("全部自检通过")
    return 0
