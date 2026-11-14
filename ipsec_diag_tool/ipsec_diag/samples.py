# -*- coding: utf-8 -*-
"""7 组自洽的典型故障样例：每组含两端配置（混合 swanctl.conf / ipsec.conf）和两端 charon 日志。

所有内容均为虚构的文档网段（RFC5737 / RFC2544 地址），不涉及真实设备。
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta

SCENARIOS: dict[str, str] = {
    "s1-ike-proposal-mismatch": "IKE 提议无交集：SA_INIT 即被 NO_PROPOSAL_CHOSEN 拒绝",
    "s2-esp-pfs-mismatch": "IKE 建链成功，ESP 提议/PFS 组不匹配，CHILD_SA 起不来",
    "s3-psk-mismatch": "预共享密钥不一致：IKE_AUTH 阶段 AUTHENTICATION_FAILED",
    "s4-subnet-mismatch": "流量选择器子网不匹配：TS_UNACCEPTABLE",
    "s5-id-mismatch": "对端 ID 与期望不符：ID 校验失败导致认证被拒",
    "s6-dpd-nat-timeout": "NAT 映射老化 + DPD 误判：重传耗尽后对端被宣告死亡",
    "s7-rekey-collision": "两端同时发起 rekey 碰撞 + 生存期差异过大（含时钟偏移）",
}

# 统一的虚构拓扑
HQ_WAN, BR_WAN = "203.0.113.10", "198.51.100.23"
HQ_LAN, BR_LAN = "10.10.0.0/16", "192.168.50.0/24"
HQ_ID, BR_ID = "fqdn:hq-vpn.example.com", "fqdn:branch-01.example.com"


def ts(base: datetime, off_ms: int) -> str:
    return (base + timedelta(milliseconds=off_ms)).strftime("%Y-%m-%d %H:%M:%S.") + \
        f"{(base + timedelta(milliseconds=off_ms)).microsecond // 1000:03d}"


def line(base: datetime, off_ms: int, thread: int, sub: str, side: str, msg: str) -> str:
    return f"{ts(base, off_ms)} {thread}[{sub}] {msg}"


# ===================================================================
# S1：IKE 提议不匹配
# ===================================================================
def s1() -> dict:
    local_conf = f"""# 本端 HQ：swanctl.conf —— 只支持 aes128
connections {{
    hq-branch {{
        version = 2
        local_addrs  = {HQ_WAN}
        remote_addrs = {BR_WAN}
        proposals = aes128-sha256-modp2048
        dpd {{ delay = 30s; timeout = 150s }}
        local {{
            id = {HQ_ID}
            auth = psk
        }}
        remote {{
            id = {BR_ID}
            auth = psk
        }}
        children {{
            net {{
                local_ts  = {HQ_LAN}
                remote_ts = {BR_LAN}
                esp_proposals = aes256-sha256
                lifetime = 1h
            }}
        }}
    }}
}}
"""
    remote_conf = f"""# 对端分支：ipsec.conf（老式语法）—— 强制 aes256
conn hq-branch
    keyexchange=ikev2
    left={BR_WAN}
    leftid={BR_ID}
    leftsubnet={BR_LAN}
    right={HQ_WAN}
    rightid={HQ_ID}
    rightsubnet={HQ_LAN}
    authby=secret
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256!
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=150s
    auto=start
"""
    b = datetime(2026, 11, 8, 10, 23, 14)
    local_log = "\n".join([
        line(b, 0, 12, "IKE", "local", f"initiating IKE_SA hq-branch[4] to {BR_WAN}"),
        line(b, 120, 12, "IKE", "local", "sending IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) V V ]"),
        line(b, 940, 12, "IKE", "local", f"received IKE_SA_INIT response 0 [ N(NO_PROPOSAL_CHOSEN) ] from {BR_WAN}"),
        line(b, 955, 12, "IKE", "local", "received NO_PROPOSAL_CHOSEN notify, no IKE_SA established"),
        line(b, 4120, 11, "IKE", "local", "initiating IKE_SA hq-branch[5] to 198.51.100.23"),
        line(b, 4240, 11, "IKE", "local", "sending IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) V V ]"),
        line(b, 5060, 11, "IKE", "local", "received IKE_SA_INIT response 0 [ N(NO_PROPOSAL_CHOSEN) ] from 198.51.100.23"),
        line(b, 5080, 11, "IKE", "local", "giving up after 2 retries due to notify NO_PROPOSAL_CHOSEN"),
    ])
    remote_log = "\n".join([
        line(b, 40, 7, "IKE", "remote", f"received IKE_SA_INIT request 0 [ SA KE No V V N(NATD_S_IP) N(NATD_D_IP) ] from {HQ_WAN}"),
        line(b, 55, 7, "CFG", "remote", "looking for an IKE config found hq-branch, matching"),
        line(b, 70, 7, "IKE", "remote", "received proposals: ESP:AES_CBC_128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048"),
        line(b, 85, 7, "IKE", "remote", "remote is enforcing aes256-sha256-modp2048, no acceptable proposal found"),
        line(b, 900, 7, "IKE", "remote", "sending IKE_SA_INIT response 0 [ N(NO_PROPOSAL_CHOSEN) ]"),
        line(b, 4160, 7, "IKE", "remote", f"received IKE_SA_INIT request 0 [ SA KE No V V ] from {HQ_WAN}"),
        line(b, 5020, 7, "IKE", "remote", "sending IKE_SA_INIT response 0 [ N(NO_PROPOSAL_CHOSEN) ]"),
    ])
    return {"local": {"swanctl.conf": local_conf, "charon.log": local_log},
            "remote": {"ipsec.conf": remote_conf, "charon.log": remote_log}}


# ===================================================================
# S2：ESP/PFS 不匹配（IKE 成功，CHILD 失败）
# ===================================================================
def s2() -> dict:
    local_conf = f"""connections {{
    hq-branch {{
        version = 2
        local_addrs  = {HQ_WAN}
        remote_addrs = {BR_WAN}
        proposals = aes256-sha256-ecp256
        dpd {{ delay = 30s; timeout = 150s }}
        local  {{ id = {HQ_ID}; auth = psk }}
        remote {{ id = {BR_ID}; auth = psk }}
        children {{
            net {{
                local_ts  = {HQ_LAN}
                remote_ts = {BR_LAN}
                esp_proposals = aes256-sha256-modp2048
                rekey_time = 9m
                lifetime = 1h
            }}
        }}
    }}
}}
"""
    remote_conf = f"""conn hq-branch
    keyexchange=ikev2
    left={BR_WAN}
    leftid={BR_ID}
    leftsubnet={BR_LAN}
    right={HQ_WAN}
    rightid={HQ_ID}
    rightsubnet={HQ_LAN}
    authby=secret
    ike=aes256-sha256-ecp256!
    esp=aes256-sha256!
    pfsgroup=modp2048
    dpddelay=30s
    dpdtimeout=150s
    auto=start
"""
    b = datetime(2026, 11, 8, 11, 2, 30)
    local_log = "\n".join([
        line(b, 0, 14, "IKE", "local", f"initiating IKE_SA hq-branch[8] to {BR_WAN}"),
        line(b, 150, 14, "IKE", "local", "sending IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) V V ]"),
        line(b, 880, 14, "IKE", "local", "received IKE_SA_INIT response 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) V V ]"),
        line(b, 900, 14, "IKE", "local", "selected proposal: IKE:AES_GCM? no -> AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ECP_256"),
        line(b, 960, 14, "IKE", "local", "sending IKE_AUTH request 1 [ IDi AUTH SA TSi TSr N(ESP_TFC_PAD_N) N(NON_FIRST_FRAG) ]"),
        line(b, 1720, 14, "IKE", "local", "received IKE_AUTH response 1 [ IDr AUTH CERTREQ N(AUTH_LFT) ]"),
        line(b, 1740, 14, "IKE", "local", f"authentication of '{BR_ID}' with pre-shared key successful"),
        line(b, 1780, 14, "IKE", "local", "IKE_SA hq-branch[8] established between 203.0.113.10[hq-vpn.example.com]...198.51.100.23[branch-01.example.com]"),
        line(b, 1820, 14, "IKE", "local", "sending CREATE_CHILD_SA request 2 [ N(REKEY_SA) SA No KE TSi TSr ]"),
        line(b, 2600, 14, "IKE", "local", "received CREATE_CHILD_SA response 2 [ N(NO_PROPOSAL_CHOSEN) ]"),
        line(b, 2620, 14, "IKE", "local", "failed to establish CHILD_SA, keeping IKE_SA"),
        line(b, 2640, 14, "IKE", "local", "received NO_PROPOSAL_CHOSEN notify, ESP proposal or PFS group rejected"),
    ])
    remote_log = "\n".join([
        line(b, 60, 5, "IKE", "remote", f"received IKE_SA_INIT request 0 [ SA KE No V V ] from {HQ_WAN}"),
        line(b, 820, 5, "IKE", "remote", "sending IKE_SA_INIT response 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) V V ]"),
        line(b, 980, 5, "IKE", "remote", f"received IKE_AUTH request 1 [ IDi AUTH SA TSi TSr ] from {HQ_WAN}"),
        line(b, 1650, 5, "IKE", "remote", f"authentication of '{HQ_ID}' with pre-shared key successful"),
        line(b, 1690, 5, "IKE", "remote", "sending IKE_AUTH response 1 [ IDr AUTH N(AUTH_LFT) ]"),
        line(b, 1860, 5, "IKE", "remote", "received CREATE_CHILD_SA request 2 [ N(REKEY_SA) SA No KE TSi TSr ]"),
        line(b, 1900, 5, "CFG", "remote", "received ESP proposal AES_CBC_256/HMAC_SHA2_256_128/MODP_2048, local proposal has no PFS KE"),
        line(b, 2550, 5, "IKE", "remote", "no acceptable ESP proposal found, sending CREATE_CHILD_SA response 2 [ N(NO_PROPOSAL_CHOSEN) ]"),
    ])
    return {"local": {"swanctl.conf": local_conf, "charon.log": local_log},
            "remote": {"ipsec.conf": remote_conf, "charon.log": remote_log}}


# ===================================================================
# S3：PSK 不一致
# ===================================================================
def s3() -> dict:
    local_conf = f"""connections {{
    hq-branch {{
        version = 2
        local_addrs  = {HQ_WAN}
        remote_addrs = {BR_WAN}
        proposals = aes256-sha256-ecp256
        dpd {{ delay = 30s; timeout = 150s }}
        local  {{ id = {HQ_ID}; auth = psk }}
        remote {{ id = {BR_ID}; auth = psk }}
        children {{ net {{ local_ts = {HQ_LAN}; remote_ts = {BR_LAN}; esp_proposals = aes256-sha256; lifetime = 1h }} }}
    }}
}}
# 本端 /etc/swanctl/ipsec.secrets: fqdn:hq-vpn.example.com : PSK "HQ-branch-2026-OLD"
"""
    remote_conf = f"""conn hq-branch
    keyexchange=ikev2
    left={BR_WAN}
    leftid={BR_ID}
    leftsubnet={BR_LAN}
    right={HQ_WAN}
    rightid={HQ_ID}
    rightsubnet={HQ_LAN}
    authby=secret
    ike=aes256-sha256-ecp256!
    esp=aes256-sha256!
    auto=start
# 对端 ipsec.secrets: fqdn:branch-01.example.com : PSK "HQ-branch-2026-NEW"
"""
    b = datetime(2026, 11, 8, 14, 40, 5)
    local_log = "\n".join([
        line(b, 0, 9, "IKE", "local", f"initiating IKE_SA hq-branch[11] to {BR_WAN}"),
        line(b, 130, 9, "IKE", "local", "sending IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) V V ]"),
        line(b, 910, 9, "IKE", "local", "received IKE_SA_INIT response 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) V V ]"),
        line(b, 980, 9, "IKE", "local", "sending IKE_AUTH request 1 [ IDi AUTH SA TSi TSr ]"),
        line(b, 1900, 9, "IKE", "local", "received IKE_AUTH response 1 [ N(AUTHENTICATION_FAILED) ]"),
        line(b, 1920, 9, "IKE", "local", "received AUTHENTICATION_FAILED notify error"),
        line(b, 5200, 9, "IKE", "local", "sending retransmit 1 of IKE_AUTH request 1 [ IDi AUTH SA TSi TSr ]"),
        line(b, 8900, 9, "IKE", "local", "sending retransmit 2 of IKE_AUTH request 1"),
        line(b, 16200, 9, "IKE", "local", "giving up after 3 retransmits, IKE_SA hq-branch[11] destroyed"),
    ])
    remote_log = "\n".join([
        line(b, 50, 6, "IKE", "remote", f"received IKE_SA_INIT request 0 [ SA KE No V V ] from {HQ_WAN}"),
        line(b, 870, 6, "IKE", "remote", "sending IKE_SA_INIT response 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) V V ]"),
        line(b, 1010, 6, "IKE", "remote", f"received IKE_AUTH request 1 [ IDi AUTH SA TSi TSr ] from {HQ_WAN}"),
        line(b, 1040, 6, "IKE", "remote", "looking for pre-shared key for peer '%s'" % HQ_ID),
        line(b, 1080, 6, "IKE", "remote", "verifying peer auth data failed"),
        line(b, 1100, 6, "IKE", "remote", "AUTHENTICATION_FAILED: computed MAC does not match (PSK wrong or wrong secret selected)"),
        line(b, 1850, 6, "IKE", "remote", "sending IKE_AUTH response 1 [ N(AUTHENTICATION_FAILED) ]"),
    ])
    return {"local": {"swanctl.conf": local_conf, "charon.log": local_log},
            "remote": {"ipsec.conf": remote_conf, "charon.log": remote_log}}


# ===================================================================
# S4：子网不匹配 TS_UNACCEPTABLE
# ===================================================================
def s4() -> dict:
    local_conf = f"""connections {{
    hq-branch {{
        version = 2
        local_addrs  = {HQ_WAN}
        remote_addrs = {BR_WAN}
        proposals = aes256-sha256-ecp256
        dpd {{ delay = 30s; timeout = 150s }}
        local  {{ id = {HQ_ID}; auth = psk }}
        remote {{ id = {BR_ID}; auth = psk }}
        children {{
            net {{
                local_ts  = 10.10.0.0/16
                remote_ts = 192.168.50.0/24
                esp_proposals = aes256-sha256
                lifetime = 1h
            }}
        }}
    }}
}}
"""
    remote_conf = f"""conn hq-branch
    keyexchange=ikev2
    left={BR_WAN}
    leftid={BR_ID}
    leftsubnet=192.168.51.0/24
    right={HQ_WAN}
    rightid={HQ_ID}
    rightsubnet=10.10.0.0/16
    authby=secret
    ike=aes256-sha256-ecp256!
    esp=aes256-sha256!
    auto=start
"""
    b = datetime(2026, 11, 8, 15, 18, 42)
    local_log = "\n".join([
        line(b, 0, 13, "IKE", "local", f"initiating IKE_SA hq-branch[14] to {BR_WAN}"),
        line(b, 140, 13, "IKE", "local", "sending IKE_SA_INIT request 0 [ SA KE No V V ]"),
        line(b, 900, 13, "IKE", "local", "received IKE_SA_INIT response 0 [ SA KE No V V ]"),
        line(b, 970, 13, "IKE", "local", "sending IKE_AUTH request 1 [ IDi AUTH SA TSi(10.10.0.0/16) TSr(192.168.50.0/24) ]"),
        line(b, 1800, 13, "IKE", "local", "received IKE_AUTH response 1 [ IDr AUTH N(TS_UNACCEPTABLE) ]"),
        line(b, 1820, 13, "IKE", "local", "received TS_UNACCEPTABLE notify, no CHILD_SA built"),
        line(b, 1840, 13, "IKE", "local", "failed to establish CHILD_SA, keeping IKE_SA hq-branch[14]"),
    ])
    remote_log = "\n".join([
        line(b, 45, 8, "IKE", "remote", f"received IKE_SA_INIT request 0 from {HQ_WAN}"),
        line(b, 860, 8, "IKE", "remote", "sending IKE_SA_INIT response 0 [ SA KE No V V ]"),
        line(b, 1000, 8, "IKE", "remote", "received IKE_AUTH request 1 [ IDi AUTH SA TSi TSr ]"),
        line(b, 1030, 8, "IKE", "remote", "traffic selectors in request: TSi 10.10.0.0/16 TSr 192.168.50.0/24"),
        line(b, 1060, 8, "CFG", "remote", "local leftsubnet is 192.168.51.0/24, no matching traffic selector for 192.168.50.0/24"),
        line(b, 1750, 8, "IKE", "remote", "traffic selectors unacceptable, sending IKE_AUTH response 1 [ N(TS_UNACCEPTABLE) ]"),
    ])
    return {"local": {"swanctl.conf": local_conf, "charon.log": local_log},
            "remote": {"ipsec.conf": remote_conf, "charon.log": remote_log}}


# ===================================================================
# S5：ID 不匹配
# ===================================================================
def s5() -> dict:
    local_conf = f"""connections {{
    hq-branch {{
        version = 2
        local_addrs  = {HQ_WAN}
        remote_addrs = {BR_WAN}
        proposals = aes256-sha256-ecp256
        dpd {{ delay = 30s; timeout = 150s }}
        local  {{ id = {HQ_ID}; auth = psk }}
        remote {{ id = fqdn:branch-99.example.com; auth = psk }}
        children {{ net {{ local_ts = {HQ_LAN}; remote_ts = {BR_LAN}; esp_proposals = aes256-sha256; lifetime = 1h }} }}
    }}
}}
"""
    remote_conf = f"""conn hq-branch
    keyexchange=ikev2
    left={BR_WAN}
    leftid={BR_ID}
    leftsubnet={BR_LAN}
    right={HQ_WAN}
    rightid={HQ_ID}
    rightsubnet={HQ_LAN}
    authby=secret
    ike=aes256-sha256-ecp256!
    esp=aes256-sha256!
    auto=start
"""
    b = datetime(2026, 11, 8, 9, 55, 11)
    local_log = "\n".join([
        line(b, 0, 10, "IKE", "local", f"initiating IKE_SA hq-branch[21] to {BR_WAN}"),
        line(b, 150, 10, "IKE", "local", "sending IKE_SA_INIT request 0 [ SA KE No V V ]"),
        line(b, 920, 10, "IKE", "local", "received IKE_SA_INIT response 0 [ SA KE No V V ]"),
        line(b, 990, 10, "IKE", "local", "sending IKE_AUTH request 1 [ IDi(fqdn:hq-vpn.example.com) AUTH SA TSi TSr ]"),
        line(b, 1900, 10, "IKE", "local", "received IKE_AUTH response 1 [ IDr(fqdn:branch-01.example.com) AUTH N(AUTHENTICATION_FAILED) ]"),
        line(b, 1930, 10, "IKE", "local", "IDir 'fqdn:branch-01.example.com' does not match constraint 'fqdn:branch-99.example.com'"),
        line(b, 1950, 10, "IKE", "local", "constraint check failed, peer ID mismatch"),
        line(b, 1970, 10, "IKE", "local", "sending INFORMATIONAL request 2 [ N(AUTHENTICATION_FAILED) ]"),
    ])
    remote_log = "\n".join([
        line(b, 60, 4, "IKE", "remote", f"received IKE_SA_INIT request 0 from {HQ_WAN}"),
        line(b, 880, 4, "IKE", "remote", "sending IKE_SA_INIT response 0 [ SA KE No V V ]"),
        line(b, 1020, 4, "IKE", "remote", "received IKE_AUTH request 1 [ IDi AUTH SA TSi TSr ]"),
        line(b, 1100, 4, "IKE", "remote", f"authentication of '{HQ_ID}' with pre-shared key successful"),
        line(b, 1140, 4, "IKE", "remote", "sending IKE_AUTH response 1 [ IDr(fqdn:branch-01.example.com) AUTH ]"),
        line(b, 2000, 4, "IKE", "remote", "received INFORMATIONAL request 2 [ N(AUTHENTICATION_FAILED) ]"),
        line(b, 2020, 4, "IKE", "remote", "peer rejected our ID, IKE_SA hq-branch[21] destroyed"),
    ])
    return {"local": {"swanctl.conf": local_conf, "charon.log": local_log},
            "remote": {"ipsec.conf": remote_conf, "charon.log": remote_log}}


# ===================================================================
# S6：DPD / NAT 映射老化，对端被宣告死亡（syslog 时间戳格式）
# ===================================================================
def s6() -> dict:
    local_conf = f"""connections {{
    hq-branch {{
        version = 2
        local_addrs  = {HQ_WAN}
        remote_addrs = {BR_WAN}
        proposals = aes256-sha256-ecp256
        dpd {{ delay = 10s; timeout = 30s }}
        local  {{ id = {HQ_ID}; auth = psk }}
        remote {{ id = {BR_ID}; auth = psk }}
        children {{ net {{ local_ts = {HQ_LAN}; remote_ts = {BR_LAN}; esp_proposals = aes256-sha256; lifetime = 1h }} }}
    }}
}}
"""
    remote_conf = f"""conn hq-branch
    keyexchange=ikev2
    left={BR_WAN}
    leftid={BR_ID}
    leftsubnet={BR_LAN}
    right={HQ_WAN}
    rightid={HQ_ID}
    rightsubnet={HQ_LAN}
    authby=secret
    ike=aes256-sha256-ecp256!
    esp=aes256-sha256!
    dpddelay=120s
    dpdtimeout=360s
    dpdaction=clear
    auto=start
"""
    def sl(off: int, thr: int, sub: str, msg: str) -> str:
        d = datetime(2026, 11, 8, 16, 30, 0) + timedelta(seconds=off)
        return f"Nov  8 {d.strftime('%H:%M:%S')} hq-gw charon[{1024}]: {thr}[{sub}] {msg}"

    local_log = "\n".join([
        sl(0, 12, "IKE", "IKE_SA hq-branch[31] established between 203.0.113.10...198.51.100.23"),
        sl(2, 12, "IKE", "CHILD_SA net[32] established with SPIs c91a2b00_i d77e10a2_o and TS 10.10.0.0/16 === 192.168.50.0/24"),
        sl(1800, 12, "IKE", "sending INFORMATIONAL request 9 [ DPD ]"),
        sl(1810, 12, "IKE", "sending retransmit 1 of INFORMATIONAL request 9 [ DPD ]"),
        sl(1820, 12, "IKE", "sending retransmit 2 of INFORMATIONAL request 9 [ DPD ]"),
        sl(1830, 12, "IKE", "timeout after 30s, giving up after 3 retransmits"),
        sl(1831, 12, "IKE", "DPD: peer 198.51.100.23 declared dead"),
        sl(1832, 12, "IKE", "destroying IKE_SA hq-branch[31] and CHILD_SA net[32]"),
        sl(1833, 12, "IKE", "sending DELETE for IKE_SA hq-branch[31]"),
    ])
    remote_log = "\n".join([
        sl(0, 7, "IKE", "IKE_SA hq-branch[31] established between 198.51.100.23...203.0.113.10"),
        # 对端 DPD 间隔 120s，且 NAT 网关映射在 ~1790s 老化，之后收不到也回不了
        sl(1785, 7, "KNL", "remote side idle, NAT gateway mapping likely expired"),
        sl(1800, 7, "NET", "packet from 203.0.113.10 dropped by upstream NAT (no mapping)"),
        sl(1900, 7, "IKE", "dpddelay 120s not yet elapsed locally; no liveness probe sent"),
        sl(1920, 7, "IKE", "received INFORMATIONAL request? nothing received on UDP 4500 for 20 minutes"),
        sl(1930, 7, "IKE", "received DELETE for IKE_SA hq-branch[31], tearing down CHILD_SA net[32]"),
    ])
    return {"local": {"swanctl.conf": local_conf, "charon.log": local_log},
            "remote": {"ipsec.conf": remote_conf, "charon.log": remote_log}}


# ===================================================================
# S7：rekey 碰撞 + 生存期差异（对端时钟比本端快 1.2s）
# ===================================================================
def s7() -> dict:
    local_conf = f"""connections {{
    hq-branch {{
        version = 2
        local_addrs  = {HQ_WAN}
        remote_addrs = {BR_WAN}
        proposals = aes256-sha256-ecp256
        reauth = no
        dpd {{ delay = 30s; timeout = 150s }}
        local  {{ id = {HQ_ID}; auth = psk }}
        remote {{ id = {BR_ID}; auth = psk }}
        children {{
            net {{
                local_ts = {HQ_LAN}; remote_ts = {BR_LAN}
                esp_proposals = aes256-sha256
                lifetime = 1h
                margin_time = 9m
            }}
        }}
    }}
}}
"""
    remote_conf = f"""conn hq-branch
    keyexchange=ikev2
    left={BR_WAN}
    leftid={BR_ID}
    leftsubnet={BR_LAN}
    right={HQ_WAN}
    rightid={HQ_ID}
    rightsubnet={HQ_LAN}
    authby=secret
    ike=aes256-sha256-ecp256!
    esp=aes256-sha256!
    lifetime=15m
    margintime=2m
    reauth=yes
    dpddelay=30s
    dpdtimeout=150s
    auto=start
"""
    b = datetime(2026, 11, 8, 17, 0, 0)
    skew = 1200  # 对端时钟快 1.2s

    def rline(off_ms: int, thr: int, sub: str, msg: str) -> str:
        return line(b, off_ms + skew, thr, sub, "remote", msg)

    local_log = "\n".join([
        line(b, 0, 15, "IKE", "local", "IKE_SA hq-branch[41] established between 203.0.113.10...198.51.100.23"),
        line(b, 120, 15, "IKE", "local", "CHILD_SA net[42] established with SPIs aa112233_i bb445566_o TS 10.10.0.0/16 === 192.168.50.0/24"),
        # 本端 1h-9m=51m 触发 rekey
        line(b, 3_060_000, 15, "IKE", "local", "scheduling rekey of CHILD_SA net[42] (lifetime 1h, margin 9m)"),
        line(b, 3_060_200, 15, "IKE", "local", "sending CREATE_CHILD_SA request 30 [ N(REKEY_SA) SA No KE TSi TSr ]"),
        line(b, 3_060_800, 15, "IKE", "local", "received CREATE_CHILD_SA request 30 [ N(REKEY_SA) SA No KE TSi TSr ] simultaneously"),
        line(b, 3_060_850, 15, "IKE", "local", "detected CHILD_SA rekey collision, handling per RFC 7296"),
        line(b, 3_061_400, 15, "IKE", "local", "received CREATE_CHILD_SA response 30 [ SA No KE TSi TSr ]"),
        line(b, 3_061_500, 15, "IKE", "local", "inbound CHILD_SA net[43] established with SPI cc778899_i"),
        line(b, 3_061_600, 15, "IKE", "local", "closing duplicate CHILD_SA net[42], sending INFORMATIONAL [ D ]"),
        line(b, 3_061_900, 15, "IKE", "local", "CHILD_SA net[43] rekeyed successfully, old SA deleted"),
    ])
    remote_log = "\n".join([
        rline(0, 5, "IKE", "IKE_SA hq-branch[41] established between 198.51.100.23...203.0.113.10"),
        rline(130, 5, "IKE", "CHILD_SA net[42] established with SPIs bb445566_i aa112233_o"),
        # 对端 15m-2m=13m 就触发，与本端窗口撞在一起（此处演示同一时刻双发）
        rline(3_060_300, 5, "IKE", "scheduling rekey of CHILD_SA net[42] (lifetime 15m, margin 2m)"),
        rline(3_060_500, 5, "IKE", "sending CREATE_CHILD_SA request 30 [ N(REKEY_SA) SA No KE TSi TSr ]"),
        rline(3_060_700, 5, "IKE", "received CREATE_CHILD_SA request 30 while own rekey in progress"),
        rline(3_060_760, 5, "IKE", "CHILD_SA rekey collision detected, both sides initiated CREATE_CHILD_SA"),
        rline(3_061_300, 5, "IKE", "sending CREATE_CHILD_SA response 30 [ SA No KE TSi TSr ]"),
        rline(3_061_800, 5, "IKE", "received INFORMATIONAL request 31 [ D ] deleting superseded CHILD_SA net[42]"),
        rline(3_061_850, 5, "IKE", "rekey collision resolved, keeping CHILD_SA net[43]"),
    ])
    return {"local": {"swanctl.conf": local_conf, "charon.log": local_log},
            "remote": {"ipsec.conf": remote_conf, "charon.log": remote_log}}


_BUILDERS = {
    "s1-ike-proposal-mismatch": s1,
    "s2-esp-pfs-mismatch": s2,
    "s3-psk-mismatch": s3,
    "s4-subnet-mismatch": s4,
    "s5-id-mismatch": s5,
    "s6-dpd-nat-timeout": s6,
    "s7-rekey-collision": s7,
}


def generate_samples(root: str) -> dict[str, str]:
    os.makedirs(root, exist_ok=True)
    for sid, builder in _BUILDERS.items():
        bundle = builder()
        for side, files in bundle.items():
            d = os.path.join(root, sid, side)
            os.makedirs(d, exist_ok=True)
            for fname, content in files.items():
                with open(os.path.join(d, fname), "w", encoding="utf-8") as fh:
                    fh.write(content)
    return dict(SCENARIOS)
