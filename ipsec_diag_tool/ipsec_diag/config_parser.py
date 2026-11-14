# -*- coding: utf-8 -*-
"""配置解析：同时支持 swanctl.conf（vici 花括号语法）和 ipsec.conf（老式段语法）。

只做文本解析，不 import 任何第三方库，也不执行配置内容。
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Optional

from .model import Connection, SideConfig, Suite


# ===================================================================
# 通用规范化工具
# ===================================================================
def _norm_algo(name: str) -> str:
    """算法名规范化：去大小写/下划线/连字符差异，如 aes256 == AES_256 == aes-256。"""
    return re.sub(r"[_\-\s]", "", name).lower()


def _split_list(value: str) -> list[str]:
    """swanctl 列表字段按逗号切分，兼容空白。"""
    return [v.strip() for v in value.split(",") if v.strip()]


def parse_duration(text: str) -> Optional[int]:
    """把 '3h' / '45m' / '3600s' / '28800' / '1d12h' 统一成秒。解析失败返回 None。"""
    if text is None:
        return None
    t = str(text).strip().lower()
    if t.isdigit():
        return int(t)
    total = 0
    matched = False
    for num, unit in re.findall(r"(\d+)\s*([dhms]?)", t):
        if not num:
            continue
        n = int(num)
        total += n * {"d": 86400, "h": 3600, "m": 60, "s": 1, "": 1}[unit]
        matched = True
    return total if matched else None


def normalize_network(net: str) -> Optional[str]:
    """子网规范化；裸主机地址按 /32（IPv4）或 /128（IPv6）处理。"""
    if not net:
        return None
    net = net.strip().strip('"')
    if net in ("0.0.0.0/0", "::/0"):
        return net
    try:
        if "/" in net:
            return str(ipaddress.ip_network(net, strict=False))
        ip = ipaddress.ip_address(net)
        return f"{ip}/{ip.max_prefixlen}"
    except ValueError:
        # id、FQDN 之类不是网络地址，原样返回
        return net


def normalize_id(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = value.strip().strip('"')
    m = re.match(r"^(fqdn|user-fqdn|keyid|ipv4|ipv6|dn)\s*:\s*(.+)$", v, re.I)
    if m:
        kind, ident = m.group(1).lower(), m.group(2).strip()
        if kind == "ipv4":
            n = normalize_network(ident)
            ident = n.split("/")[0] if n else ident
        return f"{kind}:{ident}"
    # 没写类型前缀：按最常见规则推断
    try:
        ip = ipaddress.ip_address(v)
        return f"ipv{4 if ip.version == 4 else 6}:{ip}"
    except ValueError:
        if "@" in v:
            return f"user-fqdn:{v}"
        if re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", v, re.I):
            return f"fqdn:{v}"
        return f"keyid:{v}"


# ===================================================================
# 算法表（按最常见 strongSwan 部署中的名称归一）
# ===================================================================
ENCR_ALIASES = {
    "aes128": "aes_cbc_128", "aes192": "aes_cbc_192", "aes256": "aes_cbc_256",
    "aes_cbc_128": "aes_cbc_128", "aes_cbc_192": "aes_cbc_192", "aes_cbc_256": "aes_cbc_256",
    "aesctr128": "aes_ctr_128", "aesctr256": "aes_ctr_256",
    "aes_ctr_128": "aes_ctr_128", "aes_ctr_256": "aes_ctr_256",
    "aes_gcm128": "aes_gcm_128", "aes_gcm16": "aes_gcm_128",
    "aes_gcm_128": "aes_gcm_128", "aes128gcm128": "aes_gcm_128", "aes128gcm16": "aes_gcm_128",
    "aes_gcm_256": "aes_gcm_256", "aes256gcm128": "aes_gcm_256", "aes256gcm16": "aes_gcm_256",
    "aes_gcmp_128": "aes_gcmp_128", "aes_gcmp_256": "aes_gcmp_256",
    "chacha20poly1305": "chacha20_poly1305", "chacha20poly1305_16": "chacha20_poly1305",
    "3des": "des_ede3_cbc", "des_ede3_cbc": "des_ede3_cbc",
    "camellia128": "camellia_cbc_128", "camellia256": "camellia_cbc_256",
    "null": "null",
}
PRF_ALIASES = {
    "prfmd5": "prf_md5", "md5": "prf_md5", "hmac_md5": "prf_md5", "prf_hmac_md5": "prf_md5",
    "prfsha1": "prf_sha1", "sha1": "prf_sha1", "hmac_sha1": "prf_sha1", "prf_hmac_sha1": "prf_sha1",
    "prfsha256": "prf_sha256", "sha256": "prf_sha256",
    "sha2_256": "prf_sha256", "hmac_sha2_256": "prf_sha256", "prf_hmac_sha2_256": "prf_sha256",
    "prfsha384": "prf_sha384", "sha384": "prf_sha384",
    "sha2_384": "prf_sha384", "hmac_sha2_384": "prf_sha384",
    "prfsha512": "prf_sha512", "sha512": "prf_sha512",
    "sha2_512": "prf_sha512", "hmac_sha2_512": "prf_sha512",
    "prfaesxcbc": "prf_aes128_xcbc",
}
INTEG_ALIASES = {
    "md5": "auth_hmac_md5_96", "hmac_md5_96": "auth_hmac_md5_96",
    "sha1": "auth_hmac_sha1_96", "hmac_sha1_96": "auth_hmac_sha1_96",
    "sha256": "auth_hmac_sha2_256_128", "sha2_256_128": "auth_hmac_sha2_256_128",
    "sha2_256": "auth_hmac_sha2_256_128", "hmac_sha2_256_128": "auth_hmac_sha2_256_128",
    "sha384": "auth_hmac_sha2_384_192", "sha2_384": "auth_hmac_sha2_384_192",
    "sha512": "auth_hmac_sha2_512_256", "sha2_512": "auth_hmac_sha2_512_256",
    "aesxcbc": "auth_aes_xcbc_96", "aes128gmac": "auth_aes_128_gmac",
    "aes256gmac": "auth_aes_256_gmac",
}
DH_ALIASES = {
    "modp768": "dh1", "dh1": "dh1",
    "modp1024": "dh2", "dh2": "dh2",
    "modp1536": "dh5", "dh5": "dh5",
    "modp2048": "dh14", "dh14": "dh14",
    "modp3072": "dh15", "dh15": "dh15",
    "modp4096": "dh16", "dh16": "dh16",
    "ecp256": "dh19", "dh19": "dh19",
    "ecp384": "dh20", "dh20": "dh20",
    "ecp521": "dh21", "dh21": "dh21",
    "curve25519": "dh31", "dh31": "dh31",
    "none": "none",
}
AEAD_ENCR = {"aes_gcm_128", "aes_gcm_256", "aes_gcmp_128", "aes_gcmp_256",
             "chacha20_poly1305"}


def _norm_table(table: dict[str, str]) -> dict[str, str]:
    """把别名表的 key 全部归一化，保证与 _norm_algo(token) 同口径。"""
    return {_norm_algo(k): v for k, v in table.items()}


ENCR_ALIASES = _norm_table(ENCR_ALIASES)
PRF_ALIASES = _norm_table(PRF_ALIASES)
INTEG_ALIASES = _norm_table(INTEG_ALIASES)
DH_ALIASES = _norm_table(DH_ALIASES)

# 最常见的 strongSwan 出厂默认提议（5.x 常见版本，作为兜底，报告里会标注）
DEFAULT_IKE_RAW = "aes256-sha256-ecp256, aes192-sha256-ecp256, aes256-sha384-ecp384, " \
                  "aes128-sha256-ecp256, aes128-sha256-modp2048, aes256-sha256-modp2048"
DEFAULT_ESP_RAW = "aes256-sha256, aes192-sha256, aes256-sha384, aes128-sha256, " \
                  "aes128-sha256-modp2048, aes256-sha256-modp2048"


def parse_suite(token: str, kind: str) -> Suite:
    """解析单条提议 token，如 aes256-sha256-modp2048 / aes128gcm16-prfsha256-ecp256。"""
    s = Suite(raw=token.strip(), kind=kind)
    if token.strip().lower() == "default":
        s.is_default = True
        return s
    parts = [p.strip() for p in token.split("-") if p.strip()]
    # 老式 ipsec.conf 首段是协议名（esp/ike/ah），丢掉
    if parts and parts[0].lower() in ("esp", "ike", "ah"):
        parts = parts[1:]
    for p in parts:
        key = _norm_algo(p)
        if key in ENCR_ALIASES:
            s.encr = ENCR_ALIASES[key]
        elif key in PRF_ALIASES:
            s.prf = PRF_ALIASES[key]
        elif key in INTEG_ALIASES:
            s.integ = INTEG_ALIASES[key]
        elif key in DH_ALIASES:
            s.dh = DH_ALIASES[key]
        else:
            # 识别不出来的算法保留原名，避免把不认识的新算法当成无
            if s.encr is None:
                s.encr = p.lower()
            elif s.integ is None:
                s.integ = p.lower()
    if s.encr in AEAD_ENCR:
        # AEAD 模式下 PRF 仍需显式存在；integ 由加密算法自带
        if s.integ is None:
            s.integ = "aead(内置)"
    if s.kind == "ike" and s.encr and not s.prf and not s.is_default:
        # IKE 中 PRF 缺失时 strongSwan 通常从完整性算法推导
        if s.integ and s.integ != "aead(内置)":
            guess = {"auth_hmac_md5_96": "prf_md5", "auth_hmac_sha1_96": "prf_sha1",
                     "auth_hmac_sha2_256_128": "prf_sha256",
                     "auth_hmac_sha2_384_192": "prf_sha384",
                     "auth_hmac_sha2_512_256": "prf_sha512"}.get(s.integ)
            if guess:
                s.prf = guess
    return s


def parse_proposals(raw: Optional[str], kind: str) -> list[Suite]:
    if not raw:
        return []
    out = []
    for tok in _split_list(raw):
        if tok:
            # ipsec.conf 的行尾 '!' 是 strict 标记，不是算法名的一部分
            out.append(parse_suite(tok.rstrip("!"), kind))
    return out


def expand_defaults(suites: list[Suite], kind: str) -> list[Suite]:
    """把 default 关键字展开为内置兜底提议（报告中保留 is_default 痕迹由调用方说明）。"""
    out: list[Suite] = []
    default_raw = DEFAULT_IKE_RAW if kind == "ike" else DEFAULT_ESP_RAW
    for s in suites:
        if s.is_default:
            out.extend(parse_proposals(default_raw, kind))
        else:
            out.append(s)
    return out


# ===================================================================
# swanctl.conf 花括号语法
# ===================================================================
def _tokenize(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
        elif c == "#" or (c == "/" and i + 1 < n and text[i + 1] == "/"):
            while i < n and text[i] != "\n":
                i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
        elif c in "{}":
            tokens.append((c, c))
            i += 1
        elif c == '"':
            j = i + 1
            buf = ""
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n:
                    buf += text[j + 1]
                    j += 2
                else:
                    buf += text[j]
                    j += 1
            tokens.append(("word", buf))
            i = j + 1
        else:
            j = i
            buf = ""
            while j < n and text[j] not in " \t\r\n{};\"#":
                if text[j] == "/" and j + 1 < n and text[j + 1] == "/":
                    break
                buf += text[j]
                j += 1
            if buf:
                tokens.append(("word", buf))
            i = j if buf else j + 1
    return tokens


def _parse_section(tokens: list[tuple[str, str]], pos: int) -> tuple[dict[str, Any], int]:
    """递归解析一个 { ... } 段，进入时 pos 指向 '{' 之后。"""
    node: dict[str, Any] = {}
    while pos < len(tokens):
        kind, val = tokens[pos]
        if kind == "}":
            return node, pos + 1
        if kind == "word" and val == ";":
            pos += 1
            continue
        if kind == "word":
            if pos + 1 < len(tokens) and tokens[pos + 1][0] == "{":
                sub, pos = _parse_section(tokens, pos + 2)
                if val in node:
                    if not isinstance(node[val], list):
                        node[val] = [node[val]]
                    node[val].append(sub)
                else:
                    node[val] = sub
            else:
                node[val] = ""
                # 同一行 key = value（swanctl 等号可省略，统一支持）
                if pos + 1 < len(tokens) and tokens[pos + 1] == ("word", "="):
                    if pos + 2 < len(tokens) and tokens[pos + 2][0] == "word":
                        node[val] = tokens[pos + 2][1]
                        pos += 3
                    else:
                        pos += 2
                else:
                    pos += 1
                continue
            continue
        pos += 1
    return node, pos


def parse_swanctl(text: str) -> dict[str, Any]:
    tokens = _tokenize(text)
    root, _ = _parse_section(tokens, 0)
    return root


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _first_addr(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        out = []
        for v in value:
            out.extend(_first_addr(v))
        return out
    return [str(value).strip()]


# ===================================================================
# ipsec.conf 老式语法
# ===================================================================
def parse_ipsec_conf(text: str) -> dict[str, dict[str, str]]:
    """返回 {'conn/setup名': {key: value}}，值均为字符串。"""
    sections: dict[str, dict[str, str]] = {}
    current: Optional[dict[str, str]] = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("config setup"):
            current = {}
            sections["config setup"] = current
            continue
        m = re.match(r"^(conn|ca|config)\s+(\S+)", line, re.I)
        if m:
            current = {}
            sections[f"{m.group(1).lower()} {m.group(2)}"] = current
            continue
        if "=" not in line or current is None:
            continue
        key, value = line.split("=", 1)
        current[key.strip().lower()] = value.strip()
    return sections


# ===================================================================
# 统一连接构建
# ===================================================================
def _build_swanctl_connection(name: str, node: dict[str, Any]) -> Connection:
    c = Connection(name=name, source_format="swanctl", raw=node)
    local = node.get("local", {}) or {}
    remote = node.get("remote", {}) or {}
    if isinstance(local, list):
        local = local[0]
    if isinstance(remote, list):
        remote = remote[0]

    c.local_addrs = _first_addr(local.get("address")) or _first_addr(node.get("local_addrs"))
    c.remote_addrs = _first_addr(remote.get("address")) or _first_addr(node.get("remote_addrs"))
    c.local_id = normalize_id(local.get("id") if isinstance(local, dict) else None)
    c.remote_id = normalize_id(remote.get("id") if isinstance(remote, dict) else None)
    c.local_auth = _norm_auth(local.get("auth"))
    c.remote_auth = _norm_auth(remote.get("auth"))

    children = node.get("children", {}) or {}
    child: dict[str, Any] = {}
    if isinstance(children, dict):
        if children:
            k = next(iter(children))
            child = children[k] if isinstance(children[k], dict) else {}
            if isinstance(child, list):
                child = child[0]
    c.local_nets = [n for n in (_normalize_network_list(child.get("local_ts")) or
                                _normalize_network_list(local.get("subnets"))) if n]
    c.remote_nets = [n for n in (_normalize_network_list(child.get("remote_ts")) or
                                 _normalize_network_list(remote.get("subnets"))) if n]

    c.ike_version = "ikev1" if str(node.get("version", "")).strip() in ("1", "ikev1") else \
                    ("ikev2" if str(node.get("version", "")).strip() in ("2", "ikev2") else None)
    c.ike_proposals = parse_proposals(node.get("proposals"), "ike")
    c.esp_proposals = parse_proposals(child.get("esp_proposals"), "esp")

    c.ike_lifetime = parse_duration(node.get("enforce_ike_lifetime") if False else node.get("ike_lifetime"))
    c.esp_lifetime = parse_duration(child.get("lifetime"))
    c.esp_margintime = parse_duration(child.get("margin_time"))
    c.reauth = _as_bool(node.get("reauth"))
    c.keyingtries = _as_int(node.get("keyingtries"))

    dpd = node.get("dpd", {}) or {}
    if isinstance(dpd, dict):
        c.dpd_delay = parse_duration(dpd.get("delay"))
        c.dpd_timeout = parse_duration(dpd.get("timeout"))
    # children 段也可能带 dpd
    if not c.dpd_delay and isinstance(child, dict):
        cdpd = child.get("dpd", {}) or {}
        if isinstance(cdpd, dict):
            c.dpd_delay = parse_duration(cdpd.get("delay"))
            c.dpd_timeout = parse_duration(cdpd.get("timeout"))
    return c


def _norm_auth(value: Any) -> Optional[str]:
    if not value:
        return None
    v = str(value).strip().lower().replace("-", "").replace("_", "")
    table = {
        "psk": "psk", "secret": "psk",
        "pubkey": "pubkey", "rsasig": "pubkey", "ecdsa": "pubkey", "rsasim": "pubkey",
        "eapmschapv2": "eap-mschapv2", "eaptls": "eap-tls",
        "xauthpsk": "xauth-psk", "xautheap": "xauth-eap", "never": "never",
    }
    return table.get(v, v)


def _as_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    v = str(value).strip().lower()
    if v in ("yes", "true", "1", "on"):
        return True
    if v in ("no", "false", "0", "off"):
        return False
    return None


def _as_int(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _normalize_network_list(value: Any) -> list[Optional[str]]:
    if not value:
        return []
    if isinstance(value, list):
        out: list[Optional[str]] = []
        for item in value:
            out.extend(_normalize_network_list(item))
        return out
    return [normalize_network(str(value))]


def _build_legacy_connection(name: str, sec: dict[str, str]) -> Connection:
    c = Connection(name=name, source_format="ipsec.conf", raw=sec)
    c.local_addrs = _first_addr(sec.get("left"))
    c.remote_addrs = _first_addr(sec.get("right"))
    c.local_id = normalize_id(sec.get("leftid"))
    c.remote_id = normalize_id(sec.get("rightid"))
    c.local_auth = _norm_auth(sec.get("leftauth"))
    c.remote_auth = _norm_auth(sec.get("rightauth"))

    c.local_nets = [n for n in _normalize_network_list(sec.get("leftsubnet")) if n]
    c.remote_nets = [n for n in _normalize_network_list(sec.get("rightsubnet")) if n]

    v = sec.get("keyexchange", "").lower()
    c.ike_version = "ikev1" if v in ("ikev1", "isakmp") else ("ikev2" if v == "ikev2" else None)

    c.ike_proposals = parse_proposals(sec.get("ike"), "ike")
    c.esp_proposals = parse_proposals(sec.get("esp"), "esp")

    c.ike_lifetime = parse_duration(sec.get("ikelifetime"))
    c.esp_lifetime = parse_duration(sec.get("lifetime"))
    c.esp_margintime = parse_duration(sec.get("margintime"))
    c.rekey_time = c.esp_lifetime
    c.reauth = _as_bool(sec.get("reauth"))
    c.keyingtries = _as_int(sec.get("keyingtries"))
    c.dpd_delay = parse_duration(sec.get("dpddelay"))
    c.dpd_timeout = parse_duration(sec.get("dpdtimeout"))

    # 老式 leftauth 缺省按 authby 推断（最常见 psk / secret）
    if not c.local_auth and not c.remote_auth:
        authby = sec.get("authby", "").lower().replace(" ", "")
        if authby in ("secret", "psk"):
            c.local_auth = c.remote_auth = "psk"
        elif authby in ("rsasig", "pubkey"):
            c.local_auth = c.remote_auth = "pubkey"
    return c


# ===================================================================
# 入口
# ===================================================================
def detect_format(text: str) -> str:
    head = text[:4096]
    if re.search(r"^\s*(connections|pools|secrets|authorities)\s*{", head, re.M):
        return "swanctl"
    if re.search(r"^\s*conn\s+\S+", head, re.M) or "config setup" in head.lower():
        return "ipsec.conf"
    # 兜底：有花括号就按 swanctl
    return "swanctl" if "{" in head else "ipsec.conf"


def parse_config(path: str, side: str) -> SideConfig:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    fmt = detect_format(text)
    sc = SideConfig(side=side, format=fmt, path=path)
    try:
        if fmt == "swanctl":
            root = parse_swanctl(text)
            sc.global_section = root.get("settings", {}) or {}
            conns = root.get("connections", {}) or {}
            if isinstance(conns, dict):
                for name, node in conns.items():
                    for item in _as_list(node):
                        if isinstance(item, dict):
                            sc.connections[name] = _build_swanctl_connection(name, item)
        else:
            sections = parse_ipsec_conf(text)
            sc.global_section = sections.get("config setup", {})
            for sname, sec in sections.items():
                if sname.startswith("conn "):
                    name = sname.split(" ", 1)[1]
                    sc.connections[name] = _build_legacy_connection(name, sec)
    except Exception as exc:  # 解析任何异常都不致命，交给报告展示
        sc.parse_errors.append(f"{type(exc).__name__}: {exc}")
    return sc
