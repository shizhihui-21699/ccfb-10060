# -*- coding: utf-8 -*-
"""charon/charon-systemd 日志解析。

支持的行格式（覆盖 strongSwan 5.x 常见部署）：
  Nov  8 10:23:14 gateway charon[1234]: 12[NET] ...
  2026-11-08T10:23:14.123456 12[NET] ...
  2026-11-08 10:23:14.123 12[IKE] ...
  10:23:14.123 12[ENC] ...
syslog 没有年份，用 --log-year（默认当前年）补齐。
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from .model import LogEvent, SaGroup

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# (时间戳原文, 线程, 子系统, 消息)
LINE_RE = re.compile(
    r"^(?:"
    r"(?P<syslog>(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<stime>\d{2}:\d{2}:\d{2}))"
    r"|(?P<iso>(?P<idate>\d{4}-\d{2}-\d{2})[T ](?P<itime>\d{2}:\d{2}:\d{2}(?:[.,]\d+)?))"
    r"|(?P<hms>\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)"
    r")\s+"
    r"(?:\S+\s+)?(?:charon(?:-systemd)?\[\d+\]:\s+)?"
    r"(?P<thread>\d+)\[(?P<sub>[A-Z]+)\]\s*(?P<msg>.*)$"
)

SA_RE = re.compile(r"(?:IKE_SA|IKE)[\s_](?:\([^)]*\)\s*)?(?P<name>[\w.\-]+)\[(?P<uniq>\d+)\]")
CHILD_RE = re.compile(r"CHILD_SA\s+(?P<name>[\w.\-]+)\[(?P<uniq>\d+)\]")
MSGID_RE = re.compile(r"(?:message ID\s*=|(?:request|response))\s*(\d+)", re.I)
EXCH_RE = re.compile(r"(IKE_SA_INIT|IKE_AUTH|CREATE_CHILD_SA|INFORMATIONAL|IKE_SESSION_RESUME)", re.I)
DIR_RE = re.compile(r"^\s*(sending|receiving)\b", re.I)

# 事件归类规则：(etype, 正则, 默认方向)
# 顺序敏感：带 notify 语义的具体失败事件优先于交换类型；交换类型优先于 send/recv、rekey 等通用规则
RULES: list[tuple[str, re.Pattern[str], Optional[str]]] = [
    ("collision", re.compile(r"collision|simultaneous|COLLISION", re.I), None),
    ("reauth", re.compile(r"\breauth(entication|ing|ed)?\b", re.I), None),
    ("rekey", re.compile(r"\brekey(ing|ed)?\b", re.I), None),
    ("retransmit", re.compile(r"retransmit", re.I), None),
    ("giveup", re.compile(r"giving up after|retransmit.*limit", re.I), None),
    ("ke_unsupported", re.compile(r"KE payload.*(not acceptable|unsupported)|INVALID_KE_PAYLOAD", re.I), None),
    ("auth_fail", re.compile(r"AUTHENTICATION_FAILED|authentication of .* failed|"
                             r"no shared key found|verifying peer auth data failed|"
                             r"auth data.*(failed|invalid)", re.I), None),
    ("psk_mismatch", re.compile(r"no shared key found|PSK wrong|pre.?shared key.*(mismatch|wrong|fail)|"
                                r"MAC does not match", re.I), None),
    ("id_fail", re.compile(r"IDir.*(mismatch|not matching)|ID does not match|peer ID mismatch|"
                           r"expected ID|constraint check failed", re.I), None),
    ("cert_fail", re.compile(r"certificate (expired|untrusted|revoked)|signature verification failed|"
                             r"X509.*(verif|valid)", re.I), None),
    ("no_proposal", re.compile(r"NO_PROPOSAL_CHOSEN|no acceptable proposal|proposal.*does not match|"
                               r"received.*proposal.*no match|failed to select", re.I), None),
    ("ts_unacceptable", re.compile(r"TS_UNACCEPTABLE|traffic selectors?.*(no|unacceptable|mismatch)|"
                                   r"no matching traffic selector", re.I), None),
    ("ike_init", re.compile(r"IKE_SA_INIT\s+request", re.I), None),
    ("ike_init_resp", re.compile(r"IKE_SA_INIT\s+response", re.I), None),
    ("ike_auth_req", re.compile(r"IKE_AUTH\s+request", re.I), None),
    ("ike_auth_resp", re.compile(r"IKE_AUTH\s+response", re.I), None),
    ("create_child_req", re.compile(r"CREATE_CHILD_SA\s+request", re.I), None),
    ("create_child_resp", re.compile(r"CREATE_CHILD_SA\s+response", re.I), None),
    ("informational", re.compile(r"INFORMATIONAL", re.I), None),
    ("ke", re.compile(r"key exchange|KE payload", re.I), None),
    ("nat", re.compile(r"NAT(T| detected)|keepalive", re.I), None),
    ("auth_ok", re.compile(r"authentication of .* (with|successful)|peer authenticated", re.I), None),
    ("proposal_selected", re.compile(r"select(ed|ing) proposal|proposal matches|received proposals", re.I), None),
    ("child_up", re.compile(r"CHILD_SA\s+[\w.\-]+?\[\d+\].*established|CHILD_SA.*(inbound|outbound)", re.I), None),
    ("ike_up", re.compile(r"IKE_SA\s+[\w.\-]+?\[\d+\].*established|IKE_SA.*established", re.I), None),
    ("dpd", re.compile(r"\bDPD\b|dead peer|liveness", re.I), None),
    ("timeout", re.compile(r"timeout|timed out|retransmit \d+ of", re.I), None),
    ("delete", re.compile(r"\bDELETE\b|delete IKE_SA|delete CHILD_SA|destroying IKE_SA", re.I), None),
    ("half_open", re.compile(r"half-open", re.I), None),
    ("notify", re.compile(r"^\s*(sending|receiving).*notify|received.*notify", re.I), None),
    ("send", re.compile(r"^sending\b", re.I), "out"),
    ("recv", re.compile(r"^receiving\b", re.I), "in"),
]

# 通知类型 -> 统一主题（用于和静态发现合并）
NOTIFY_TOPICS = [
    (re.compile(r"NO_PROPOSAL_CHOSEN", re.I), "proposal"),
    (re.compile(r"INVALID_KE_PAYLOAD", re.I), "dh-group"),
    (re.compile(r"AUTHENTICATION_FAILED", re.I), "auth"),
    (re.compile(r"TS_UNACCEPTABLE", re.I), "ts"),
    (re.compile(r"INVALID_SYNTAX", re.I), "malformed"),
    (re.compile(r"COOKIE", re.I), "cookie"),
    (re.compile(r"EAP_", re.I), "eap"),
]


def parse_timestamp(m: re.Match[str], year: int) -> tuple[datetime, str]:
    if m.group("syslog"):
        dt = datetime(year, MONTHS[m.group("mon")], int(m.group("day")),
                      *[int(x) for x in m.group("stime").split(":")])
        return dt, m.group("syslog")
    if m.group("iso"):
        raw = f"{m.group('idate')} {m.group('itime').replace(',', '.')}"
        dt = datetime.strptime(raw.split(".")[0], "%Y-%m-%d %H:%M:%S")
        if "." in raw:
            frac = float("0." + raw.split(".")[1])
            dt = dt.replace(microsecond=int(frac * 1_000_000))
        return dt, m.group("iso")
    raw = m.group("hms").replace(",", ".")
    dt = datetime.strptime(raw.split(".")[0], "%H:%M:%S").replace(year=year)
    if "." in raw:
        frac = float("0." + raw.split(".")[1])
        dt = dt.replace(microsecond=int(frac * 1_000_000))
    return dt, m.group("hms")


def classify(msg: str) -> tuple[Optional[str], Optional[str]]:
    dm = DIR_RE.match(msg)
    word_dir = "out" if dm and dm.group(1).lower() == "sending" else \
               ("in" if dm else None)
    for etype, rx, direction in RULES:
        if rx.search(msg):
            return etype, direction or word_dir
    return None, None


def extract_sa(msg: str) -> tuple[Optional[str], Optional[str]]:
    m = SA_RE.search(msg)
    if m:
        return f"{m.group('name')}[{m.group('uniq')}]", m.group("uniq")
    # 兜底：仅在明确的 SA 上下文中识别 'name[N]'，避免把消息 ID/SPI/CHILD_SA 当成 IKE_SA
    m2 = re.search(r"(?:IKE_SA|IKE|initiating|rekey of|destroying|DELETE for)\s+"
                   r"(?P<name>[A-Za-z][\w.\-]*)\[(?P<uniq>\d+)\]", msg)
    if m2:
        return f"{m2.group('name')}[{m2.group('uniq')}]", m2.group("uniq")
    return None, None


def parse_log(path: str, side: str, year: int) -> list[LogEvent]:
    events: list[LogEvent] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = LINE_RE.match(line)
            if not m:
                continue
            try:
                dt, raw_ts = parse_timestamp(m, year)
            except (ValueError, KeyError):
                continue
            msg = m.group("msg").strip()
            etype, direction = classify(msg)
            sa, _uniq = extract_sa(msg)
            cm = CHILD_RE.search(msg)
            child = f"{cm.group('name')}[{cm.group('uniq')}]" if cm else None
            ex = EXCH_RE.search(msg)
            mm = MSGID_RE.search(msg)
            events.append(LogEvent(
                side=side, raw_ts=raw_ts, ts=dt.timestamp(),
                thread=m.group("thread"), subsystem=m.group("sub"),
                message=msg, ike=sa, child=child, etype=etype,
                direction=direction,
                exchange=ex.group(1).upper() if ex else None,
                msg_id=mm.group(1) if mm else None))
    return events


# -------------------------------------------------------------------
# 时钟偏移估计：用"发送/接收"配对（同一消息 ID 优先），取中位差
# -------------------------------------------------------------------
def estimate_skew(events: list[LogEvent]) -> tuple[Optional[float], int]:
    local = [e for e in events if e.side == "local"]
    remote = [e for e in events if e.side == "remote"]
    if not local or not remote:
        return None, 0
    diffs: list[float] = []
    # 按消息 ID + 交换类型精确配对（方向不同优先；方向缺失时也接受）
    for exch in ("IKE_SA_INIT", "IKE_AUTH", "CREATE_CHILD_SA", "INFORMATIONAL"):
        lo = [e for e in local if e.exchange == exch]
        ro = [e for e in remote if e.exchange == exch]
        for a in lo:
            if not a.msg_id:
                continue
            for b in ro:
                if b.msg_id != a.msg_id:
                    continue
                if a.direction and b.direction and a.direction == b.direction:
                    continue
                diffs.append(b.ts - a.ts)
    # 退而求其次：同事件类型按顺序就近配对（不再强制方向，部分日志无 sending/receiving 前缀）
    if len(diffs) < 2:
        diffs = []
        for et in ("send", "recv", "ike_init", "ike_init_resp", "ike_auth_req",
                   "ike_auth_resp", "create_child_req", "create_child_resp",
                   "informational", "delete", "dpd", "rekey", "collision"):
            la = sorted((e for e in local if e.etype == et), key=lambda e: e.ts)
            ra = sorted((e for e in remote if e.etype == et), key=lambda e: e.ts)
            for a, b in zip(la, ra):
                diffs.append(b.ts - a.ts)
    if not diffs:
        return None, 0
    diffs.sort()
    median = diffs[len(diffs) // 2]
    return median, len(diffs)


def apply_skew(events: list[LogEvent], skew: Optional[float]) -> None:
    for e in events:
        e.corrected_ts = e.ts - (skew or 0.0) if e.side == "remote" else e.ts


# -------------------------------------------------------------------
# 按 IKE_SA 归并生命周期
# -------------------------------------------------------------------
def group_sa_lifecycles(events: list[LogEvent]) -> list[SaGroup]:
    groups: dict[str, SaGroup] = {}
    anon: list[LogEvent] = []
    for e in events:
        if e.ike:
            g = groups.setdefault(e.ike, SaGroup(key=e.ike, side=e.side))
            g.events.append(e)
            if e.exchange and e.exchange not in g.exchanges:
                g.exchanges.append(e.exchange)
        else:
            anon.append(e)
    # 没有 SA 标识的事件（如第一行 receiving IKE_SA_INIT 前）挂到时间最近的组
    for e in anon:
        if groups:
            nearest = min(groups.values(),
                          key=lambda g: min(abs(x.ts - e.ts) for x in g.events[:1] + g.events[-1:]))
            nearest.events.append(e)
    for g in groups.values():
        g.events.sort(key=lambda x: x.corrected_ts)
        g.phase = _phase_of(g)
    return sorted(groups.values(), key=lambda g: g.events[0].corrected_ts if g.events else 0)


def _phase_of(g: SaGroup) -> str:
    types = {e.etype for e in g.events if e.etype}
    if any(t in types for t in ("rekey", "collision", "reauth")):
        return "rekey"
    if "dead" in " ".join(e.message for e in g.events).lower() or "dpd" in types:
        return "dead"
    if "child_up" in types:
        return "established"
    if "ike_up" in types:
        return "child"
    if any(t in types for t in ("ike_auth_req", "ike_auth_resp", "auth_ok", "auth_fail")):
        return "auth"
    return "init"
