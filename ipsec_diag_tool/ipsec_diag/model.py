# -*- coding: utf-8 -*-
"""核心数据模型：配置、比对结果、日志事件、诊断结论。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------- 配置模型
@dataclass
class Suite:
    """一条规范化后的提议（IKE 或 ESP/AH）。"""
    raw: str = ""
    kind: str = "ike"                 # ike | esp
    encr: Optional[str] = None
    prf: Optional[str] = None
    integ: Optional[str] = None
    dh: Optional[str] = None          # 也用于 ESP 的 PFS 组
    is_default: bool = False

    def label(self) -> str:
        if self.kind == "ike":
            parts = [self.encr or "?", self.prf or "-", self.integ or "-", self.dh or "-"]
            return "/".join(parts)
        parts = [self.encr or "?", self.integ or "-"]
        if self.dh:
            parts.append(self.dh)
        return "/".join(parts)


@dataclass
class Connection:
    """一条规范化后的 site-to-site 连接（取最常见部署形态：tunnel/route 模式）。"""
    name: str
    source_format: str = "swanctl"    # swanctl | ipsec.conf
    raw: dict[str, Any] = field(default_factory=dict)

    ike_version: Optional[str] = None        # "ikev1" | "ikev2"
    ike_proposals: list[Suite] = field(default_factory=list)
    esp_proposals: list[Suite] = field(default_factory=list)

    local_addrs: list[str] = field(default_factory=list)
    remote_addrs: list[str] = field(default_factory=list)
    local_id: Optional[str] = None
    remote_id: Optional[str] = None
    local_auth: Optional[str] = None         # psk | pubkey | eap-mschapv2 | xauth-psk ...
    remote_auth: Optional[str] = None

    local_nets: list[str] = field(default_factory=list)
    remote_nets: list[str] = field(default_factory=list)

    ike_lifetime: Optional[int] = None       # 秒
    esp_lifetime: Optional[int] = None       # 秒
    esp_margintime: Optional[int] = None
    dpd_delay: Optional[int] = None
    dpd_timeout: Optional[int] = None
    rekey_time: Optional[int] = None         # ipsec.conf 的 rekey/ikelifetime 派生
    reauth: Optional[bool] = None
    keyingtries: Optional[int] = None


@dataclass
class SideConfig:
    """一端（本端/对端）解析后的全部配置。"""
    side: str                                # local | remote
    format: Optional[str] = None
    path: Optional[str] = None
    connections: dict[str, Connection] = field(default_factory=dict)
    parse_errors: list[str] = field(default_factory=list)
    global_section: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------- 静态比对
@dataclass
class CompareRow:
    item: str
    local_value: str
    remote_value: str
    status: str                      # ok | mismatch | warn | info
    note: str = ""


@dataclass
class Finding:
    severity: str                    # error | warn | info
    topic: str                       # 用于静态/动态证据合并的稳定标识
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    fixes: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)   # static | log:local | log:remote


@dataclass
class StaticReport:
    rows: list[CompareRow] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    conn_local: Optional[str] = None
    conn_remote: Optional[str] = None


# ---------------------------------------------------------------- 日志模型
@dataclass
class LogEvent:
    side: str                        # local | remote
    raw_ts: str
    ts: float                        # 解析后的 epoch（年份缺失时补 LOG_YEAR）
    thread: str
    subsystem: str
    message: str
    ike: Optional[str] = None        # IKE_SA 标识: "uniq[4]"
    child: Optional[str] = None      # CHILD_SA 名称
    etype: Optional[str] = None      # 归类后的事件类型
    direction: Optional[str] = None  # in | out
    exchange: Optional[str] = None   # IKE_SA_INIT / IKE_AUTH / CREATE_CHILD_SA / INFORMATIONAL
    msg_id: Optional[str] = None
    corrected_ts: float = 0.0        # 时钟偏移修正后的时间


@dataclass
class SaGroup:
    """按 IKE_SA 归并的一次协商/生命周期。"""
    key: str
    side: str
    events: list[LogEvent] = field(default_factory=list)
    phase: str = "unknown"           # init | auth | child | established | rekey | dead
    exchanges: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- 总报告
@dataclass
class DiagReport:
    generated_at: str = ""
    log_year: int = 0
    clock_skew: Optional[float] = None
    skew_pairs: int = 0
    static: Optional[StaticReport] = None
    events: list[LogEvent] = field(default_factory=list)
    groups: list[SaGroup] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    side_config: dict[str, SideConfig] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    inputs: dict[str, str] = field(default_factory=dict)


SEVERITY_ORDER = {"error": 0, "warn": 1, "info": 2}
STATUS_LABEL = {"ok": "匹配", "mismatch": "不匹配", "warn": "风险", "info": "信息"}
