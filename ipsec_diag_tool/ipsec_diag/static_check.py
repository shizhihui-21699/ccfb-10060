# -*- coding: utf-8 -*-
"""静态比对：把两端规范化后的 Connection 逐项对比，产出比对表和诊断结论。"""
from __future__ import annotations

import ipaddress
from typing import Optional

from .config_parser import expand_defaults, normalize_network
from .model import CompareRow, Connection, Finding, SideConfig, StaticReport, Suite


# 最常见部署的默认值（swanctl 缺省 / strongSwan 5.x 常见值）
DEFAULT_IKE_LIFETIME = 10800        # 3h
DEFAULT_ESP_LIFETIME = 3600         # 1h
DEFAULT_DPD_DELAY = 30
DEFAULT_DPD_TIMEOUT = 150
LIFETIME_RATIO_WARN = 2             # 两端生存期相差 2 倍以上给风险提示


def _row(item: str, lv, rv, status: str, note: str = "") -> CompareRow:
    return CompareRow(item=item, local_value=str(lv), remote_value=str(rv),
                      status=status, note=note)


def _suite_intersection(a: list[Suite], b: list[Suite], kind: str) -> tuple[list[Suite], list[str]]:
    """返回（可达成的交集列表，未命中原因）。"""
    aa = expand_defaults(a, kind)
    bb = expand_defaults(b, kind)
    if not aa:
        aa = expand_defaults([Suite(raw="default", is_default=True, kind=kind)], kind)
    if not bb:
        bb = expand_defaults([Suite(raw="default", is_default=True, kind=kind)], kind)
    reasons: list[str] = []
    hits: list[Suite] = []
    for x in aa:
        for y in bb:
            ok, why = _suite_match(x, y, kind)
            if ok:
                hits.append(x)
            else:
                reasons.append(f"{x.label()} ↔ {y.label()}：{why}")
    return hits, reasons


def _suite_match(x: Suite, y: Suite, kind: str) -> tuple[bool, str]:
    miss: list[str] = []
    if x.encr != y.encr:
        miss.append(f"加密算法 {x.encr}≠{y.encr}")
    if kind == "ike":
        if x.prf and y.prf and x.prf != y.prf:
            miss.append(f"PRF {x.prf}≠{y.prf}")
        if x.integ and y.integ and x.integ != y.integ and "内置" not in (x.integ + y.integ):
            miss.append(f"完整性 {x.integ}≠{y.integ}")
        if x.dh and y.dh and x.dh != y.dh:
            miss.append(f"DH 组 {x.dh}≠{y.dh}")
    else:
        if x.integ and y.integ and x.integ != y.integ and "内置" not in (x.integ + y.integ):
            miss.append(f"完整性 {x.integ}≠{y.integ}")
        # ESP 的 DH 是 PFS；一端 none 一端有组时不匹配，但可通过关闭 PFS 谈成
        if x.dh and y.dh and x.dh != y.dh:
            miss.append(f"PFS 组 {x.dh}≠{y.dh}")
    return (not miss), "；".join(miss) if miss else ""


def _proposal_text(suites: list[Suite], kind: str) -> str:
    expanded = expand_defaults(suites, kind)
    if not expanded:
        return "未配置(用 strongSwan 默认)"
    return "，".join(s.label() for s in expanded)


def _auth_compatible(a: Optional[str], b: Optional[str]) -> tuple[str, str]:
    """认证方式比对，返回 (status, note)。"""
    if not a or not b:
        return "warn", "一端未显式配置认证方式，按部署惯例推断，建议两端显式写一致"
    if a == b:
        return "ok", ""
    psk_like = {"psk", "xauth-psk"}
    if a in psk_like and b in psk_like:
        return "warn", f"{a} 与 {b} 同属预共享密钥体系但模式不同，IKEv2 站点间应统一用 psk"
    return "mismatch", f"认证方式 {a} 与 {b} 无法互相验证"


def _nets_overlap(a: list[str], b: list[str]) -> tuple[bool, str]:
    """本端 local_ts 要和对端 remote_ts 对得上：至少一对子网有交集。"""
    def parse(nets):
        out = []
        for n in nets:
            try:
                out.append(ipaddress.ip_network(n, strict=False))
            except ValueError:
                pass
        return out
    na, nb = parse(a), parse(b)
    if not na or not nb:
        return False, "至少一端未配置流量选择器子网"
    for x in na:
        for y in nb:
            if x.version != y.version:
                continue
            if x.subnet_of(y) or y.subnet_of(x) or x.overlaps(y):
                return True, ""
    return False, f"{a} 与 {b} 无任何交集"


def _ids_compatible(a: Optional[str], b: Optional[str]) -> tuple[str, str]:
    if not a and not b:
        return "warn", "两端都没显式配置 ID，将回退为对端 IP 作为 ID，IP 变化即断"
    if not a or not b:
        return "warn", "只有一端显式配置 ID，另一端按 IP 回退，容易触发 ID 校验失败"
    if a == b:
        return "ok", ""
    # 同值不同前缀（keyid 与裸串）只告警
    va, vb = a.split(":", 1)[-1], b.split(":", 1)[-1]
    if va == vb:
        return "warn", f"ID 值相同但类型前缀不同：{a} ↔ {b}"
    return "mismatch", f"本端期望对端 ID 为 {a}，对端实际声明 {b}"


def _lifetime_status(la: Optional[int], lb: Optional[int], default: int, label: str
                     ) -> tuple[str, str, str, str, str]:
    va = la if la is not None else default
    vb = lb if lb is not None else default
    ta = f"{va}s" + ("" if la is not None else "(默认)")
    tb = f"{vb}s" + ("" if lb is not None else "(默认)")
    if max(va, vb) >= min(va, vb) * LIFETIME_RATIO_WARN:
        note = (f"{label}相差 {max(va, vb) / min(va, vb):.1f} 倍：生存期由较短一端决定，"
                "长端会被对端 DELETE 后被动重建，表现为'隔三差五断'")
        return ta, tb, "warn", note
    return ta, tb, "ok", ""


def pick_connections(local: SideConfig, remote: SideConfig) -> tuple[Optional[Connection], Optional[Connection]]:
    """连接配对：同名优先，否则各取第一条（分支常见每端只配一条隧道）。"""
    if not local.connections or not remote.connections:
        return (next(iter(local.connections.values()), None),
                next(iter(remote.connections.values()), None))
    for name, conn in local.connections.items():
        if name in remote.connections:
            return conn, remote.connections[name]
    return next(iter(local.connections.values())), next(iter(remote.connections.values()))


def compare(local: SideConfig, remote: SideConfig) -> StaticReport:
    rep = StaticReport()
    cl, cr = pick_connections(local, remote)
    rep.conn_local = cl.name if cl else None
    rep.conn_remote = cr.name if cr else None
    if cl is None or cr is None:
        rep.findings.append(Finding(
            "error", "cfg-missing", "缺少可比对的连接配置",
            f"本端连接 {list(local.connections)}，对端连接 {list(remote.connections)}",
            fixes=["确认输入文件是 swanctl.conf 或 ipsec.conf，且至少各含一个 connections/conn 段"],
            sources=["static"]))
        return rep

    rows: list[CompareRow] = []
    findings: list[Finding] = []

    # ---- IKE 版本
    va, vb = cl.ike_version or "未指定(按 IKEv2)", cr.ike_version or "未指定(按 IKEv2)"
    if cl.ike_version and cr.ike_version and cl.ike_version != cr.ike_version:
        rows.append(_row("IKE 版本", va, vb, "mismatch", "IKEv1 与 IKEv2 无法互通"))
        findings.append(Finding("error", "ike-version", "IKE 版本不一致",
                                f"本端 {va}，对端 {vb}，第一条 IKE_SA_INIT 就会被拒",
                                fixes=[f"两端统一 keyexchange/version（常见部署统一为 IKEv2：swanctl 写 version=2，"
                                       "ipsec.conf 写 keyexchange=ikev2）"], sources=["static"]))
    else:
        rows.append(_row("IKE 版本", va, vb, "ok"))

    # ---- IKE 提议
    ike_hits, ike_reasons = _suite_intersection(cl.ike_proposals, cr.ike_proposals, "ike")
    rows.append(_row("IKE 提议", _proposal_text(cl.ike_proposals, "ike"),
                     _proposal_text(cr.ike_proposals, "ike"),
                     "ok" if ike_hits else "mismatch",
                     "" if ike_hits else "无交集，对端将回 NO_PROPOSAL_CHOSEN"))
    if not ike_hits:
        findings.append(Finding(
            "error", "ike-proposal", "IKE 提议无交集（IKE_SA_INIT 阶段必断）",
            "两端加密/PRF/完整性/DH 组合没有任何一条能同时满足；" + "；".join(ike_reasons[:6]),
            evidence=[f"本端: {_proposal_text(cl.ike_proposals, 'ike')}",
                      f"对端: {_proposal_text(cr.ike_proposals, 'ike')}"],
            fixes=["两端 proposals/ike 行写同一组，最常见稳妥组合：aes256-sha256-ecp256（或 modp2048）",
                   "swanctl: proposals = aes256-sha256-ecp256",
                   "ipsec.conf: ike=aes256-sha256-modp2048!"],
            sources=["static"]))

    # ---- ESP 提议
    esp_hits, esp_reasons = _suite_intersection(cl.esp_proposals, cr.esp_proposals, "esp")
    rows.append(_row("ESP 提议", _proposal_text(cl.esp_proposals, "esp"),
                     _proposal_text(cr.esp_proposals, "esp"),
                     "ok" if esp_hits else "mismatch",
                     "" if esp_hits else "无交集，CREATE_CHILD_SA 阶段被拒"))
    if not esp_hits:
        findings.append(Finding(
            "error", "esp-proposal", "ESP/CHILD_SA 提议无交集（IKE 通了但隧道起不来）",
            "IKE 控制通道可以建立，但 CREATE_CHILD_SA 时算法/PFS 谈不拢；" + "；".join(esp_reasons[:6]),
            evidence=[f"本端: {_proposal_text(cl.esp_proposals, 'esp')}",
                      f"对端: {_proposal_text(cr.esp_proposals, 'esp')}"],
            fixes=["两端 esp_proposals/esp 写同一组，最常见：aes256-sha256（需要 PFS 则加 -modp2048）",
                   "swanctl: esp_proposals = aes256-sha256",
                   "ipsec.conf: esp=aes256-sha256!"],
            sources=["static"]))

    # ---- 认证方式
    st, note = _auth_compatible(cl.local_auth, cr.remote_auth)
    rows.append(_row("认证方式", cl.local_auth or "未指定", cr.remote_auth or "未指定", st, note))
    if st == "mismatch":
        findings.append(Finding(
            "error", "auth-method", "认证方式不匹配，IKE_AUTH 阶段必失败",
            note,
            fixes=["两端统一 auth：站点间最常见 psk（swanctl: auth=psk；ipsec.conf: authby=secret）",
                   "用证书则两端都写 pubkey 并确认各自证书链受信"],
            sources=["static"]))

    # ---- ID
    st, note = _ids_compatible(cl.remote_id, cr.local_id)
    rows.append(_row("对端 ID 期望", cl.remote_id or "未指定(按 IP)",
                     cr.local_id or "未指定(按 IP)", st, note))
    if st == "mismatch":
        findings.append(Finding(
            "error", "id-mismatch", "ID 校验会失败（AUTHENTICATION_FAILED）",
            note,
            evidence=[f"本端 remote/id = {cl.remote_id}", f"对端 local/id = {cr.local_id}"],
            fixes=[f"在本端把对端 ID 显式写成对端实际声明的值：{cr.local_id}",
                   "或两端统一使用稳定 FQDN（id = fqdn:hq-vpn.example.com），不要依赖回退 IP"],
            sources=["static"]))
    elif st == "warn":
        findings.append(Finding("warn", "id-implicit", "ID 配置不完整", note,
                                fixes=["两端都显式配置 id，避免 IP 变动后 ID 校验失败"],
                                sources=["static"]))

    # ---- 子网（本端 local 对 对端 remote，双向都查）
    ok1, why1 = _nets_overlap(cl.local_nets, cr.remote_nets)
    ok2, why2 = _nets_overlap(cr.local_nets, cl.remote_nets)
    nets_status = "ok" if ok1 and ok2 else "mismatch"
    rows.append(_row("流量选择器(子网)",
                     f"{cl.local_nets} ↔ {cl.remote_nets}",
                     f"{cr.local_nets} ↔ {cr.remote_nets}", nets_status,
                     "" if nets_status == "ok" else (why1 + "；" + why2)))
    if nets_status != "ok":
        findings.append(Finding(
            "error", "ts-mismatch", "子网/流量选择器不匹配（TS_UNACCEPTABLE）",
            f"本端 local_ts={cl.local_nets} 对端 remote_ts={cr.remote_nets}：{why1}；反向：{why2}",
            fixes=["两端 local_ts/remote_ts（ipsec.conf 的 leftsubnet/rightsubnet）写成互为镜像的同一对子网",
                   "检查是否漏写掩码、把接口地址写成了网段，或 NAT 后的网段未在对端登记"],
            sources=["static"]))

    # ---- IKE 生存期
    ta, tb, st, note = _lifetime_status(cl.ike_lifetime, cr.ike_lifetime,
                                        DEFAULT_IKE_LIFETIME, "IKE 生存期")
    rows.append(_row("IKE 生存期", ta, tb, st, note))
    if st == "warn":
        findings.append(Finding("warn", "ike-lifetime", "IKE 生存期两端差异过大", note,
            fixes=["两端 ike_lifetime/ikelifetime 统一（常见 3h=10800s），"
                   "并保证 DPD/重协商窗口不与业务高峰重叠"], sources=["static"]))

    # ---- ESP 生存期
    ta, tb, st, note = _lifetime_status(cl.esp_lifetime, cr.esp_lifetime,
                                        DEFAULT_ESP_LIFETIME, "ESP 生存期")
    rows.append(_row("ESP 生存期", ta, tb, st, note))
    if st == "warn":
        findings.append(Finding("warn", "esp-lifetime", "ESP 生存期两端差异过大，周期性断流的典型诱因", note,
            evidence=[f"本端 lifetime={cl.esp_lifetime}", f"对端 lifetime={cr.esp_lifetime}"],
            fixes=["两端 lifetime 统一为 3600s，并配置 margintime（常见 5~10 分钟）让 rekey 平滑提前",
                   "swanctl children 段: lifetime=1h, margin_time=10m；ipsec.conf: lifetime=1h, margintime=10m"],
            sources=["static"]))

    # ---- DPD
    da = cl.dpd_delay if cl.dpd_delay is not None else DEFAULT_DPD_DELAY
    db = cr.dpd_delay if cr.dpd_delay is not None else DEFAULT_DPD_DELAY
    ta = f"{da}s/{cl.dpd_timeout or DEFAULT_DPD_TIMEOUT}s" + ("" if cl.dpd_delay is not None else "(默认)")
    tb = f"{db}s/{cr.dpd_timeout or DEFAULT_DPD_TIMEOUT}s" + ("" if cr.dpd_delay is not None else "(默认)")
    dpd_status, dpd_note = "ok", ""
    if (cl.dpd_delay == 0) != (cr.dpd_delay == 0):
        dpd_status, dpd_note = "mismatch", "一端关闭 DPD 一端开启：开启端会单方面判定对端死亡并 DELETE SA"
    elif max(da, db) >= min(da, db) * 3:
        dpd_status, dpd_note = "warn", "DPD 间隔差异大，一端可能在对端感知前就拆除 SA"
    rows.append(_row("DPD(delay/timeout)", ta, tb, dpd_status, dpd_note))
    if dpd_status == "mismatch":
        findings.append(Finding("error", "dpd-mismatch", "DPD 开关两端不一致", dpd_note,
            fixes=["两端都开启 DPD 且参数对齐，最常见 dpd_delay=30s、dpd_timeout=150s（swanctl connections.dpd 段）"],
            sources=["static"]))
    elif dpd_status == "warn":
        findings.append(Finding("warn", "dpd-tuning", "DPD 参数差异较大", dpd_note,
            fixes=["两端 dpd_delay 统一为 30s、timeout 统一为 150s"], sources=["static"]))

    # ---- reauth/rekey 策略
    ra = cl.reauth if cl.reauth is not None else True
    rb = cr.reauth if cr.reauth is not None else True
    if ra != rb:
        rows.append(_row("reauth 策略", str(ra), str(rb), "warn",
                         "一端 reauth=yes 一端 no：到期时一端整 SA 重建、一端只 rekey，容易撞车"))
        findings.append(Finding("warn", "reauth-policy", "reauth/rekey 策略两端不一致",
            "IKEv2 站点间推荐两端都 reauth=no、靠 CREATE_CHILD_SA rekey，避免整通道重建造成瞬断",
            fixes=["swanctl: reauth = no（两端都配）；ipsec.conf: reauth=no"],
            sources=["static"]))
    else:
        rows.append(_row("reauth 策略", str(ra), str(rb), "ok"))

    rep.rows = rows
    rep.findings = findings
    return rep
