# -*- coding: utf-8 -*-
"""协商重建与诊断：把两端事件按修正时间对齐，还原步骤、定位卡点、识别 rekey 碰撞。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .model import DiagReport, Finding, LogEvent, SaGroup, StaticReport

# IKEv2 site-to-site 的标准协商步骤（最常见部署形态）
STEPS = [
    ("IKE_SA_INIT 发起", {"ike_init", "send"}),
    ("IKE_SA_INIT 应答/DH+Nonce", {"ike_init_resp", "recv", "ke"}),
    ("IKE_AUTH 发起（认证+TS）", {"ike_auth_req", "send"}),
    ("IKE_AUTH 认证校验", {"auth_ok", "auth_fail", "id_fail", "psk_mismatch", "cert_fail"}),
    ("CREATE_CHILD_SA 建隧道", {"create_child_req", "create_child_resp", "ts_unacceptable"}),
    ("CHILD_SA 上线", {"child_up", "ike_up"}),
    ("保活/DPD 与生命周期", {"dpd", "rekey", "reauth", "delete", "collision", "timeout"}),
]

STEP_HINT = {
    0: "IKE_SA_INIT 一去不回：网络不通、UDP 500/4500 被拦截或对端 charon 未运行",
    1: "IKE_SA_INIT 阶段被拒：IKE 提议/DH 组无交集，或 COOKIE/半开连接限流",
    2: "IKE_AUTH 发不出：SA_INIT 未成功或本端策略加载异常",
    3: "认证阶段失败：PSK 不一致、证书不受信或对端 ID 与期望不符",
    4: "CHILD_SA 协商失败：ESP 提议无交集或流量选择器(子网)不被接受",
    5: "SA 已建立但业务仍不通：问题在路由/防火墙/SNAT，而非 IKE",
    6: "已进入保活/重协商阶段：重点看 DPD、rekey 碰撞与生存期",
}


@dataclass
class TimelineStep:
    index: int
    name: str
    events: list[LogEvent] = field(default_factory=list)
    reached: bool = False


def build_timeline(events: list[LogEvent]) -> list[TimelineStep]:
    timeline = [TimelineStep(i, name) for i, (name, _) in enumerate(STEPS)]
    for e in events:
        if not e.etype:
            continue
        for i, (_name, want) in enumerate(STEPS):
            if e.etype in want:
                timeline[i].events.append(e)
                timeline[i].reached = True
                break
    for t in timeline:
        t.events.sort(key=lambda x: x.corrected_ts)
    return timeline


def stuck_step(timeline: list[TimelineStep], groups: list[SaGroup]) -> Optional[int]:
    """第一个'达到过但没走到下一步'的步骤；全部走完则返回 None。"""
    reached = [t.reached for t in timeline]
    if not any(reached):
        return 0
    last = max(i for i, r in enumerate(reached) if r)
    if last == len(STEPS) - 1 and timeline[-1].reached:
        return None
    return last


# ---------------------------------------------------------------- 日志侧诊断
def _notify_of(msg: str) -> Optional[str]:
    for rx, topic in [
        (r"NO_PROPOSAL_CHOSEN", "proposal"),
        (r"AUTHENTICATION_FAILED", "auth"),
        (r"TS_UNACCEPTABLE", "ts"),
        (r"INVALID_KE_PAYLOAD", "dh-group"),
        (r"COOKIE", "cookie"),
        (r"INVALID_SYNTAX", "malformed"),
    ]:
        if __import__("re").search(rx, msg, __import__("re").I):
            return topic
    return None


def diagnose_logs(events: list[LogEvent], groups: list[SaGroup],
                  timeline: list[TimelineStep]) -> list[Finding]:
    findings: list[Finding] = []
    all_text = " ".join(e.message for e in events)
    both_sides = {e.side for e in events}

    def add(sev: str, topic: str, title: str, detail: str, fixes: list[str],
            evidence: Optional[list[str]] = None, sides: Optional[list[str]] = None):
        findings.append(Finding(sev, topic, title, detail,
                                evidence or [], fixes,
                                sides or sorted(both_sides)))

    # ---- 1. NO_PROPOSAL_CHOSEN：区分 IKE 阶段还是 CHILD 阶段
    no_prop = [e for e in events if e.etype == "no_proposal"]
    if no_prop:
        phase = "IKE_SA_INIT"
        # 证据来源：事件自身的交换标记、CHILD_SA 关联，或时间轴上相邻的 CREATE_CHILD_SA
        for e in no_prop:
            if e.exchange == "CREATE_CHILD_SA" or e.child:
                phase = "CREATE_CHILD_SA"
                break
            pos = events.index(e)
            nearby = events[max(0, pos - 3): pos] + events[pos + 1: pos + 4]
            if any(n.exchange == "CREATE_CHILD_SA" or n.child or
                   "CHILD_SA" in n.message or "ESP proposal" in n.message for n in nearby):
                phase = "CREATE_CHILD_SA"
                break
        sample = no_prop[0].message
        if phase == "IKE_SA_INIT":
            add("error", "ike-proposal",
                "日志确认：IKE 提议被拒（NO_PROPOSAL_CHOSEN @ IKE_SA_INIT）",
                f"对端在 SA_INIT 即返回 NO_PROPOSAL_CHOSEN，加密/PRF/完整性/DH 组合无交集。样例：{sample[:160]}",
                ["两端 proposals/ike 对齐为同一组，最常见 aes256-sha256-ecp256（不支持 ECP 则 modp2048）",
                 "swanctl: proposals = aes256-sha256-ecp256；ipsec.conf: ike=aes256-sha256-modp2048!",
                 "用 `swanctl --list-algs` 确认两端 charon 插件实际支持的算法"],
                sides=[e.side for e in no_prop])
        else:
            add("error", "esp-proposal",
                "日志确认：ESP 提议被拒（NO_PROPOSAL_CHOSEN @ CREATE_CHILD_SA）",
                f"IKE 通道已建立，CHILD_SA 阶段算法或 PFS 组谈不拢。样例：{sample[:160]}",
                ["两端 esp_proposals/esp 对齐：aes256-sha256；若一端配了 PFS 另一端 none，统一为 modp2048 或同时关闭"],
                sides=[e.side for e in no_prop])

    # ---- 2. INVALID_KE_PAYLOAD / DH 组
    if any(e.etype == "ke_unsupported" for e in events) or "INVALID_KE_PAYLOAD" in all_text:
        add("error", "dh-group", "DH/PFS 组不被对端接受（INVALID_KE_PAYLOAD）",
            "通知里通常带对端支持的组号；IKE 阶段看 proposals 的 DH，ESP 阶段看 PFS 配置",
            ["按通知中的组号改两端一致（老旧设备常见 modp2048=14，新部署推荐 ecp256=19 或 curve25519=31）"])

    # ---- 3. 认证失败：PSK / 证书 / ID 细分
    psk = [e for e in events if e.etype == "psk_mismatch"]
    auth_fail = [e for e in events if e.etype == "auth_fail"]
    id_fail = [e for e in events if e.etype == "id_fail"]
    if psk or ("AUTHENTICATION_FAILED" in all_text and not id_fail and not any(
            e.etype == "cert_fail" for e in events)):
        src = psk or auth_fail
        add("error", "psk-mismatch", "预共享密钥校验失败（AUTHENTICATION_FAILED / no shared key found）",
            "两端 secret 不一致，或 id 与 secrets 段的 id 选择器对不上导致取错密钥。"
            f"样例：{(src[0].message if src else all_text)[:160]}",
            ["核对两端 /etc/swanctl/ipsec.secrets（或 ipsec.secrets）中的 PSK 完全一致，注意首尾空格",
             "secrets 选择器要和 connections 里的 id/地址对应，例如：HQ-ID : PSK \"xxxx\"",
             "改完执行 swanctl --load-secrets（老式: ipsec secrets）"],
            sides=[e.side for e in src] or None)
    if id_fail:
        add("error", "id-mismatch", "对端 ID 与本端期望不符（ID 校验失败）",
            "样例：" + id_fail[0].message[:180],
            ["把本端 remote/id 改成对端实际声明的 ID，或两端统一用稳定 FQDN",
             "临时排查可在 swanctl 加 remote id 显式指定，切勿长期用宽松校验"])
    cert = [e for e in events if e.etype == "cert_fail"]
    if cert:
        add("error", "cert-fail", "证书链校验失败",
            "样例：" + cert[0].message[:180],
            ["检查 CA 证书是否已装入 /etc/swanctl/x509ca 并 load-credentials",
             "核对证书有效期、SAN 是否覆盖对端 ID、主机时间是否正确（时间偏差会直接导致有效期判定失败）"])

    # ---- 4. TS_UNACCEPTABLE 子网
    ts = [e for e in events if e.etype == "ts_unacceptable"]
    if ts:
        add("error", "ts-mismatch", "流量选择器被拒（TS_UNACCEPTABLE）",
            "对端不认可发起方请求的子网区间。样例：" + ts[0].message[:180],
            ["两端 local_ts/remote_ts（leftsubnet/rightsubnet）镜像一致，掩码精确到网段",
             "确认 NAT 后的地址段已在对端配置，必要时用 pool 虚拟地址"])

    # ---- 5. DPD / 超时 / 重传放弃
    giveup = [e for e in events if e.etype == "giveup"]
    retrans = [e for e in events if e.etype == "retransmit" or e.etype == "timeout"]
    dpd = [e for e in events if e.etype == "dpd"]
    if giveup:
        add("error", "peer-unreachable", "重传达到上限后放弃（giving up after N retransmits）",
            "发出的请求始终收不到响应：链路中断、NAT 映射老化、对端宕机或被防火墙静默丢弃。"
            "样例：" + giveup[0].message[:160],
            ["先在两端抓包确认 UDP 500/4500 的双向可达（tcpdump -ni any udp port 500 or 4500）",
             "NAT 环境开启 NAT-T 并调小 dpd_delay（常见 30s），让 NAT 映射保持活跃",
             "检查中间设备的会话超时是否短于 DPD 间隔"],
            sides=[e.side for e in giveup])
    elif dpd and any("dead" in e.message.lower() or "timeout" in e.message.lower() for e in dpd):
        add("error", "dpd-dead", "DPD 判定对端死亡并拆除 SA",
            "样例：" + next(e.message for e in dpd if "dead" in e.message.lower() or "timeout" in e.message.lower())[:180],
            ["两端 dpd_delay 对齐（30s）、dpd_timeout 对齐（150s），一端过严会误杀",
             "排查中间链路丢包与 NAT 映射老化；必要时 dpd_delay 降到 10~15s"])
    elif retrans and not no_prop and not auth_fail:
        add("warn", "retrans", "出现 IKE 重传（链路或对端响应慢）",
            f"共 {len(retrans)} 条重传/超时事件，若持续出现且最终恢复，多为链路抖动或对端 CPU 饱和",
            ["抓包定位丢包方向；确认对端 charon 没有在频繁 reload 配置",
             "适当调大 retransmit_timeout/重试次数可缓解，但根因仍在网络"])

    # ---- 6. rekey / reauth 碰撞
    coll = [e for e in events if e.etype == "collision"]
    rekey_events = [e for e in events if e.etype == "rekey"]
    reauth_events = [e for e in events if e.etype == "reauth"]
    if coll:
        add("warn", "rekey-collision", "检测到 rekey/reauth 碰撞（两端同时发起重协商）",
            "两端在同一窗口各自发起 CREATE_CHILD_SA，strongSwan 按 RFC 7296 处理碰撞（通常保留一个、删另一个），"
            "碰撞瞬间可能出现瞬断或告警。样例：" + coll[0].message[:180],
            ["让生存期不同端错峰：主动端 lifetime 略短（如 3600s），对端 3600s 且 margin_time 错开",
             "两端都设 reauth=no，只做 CHILD_SA rekey（CREATE_CHILD_SA），避免整 IKE_SA 重建撞车",
             "确认两端 strongSwan 版本不过旧（5.5 之前碰撞处理缺陷较多）"])
    elif rekey_events and len(rekey_events) >= 2:
        sides = {e.side for e in rekey_events}
        if len(sides) == 2:
            add("warn", "rekey-collision", "两端都在发起 rekey（疑似碰撞窗口）",
                "未出现显式 collision 日志，但两端在相近时间各自发起重协商，参数不当时会互相 DELETE",
                ["错峰配置 lifetime/margintime，并统一 reauth=no"])
    if reauth_events:
        add("info", "reauth", "日志中出现整 SA 重认证（reauth）",
            "reauth 会拆除并重建整个 IKE_SA，比重 key 更容易造成业务瞬断",
            ["站点间推荐 swanctl reauth=no / ipsec.conf reauth=no，依赖定期 rekey 即可"])

    # ---- 7. DELETE 与建链失败的卡点
    deletes = [e for e in events if e.etype == "delete"]
    if deletes and not giveup and not dpd:
        add("info", "delete", f"观察到 {len(deletes)} 次 SA 删除（DELETE/销毁）",
            "主动删除通常来自生存期到期、对端配置 reload 或管理操作；结合时间轴判断是否与断流时刻吻合",
            ["若删除时间点与业务中断一致，对照两端 lifetime 与 rekey 日志确认是否重协商失败后被拆"])

    stuck = stuck_step(timeline, groups)
    if stuck is not None and not any(f.severity == "error" for f in findings):
        add("warn", "stuck", f"协商停在第 {stuck + 1} 步：{STEPS[stuck][0]}",
            STEP_HINT[stuck],
            ["在两端同时开 charon 调试日志（charon-logging 或 stroke: logcfg=ike:2,cfg:2,net:2）复现一次"])

    return findings


# ---------------------------------------------------------------- 证据合并
def merge_findings(static: Optional[StaticReport], log_findings: list[Finding]) -> list[Finding]:
    """静态配置问题与日志证据按 topic 合并：两边都出现时升级为'已证实'。"""
    merged: dict[str, Finding] = {}
    order: list[str] = []

    def key_of(topic: str) -> str:
        # 把 ike-proposal/esp-proposal/psk-mismatch 等归并到静态 topic
        alias = {"psk-mismatch": "psk-mismatch", "dh-group": "ike-proposal",
                 "cert-fail": "cert-fail"}
        return alias.get(topic, topic)

    if static:
        for f in static.findings:
            k = key_of(f.topic)
            merged[k] = Finding(f.severity, k, f.title, f.detail,
                                list(f.evidence), list(f.fixes), list(f.sources))
            order.append(k)
    for f in log_findings:
        k = key_of(f.topic)
        if k in merged:
            m = merged[k]
            tag = "【日志已证实】"
            if tag not in m.title:
                m.title = tag + m.title
            m.evidence.extend(f.evidence or [f.detail[:200]])
            m.sources.extend(f.sources)
            if f.severity == "error":
                m.severity = "error"
            for fix in f.fixes:
                if fix not in m.fixes:
                    m.fixes.append(fix)
        else:
            merged[k] = Finding(f.severity, k, f.title, f.detail,
                                list(f.evidence), list(f.fixes), list(f.sources))
            order.append(k)
    out = [merged[k] for k in order]
    out.sort(key=lambda f: {"error": 0, "warn": 1, "info": 2}[f.severity])
    # 去重证据
    for f in out:
        f.evidence = list(dict.fromkeys(f.evidence))[:8]
        f.sources = list(dict.fromkeys(f.sources))
    return out


def summarize(events: list[LogEvent], groups: list[SaGroup],
              timeline: list[TimelineStep], findings: list[Finding]) -> dict:
    etypes = [e.etype for e in events if e.etype]
    established = any(t.reached for t in timeline[5:6])
    return {
        "event_count": len(events),
        "sa_count": len(groups),
        "rekey_count": etypes.count("rekey"),
        "reauth_count": etypes.count("reauth"),
        "retrans_count": etypes.count("retransmit") + etypes.count("timeout"),
        "delete_count": etypes.count("delete"),
        "ever_established": established,
        "stuck_step": (None if stuck_step(timeline, groups) is None
                       else STEPS[stuck_step(timeline, groups)][0]),
        "error_count": sum(1 for f in findings if f.severity == "error"),
        "warn_count": sum(1 for f in findings if f.severity == "warn"),
        "time_span": (max((e.corrected_ts for e in events), default=0) -
                      min((e.corrected_ts for e in events), default=0)),
    }
