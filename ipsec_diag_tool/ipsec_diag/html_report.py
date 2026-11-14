# -*- coding: utf-8 -*-
"""单文件 HTML 报告生成：内嵌 CSS + 原生 JS，无任何外部依赖。"""
from __future__ import annotations

import html
from datetime import datetime

from .model import DiagReport, Finding, STATUS_LABEL
from .diagnose import STEPS, TimelineStep

CSS = """
:root{--bg:#f5f7fa;--card:#fff;--ink:#1f2933;--muted:#6b7280;--line:#e5e7eb;
--blue:#2563eb;--red:#dc2626;--amber:#d97706;--green:#059669;--code:#0f172a}
*{box-sizing:border-box}
body{margin:0;font:14px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",
"Microsoft YaHei",sans-serif;background:var(--bg);color:var(--ink)}
header{background:linear-gradient(135deg,#1e3a8a,#2563eb);color:#fff;padding:26px 32px}
header h1{margin:0 0 6px;font-size:22px}
header .meta{opacity:.85;font-size:13px}
.wrap{max-width:1180px;margin:0 auto;padding:24px 28px 60px}
nav{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0 24px}
nav a{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:7px 14px;
text-decoration:none;color:var(--blue);font-size:13px}
nav a:hover{border-color:var(--blue)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:20px 24px;margin-bottom:20px;box-shadow:0 1px 2px rgba(15,23,42,.04)}
.card h2{margin:0 0 14px;font-size:17px;border-left:4px solid var(--blue);padding-left:10px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.kpi{background:#f8fafc;border:1px solid var(--line);border-radius:10px;padding:14px}
.kpi .v{font-size:24px;font-weight:700}
.kpi .l{color:var(--muted);font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{border:1px solid var(--line);padding:9px 11px;text-align:left;vertical-align:top}
th{background:#f1f5f9;font-weight:600}
td.mono,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.b-ok{background:#d1fae5;color:var(--green)}
.b-mismatch{background:#fee2e2;color:var(--red)}
.b-warn{background:#fef3c7;color:var(--amber)}
.b-info{background:#dbeafe;color:var(--blue)}
.b-error{background:#fee2e2;color:var(--red)}
.finding{border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:12px;
border-left-width:5px}
.finding.error{border-left-color:var(--red);background:#fff7f7}
.finding.warn{border-left-color:var(--amber);background:#fffdf5}
.finding.info{border-left-color:var(--blue);background:#f7faff}
.finding h3{margin:0 0 6px;font-size:15px}
.finding .src{color:var(--muted);font-size:12px;margin-left:8px}
.finding ul{margin:8px 0 0;padding-left:20px}
.finding li{margin:3px 0}
.fix{background:var(--code);color:#d7e3f4;border-radius:8px;padding:10px 12px;margin:6px 0;
font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;white-space:pre-wrap;word-break:break-all}
.flow{display:flex;flex-wrap:wrap;gap:6px;align:center;margin-bottom:16px}
.fstep{border:1px solid var(--line);border-radius:8px;padding:8px 12px;background:#f8fafc;font-size:12.5px}
.fstep.done{border-color:var(--green);background:#ecfdf5}
.fstep.stuck{border-color:var(--red);background:#fef2f2;font-weight:700}
.fstep .n{display:inline-block;width:18px;height:18px;border-radius:50%;background:#cbd5e1;
color:#fff;text-align:center;line-height:18px;font-size:11px;margin-right:6px}
.fstep.done .n{background:var(--green)}
.fstep.stuck .n{background:var(--red)}
.arrow{color:var(--muted)}
.tl{border-left:2px solid var(--line);margin-left:8px;padding-left:0}
.ev{position:relative;padding:8px 0 8px 22px;font-size:13px}
.ev::before{content:"";position:absolute;left:-7px;top:14px;width:12px;height:12px;border-radius:50%;
background:var(--card);border:2px solid var(--blue)}
.ev.local::before{border-color:var(--blue)}
.ev.remote::before{border-color:var(--amber)}
.ev .t{font-family:ui-monospace,Menlo,monospace;color:var(--muted);font-size:12px;margin-right:8px}
.ev .side{font-weight:700;margin-right:8px}
.ev.local .side{color:var(--blue)}
.ev.remote .side{color:var(--amber)}
.ev .tag{font-size:11px;background:#eef2ff;color:#4338ca;border-radius:5px;padding:1px 6px;margin-right:6px}
.ev .msg{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#334155;word-break:break-all}
.ev.out .msg::before{content:"\\2197 ";color:var(--muted)}
.ev.in .msg::before{content:"\\2198 ";color:var(--muted)}
.filters{margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap}
.filters button{border:1px solid var(--line);background:#fff;border-radius:8px;padding:5px 12px;
cursor:pointer;font-size:12.5px}
.filters button.active{background:var(--blue);color:#fff;border-color:var(--blue)}
.sagroup{border:1px dashed var(--line);border-radius:10px;padding:10px 14px;margin-bottom:14px;background:#fcfdff}
.sagroup h4{margin:4px 0 8px;font-size:13.5px;color:#334155}
.muted{color:var(--muted);font-size:12.5px}
.pill{font-size:11px;padding:1px 8px;border-radius:999px;background:#e5e7eb;margin-right:6px}
"""

JS = """
function setFilter(side, btn){
  document.querySelectorAll('.filters button').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.ev').forEach(ev=>{
    ev.style.display = (side==='all'||ev.classList.contains(side)) ? '' : 'none';
  });
}
function jump(id){document.getElementById(id).scrollIntoView({behavior:'smooth'});}
"""


def esc(x) -> str:
    return html.escape(str(x), quote=True)


def _badge(status: str) -> str:
    label = STATUS_LABEL.get(status, status)
    return f'<span class="badge b-{esc(status)}">{esc(label)}</span>'


def _finding(f: Finding) -> str:
    src = "、".join({"static": "静态配置", "local": "本端日志", "remote": "对端日志"}.get(s, s)
                    for s in f.sources)
    ev = ""
    if f.evidence:
        ev = "<ul>" + "".join(f"<li class='mono'>{esc(e)}</li>" for e in f.evidence) + "</ul>"
    fixes = "".join(f'<div class="fix">{esc(x)}</div>' for x in f.fixes)
    return (f"<div class='finding {esc(f.severity)}'>"
            f"<h3><span class='badge b-{esc(f.severity)}'>"
            f"{'错误' if f.severity == 'error' else '风险' if f.severity == 'warn' else '信息'}"
            f"</span> {esc(f.title)}<span class='src'>来源：{esc(src)}</span></h3>"
            f"<div>{esc(f.detail)}</div>{ev}<div class='muted' style='margin-top:8px'>改法：</div>{fixes}</div>")


def _event(e) -> str:
    t = datetime.fromtimestamp(e.corrected_ts).strftime("%H:%M:%S.%f")[:-3]
    tag = e.etype or (e.subsystem.lower() if e.subsystem else "")
    arrow = e.direction or ""
    exch = f"[{esc(e.exchange)}] " if e.exchange else ""
    sa = f"<span class='pill'>{esc(e.ike or 'pre-SA')}</span>" if e.ike else ""
    return (f"<div class='ev {esc(e.side)} {esc(arrow)}' data-side='{esc(e.side)}'>"
            f"<span class='t'>{t}</span><span class='side'>"
            f"{'本端' if e.side == 'local' else '对端'}</span>"
            f"<span class='tag'>{esc(tag)}</span>{sa}{exch}"
            f"<span class='msg'>{esc(e.message)}</span></div>")


def render(rep: DiagReport) -> str:
    s = rep.summary
    # ---- KPI
    kpis = [
        ("日志事件", s.get("event_count", 0)),
        ("IKE SA 组数", s.get("sa_count", 0)),
        ("错误结论", s.get("error_count", 0)),
        ("风险提示", s.get("warn_count", 0)),
        ("重传次数", s.get("retrans_count", 0)),
        ("rekey 次数", s.get("rekey_count", 0)),
        ("reauth 次数", s.get("reauth_count", 0)),
        ("DELETE 次数", s.get("delete_count", 0)),
    ]
    kpi_html = "".join(f"<div class='kpi'><div class='v'>{esc(v)}</div>"
                       f"<div class='l'>{esc(k)}</div></div>" for k, v in kpis)

    # ---- 协商流程
    flow = []
    stuck = s.get("stuck_step")
    for i, (name, _) in enumerate(STEPS):
        reached = any(t.reached for t in _tl_steps(rep)) and _is_reached(rep, i)
        cls = "done" if reached else ("stuck" if stuck == name else "")
        flow.append(f"<span class='fstep {cls}'><span class='n'>{i + 1}</span>{esc(name)}</span>")
        if i < len(STEPS) - 1:
            flow.append("<span class='arrow'>→</span>")
    flow_html = "".join(flow)

    # ---- 静态比对表
    static_html = "<p class='muted'>未提供两端配置，跳过静态比对。</p>"
    if rep.static and rep.static.rows:
        rows = "".join(
            f"<tr><td>{esc(r.item)}</td><td class='mono'>{esc(r.local_value)}</td>"
            f"<td class='mono'>{esc(r.remote_value)}</td><td>{_badge(r.status)}</td>"
            f"<td class='muted'>{esc(r.note)}</td></tr>" for r in rep.static.rows)
        conn = f"{esc(rep.static.conn_local)} ↔ {esc(rep.static.conn_remote)}"
        static_html = (f"<p class='muted'>配对连接：{conn}</p>"
                       f"<table><thead><tr><th>比对项</th><th>本端</th><th>对端</th>"
                       f"<th>结论</th><th>说明</th></tr></thead><tbody>{rows}</tbody></table>")

    # ---- 结论
    findings_html = "".join(_finding(f) for f in rep.findings) or \
        "<p class='muted'>未发现明显问题：若业务仍中断，按时间轴最后一步抓包确认链路层。</p>"

    # ---- 时间轴
    skew_txt = ("未估计（缺少任一端日志或无法配对）" if rep.clock_skew is None
                else f"{rep.clock_skew:+.3f} 秒（基于 {rep.skew_pairs} 组收发配对，对端时间已修正显示）")
    tl_html_parts = [f"<p class='muted'>时钟偏移估计：{esc(skew_txt)}</p>",
                     "<div class='filters'><button class='active' onclick=\"setFilter('all',this)\">全部</button>",
                     "<button onclick=\"setFilter('local',this)\">仅本端</button>",
                     "<button onclick=\"setFilter('remote',this)\">仅对端</button></div>"]
    if rep.groups:
        for g in rep.groups:
            evs = "".join(_event(e) for e in g.events)
            tl_html_parts.append(
                f"<div class='sagroup'><h4>IKE_SA {esc(g.key)} "
                f"<span class='pill'>{esc(g.phase)}</span>"
                f"<span class='pill'>{esc(' / '.join(g.exchanges) or '无交换记录')}</span>"
                f"<span class='muted'>{len(g.events)} 条事件</span></h4><div class='tl'>{evs}</div></div>")
    else:
        tl_html_parts.append("<p class='muted'>没有可解析的 charon 日志。</p>")

    # ---- 输入与解析错误
    inputs = "".join(f"<tr><td>{esc(k)}</td><td class='mono'>{esc(v)}</td></tr>"
                     for k, v in rep.inputs.items())
    parse_err = ""
    for side, sc in rep.side_config.items():
        for err in sc.parse_errors:
            parse_err += f"<li>{esc(side)}: {esc(err)}</li>"
    parse_block = f"<ul>{parse_err}</ul>" if parse_err else "<p class='muted'>无解析错误。</p>"

    fmt = lambda dt: dt  # noqa
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IPSec/strongSwan 协商诊断报告</title>
<style>{CSS}</style></head><body>
<header><h1>IPSec / strongSwan 站点间隧道诊断报告</h1>
<div class="meta">生成时间 {esc(rep.generated_at)} ｜ 日志补全年份 {esc(rep.log_year)} ｜
静态比对 + 双端 charon 日志时间对齐重建</div></header>
<div class="wrap">
<nav><a onclick="jump('overview')">总览</a><a onclick="jump('flow')">协商流程</a>
<a onclick="jump('findings')">诊断结论与改法 ({len(rep.findings)})</a>
<a onclick="jump('static')">静态配置比对</a>
<a onclick="jump('timeline')">双端时间轴</a><a onclick="jump('inputs')">输入与解析</a></nav>

<section class="card" id="overview"><h2>一、总览</h2><div class="kpis">{kpi_html}</div>
<p style="margin-top:14px">曾成功建立 CHILD_SA：
<b>{'是' if s.get('ever_established') else '否'}</b> ｜ 卡点：
<b>{esc(s.get('stuck_step') or '无（流程走通，问题在保活/链路层）')}</b> ｜
时间轴跨度：{esc(round(s.get('time_span', 0), 1))} 秒</p></section>

<section class="card" id="flow"><h2>二、协商流程还原（IKEv2 站点间标准 7 步）</h2>
<div class="flow">{flow_html}</div>
<p class="muted">绿色=日志中出现过该步骤；红色框=流程停滞步骤。</p></section>

<section class="card" id="findings"><h2>三、诊断结论与修改建议</h2>{findings_html}</section>

<section class="card" id="static"><h2>四、静态配置比对（swanctl.conf / ipsec.conf 双格式）</h2>
{static_html}</section>

<section class="card" id="timeline"><h2>五、双端 charon 日志对齐时间轴</h2>
{''.join(tl_html_parts)}</section>

<section class="card" id="inputs"><h2>六、输入文件与解析状态</h2>
<table><tbody>{inputs}</tbody></table><div style="margin-top:10px">{parse_block}</div></section>
</div><script>{JS}</script></body></html>"""


def _tl_steps(rep: DiagReport) -> list[TimelineStep]:
    # 复用 diagnose.build_timeline 的结果（由 main 注入 summary 时步骤缓存在 rep 上）
    return getattr(rep, "_timeline", [])


def _is_reached(rep: DiagReport, i: int) -> bool:
    tl = _tl_steps(rep)
    return bool(tl and tl[i].reached)
