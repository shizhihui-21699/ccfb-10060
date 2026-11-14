# -*- coding: utf-8 -*-
"""命令行入口。

两种输入布局：
  1) --local-conf/--remote-conf/--local-log/--remote-log 显式指定
  2) --local-dir DIR --remote-dir DIR 自动发现 swanctl.conf|ipsec.conf、charon.log|ipsec.log|syslog
另提供：
  --gen-samples DIR   生成 7 组典型故障样例
  --demo DIR          对样例逐组跑完整分析并输出报告 + 索引页
"""
from __future__ import annotations

import argparse
import glob
import os
import sys
from datetime import datetime

from . import __version__
from .config_parser import parse_config
from .diagnose import build_timeline, diagnose_logs, merge_findings, summarize
from .html_report import render
from .log_parser import apply_skew, estimate_skew, group_sa_lifecycles, parse_log
from .model import DiagReport
from .static_check import compare

CONF_GLOBS = ("swanctl.conf", "ipsec.conf", "*.swanctl.conf", "ipsec*.conf")
LOG_GLOBS = ("charon.log", "charon*.log", "ipsec.log", "syslog", "*.log")


def discover(directory: str, globs: tuple[str, ...]) -> str | None:
    for g in globs:
        hits = sorted(p for p in glob.glob(os.path.join(directory, g))
                      if os.path.isfile(p) and os.path.getsize(p) > 0)
        if hits:
            return hits[0]
    return None


def build_report(local_conf: str | None, remote_conf: str | None,
                 local_log: str | None, remote_log: str | None,
                 log_year: int) -> DiagReport:
    rep = DiagReport(generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     log_year=log_year)
    rep.inputs = {k: v for k, v in {
        "本端配置": local_conf, "对端配置": remote_conf,
        "本端日志": local_log, "对端日志": remote_log}.items() if v}

    # ---- 配置
    if local_conf:
        rep.side_config["local"] = parse_config(local_conf, "local")
    if remote_conf:
        rep.side_config["remote"] = parse_config(remote_conf, "remote")
    if "local" in rep.side_config and "remote" in rep.side_config:
        rep.static = compare(rep.side_config["local"], rep.side_config["remote"])

    # ---- 日志
    events = []
    if local_log:
        events.extend(parse_log(local_log, "local", log_year))
    if remote_log:
        events.extend(parse_log(remote_log, "remote", log_year))
    skew, pairs = estimate_skew(events)
    rep.clock_skew, rep.skew_pairs = skew, pairs
    apply_skew(events, skew)
    events.sort(key=lambda e: (e.corrected_ts, 0 if e.side == "local" else 1))
    rep.events = events
    rep.groups = group_sa_lifecycles(events)
    timeline = build_timeline(events)
    setattr(rep, "_timeline", timeline)

    log_findings = diagnose_logs(events, rep.groups, timeline)
    rep.findings = merge_findings(rep.static, log_findings)
    rep.summary = summarize(events, rep.groups, timeline, rep.findings)
    return rep


def write_report(rep: DiagReport, out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(render(rep))


def _resolve_dirs(args: argparse.Namespace) -> tuple[str | None, str | None, str | None, str | None]:
    lc, rc, ll, rl = args.local_conf, args.remote_conf, args.local_log, args.remote_log
    if args.local_dir:
        lc = lc or discover(args.local_dir, CONF_GLOBS)
        ll = ll or discover(args.local_dir, LOG_GLOBS)
    if args.remote_dir:
        rc = rc or discover(args.remote_dir, CONF_GLOBS)
        rl = rl or discover(args.remote_dir, LOG_GLOBS)
    return lc, rc, ll, rl


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ipsec_diag",
        description="strongSwan/IPSec 站点间隧道排障：静态配置比对 + 双端 charon 日志协商重建，出 HTML")
    p.add_argument("--local-conf", help="本端 swanctl.conf 或 ipsec.conf 路径")
    p.add_argument("--remote-conf", help="对端 swanctl.conf 或 ipsec.conf 路径")
    p.add_argument("--local-log", help="本端 charon 日志路径")
    p.add_argument("--remote-log", help="对端 charon 日志路径")
    p.add_argument("--local-dir", help="本端目录（自动发现配置和日志）")
    p.add_argument("--remote-dir", help="对端目录（自动发现配置和日志）")
    p.add_argument("-o", "--output", default="ipsec_diag_report.html", help="HTML 输出路径")
    p.add_argument("--log-year", type=int, default=datetime.now().year,
                   help="syslog 格式日志没有年份，用该值补齐（默认当前年）")
    p.add_argument("--gen-samples", metavar="DIR", help="在 DIR 下生成 7 组典型故障样例")
    p.add_argument("--demo", metavar="SAMPLES_DIR",
                   help="对样例目录逐组分析，报告写到 ./demo_reports/ 并生成索引页")
    p.add_argument("--selftest", action="store_true", help="内置解析/比对/日志规则自检")
    p.add_argument("--version", action="version", version=f"ipsec_diag {__version__}")
    args = p.parse_args(argv)

    if args.gen_samples:
        from .samples import generate_samples
        info = generate_samples(args.gen_samples)
        print(f"已生成 {len(info)} 组样例到 {os.path.abspath(args.gen_samples)}")
        for sid, desc in info.items():
            print(f"  {sid}: {desc}")
        return 0

    if args.demo:
        return run_demo(args.demo, args.log_year)

    if args.selftest:
        from .selftest import run_selftest
        return run_selftest()

    lc, rc, ll, rl = _resolve_dirs(args)
    if not any((lc, rc, ll, rl)):
        p.error("至少要给一对配置或日志（显式路径或 --local-dir/--remote-dir）")
    rep = build_report(lc, rc, ll, rl, args.log_year)
    write_report(rep, args.output)
    print(f"报告已生成：{os.path.abspath(args.output)}")
    print(f"结论 {len(rep.findings)} 条（错误 {rep.summary.get('error_count', 0)} / "
          f"风险 {rep.summary.get('warn_count', 0)}），事件 {rep.summary.get('event_count', 0)} 条，"
          f"SA 组 {rep.summary.get('sa_count', 0)} 个")
    return 0


def run_demo(samples_dir: str, log_year: int) -> int:
    from .samples import SCENARIOS
    out_dir = os.path.join(os.getcwd(), "demo_reports")
    os.makedirs(out_dir, exist_ok=True)
    index_rows = []
    for sid in sorted(SCENARIOS):
        base = os.path.join(samples_dir, sid)
        lc = discover(os.path.join(base, "local"), CONF_GLOBS)
        rc = discover(os.path.join(base, "remote"), CONF_GLOBS)
        ll = discover(os.path.join(base, "local"), LOG_GLOBS)
        rl = discover(os.path.join(base, "remote"), LOG_GLOBS)
        rep = build_report(lc, rc, ll, rl, log_year)
        out = os.path.join(out_dir, f"{sid}.html")
        write_report(rep, out)
        index_rows.append((sid, SCENARIOS[sid], out, rep))
        print(f"[OK] {sid}: {len(rep.findings)} 条结论 -> {out}")
    # 索引页
    cards = []
    for sid, desc, out, rep in index_rows:
        href = os.path.basename(out)
        sev = "".join(
            f"<span class='badge b-{f.severity}'>{f.severity}</span>" for f in rep.findings[:4])
        cards.append(f"<li><a href='{href}'><b>{esc(sid)}</b></a> — {esc(desc)}<br>"
                     f"<span class='muted'>错误 {rep.summary['error_count']} / 风险 "
                     f"{rep.summary['warn_count']} / 事件 {rep.summary['event_count']}</span> {sev}</li>")
    index = f"""<!DOCTYPE html><html lang="zh-CN"><meta charset="utf-8">
<title>ipsec_diag 样例诊断索引</title><style>
body{{font:14px -apple-system,"PingFang SC",sans-serif;max-width:900px;margin:40px auto;padding:0 20px}}
li{{margin:14px 0;line-height:1.7}} .badge{{padding:2px 8px;border-radius:999px;font-size:11px;margin-left:6px}}
.b-error{{background:#fee2e2;color:#dc2626}}.b-warn{{background:#fef3c7;color:#d97706}}
.b-info{{background:#dbeafe;color:#2563eb}}.muted{{color:#6b7280;font-size:12.5px}}</style>
<h1>ipsec_diag 七组典型故障诊断索引</h1><ul>{''.join(cards)}</ul></html>"""
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(index)
    print(f"索引页：{os.path.join(out_dir, 'index.html')}")
    return 0


def esc(x) -> str:
    from html import escape
    return escape(str(x))


if __name__ == "__main__":
    sys.exit(main())
