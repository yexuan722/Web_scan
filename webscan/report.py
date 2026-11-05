"""报告导出：自包含 HTML、Markdown、JSON。"""

from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Any

from .models import SEV_LABEL, SEVERITIES

SEV_COLOR = {
    "critical": "#b3261e",
    "high": "#d93025",
    "medium": "#e8710a",
    "low": "#1a73e8",
    "info": "#5f6368",
}


def _esc(text: Any) -> str:
    return html.escape(str(text or ""))


def to_json(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def to_markdown(data: dict[str, Any]) -> str:
    target = data.get("target", "")
    lines = [
        f"# WebScan 安全扫描报告",
        "",
        f"- 目标：{target}",
        f"- 扫描时间：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data.get('started_at', 0)))}",
        f"- 健康评分：**{data.get('score', 0)} / 100**（{data.get('grade_label', '')}）",
        f"- 发现总数：{len(data.get('findings', []))}",
        "",
        "## 风险分布",
        "",
        "| 等级 | 数量 |",
        "| --- | --- |",
    ]
    counts = {s: 0 for s in SEVERITIES}
    for f in data.get("findings", []):
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    for sev in SEVERITIES:
        lines.append(f"| {SEV_LABEL[sev]} | {counts[sev]} |")
    lines += ["", "## 漏洞清单", ""]

    for i, f in enumerate(data.get("findings", []), 1):
        lines += [
            f"### {i}. [{SEV_LABEL.get(f['severity'], f['severity'])}] {f['title']}",
            "",
            f"- 规则：`{f['rule_id']}`　置信度：{f['confidence']}　已验证：{'是' if f['verified'] else '否'}",
            f"- 位置：`{f['url']}`" + (f"　参数：`{f['param']}`" if f.get("param") else ""),
            f"- 说明：{f['detail']}",
            f"- 修复建议：{f['remediation']}",
        ]
        if f.get("evidence"):
            lines += ["", "```", f["evidence"], "```"]
        if f.get("response_snippet"):
            lines += ["", "响应片段：", "```", f["response_snippet"][:800], "```"]
        lines.append("")
    return "\n".join(lines)


def to_html(data: dict[str, Any]) -> str:
    target = _esc(data.get("target", ""))
    score = data.get("score", 0)
    grade = _esc(data.get("grade_label", ""))
    grade_key = data.get("grade", "")
    started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data.get("started_at", 0)))
    findings = data.get("findings", [])
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    score_color = {"good": "#188038", "fair": "#e8710a", "risky": "#d93025", "bad": "#b3261e"}.get(
        grade_key, "#5f6368"
    )

    cards = []
    for f in findings:
        color = SEV_COLOR.get(f["severity"], "#5f6368")
        ev = ""
        if f.get("evidence"):
            ev += f"<div class='lbl'>证据</div><pre>{_esc(f['evidence'])}</pre>"
        if f.get("response_snippet"):
            ev += f"<div class='lbl'>响应片段</div><pre>{_esc(f['response_snippet'][:1500])}</pre>"
        if f.get("request_snippet"):
            ev += f"<div class='lbl'>请求</div><pre>{_esc(f['request_snippet'])}</pre>"
        cards.append(
            f"""
    <div class="card">
      <div class="card-h">
        <span class="badge" style="background:{color}">{SEV_LABEL.get(f['severity'], f['severity'])}</span>
        <span class="title">{_esc(f['title'])}</span>
        <span class="rid">{_esc(f['rule_id'])}</span>
      </div>
      <div class="meta">位置 <code>{_esc(f['url'])}</code>
        {(' · 参数 <code>' + _esc(f['param']) + '</code>') if f.get('param') else ''}
        · 置信度 {f['confidence']} · {'已验证' if f['verified'] else '未验证'}</div>
      <p>{_esc(f['detail'])}</p>
      <div class="fix"><b>修复建议：</b>{_esc(f['remediation'])}</div>
      {ev}
    </div>"""
        )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WebScan 报告 - {target}</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
         background:#f5f6f8; color:#1f2328; line-height:1.65; }}
  .wrap {{ max-width: 960px; margin: 0 auto; padding: 32px 20px 80px; }}
  header {{ display:flex; align-items:center; justify-content:space-between; gap:24px;
            background:#fff; border-radius:14px; padding:24px 28px; box-shadow:0 1px 3px rgba(0,0,0,.08); }}
  h1 {{ font-size:20px; margin:0 0 6px; }}
  .sub {{ color:#5f6368; font-size:13px; }}
  .score {{ text-align:center; min-width:130px; }}
  .score .n {{ font-size:44px; font-weight:700; color:{score_color}; line-height:1; }}
  .score .g {{ font-size:13px; color:{score_color}; margin-top:4px; }}
  .dist {{ display:flex; gap:10px; margin:20px 0 28px; flex-wrap:wrap; }}
  .dist div {{ background:#fff; border-radius:10px; padding:10px 18px; font-size:13px;
               box-shadow:0 1px 2px rgba(0,0,0,.06); }}
  .dist b {{ font-size:18px; display:block; }}
  .card {{ background:#fff; border-radius:12px; padding:18px 20px; margin-bottom:14px;
           box-shadow:0 1px 3px rgba(0,0,0,.07); border-left:4px solid #ddd; }}
  .card-h {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .badge {{ color:#fff; font-size:12px; padding:2px 9px; border-radius:20px; }}
  .title {{ font-weight:600; font-size:15px; }}
  .rid {{ margin-left:auto; font-size:12px; color:#8a8f98; font-family:ui-monospace, monospace; }}
  .meta {{ font-size:12.5px; color:#5f6368; margin:6px 0 8px; word-break:break-all; }}
  code {{ background:#f1f3f4; padding:1px 5px; border-radius:4px; font-size:12.5px; }}
  pre {{ background:#0d1117; color:#d1d5db; padding:12px 14px; border-radius:8px;
         overflow:auto; font-size:12px; line-height:1.5; white-space:pre-wrap; word-break:break-all; }}
  .lbl {{ font-size:12px; color:#8a8f98; margin:10px 0 4px; }}
  .fix {{ background:#f6f8fa; border-radius:8px; padding:10px 12px; font-size:13px; }}
  .card {{ border-left-color: var(--c, #ddd); }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>WebScan 安全扫描报告</h1>
      <div class="sub">{target} · {started}</div>
    </div>
    <div class="score">
      <div class="n">{score}</div>
      <div class="g">{grade}</div>
    </div>
  </header>

  <div class="dist">
    {''.join(f'<div><b>{counts[s]}</b>{SEV_LABEL[s]}</div>' for s in SEVERITIES)}
  </div>

  {''.join(cards) if cards else '<p style="color:#5f6368">未发现风险项。</p>'}
</div>
</body>
</html>"""


def write_report(data: dict[str, Any], out_dir: Path) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"scan-{data.get('id', 'report')}"
    paths = {}
    for fmt, content in (
        ("html", to_html(data)),
        ("md", to_markdown(data)),
        ("json", to_json(data)),
    ):
        p = out_dir / f"{stem}.{fmt}"
        p.write_text(content, encoding="utf-8")
        paths[fmt] = str(p)
    return paths
