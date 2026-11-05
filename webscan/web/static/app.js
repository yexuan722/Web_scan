/* WebScan 前端逻辑：无框架，fetch + 轮询 */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const SEV_LABEL = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" };
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const STAGE_LABEL = { crawl: "爬取", analyze: "分析", probe: "探测", active: "主动检测" };
const STAGE_WEIGHT = { crawl: 50, analyze: 15, probe: 10, active: 25 };

let state = { scanId: null, timer: null, view: "new" };

/* 服务端注入的一次性令牌：写操作必须带上，防止本地网页跨站调用 */
const TOKEN = document.querySelector('meta[name="webscan-token"]')?.content || "";
function authHeaders(extra = {}) {
  const h = { ...extra };
  if (TOKEN && TOKEN !== "__WEBSCAN_TOKEN__") h["X-WebScan-Token"] = TOKEN;
  return h;
}

/* ---------------------------------------------------------------- 工具 */
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function fmtTime(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function gradeColor(score) {
  if (score >= 90) return "var(--good)";
  if (score >= 75) return "var(--fair)";
  if (score >= 50) return "var(--risky)";
  return "var(--bad)";
}

/* ---------------------------------------------------------------- 导航 */
function switchView(view) {
  state.view = view;
  $$(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  $$(".view").forEach((v) => v.classList.add("hidden"));
  $(`#view-${view}`).classList.remove("hidden");
  if (view === "history") loadHistory();
}

$$(".nav-item").forEach((btn) => btn.addEventListener("click", () => switchView(btn.dataset.view)));

/* ---------------------------------------------------------------- 表单 */
$("#maxPages").addEventListener("input", (e) => ($("#maxPagesVal").textContent = e.target.value));
$("#maxDepth").addEventListener("input", (e) => ($("#maxDepthVal").textContent = e.target.value));

$("#url").addEventListener("keydown", (e) => {
  if (e.key === "Enter") startScan();
});

$("#startBtn").addEventListener("click", startScan);

async function startScan() {
  const url = $("#url").value.trim();
  const warn = $("#warnBox");
  warn.textContent = "";

  if (!url) { warn.textContent = "请输入目标地址"; return; }
  if (!$("#authorized").checked) {
    warn.textContent = "请先勾选授权确认 —— 未授权扫描他人站点是违法行为。";
    return;
  }

  $("#startBtn").disabled = true;
  $("#startBtn").textContent = "扫描中…";
  $("#reportArea").innerHTML = "";
  $("#progressCard").classList.remove("hidden");
  $("#progressTitle").textContent = "正在扫描";
  $("#progressPct").textContent = "0%";
  $("#barFill").style.width = "0%";
  $("#progressMsg").textContent = "提交任务…";
  renderStages("crawl", 0);

  try {
    const res = await fetch("/api/scans", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        url,
        max_pages: Number($("#maxPages").value),
        max_depth: Number($("#maxDepth").value),
        deep: $("#deep").checked,
        authorized: true,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `请求失败 (${res.status})`);
    }
    const data = await res.json();
    state.scanId = data.id;
    poll();
  } catch (err) {
    warn.textContent = err.message;
    resetStartButton();
  }
}

function resetStartButton() {
  $("#startBtn").disabled = false;
  $("#startBtn").textContent = "开始扫描";
}

/* ---------------------------------------------------------------- 轮询 */
function poll() {
  clearTimeout(state.timer);
  state.timer = setTimeout(async () => {
    try {
      const res = await fetch(`/api/scans/${state.scanId}`);
      if (!res.ok) throw new Error("任务已丢失");
      const scan = await res.json();
      renderProgress(scan);

      if (scan.status === "done") {
        resetStartButton();
        renderReport(scan);
        $("#progressTitle").textContent = "扫描完成";
      } else if (scan.status === "failed") {
        resetStartButton();
        $("#progressTitle").textContent = "扫描失败";
        $("#progressMsg").textContent = scan.error || "未知错误";
      } else {
        state.timer = setTimeout(poll, 900);
      }
    } catch (err) {
      $("#progressMsg").textContent = err.message;
      resetStartButton();
    }
  }, 900);
}

/* ---------------------------------------------------------------- 进度 */
function renderStages(activeStage, doneMap = {}) {
  const order = ["crawl", "analyze", "probe", "active"];
  $("#stages").innerHTML = order
    .map((s) => {
      let cls = "";
      if (s === activeStage) cls = "active";
      else if (order.indexOf(s) < order.indexOf(activeStage)) cls = "done";
      return `<span class="stage-chip ${cls}">${STAGE_LABEL[s]}</span>`;
    })
    .join("");
}

function renderProgress(scan) {
  const p = scan.progress || {};
  const stage = p.stage || "crawl";
  if (stage !== "start" && stage !== "queued") renderStages(stage);

  let pct = 0;
  if (scan.status === "done") {
    pct = 100;
  } else if (stage === "crawl") {
    const ratio = p.total ? Math.min(1, p.done / p.total) : 0;
    pct = ratio * STAGE_WEIGHT.crawl;
  } else {
    const base = { analyze: 50, probe: 65, active: 75 }[stage] ?? 50;
    const span = STAGE_WEIGHT[stage] || 10;
    const ratio = p.total ? Math.min(1, p.done / p.total) : 0;
    pct = base + ratio * span;
  }

  $("#barFill").style.width = `${Math.round(pct)}%`;
  $("#progressPct").textContent = `${Math.round(pct)}%`;
  if (p.message) $("#progressMsg").textContent = p.message;
}

/* ---------------------------------------------------------------- 报告 */
function renderReport(scan) {
  const findings = scan.findings || [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => (counts[f.severity] = (counts[f.severity] || 0) + 1));

  const score = scan.score || 0;
  const color = gradeColor(score);
  const C = 2 * Math.PI * 52;
  const offset = C * (1 - score / 100);
  const stats = scan.stats || {};

  const chips = SEV_ORDER.filter((s) => counts[s] > 0)
    .map((s) => `<span class="chip c-${s}">${SEV_LABEL[s]} <b>${counts[s]}</b></span>`)
    .join("");

  const metaChips = [
    `<span class="chip">页面 <b>${stats.pages ?? 0}</b></span>`,
    `<span class="chip">请求 <b>${stats.requests ?? 0}</b></span>`,
    `<span class="chip">耗时 <b>${stats.elapsed ?? 0}s</b></span>`,
    `<span class="chip">正文截断 <b>${stats.truncated_pages ?? 0}</b></span>`,
  ].join("");

  const cards = findings
    .map((f, i) => {
      const ev = [];
      if (f.evidence) ev.push(`<div class="lbl">证据</div><pre>${esc(f.evidence)}</pre>`);
      if (f.request_snippet) ev.push(`<div class="lbl">请求</div><pre>${esc(f.request_snippet)}</pre>`);
      if (f.response_snippet) ev.push(`<div class="lbl">响应片段</div><pre>${esc(f.response_snippet)}</pre>`);
      return `
      <details class="finding">
        <summary>
          <span class="badge sev-${f.severity}">${SEV_LABEL[f.severity] || f.severity}</span>
          <span class="f-title">${esc(f.title)}</span>
          <span class="f-verified">${esc(f.assessment ?? (f.verified ? "已验证" : "疑似"))}</span>
          <span class="f-rule">${esc(f.rule_id)}</span>
        </summary>
        <div class="finding-body">
          <div class="meta">位置 <code>${esc(f.url)}</code>${f.param ? ` · 参数 <code>${esc(f.param)}</code>` : ""}
            · 置信度 ${f.confidence}</div>
          <p>${esc(f.detail)}</p>
          ${f.remediation ? `<div class="fix"><b>修复建议：</b>${esc(f.remediation)}</div>` : ""}
          ${ev.join("")}
        </div>
      </details>`;
    })
    .join("");

  $("#reportArea").innerHTML = `
    <div class="card report-head">
      <div class="gauge">
        <svg width="122" height="122" viewBox="0 0 122 122">
          <circle cx="61" cy="61" r="52" fill="none" stroke="#eef1f5" stroke-width="10"></circle>
          <circle cx="61" cy="61" r="52" fill="none" stroke="${color}" stroke-width="10"
                  stroke-linecap="round" stroke-dasharray="${C}" stroke-dashoffset="${offset}"
                  style="transition: stroke-dashoffset .8s ease"></circle>
        </svg>
        <div class="num" style="color:${color}">${score}</div>
      </div>
      <div class="report-meta">
        <h2>健康评分 ${score} / 100 · <span style="color:${color}">${esc(scan.grade_label || "")}</span></h2>
        <div class="target">${esc(scan.target)} · ${fmtTime(scan.started_at)}</div>
        <div class="chips">${chips || '<span class="chip">未发现风险项</span>'}</div>
        <div class="chips">${metaChips}</div>
        <div class="actions">
          <a class="btn ghost" href="/api/scans/${scan.id}/export?fmt=html" target="_blank">导出 HTML</a>
          <a class="btn ghost" href="/api/scans/${scan.id}/export?fmt=md" target="_blank">导出 Markdown</a>
          <a class="btn ghost" href="/api/scans/${scan.id}/export?fmt=json" target="_blank">导出 JSON</a>
        </div>
      </div>
    </div>
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:14px">
        <b style="font-size:15px">漏洞清单</b>
        <span style="color:var(--muted);font-size:12.5px">共 ${findings.length} 条，点击展开证据</span>
      </div>
      ${cards || '<div class="empty">未发现风险项 🎉</div>'}
    </div>`;

  $("#progressCard").classList.add("hidden");
  try {
    history.replaceState(null, "", `#scan/${scan.id}`);
  } catch (_) { /* file:// 下忽略 */ }
  $("#reportArea").scrollIntoView({ behavior: "smooth", block: "start" });
}

/* ---------------------------------------------------------------- 历史 */
async function loadHistory() {
  const box = $("#historyList");
  box.innerHTML = '<div class="empty">加载中…</div>';
  try {
    const res = await fetch("/api/scans");
    const data = await res.json();
    if (!data.items.length) {
      box.innerHTML = '<div class="empty">还没有扫描记录</div>';
      return;
    }
    box.innerHTML = data.items
      .map(
        (s) => `
      <div class="h-item" data-id="${s.id}">
        <div>
          <div class="h-target">${esc(s.target)}</div>
          <div class="h-time">${fmtTime(s.started_at)} · ${s.status} · ${(s.stats && s.stats.pages) || 0} 页</div>
        </div>
        <div class="h-score" style="color:${s.status === "done" ? gradeColor(s.score) : "var(--muted)"}">
          ${s.status === "done" ? s.score : "—"}
        </div>
        <span class="h-del" data-del="${s.id}">删除</span>
      </div>`
      )
      .join("");

    $$(".h-item").forEach((el) => {
      el.addEventListener("click", async (ev) => {
        if (ev.target.dataset.del) {
          ev.stopPropagation();
          await fetch(`/api/scans/${ev.target.dataset.del}`, {
            method: "DELETE",
            headers: authHeaders(),
          });
          loadHistory();
          return;
        }
        const scan = await (await fetch(`/api/scans/${el.dataset.id}`)).json();
        switchView("new");
        $("#progressCard").classList.add("hidden");
        renderReport(scan);
      });
    });
  } catch (err) {
    box.innerHTML = `<div class="empty">加载失败：${esc(err.message)}</div>`;
  }
}

/* ---------------------------------------------------------------- 启动 */
(async function init() {
  try {
    const h = await (await fetch("/api/health")).json();
    document.title = `${h.name} ${h.version} · Web 漏洞扫描器`;
  } catch (_) { /* 忽略 */ }

  // 直接打开 /#scan/<id> 时恢复报告
  const m = location.hash.match(/^#scan\/([0-9a-zA-Z]+)/);
  if (m) {
    try {
      const scan = await (await fetch(`/api/scans/${m[1]}`)).json();
      if (scan && scan.id) {
        $("#progressCard").classList.add("hidden");
        renderReport(scan);
      }
    } catch (_) { /* 无效 id 忽略 */ }
  }
})();
