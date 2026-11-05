/* WebScan 工作台。目标站返回的内容只作为文本显示。 */
const $ = (selector) => document.querySelector(selector);
const token = $('meta[name="webscan-token"]').content;
const severity = {critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示"};
const labels = {home: "工作台", scan: "新建扫描", map: "网站地图", findings: "漏洞复核", checkup: "安全体检", history: "扫描历史"};
const scanStatus = {pending: "排队中", running: "运行中", done: "已完成", failed: "失败"};
const stages = {crawl: "爬取页面", analyze: "分析响应", probe: "额外探测", active: "深度检测"};
const state = {view: "", scans: [], selected: "", scan: null, taskId: "", generation: 0};

function element(tag, text, css) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (css) node.className = css;
  return node;
}
function button(text, action, css) {
  const node = element("button", text, css);
  node.type = "button";
  node.addEventListener("click", () => Promise.resolve().then(action).catch(showError));
  return node;
}
function notice(text, error = false) {
  const node = $("#notice");
  node.hidden = !text;
  node.textContent = text;
  node.classList.toggle("error", error);
}
function showError(error) { notice(error.message, true); }

async function api(path, body, method = body === undefined ? "GET" : "POST") {
  const response = await fetch(path, {
    method, headers: {"X-WebScan-Token": token, "Content-Type": "application/json"},
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || "操作失败");
  return data;
}
function scanPath(id) { return "/api/scans/" + encodeURIComponent(id); }
function time(value) { return value ? new Date(value * 1000).toLocaleString() : "—"; }
function empty(node, text) { node.replaceChildren(element("p", text, "muted")); }
function updateSelect(id) {
  const select = $(id);
  const finished = state.scans.filter((scan) => scan.status === "done");
  if (!finished.some((scan) => scan.id === state.selected)) state.selected = finished[0]?.id || "";
  select.replaceChildren(...finished.map((scan) => new Option(scan.target + " · " + time(scan.started_at), scan.id)));
  select.value = state.selected;
  select.disabled = !finished.length;
}
async function refresh() { state.scans = (await api("/api/scans")).items; }

function scanRow(scan, compact) {
  const row = element("div", undefined, "row");
  row.append(element("strong", scan.target), element("p", time(scan.started_at) + " · " + (scanStatus[scan.status] || scan.status), "muted"));
  const actions = element("div", undefined, "actions");
  if (scan.status === "done") {
    actions.append(
      button("网站地图", () => go("map", scan.id)),
      button("查看发现", () => go("findings", scan.id))
    );
    if (!compact) {
      for (const [kind, label] of [["html", "HTML"], ["md", "Markdown"], ["json", "JSON"]]) {
        const link = element("a", "导出 " + label, "button");
        link.href = scanPath(scan.id) + "/export?fmt=" + kind;
        link.download = "";
        actions.append(link);
      }
    }
  } else if (scan.status === "pending" || scan.status === "running") {
    if (scan.progress?.message) row.append(element("p", scan.progress.message, "muted"));
    actions.append(button("查看进度", () => { go("scan"); return track(scan.id); }));
  } else if (scan.status === "failed") {
    actions.append(button("查看错误", async () => notice((await api(scanPath(scan.id))).error || "扫描失败", true)));
  }
  if (!compact && ["done", "failed"].includes(scan.status)) {
    actions.append(button("删除记录", async () => {
      if (!window.confirm("删除这次扫描及其本地快照和复核记录？")) return;
      await api(scanPath(scan.id), undefined, "DELETE");
      await go("history");
    }));
  }
  row.append(actions);
  return row;
}
function renderHistory(node, scans, compact = false) {
  if (!scans.length) { empty(node, "还没有扫描记录。可以先运行一次本地演示。"); return; }
  node.replaceChildren(...scans.map((scan) => scanRow(scan, compact)));
}
function dashboard() {
  const last = state.scans.find((scan) => scan.status === "done");
  const counts = last?.stats?.counts || {};
  const cards = [
    ["最近记录", state.scans.length],
    ["进行中", state.scans.filter((scan) => scan.status === "pending" || scan.status === "running").length],
    ["最近一次抓取页面", last?.stats?.pages ?? "—"],
    ["最近健康参考分", last ? last.score + "/100" : "—"],
  ];
  $("#metrics").replaceChildren(...cards.map(([title, value]) => {
    const card = element("div", undefined, "card metric");
    card.append(element("span", title, "muted"), element("strong", value));
    return card;
  }));
  const recent = $("#recent");
  renderHistory(recent, state.scans.slice(0, 5), true);
  if (last) {
    const distribution = element("div", undefined, "row");
    distribution.append(element("strong", "最近完成 · 风险分布"), element("br"));
    for (const [key, label] of Object.entries(severity)) {
      distribution.append(element("span", label + " " + (counts[key] || 0), "badge sev-" + key));
    }
    recent.prepend(distribution);
  }
}

async function go(view, id) {
  if (id) state.selected = id;
  state.view = view;
  const generation = ++state.generation;
  for (const name of Object.keys(labels)) $("#" + name).hidden = name !== view;
  for (const nav of document.querySelectorAll("[data-view]")) {
    nav.classList.toggle("active", nav.dataset.view === view);
    if (nav.dataset.view === view) nav.setAttribute("aria-current", "page");
    else nav.removeAttribute("aria-current");
  }
  $("#breadcrumb").textContent = labels[view];
  notice("");
  if (view === "scan" || view === "checkup") return;
  await refresh();
  if (generation !== state.generation) return;
  if (view === "home") dashboard();
  if (view === "history") renderHistory($("#historyList"), state.scans);
  if (view === "map" || view === "findings") {
    updateSelect(view === "map" ? "#mapScan" : "#findingScan");
    if (view === "map") await renderMap(generation);
    else await loadFindings(generation);
  }
}
async function renderMap(generation) {
  const tree = $("#tree"), detail = $("#pageDetail");
  empty(detail, "选择一个页面查看详情。");
  if (!state.selected) { empty(tree, "请先完成一次扫描。"); return; }
  const base = scanPath(state.selected);
  const [pages, scan] = await Promise.all([api(base + "/pages"), api(base)]);
  if (generation !== state.generation) return;
  if (!pages.items.length) { empty(tree, "本次扫描没有页面记录。"); return; }
  tree.replaceChildren();
  const groups = new Map();
  for (const page of pages.items) {
    const url = new URL(page.url);
    let parent = tree, key = "";
    const segments = [url.host, ...url.pathname.split("/").filter(Boolean).slice(0, -1)];
    for (const label of segments) {
      key += "/" + label;
      if (!groups.has(key)) {
        const group = element("details", undefined, "tree-group");
        group.open = segments.length < 4;
        const children = element("div");
        group.append(element("summary", label), children);
        parent.append(group);
        groups.set(key, children);
      }
      parent = groups.get(key);
    }
    const title = (url.pathname.split("/").filter(Boolean).at(-1) || "/") + url.search;
    parent.append(button((page.status || "失败") + "  " + title, () => showPage(page, scan, base), "list-button"));
  }
}
function showPage(page, scan, base) {
  const detail = $("#pageDetail");
  detail.replaceChildren(element("h2", page.url));
  const meta = [page.method, page.status || "请求失败", page.length + " B", page.elapsed_ms + " ms"];
  if (page.truncated) meta.push("正文已截断");
  if (page.rendered) meta.push("已动态渲染");
  detail.append(element("p", meta.join(" · "), "muted"));
  if (page.error) detail.append(element("p", page.error, "notice error"));
  const findings = scan.findings.filter((item) => {
    try {
      const url = new URL(item.url), current = new URL(page.url);
      return url.origin === current.origin && url.pathname === current.pathname;
    } catch { return false; }
  });
  detail.append(element("h2", "发现的表单"));
  if (!page.forms?.length) detail.append(element("p", "没有记录到表单。", "muted"));
  for (const form of page.forms || []) {
    detail.append(element("p", form.method + " " + form.action + " · " +
      (form.fields.map((field) => field.name + " (" + field.type + ")").join("、") || "无命名字段"), "row"));
  }
  detail.append(element("h2", "关联问题"));
  if (!findings.length) detail.append(element("p", "本次未记录到该路径的发现。", "muted"));
  for (const finding of findings) {
    detail.append(button(finding.title, async () => {
      $("#severity").value = ""; $("#assessment").value = ""; $("#filter").value = "";
      await go("findings", scan.id);
      showFinding(finding);
    }, "list-button"));
  }
  detail.append(element("h2", "源码快照"));
  if (!page.has_source && !page.has_rendered) {
    detail.append(element("p", "没有保存该页面的快照。可在新建扫描时勾选保存 HTML。", "muted"));
    return;
  }
  const actions = element("div", undefined, "actions");
  const preview = element("div");
  for (const [kind, enabled, label] of [["source", page.has_source, "原始 HTML"], ["rendered", page.has_rendered, "渲染后 HTML"]]) {
    if (!enabled) continue;
    actions.append(button(label, async () => {
      const data = await api(base + "/pages/" + page.id + "?kind=" + kind);
      preview.replaceChildren(element("pre", data.text), button("导出文本快照", () => {
        const href = URL.createObjectURL(new Blob([data.text], {type: "text/plain;charset=utf-8"}));
        const link = element("a");
        link.href = href;
        link.download = "webscan-" + scan.id + "-page-" + page.id + "-" + kind + ".html.txt";
        link.click();
        setTimeout(() => URL.revokeObjectURL(href), 1000);
      }));
    }));
  }
  detail.append(actions, preview);
}

async function loadFindings(generation) {
  const scan = state.selected ? await api(scanPath(state.selected)) : null;
  if (generation !== state.generation) return;
  state.scan = scan;
  empty($("#findingDetail"), "选择一条发现查看证据。");
  renderFindings();
}
function renderFindings() {
  const list = $("#findingList");
  const query = $("#filter").value.trim().toLowerCase();
  const items = (state.scan?.findings || []).filter((item) =>
    (!$("#severity").value || item.severity === $("#severity").value) &&
    (!$("#assessment").value || item.assessment === $("#assessment").value) &&
    (!query || [item.title, item.url].some((value) => value.toLowerCase().includes(query))));
  if (!items.length) { empty(list, "没有符合条件的发现。"); return; }
  list.replaceChildren(...items.map((item) => {
    const node = button(undefined, () => showFinding(item), "list-button");
    node.append(element("strong", item.title), element("br"),
      element("span", severity[item.severity], "badge sev-" + item.severity),
      element("span", item.assessment, "badge"));
    if (item.review) node.append(element("span", item.review, "badge"));
    return node;
  }));
}
function showFinding(item) {
  const scan = state.scan;
  if (!scan) return;
  const detail = $("#findingDetail");
  detail.replaceChildren(element("h2", item.title), element("p", item.url, "muted"),
    element("span", severity[item.severity], "badge sev-" + item.severity),
    element("span", item.assessment, "badge"),
    element("p", item.detail), element("p", "修复建议 · " + item.remediation));
  if (item.param) detail.append(element("p", "触发参数 · " + item.param, "muted"));
  for (const [title, value] of [["判定依据", item.evidence], ["请求", item.request_snippet], ["响应", item.response_snippet]]) {
    if (value) detail.append(element("h2", title), element("pre", value));
  }
  const select = element("select");
  for (const label of ["待复核", "误报", "已修复待验证"]) select.add(new Option(label, label));
  select.value = item.review || "待复核";
  const label = element("label", "人工复核");
  label.append(select);
  detail.append(label, button("保存复核", async () => {
    const status = select.value;
    await api("/api/reviews", {scan_id: scan.id, finding_id: item.id, status});
    item.review = status;
    const saved = scan.findings.find((finding) => finding.id === item.id);
    if (saved) saved.review = status;
    renderFindings();
    notice("复核状态已保存。");
  }));
}

async function track(id) {
  state.taskId = id;
  const panel = $("#task");
  panel.hidden = false;
  empty(panel, "正在启动任务…");
  while (state.taskId === id) {
    const scan = await api(scanPath(id));
    if (state.taskId !== id) return;
    const progress = scan.progress || {};
    panel.replaceChildren(element("h2", stages[progress.stage] || scanStatus[scan.status] || "扫描任务"),
      element("p", progress.message || scan.target, "muted"));
    if (scan.status === "done") {
      const stats = scan.stats || {};
      panel.append(element("p", "抓取 " + stats.pages + " 页 · 动态渲染 " + (stats.rendered_pages || 0) +
        "/" + (stats.render_attempts || 0) + " 页 · " + scan.findings.length + " 条发现 · 参考分 " + scan.score));
      panel.append(button("查看网站地图", () => go("map", id)), button("复核发现", () => go("findings", id)));
      state.selected = id;
      if (state.view === "home") { await refresh(); dashboard(); }
      return;
    }
    if (scan.status === "failed") { panel.append(element("p", scan.error, "notice error")); return; }
    const bar = element("progress");
    if (progress.total > 0) { bar.max = progress.total; bar.value = progress.done || 0; }
    panel.append(bar);
    await new Promise((resolve) => setTimeout(resolve, 850));
  }
}
async function startScan(path, body) {
  notice("");
  const {id} = await api(path, body);
  await go("scan");
  await track(id);
}
function formAction(selector, action) {
  $(selector).addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = event.submitter;
    submit.disabled = true;
    try { await action(Object.fromEntries(new FormData(event.currentTarget))); }
    catch (error) { showError(error); }
    finally { submit.disabled = false; }
  });
}
function demo(dynamic) { return startScan("/api/demo", {dynamic}); }

formAction("#scanForm", (data) => startScan("/api/scans", {
  ...data, authorized: data.authorized === "on", deep: data.deep === "on",
  dynamic: data.dynamic === "on", probe_sensitive: data.probe_sensitive === "on",
  save_snapshots: data.save_snapshots === "on",
}));
formAction("#checkupForm", async (data) => {
  const node = $("#checkupResult");
  notice("");
  empty(node, "正在检查证书和响应头…");
  let result;
  try { result = await api("/api/checkup", {url: data.url, authorized: data.authorized === "on"}); }
  catch (error) { node.replaceChildren(); throw error; }
  const card = element("div", undefined, "card");
  card.append(element("h2", "体检结果 · " + result.target));
  const certificate = result.certificate;
  card.append(element("p", certificate.valid ?
    "HTTPS 证书有效 · 剩余约 " + certificate.days + " 天 · " + certificate.expires :
    "证书检查未通过 · " + certificate.error, "row"));
  const redirect = result.redirect;
  card.append(element("p", redirect.error ? "HTTP 检查失败 · " + redirect.error :
    "HTTP " + redirect.status + (redirect.enabled ? " · 跳转到同站 HTTPS" : " · 未观察到同站 HTTPS 跳转") +
    (redirect.location ? " · " + redirect.location : ""), "row"));
  card.append(element("h2", "HTTPS 响应头"));
  if (result.https_error) card.append(element("p", result.https_error, "muted"));
  else card.append(element("p", "HTTPS 状态 " + result.https_status, "muted"));
  for (const header of result.headers) {
    const row = element("div", undefined, "row");
    row.append(element("strong", header.name), element("p", header.value || "未返回 · " + header.description, "muted"));
    card.append(row);
  }
  node.replaceChildren(card);
});

for (const nav of document.querySelectorAll("[data-view]")) {
  nav.addEventListener("click", () => go(nav.dataset.view).catch(showError));
}
$("#topScan").onclick = () => go("scan");
$("#homeDemo").onclick = () => go("scan").then(() => demo(true)).catch(showError);
$("#staticDemo").onclick = () => demo(false).catch(showError);
$("#dynamicDemo").onclick = () => demo(true).catch(showError);
for (const [selector, view] of [["#mapScan", "map"], ["#findingScan", "findings"]]) {
  $(selector).onchange = (event) => go(view, event.target.value).catch(showError);
}
for (const [key, label] of Object.entries(severity)) $("#severity").add(new Option(label, key));
$("#severity").onchange = renderFindings;
$("#assessment").onchange = renderFindings;
$("#filter").oninput = renderFindings;
go("home").catch(showError);
