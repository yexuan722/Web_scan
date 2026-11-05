# AGENTS.md

给接手的 AI 或开发者：读这一份就能上手。项目背景、踩过的坑、不能碰的线，都在这里。

---

## 1. 项目是什么

**WebScan 1.1** —— Web 漏洞扫描器（课程课题 30：网站漏洞扫描系统）。

输入一个**已授权**的网址 → 爬取攻击面 → 被动规则 + 只读探测 + 主动 PoC →
输出分级漏洞清单 + 可复算的健康评分 + 可导出的报告。

形态：Python 后端（标准库 HTTP 服务）+ 原生 Qt WebEngine 窗口（内嵌 Chromium），
PyInstaller onedir 打包成绿色版 exe。

---

## 2. 技术栈

| 层 | 选型 |
| --- | --- |
| 语言 | Python 3.12 |
| HTTP 客户端 | httpx（唯一必需的第三方运行时依赖） |
| 服务层 | 标准库 `http.server`（**没有** FastAPI/uvicorn） |
| 界面 | 原生 HTML/CSS/JS（无构建链）+ Qt WebEngine 窗口 |
| 数据库 | SQLite（WAL，标准库 `sqlite3`，无 ORM） |
| 托盘 | pystray + Pillow |
| 打包 | PyInstaller（onedir） |

---

## 3. 目录与职责

```
webscan/
├── config.py      所有阈值/规则常量（改规则先看这里）
├── models.py      Page / Form / Finding / ScanResult
├── fetcher.py     httpx 封装：并发、每主机限速、响应截断
├── crawler.py     同源 BFS、URL 规范化、破坏性路径排除
├── storage.py     SQLite（扫描历史、页面、快照、人工复核）
├── renderer.py    隔离的 Chromium 渲染（复用受限 HTTP 抓取层）
├── checkup.py     证书、HTTPS 升级和响应头体检
├── scoring.py     noisy-OR 健康评分
├── report.py      HTML / Markdown / JSON 导出
├── engine.py      编排：爬取 → 被动 → 探测 → 主动 → 评分
├── api.py         HTTP 服务、单实例、端口回落、本地令牌
├── window.py      Qt 窗口（**注意第 7 节的沙箱坑**）
├── tray.py        系统托盘
├── cli.py         命令行入口
├── rules/
│   ├── passive.py 只看已有响应（零额外请求）
│   ├── probe.py   只读 GET 探测（敏感文件、CORS）
│   └── active.py  主动 PoC（默认关闭，需显式开启）
└── web/           前端（index.html + static/）
labs/vuln_app.py   故意含漏洞的本地靶站（仅 127.0.0.1）
tests/test_core.py 单元测试（unittest，无 pytest）
```

**核心边界**：`engine.py` 及其依赖不认识 HTTP/UI，可被 CLI、测试直接调用。
所有界面逻辑在 `api.py` / `web/`，不要把业务逻辑塞进去。

---

## 4. 常用命令

```bash
# 跑测试（必须全绿再提交）
python -m unittest discover -s tests -v

# 启动靶站（另开一个终端）
python labs/vuln_app.py 8899

# 从源码启动（Qt 窗口）
python -m webscan

# 命令行扫一次
python -m webscan --scan http://127.0.0.1:8899/ --deep

# 打包（产物 ~600 MB，勿入 Git）
python -m PyInstaller --noconfirm --clean webscan.spec
```

依赖安装：`pip install -r requirements.txt`，打包再加 `pyinstaller`。

---

## 5. 代码约定（改代码前必读）

1. **每条发现必须有证据**：`Finding.evidence` 不能为空，主动类还要有 `request_snippet` /
   `response_snippet`。没有证据的发现不要产出。
2. **主动 PoC 必须二次验证**：换载荷能复现才算命中；所有探测请求 `follow=False`，
   避免把 A 接口的注入打到 B 接口上（踩过这个坑，见 `docs/03` 第 6 节）。
3. **默认只读**：只发 GET；破坏性路径（logout/delete/pay…）由 `config.DANGEROUS_PATH_PATTERN` 排除。
4. **限速**：默认每主机 6 req/s，改大要慎重。
5. **规则要可解释**：新增规则请写清判定条件、误报边界、修复建议。
6. **中文注释与文案**：项目面向中文用户，保持风格一致。
7. **不加依赖**：能标准库就标准库，加第三方前先说明理由。

---

## 6. 数据与配置

- 数据目录优先级：`WEBSCAN_DATA_DIR` 环境变量 → exe 同级 `data/` → `%LOCALAPPDATA%\WebScan\data` → `%TEMP%`
  （见 `config.py::_resolve_data_dir`，每级都真写文件验证）。
- 默认端口 **8770**，被占用会自动向后顺延 20 个。
- 单实例：`data/instance.json` + 健康探测，重复启动只唤出已有窗口。
- 本地访问保护：校验 `Host` 头 + 一次性令牌（注入首页 `<meta name="webscan-token">`，
  写操作需带 `X-WebScan-Token` 头）。**不要绕过它。**

---

## 7. 已知坑（都踩过，别再踩）

1. **Qt 窗口白屏**：打包后 Chromium 沙箱子进程起不来，表现是窗口全黑、没有
   `QtWebEngineProcess.exe` 进程。修复方式是在 `window.py` **导入 QtWebEngine 之前**
   设置 `QTWEBENGINE_DISABLE_SANDBOX=1`。**不要把这一行挪到 import 之后**，会失效。
2. **PyInstaller 必须 onedir**：onefile 在本机 `%TEMP%` 解压失败（`Could not create temporary directory`）。
3. **端口 8765 被别的服务占用**（本机有一个常驻 bot），别再改回 8765。
4. **窗口版没有控制台**：崩溃时什么都看不到。排查时临时编一个 `console=True` 的包，
   或看 `data/logs/webscan.log`（Qt 的消息也被接进日志了）。
5. **Windows 上 `webbrowser.open()` 会撞"提权实例"**：有管理员权限的 Edge 在跑时会弹框。
   现在用 Qt 窗口，基本绕开了；`--browser` 模式仍有这个风险。
6. **不要把 `dist/`、`data/` 提交进 Git**（`.gitignore` 已挡）。

---

## 8. 安全红线（不可协商）

- 只对**自己拥有**或**已获书面授权**的目标扫描。代码里有强制授权闸门，不要移除。
- 不实现漏洞利用、写入/删除、密码爆破、WAF 对抗、端口扫描。
- 扫描结果可能含敏感信息，只存本地。快照按扫描开启，导出为纯文本，不能把目标网页直接渲染进工作台窗口。

---

## 9. 当前状态与下一步

**已完成**：爬虫、11 条被动规则、敏感文件/CORS 探测、4 类主动 PoC、noisy-OR 评分、
HTML/MD/JSON 报告、Qt 桌面窗口、托盘、单实例、打包。

**未做（按优先级）**：

1. POST 表单与登录态（覆盖率提升最大）
2. 报告按 OWASP Top 10 归类
3. 安装包（Inno Setup）与代码签名

**验证基线**：对 `labs/vuln_app.py` 全量扫描应得到 13 条发现、评分 10/100；动态演示会比普通演示多发现 /browser-only。
改动后请跑一遍，条数变化要能解释。
