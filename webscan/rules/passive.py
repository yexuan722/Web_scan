"""被动规则：只看已经抓到的响应，不发任何额外请求，零风险、零误伤。"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .. import config
from ..models import Finding, Page, SEV_RANK


def _mk(**kw) -> Finding:
    return Finding(**kw)


def analyze_host(host: str, pages: list[Page]) -> list[Finding]:
    """按主机聚合的检查：安全响应头、HSTS、TLS。"""
    out: list[Finding] = []
    ok_pages = [p for p in pages if p.ok and p.status < 400]
    if not ok_pages:
        return out
    sample = max(ok_pages, key=lambda p: len(p.body))
    is_https = any(urlsplit(p.url).scheme == "https" for p in ok_pages)

    # ---- 安全响应头 -----------------------------------------------------
    missing: list[tuple[str, str, str]] = []
    for header, desc, sev in config.SECURITY_HEADERS:
        if header == "x-frame-options":
            # CSP frame-ancestors 可以替代
            csp = sample.header("content-security-policy")
            if "frame-ancestors" in csp.lower():
                continue
        if not sample.header(header):
            missing.append((header, desc, sev))

    if missing:
        worst = min((m[2] for m in missing), key=lambda s: SEV_RANK[s])
        out.append(
            _mk(
                rule_id="SEC-HEADERS",
                title="安全响应头缺失",
                severity=worst,
                category="配置安全",
                url=f"{urlsplit(sample.url).scheme}://{host}/",
                detail="；".join(m[1] for m in missing),
                remediation=(
                    "在 Web 服务器或应用层统一添加：\n"
                    "  Content-Security-Policy: default-src 'self'\n"
                    "  X-Content-Type-Options: nosniff\n"
                    "  X-Frame-Options: DENY\n"
                    "  Referrer-Policy: no-referrer\n"
                    "  Permissions-Policy: geolocation=(), microphone=(), camera=()"
                ),
                confidence=1.0,
                verified=True,
                evidence="缺少的响应头：" + ", ".join(m[0] for m in missing),
                dedupe_key=f"SEC-HEADERS|{host}",
            )
        )

    csp = sample.header("content-security-policy")
    if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp or "*" in csp):
        out.append(
            _mk(
                rule_id="CSP-WEAK",
                title="CSP 策略过宽",
                severity="medium",
                category="配置安全",
                url=f"{urlsplit(sample.url).scheme}://{host}/",
                detail=f"当前 CSP 含宽松指令，XSS 缓解能力大幅削弱：{csp[:200]}",
                remediation="移除 unsafe-inline / unsafe-eval / 通配符来源，改用 nonce 或 hash。",
                confidence=0.9,
                evidence=csp[:300],
                dedupe_key=f"CSP-WEAK|{host}",
            )
        )

    # ---- 版本/框架信息泄露（按主机聚合）---------------------------------
    banners: list[tuple[str, str]] = []
    for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        value = sample.header(hdr)
        if value and re.search(r"\d", value):
            banners.append((hdr, value))
    if banners:
        out.append(
            _mk(
                rule_id="BANNER",
                title="服务器/框架版本信息泄露",
                severity="low",
                category="信息泄露",
                url=f"{urlsplit(sample.url).scheme}://{host}/",
                detail="响应头暴露了组件与版本号，攻击者可据此匹配已知漏洞："
                + "；".join(f"{h}: {v}" for h, v in banners),
                remediation="关闭版本号输出（nginx: server_tokens off；"
                "Apache: ServerTokens Prod；PHP: expose_php Off）。",
                confidence=0.95,
                evidence="\n".join(f"{h}: {v}" for h, v in banners),
                dedupe_key=f"BANNER|{host}",
            )
        )

    if is_https and not sample.header("strict-transport-security"):
        out.append(
            _mk(
                rule_id="HSTS-MISSING",
                title="未启用 HSTS",
                severity="low",
                category="配置安全",
                url=f"https://{host}/",
                detail="HTTPS 站点未返回 Strict-Transport-Security，存在 SSL 剥离降级风险。",
                remediation="添加 header：Strict-Transport-Security: max-age=31536000; includeSubDomains",
                confidence=1.0,
                verified=True,
                dedupe_key=f"HSTS-MISSING|{host}",
            )
        )
    return out


def analyze_page(page: Page, host: str) -> list[Finding]:
    """单页检查：Cookie、版本泄露、目录列表、报错、注释、混合内容、表单。"""
    out: list[Finding] = []
    if not page.ok:
        return out

    # ---- Cookie 安全属性 -------------------------------------------------
    for raw in page.set_cookies or []:
        head = raw.split(";", 1)[0]
        if "=" not in head:
            continue
        name = head.split("=", 1)[0].strip()
        flags = raw.lower()
        problems = []
        if "secure" not in flags and page.url.startswith("https"):
            problems.append("缺少 Secure")
        if "httponly" not in flags:
            problems.append("缺少 HttpOnly")
        if "samesite" not in flags:
            problems.append("缺少 SameSite")
        if problems:
            out.append(
                _mk(
                    rule_id="COOKIE-FLAGS",
                    title=f"Cookie「{name}」安全属性不全",
                    severity="medium" if "缺少 HttpOnly" in problems else "low",
                    category="会话安全",
                    url=page.url,
                    param=name,
                    detail="；".join(problems) + "。若该 Cookie 承载会话，可能被 XSS 窃取或跨站携带。",
                    remediation="Set-Cookie 追加：Secure; HttpOnly; SameSite=Lax（或 Strict）。",
                    confidence=1.0,
                    verified=True,
                    evidence=raw[:300],
                    dedupe_key=f"COOKIE-FLAGS|{host}|{name}",
                )
            )

    # ---- 目录列表 --------------------------------------------------------
    head = page.body[:3000]
    if re.search(r"<title>\s*Index of /", head, re.I) or "Directory listing for" in head:
        out.append(
            _mk(
                rule_id="DIR-LISTING",
                title="目录浏览未关闭",
                severity="medium",
                category="信息泄露",
                url=page.url,
                detail="服务器直接列出目录内容，可能暴露备份、源码、配置等敏感文件。",
                remediation="关闭自动索引（nginx: autoindex off；Apache: Options -Indexes）。",
                confidence=1.0,
                verified=True,
                evidence=re.search(r"<title>.{0,80}</title>", head, re.I).group(0)
                if re.search(r"<title>.{0,80}</title>", head, re.I) else "",
                dedupe_key=f"DIR-LISTING|{host}{urlsplit(page.url).path}",
            )
        )

    # ---- 错误信息泄露 ----------------------------------------------------
    for pattern, desc in config.ERROR_SIGNATURES:
        m = re.search(pattern, page.body)
        if m:
            out.append(
                _mk(
                    rule_id="ERROR-DISCLOSURE",
                    title=desc,
                    severity="medium",
                    category="信息泄露",
                    url=page.url,
                    detail="页面回显了内部错误细节，可用于推断技术栈与数据库结构。",
                    remediation="生产环境关闭详细报错，统一返回自定义错误页并记录到服务端日志。",
                    confidence=0.9,
                    evidence=m.group(0)[:300],
                    response_snippet=page.body[max(0, m.start() - 120): m.end() + 120],
                    dedupe_key=f"ERROR-DISCLOSURE|{host}|{desc}",
                )
            )

    # ---- HTML 注释 -------------------------------------------------------
    if "html" in page.content_type or page.body.lstrip().startswith("<"):
        for comment in re.findall(config.COMMENT_PATTERN, page.body, re.S)[:80]:
            for pattern, desc in config.COMMENT_RISK:
                if re.search(pattern, comment):
                    out.append(
                        _mk(
                            rule_id="HTML-COMMENT",
                            title=desc,
                            severity="low",
                            category="信息泄露",
                            url=page.url,
                            detail="HTML 注释中残留敏感信息，公开可见。",
                            remediation="上线前移除开发注释，或用构建流程剥离注释。",
                            confidence=0.7,
                            evidence=comment.strip()[:300],
                            dedupe_key=f"HTML-COMMENT|{host}|{desc}",
                        )
                    )
                    break

    # ---- 混合内容 --------------------------------------------------------
    if page.url.startswith("https://") and "html" in page.content_type:
        mixed = re.findall(
            r"""(?:src|href|action)\s*=\s*["'](http://[^"'>\s]+)""", page.body, re.I
        )
        if mixed:
            out.append(
                _mk(
                    rule_id="MIXED-CONTENT",
                    title="HTTPS 页面加载 HTTP 资源",
                    severity="medium",
                    category="传输安全",
                    url=page.url,
                    detail=f"发现 {len(set(mixed))} 个明文 HTTP 资源引用，可被中间人篡改。",
                    remediation="将所有资源改为相对协议或 https://，并配置 upgrade-insecure-requests。",
                    confidence=0.95,
                    evidence=", ".join(sorted(set(mixed))[:5]),
                    dedupe_key=f"MIXED-CONTENT|{host}",
                )
            )

    # ---- 表单安全 --------------------------------------------------------
    for form in page.forms:
        has_pwd = any(f.type.lower() == "password" for f in form.fields)
        if not has_pwd:
            continue
        if form.action.lower().startswith("http://"):
            downgrade = page.url.startswith("https://")
            out.append(
                _mk(
                    rule_id="FORM-CLEARTEXT",
                    title="登录表单降级到 HTTP 提交" if downgrade else "登录页未启用 HTTPS",
                    severity="high" if downgrade else "medium",
                    category="传输安全",
                    url=form.action or page.url,
                    detail=(
                        "HTTPS 页面的登录表单指向 HTTP，属于降级提交，凭据以明文经过网络。"
                        if downgrade
                        else "包含密码字段的表单通过明文 HTTP 提交，凭据可被链路窃听。"
                    ),
                    remediation="全站启用 HTTPS，表单 action 改为 https://。",
                    confidence=1.0,
                    verified=True,
                    evidence=f"action={form.action}",
                    dedupe_key=f"FORM-CLEARTEXT|{host}|{form.action}",
                )
            )
        if form.method.upper() == "GET":
            out.append(
                _mk(
                    rule_id="FORM-GET-PWD",
                    title="密码字段使用 GET 提交",
                    severity="medium",
                    category="会话安全",
                    url=form.action or page.url,
                    detail="密码会出现在 URL、浏览器历史与代理日志中。",
                    remediation="改用 POST 提交登录表单。",
                    confidence=1.0,
                    verified=True,
                    evidence=f"method=GET action={form.action}",
                    dedupe_key=f"FORM-GET-PWD|{host}|{form.action}",
                )
            )

    # ---- Source Map ------------------------------------------------------
    m = re.search(r"sourceMappingURL=([^\s*]+)", page.body)
    if m:
        out.append(
            _mk(
                rule_id="SOURCE-MAP",
                title="生产环境暴露 source map",
                severity="low",
                category="信息泄露",
                url=page.url,
                detail="可从 .map 文件还原前端源码，便于攻击者找接口与逻辑缺陷。",
                remediation="生产构建关闭 sourcemap，或限制 .map 的访问。",
                confidence=0.8,
                evidence=m.group(0)[:200],
                dedupe_key=f"SOURCE-MAP|{host}|{urlsplit(page.url).path}",
            )
        )

    return out
