"""扫描引擎：编排爬取、规则、评分、落库。与 UI 完全解耦。"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Awaitable, Callable
from urllib.parse import urlsplit

from . import config
from .crawler import crawl, normalize_url
from .fetcher import Fetcher
from .models import Finding, ScanOptions, ScanResult, SEV_RANK
from .rules import analyze_host, analyze_page, probe_cors, probe_sensitive_paths, run_active_tests
from .scoring import compute_score
from .storage import Store

Emitter = Callable[[dict], Awaitable[None]]


async def _noop(event: dict) -> None:  # pragma: no cover
    return None


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


async def run_scan(
    store: Store,
    scan: ScanResult,
    options: ScanOptions,
    emit: Emitter | None = None,
) -> ScanResult:
    emit = emit or _noop
    started = time.monotonic()

    try:
        target = normalize_url(scan.target)
        if not target:
            raise ValueError("目标地址无效：只支持 http:// 或 https:// 开头的 URL")
        scan.target = target
        scan.status = "running"
        await emit({"type": "stage", "stage": "start", "message": f"开始扫描 {target}"})

        fetcher = Fetcher(
            target=target,
            concurrency=options.concurrency,
            rps=options.rps,
        )
        try:
            # ---------------- 1. 爬取 ----------------
            await emit({"type": "stage", "stage": "crawl", "message": "正在爬取站点…"})

            async def on_page(page, done, total):
                await emit({
                    "type": "progress",
                    "stage": "crawl",
                    "done": done,
                    "total": total,
                    "message": f"已抓取 {done}/{total}：{page.url[:90]}",
                })

            pages, skipped = await crawl(
                target,
                fetcher,
                max_pages=options.max_pages,
                max_depth=options.max_depth,
                on_page=on_page,
            )
            if not pages or not any(p.ok for p in pages):
                err = pages[0].error if pages else "无法访问目标"
                raise RuntimeError(f"目标不可达或返回异常：{err}")

            store.add_pages(
                scan.id,
                [(p.url, p.method, p.status, p.length, p.elapsed_ms) for p in pages],
            )

            # ---------------- 2. 被动分析 ----------------
            await emit({"type": "stage", "stage": "analyze", "message": "正在分析页面与响应头…"})
            findings: dict[str, Finding] = {}

            by_host = defaultdict(list)
            for p in pages:
                by_host[urlsplit(p.url).netloc].append(p)

            for host, host_pages in by_host.items():
                for f in analyze_host(host, host_pages):
                    findings.setdefault(f.key(), f)
                for p in host_pages:
                    for f in analyze_page(p, host):
                        findings.setdefault(f.key(), f)

            await emit({
                "type": "progress",
                "stage": "analyze",
                "done": len(pages),
                "total": len(pages),
                "message": f"分析了 {len(pages)} 个页面，命中 {len(findings)} 条",
            })

            # ---------------- 3. 只读探测 ----------------
            if options.probe_sensitive:
                await emit({"type": "stage", "stage": "probe", "message": "正在探测敏感文件与 CORS…"})
                landing = pages[0].url
                origin = _origin(landing)
                probed = await probe_sensitive_paths(origin, fetcher)
                probed += await probe_cors(landing, fetcher)
                for f in probed:
                    findings.setdefault(f.key(), f)
                await emit({
                    "type": "progress",
                    "stage": "probe",
                    "done": 1,
                    "total": 1,
                    "message": f"探测完成，新增 {len(probed)} 条",
                })

            # ---------------- 4. 主动 PoC ----------------
            if options.deep:
                await emit({"type": "stage", "stage": "active", "message": "主动 PoC 检测中（仅只读载荷）…"})

                async def on_active(done, total, msg):
                    await emit({
                        "type": "progress",
                        "stage": "active",
                        "done": done,
                        "total": total,
                        "message": f"测试参数 {done}/{total}：{msg[:80]}",
                    })

                active = await run_active_tests(
                    pages,
                    fetcher,
                    limit=config.ACTIVE_MAX_TARGETS,
                    on_progress=on_active,
                )
                for f in active:
                    findings.setdefault(f.key(), f)
        finally:
            requests_made = fetcher.requests
            await fetcher.close()

        # ---------------- 5. 评分与落库 ----------------
        items = sorted(findings.values(), key=lambda f: (SEV_RANK.get(f.severity, 9), f.rule_id))
        scored = compute_score(items)

        scan.findings = items
        scan.score = scored["score"]
        scan.grade = scored["grade"]
        scan.grade_label = scored["grade_label"]
        scan.status = "done"
        scan.finished_at = time.time()
        scan.stats = {
            "pages": len(pages),
            "truncated_pages": sum(p.truncated for p in pages),
            "skipped": len(skipped),
            "requests": requests_made,
            "elapsed": round(time.monotonic() - started, 1),
            "counts": scored["counts"],
            "verified": scored["verified"],
            "risk": scored["risk"],
            "deep": options.deep,
        }
        store.update_scan(scan)

        await emit({
            "type": "done",
            "scan_id": scan.id,
            "score": scan.score,
            "grade": scan.grade_label,
            "stats": scan.stats,
        })
        return scan

    except Exception as exc:
        scan.status = "failed"
        scan.error = f"{type(exc).__name__}: {exc}"
        scan.finished_at = time.time()
        scan.stats = {"elapsed": round(time.monotonic() - started, 1)}
        try:
            store.update_scan(scan)
        except Exception:
            pass
        await emit({"type": "error", "message": scan.error})
        return scan
