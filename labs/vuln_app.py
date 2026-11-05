"""故意做成有漏洞的本地靶站，只用于测试扫描器。

启动：python labs/vuln_app.py [port]
只绑定 127.0.0.1，绝不要部署到公网。
"""

from __future__ import annotations

import html
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PAGE = """<!DOCTYPE html>
<html><head><title>ACME Shop</title></head>
<body>
<h1>ACME Shop</h1>
<!-- TODO: 上线前删掉测试账号 admin / Passw0rd! -->
<nav>
  <a href="/">首页</a>
  <a href="/search?q=book">搜索</a>
  <a href="/dynamic">动态页面演示</a>
  <a href="/item?id=1">商品</a>
  <a href="/download?file=readme.txt">下载</a>
  <a href="/redirect?next=/item?id=2">跳转</a>
  <a href="/login">登录</a>
  <a href="/files/">文件</a>
</nav>
<form action="/search" method="get">
  <input name="q" placeholder="搜索关键词">
  <input type="submit" value="搜索">
</form>
</body></html>"""

LOGIN = """<!DOCTYPE html>
<html><head><title>登录 - ACME Shop</title></head>
<body>
<h1>登录</h1>
<form action="/login" method="get">
  <input name="user" placeholder="用户名">
  <input name="pass" type="password" placeholder="密码">
  <input type="submit" value="登录">
</form>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "ACME-Server/1.2.3"
    sys_version = ""

    def version_string(self) -> str:
        return "ACME-Server/1.2.3"

    def _send(
        self,
        body: str,
        status: int = 200,
        headers: dict[str, str] | None = None,
        ctype: str = "text/html; charset=utf-8",
    ) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "PHP/7.2.1")
        self.send_header("Set-Cookie", "session=abc123def; Path=/")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        path = parts.path
        qs = parse_qs(parts.query)
        q = qs.get("q", [""])[0]

        if path == "/":
            return self._send(PAGE)

        # 1) 反射型 XSS：原样回显，不转义
        if path == "/dynamic":
            return self._send("""<html><body><h1>动态页面演示</h1><div id="mount"></div>
<script>
setTimeout(() => {
    const link = document.createElement("a");
    link.href = ["/", "browser", "-only"].join("");
    link.textContent = "JavaScript 生成的页面入口";
    document.getElementById("mount").appendChild(link);
}, 120);
</script></body></html>""")

        if path == "/browser-only":
            return self._send("<html><body><h1>只有动态爬虫发现的页面</h1></body></html>")

        if path == "/search":
            return self._send(
                f"<html><head><title>搜索结果</title></head><body>"
                f"<h1>搜索：{q}</h1><p>没有找到相关商品。</p></body></html>"
            )

        # 2) 错误型 SQL 注入：单引号触发数据库报错
        if path == "/item":
            item_id = qs.get("id", ["1"])[0]
            if "'" in item_id or '"' in item_id:
                return self._send(
                    "<html><body><h1>Database Error</h1>"
                    "You have an error in your SQL syntax; check the manual that "
                    "corresponds to your MySQL server version for the right syntax "
                    "to use near '' at line 1</body></html>",
                    500,
                )
            return self._send(
                f"<html><body><h1>商品 #{html.escape(item_id)}</h1>"
                f"<p>价格 19.90</p></body></html>"
            )

        # 3) 路径穿越 / 本地文件包含
        if path == "/download":
            name = qs.get("file", ["readme.txt"])[0]
            if "etc/passwd" in name:
                return self._send(
                    "<pre>root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</pre>"
                )
            return self._send(f"<pre>这是文件 {html.escape(name)} 的内容</pre>")

        # 4) 开放重定向
        if path == "/redirect":
            target = qs.get("next", ["/"])[0]
            return self._send(
                "<html><body>跳转中…</body></html>", 302, {"Location": target}
            )

        if path == "/login":
            return self._send(LOGIN)

        # 5) 目录列表
        if path in ("/files", "/files/"):
            return self._send(
                "<html><head><title>Index of /files</title></head><body>"
                "<h1>Index of /files</h1>"
                '<a href="backup.zip">backup.zip</a><br>'
                '<a href="db.sql">db.sql</a></body></html>'
            )

        # 6) 敏感文件
        if path == "/.git/config":
            return self._send(
                "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
                "\tbare = false\n[remote \"origin\"]\n\turl = git@github.com:acme/shop.git\n",
                200,
                ctype="text/plain; charset=utf-8",
            )
        if path == "/.env":
            return self._send(
                "APP_ENV=production\nAPP_KEY=base64:Zm9vYmFy\n"
                "DB_HOST=127.0.0.1\nDB_PASSWORD=Passw0rd!\n",
                200,
                ctype="text/plain; charset=utf-8",
            )

        # 7) 报错信息泄露
        if path == "/debug":
            return self._send(
                "<html><body><h1>500</h1><pre>Traceback (most recent call last):\n"
                '  File "app.py", line 88, in handler\n    raise ValueError\n'
                "ValueError: bad request</pre></body></html>",
                500,
            )

        if path == "/admin":
            return self._send("<html><body>403 Forbidden</body></html>", 403)

        return self._send("<html><body><h1>404 Not Found</h1></body></html>", 404)

    def log_message(self, fmt: str, *args) -> None:  # 安静一点
        return


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print("=" * 60)
    print("  [!!] 这是一个故意包含漏洞的靶站，仅供本地测试")
    print(f"  [!!] 地址：http://127.0.0.1:{port}/  （Ctrl+C 停止）")
    print("=" * 60)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
