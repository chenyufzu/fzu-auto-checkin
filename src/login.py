"""智汇福大 SSO（sso.fzu.edu.cn）自动登录，换取晚点名免登 token。

协议逆向自 cas-login-new 前端（Angular）：
1. GET /login?service=<晚点名callback> → 解析页面内嵌的
   `#login-croypto`（16 字节一次性密钥，Base64）与 `#login-page-flowkey`（execution）
2. password 字段 = AES-128-ECB-PKCS7(key=croypto, data=明文密码) 的 Base64
   ——前端用用户密码本身加密页面下发的挑战值，服务端解密比对
3. 表单 POST /login?service=...，字段：
   type=UsernamePassword, _eventId=submit, geolocation=, execution=, croypto=, username=, password=
4. 成功后 302 链 → yzsxg callback.action?ticket=ST-xxx → authorize.action?token=xxx
   从重定向链 URL 中提取 token

若服务器要求验证码，登录会失败并在页面返回错误信息，此处直接抛出。
"""
import base64
import re

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

SSO_BASE = "https://sso.fzu.edu.cn/login"
SERVICE = (
    "https://yzsxg.fzu.edu.cn/livecloud/project/fzu/attn/oauth2/callback.action"
)

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)


def _parse_field(html: str, elem_id: str) -> str:
    m = re.search(rf'id="{elem_id}"\s*>(.*?)</p>', html, re.S)
    if not m:
        raise RuntimeError(f"登录页缺少元素 #{elem_id}，页面结构可能已变化")
    return m.group(1).strip()


def _encrypt_password(croypto: str, password: str) -> str:
    cipher = AES.new(base64.b64decode(croypto), AES.MODE_ECB)
    return base64.b64encode(
        cipher.encrypt(pad(password.encode(), AES.block_size))
    ).decode()


def _extract_token(url: str):
    m = re.search(r"[?&]token=([A-Za-z0-9]{20,})", url)
    return m.group(1) if m else None


def login(username: str, password: str) -> str:
    """学号密码登录 SSO，返回晚点名免登 token。失败抛 RuntimeError。"""
    s = requests.Session()
    s.headers.update({"User-Agent": UA})

    # 1. 拿登录页（croypto + execution）
    r = s.get(SSO_BASE, params={"service": SERVICE}, timeout=15)
    r.raise_for_status()
    croypto = _parse_field(r.text, "login-croypto")
    execution = _parse_field(r.text, "login-page-flowkey")

    # 2. 加密密码并提交表单
    data = {
        "type": "UsernamePassword",
        "_eventId": "submit",
        "geolocation": "",
        "execution": execution,
        "croypto": croypto,
        "username": username,
               "password": _encrypt_password(croypto, password),
        "captcha_code": "",
        "captcha_payload": _encrypt_password(croypto, "{}"),
    }
    r2 = s.post(
        SSO_BASE,
        params={"service": SERVICE},
        data=data,
        timeout=20,
        allow_redirects=True,
    )

    # 3. 从重定向链和最终 URL 提取 token
    for url in [h.url for h in r2.history] + [r2.url]:
        token = _extract_token(url)
        if token:
            return token

    import html
    from urllib.parse import urlsplit

    def clean_text(value):
        value = html.unescape(re.sub(r"<[^>]+>", " ", value))
        for secret in (username, password):
            if secret:
                value = value.replace(str(secret), "<已隐藏>")
        value = re.sub(r"(?:ST|TGT)-[A-Za-z0-9._-]+|[A-Za-z0-9_]{24,}", "<长标识已隐藏>", value)
        return re.sub(r"\s+", " ", value).strip()[:180]

    def page_field(field):
        match = re.search(rf'id=["\']{field}["\'][^>]*>(.*?)</', r2.text, re.S | re.I)
        return clean_text(match.group(1)) if match else ""

    title = re.search(r"<title[^>]*>(.*?)</title>", r2.text, re.S | re.I)
    print("账号仍为模板文字：", username.strip() in {"你的学号", "填写学号"})
    print("密码仍为模板文字：", password in {"你登录智汇福大的密码", "你当前登录智汇福大的密码", "填写APP密码"})
    print("页面标题：", clean_text(title.group(1)) if title else "未提供")
    print("响应状态：", r2.status_code, "；页面长度：", len(r2.text))
    print("跳转过程（不显示网址参数）：")
    for reply in [*r2.history, r2]:
        address = urlsplit(reply.url)
        path = clean_text(address.path)
        print(reply.status_code, reply.request.method, address.hostname, path)
    print("会话Cookie名称：", clean_text(", ".join(sorted({cookie.name for cookie in s.cookies}))))
    print("学校错误码：", page_field("login-error-code") or "未提供")
    print("学校错误提示：", page_field("login-error-msg") or "未提供")
    print("当前认证方式：", page_field("current-login-type") or "未提供")
    print("页面是否提供验证码地址：", bool(page_field("captcha-url")))
    raise RuntimeError("尚未取得晚点名登录凭据，请查看上面的诊断信息")
