"""静态前端资源（JS/CSS/图片/字体）识别。

webshell 检测器原本对每一个 HTTP 请求-响应对都跑一遍通用响应特征，
包括浏览器加载 jquery.js 这种纯前端资源。JS 里 `a || b || c` 这种
逻辑或会被"菜刀 || 分隔符"特征命中，凭空拿到几十分权重，最后以
「哥斯拉/菜刀」的名义出现在结果里 —— 这是取证工具最不该有的噪声。

这里把"这是不是前端静态资源"单独抽出来，让检测器可以据此收敛那些
在正常网页内容里也会出现的模糊特征。注意 **不能只看 Content-Type**：
实测 webone.pcap 里 jquery.autotextarea.js 是以
`text/html; charset=iso-8859-1` 返回的，只信 Content-Type 会漏掉。
"""

import re
from typing import Optional
from urllib.parse import urlparse

# 前端静态资源扩展名。故意不含 .html/.htm —— webshell 藏在 .html 里
# 是真实手法，那类响应必须继续按正常流量检测。
STATIC_EXTENSIONS = frozenset({
    "js", "mjs", "cjs", "jsx", "ts", "tsx",
    "css", "scss", "less",
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "svg", "avif",
    "woff", "woff2", "ttf", "eot", "otf",
    "mp3", "mp4", "webm", "ogg", "wav", "avi", "mov",
    "map", "pdf", "swf",
})

# 静态资源 Content-Type 前缀
STATIC_CONTENT_TYPE_PREFIXES = (
    "image/",
    "font/",
    "audio/",
    "video/",
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "application/font",
    "application/vnd.ms-fontobject",
)

# 典型静态资源目录
STATIC_PATH_PATTERNS = (
    re.compile(r"/static/", re.IGNORECASE),
    re.compile(r"/assets/", re.IGNORECASE),
    re.compile(r"/dist/", re.IGNORECASE),
    re.compile(r"/node_modules/", re.IGNORECASE),
    re.compile(r"/_next/static/", re.IGNORECASE),
)

_EXTENSION_RE = re.compile(r"\.([A-Za-z0-9]{1,8})$")


def uri_extension(uri: str) -> str:
    """取 URI 路径部分的扩展名（小写，不含点），取不到返回空串。"""
    if not uri:
        return ""

    path = uri
    if "://" in path:
        try:
            path = urlparse(path).path
        except ValueError:
            path = path.split("?", 1)[0]
    else:
        path = path.split("?", 1)[0].split("#", 1)[0]

    match = _EXTENSION_RE.search(path)
    return match.group(1).lower() if match else ""


def is_static_asset_uri(uri: str) -> bool:
    """URI 看起来是不是前端静态资源。"""
    if not uri:
        return False

    if uri_extension(uri) in STATIC_EXTENSIONS:
        return True

    return any(pattern.search(uri) for pattern in STATIC_PATH_PATTERNS)


def is_static_asset_content_type(content_type: Optional[str]) -> bool:
    """Content-Type 是不是静态资源类型。"""
    if not content_type:
        return False

    normalized = content_type.strip().lower()
    return normalized.startswith(STATIC_CONTENT_TYPE_PREFIXES)


def is_static_asset(uri: str = "", content_type: Optional[str] = None) -> bool:
    """综合 URI 和响应 Content-Type 判断是否前端静态资源。

    两者任一命中即算静态资源：Content-Type 可能被服务端配错（实测有 .js
    以 text/html 返回），URI 也可能被重写掉扩展名。
    """
    return is_static_asset_uri(uri) or is_static_asset_content_type(content_type)
