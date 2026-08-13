"""对着真实抓包检查 webshell 检测有没有把正常流量算成攻击。

单元测试用的是合成载荷，挡不住"某个正则在真实压缩 JS 上恰好命中"这类
问题 —— webone.pcap 里 jquery.min.js 被判成蚁剑中危、jquery.tab.js 被判成
哥斯拉，都是单测全绿的情况下发生的。改完检测规则后拿真包跑一遍。

用法:
    .venv/Scripts/python.exe tools/check_webshell_fp.py <pcap> [HTTP包数上限]

输出每条命中的工具、置信度、权重和触发的特征名。重点看落在
.js/.css/.png 这类静态资源上的 GET 请求 —— 那些基本都是误报。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.static_asset import is_static_asset_uri
from core.tshark_locator import find_tshark
from core.tshark_stream import OutputFormat, StreamConfig, TsharkProcessHandler
from core.webshell_detect import WebShellDetector

TOOLS = ("antsword", "caidao", "behinder", "godzilla", "suspicious")


def main(pcap: str, limit: int = 4000) -> int:
    tshark = find_tshark()
    if not tshark:
        print("找不到 tshark", file=sys.stderr)
        return 2

    handler = TsharkProcessHandler(tshark)
    config = StreamConfig(
        pcap_path=pcap,
        display_filter="http",
        output_format=OutputFormat.EK,
        disable_name_resolution=True,
        line_buffered=True,
    )

    packets = []
    for packet in handler.stream_pyshark_compatible(config):
        packets.append(packet)
        if len(packets) >= limit:
            break
    print(f"收集 HTTP 包 {len(packets)} 个")

    results = WebShellDetector().detect(packets)

    static_hits = 0
    for tool in TOOLS:
        for result in results[tool]:
            uri = result.get("uri") or ""
            method = result.get("method") or ""
            static = is_static_asset_uri(uri)
            if static:
                static_hits += 1
            print(f"[{tool:10s}] conf={result.get('confidence'):10s} "
                  f"w={result.get('total_weight'):4d} {method} {uri}"
                  f"{'   <-- 静态资源' if static else ''}")
            for ind in result.get("indicators", []):
                print(f"      req  {ind['name']} (+{ind['weight']})")
            for ind in result.get("response_indicators", []):
                print(f"      resp {ind['name']} (+{ind['weight']}) "
                      f"{ind.get('matched_text', '')!r}")

    print(f"\nsummary: {results['summary']}")
    print(f"落在静态资源上的命中: {static_hits}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(1)
    raise SystemExit(main(sys.argv[1],
                          int(sys.argv[2]) if len(sys.argv) > 2 else 4000))
