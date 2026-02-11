# http_formatter.py - HTTP请求格式化

import sys
import os
import time
import logging
from typing import Optional, Dict, Any, List

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DEFAULT_OUTPUT_DIR = os.path.join(PROJECT_ROOT, "output")

if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from utils import picture, hex_to_string, create_folder_if_not_exists

logger = logging.getLogger(__name__)


def run_image_extraction(http_packets) -> List[str]:
    extracted_files = []
    for packet in http_packets:
        content_type = getattr(packet.http, 'content_type', '')
        if "image/png" in content_type:
            result = picture(packet)
            if result:
                extracted_files.append(result)
    return extracted_files


def burp_format_request(packet, http_layer, output_folder: str = None, save_to_file: bool = True) -> Optional[Dict[str, Any]]:
    """格式化为Burp Suite请求格式"""
    if output_folder is None:
        output_folder = DEFAULT_OUTPUT_DIR

    try:
        method = getattr(http_layer, 'request_method', 'GET').upper()
        uri = getattr(http_layer, 'request_uri', '/')
        http_version = getattr(http_layer, 'request_version', 'HTTP/1.1')

        request_str = f"{method} {uri} {http_version}\n"

        headers = {}
        header_fields = {
            'Host': 'host',
            'User-Agent': 'user_agent',
            'Accept': 'accept',
            'Accept-Encoding': 'accept_encoding',
            'Accept-Language': 'accept_language',
            'Connection': 'connection',
            'Content-Type': 'content_type',
            'Content-Length': 'content_length',
            'Sec-Fetch-Site': 'sec_fetch_site',
            'Sec-Fetch-Mode': 'sec_fetch_mode',
            'Sec-Fetch-Dest': 'sec_fetch_dest',
            'Priority': 'priority',
            'Referer': 'referer',
            'Cookie': 'cookie',
            'Authorization': 'authorization',
        }

        for header_name, attr_name in header_fields.items():
            if hasattr(http_layer, attr_name):
                value = getattr(http_layer, attr_name)
                if value:
                    headers[header_name] = value

        for header_name, header_value in headers.items():
            request_str += f"{header_name}: {header_value}\n"

        body = ""
        if method in ('POST', 'PUT', 'PATCH'):
            if hasattr(http_layer, 'file_data'):
                body_data = http_layer.file_data
                body = hex_to_string(body_data) if body_data else ""
            elif hasattr(http_layer, 'request_body'):
                body = getattr(http_layer, 'request_body', '')

        request_str += "\n"
        if body:
            request_str += body

        result = {
            "file_path": None,
            "full_request": request_str,
            "method": method,
            "uri": uri,
            "headers": headers,
            "body": body
        }

        if save_to_file:
            create_folder_if_not_exists(output_folder)
            timestamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
            filename = os.path.join(output_folder, f"request_{timestamp}.txt")

            with open(filename, 'a', encoding='utf-8') as f:
                f.write(request_str + "\n\n")

            result["file_path"] = filename
            logger.debug(f"请求已保存到: {filename}")

        return result

    except Exception as e:
        logger.error(f"Burp格式化异常: {e}")
        return None


def format_antsword_results(results: List[Dict]) -> Dict[str, Any]:
    """格式化蚁剑检测结果"""
    if not results:
        return {"count": 0, "results": []}

    formatted_results = []

    for result in results:
        formatted = {
            "method": result.get('method', 'Unknown'),
            "uri": result.get('uri', 'Unknown'),
            "confidence": result.get('confidence', 'unknown'),
            "total_weight": result.get('total_weight', 0),
            "indicators": [],
            "payloads": [],
            "response_sample": result.get('response_sample', '')
        }

        for ind in result.get('indicators', []):
            formatted["indicators"].append({
                "name": ind.get('name', ''),
                "weight": ind.get('weight', 0),
                "description": ind.get('description', '')
            })

        payloads = result.get('payload') or result.get('payloads', {})
        if isinstance(payloads, dict):
            if 'payloads' in payloads:
                payloads = payloads['payloads']

            for key, val in payloads.items():
                if isinstance(val, dict):
                    # 跳过PHP_Code类型，只保留命令和参数
                    if 'PHP_Code' not in val.get('type', ''):
                        formatted["payloads"].append({
                            "param_name": key,
                            "type": val.get('type', ''),
                            "method": val.get('method', ''),
                            "decoded": str(val.get('decoded', val.get('decoded_content', '')))[:200]
                        })

        formatted_results.append(formatted)

    return {
        "count": len(formatted_results),
        "results": formatted_results
    }


def format_detection_for_display(detection: Dict) -> str:
    """格式化成可读字符串，调试用"""
    lines = []

    lines.append(f"类型: {detection.get('type', 'Unknown')}")
    lines.append(f"方法: {detection.get('method', 'Unknown')}")
    lines.append(f"URI: {detection.get('uri', 'Unknown')}")
    lines.append(f"置信度: {detection.get('confidence', 'unknown')}")
    lines.append(f"权重: {detection.get('total_weight', 0)}")

    indicators = detection.get('indicators', [])
    if indicators:
        lines.append(f"匹配特征 ({len(indicators)}):")
        for ind in indicators[:5]:
            lines.append(f"  - {ind.get('name', '')} (权重:{ind.get('weight', 0)})")
        if len(indicators) > 5:
            lines.append(f"  ... 还有 {len(indicators) - 5} 个特征")

    payloads = detection.get('payloads', {})
    if payloads:
        lines.append(f"载荷参数 ({len(payloads)}):")
        for key, val in list(payloads.items())[:3]:
            if isinstance(val, dict):
                lines.append(f"  - {key}: {val.get('type', '')} [{val.get('method', '')}]")

    return "\n".join(lines)


def extract_request_info(packet, http_layer) -> Dict[str, Any]:
    info = {
        "method": getattr(http_layer, 'request_method', ''),
        "uri": getattr(http_layer, 'request_uri', ''),
        "full_uri": getattr(http_layer, 'request_full_uri', ''),
        "host": getattr(http_layer, 'host', ''),
        "user_agent": getattr(http_layer, 'user_agent', ''),
        "content_type": getattr(http_layer, 'content_type', ''),
        "content_length": getattr(http_layer, 'content_length', ''),
        "body": None
    }

    if hasattr(http_layer, 'file_data'):
        body_data = http_layer.file_data
        info["body"] = hex_to_string(body_data) if body_data else None
    elif hasattr(http_layer, 'request_body'):
        info["body"] = getattr(http_layer, 'request_body', None)

    if hasattr(packet, 'ip'):
        info["src_ip"] = getattr(packet.ip, 'src', '')
        info["dst_ip"] = getattr(packet.ip, 'dst', '')

    return info


def extract_response_info(packet, http_layer) -> Dict[str, Any]:
    info = {
        "status_code": getattr(http_layer, 'response_code', ''),
        "content_type": getattr(http_layer, 'content_type', ''),
        "content_length": getattr(http_layer, 'content_length', ''),
        "body": None
    }

    if hasattr(http_layer, 'file_data'):
        body_data = http_layer.file_data
        info["body"] = hex_to_string(body_data) if body_data else None

    return info
