# tshark_stream.py - tshark流式处理
# 用subprocess跑tshark，边读边解析，不会炸内存
# PacketWrapper兼容pyshark的字段访问方式

import os
import sys
import json
import signal
import logging
import threading
import subprocess
import shutil
import time
from typing import Iterator, Optional, Dict, Any, Callable, List, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from queue import Queue, Empty
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class TsharkError(Exception):
    pass


class TsharkNotFoundError(TsharkError):
    pass


class TsharkInvalidFilterError(TsharkError):
    pass


class TsharkInvalidInterfaceError(TsharkError):
    pass


class TsharkProcessError(TsharkError):
    pass


class TsharkTimeoutError(TsharkError):
    pass


class TsharkPermissionError(TsharkError):
    pass


class OutputFormat(Enum):
    EK = "ek"          # 每行一个完整JSON，流式处理最合适
    JSON = "json"
    FIELDS = "fields"


class LayerWrapper:
    """EK字段 → PyShark风格属性访问"""

    def __init__(self, layer_name: str, layer_data: Dict[str, Any]):
        self._layer_name = layer_name
        self._data = layer_data or {}

    def __getattr__(self, name: str) -> Any:
        if name.startswith('_'):
            raise AttributeError(name)

        ek_field_name = f"{self._layer_name}_{self._layer_name}_{name}"

        possible_names = [
            ek_field_name,
            f"{self._layer_name}_{name}",
            name,
            f"{self._layer_name}.{name}",
        ]

        for field_name in possible_names:
            if field_name in self._data:
                value = self._data[field_name]
                if isinstance(value, list) and len(value) > 0:
                    return value[0]
                return value

        if name == 'file_data':
            for key in self._data:
                if 'file_data' in key.lower():
                    value = self._data[key]
                    if isinstance(value, list) and len(value) > 0:
                        return value[0]
                    return value

        # request_full_uri需要拼接
        if name == 'request_full_uri':
            uri = self._get_field('request_uri')
            host = self._get_field('host')
            if uri:
                if host:
                    return f"http://{host}{uri}"
                return uri
            return None

        return None

    def _get_field(self, suffix):
        ek_name = f"{self._layer_name}_{self._layer_name}_{suffix}"
        if ek_name in self._data:
            value = self._data[ek_name]
            if isinstance(value, list) and len(value) > 0:
                return value[0]
            return value
        return None

    def __repr__(self):
        return f"<LayerWrapper {self._layer_name}: {len(self._data)} fields>"


class PacketWrapper:
    # 把tshark ek json包装成pyshark风格的packet对象，可以直接丢给WebShellDetector用

    def __init__(self, ek_data):
        self._layers_data = ek_data.get('layers', {})
        self._layers = {}
        self._frame_number = 0

        frame = self._layers_data.get('frame', {})
        fn = frame.get('frame_frame_number', [0])
        self._frame_number = int(fn[0]) if isinstance(fn, list) and fn else int(fn) if fn else 0

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)

        if name in self._layers:
            return self._layers[name]

        if name in self._layers_data:
            wrapper = LayerWrapper(name, self._layers_data[name])
            self._layers[name] = wrapper
            return wrapper

        # 层不存在就返回None，别炸
        return None

    def __hasattr__(self, name):
        return name in self._layers_data

    @property
    def layers(self):
        for name in self._layers_data:
            if name not in self._layers:
                self._layers[name] = LayerWrapper(name, self._layers_data[name])
        return self._layers

    @property
    def frame_number(self):
        return self._frame_number

    @property
    def number(self):  # pyshark兼容
        return self._frame_number

    def has_layer(self, layer_name):
        return layer_name in self._layers_data

    def __repr__(self):
        layer_names = list(self._layers_data.keys())
        return f"<PacketWrapper #{self._frame_number} layers={layer_names}>"


def _packet_has_layer(packet, layer_name):  # hasattr替代方案
    return layer_name in packet._layers_data


@dataclass
class PacketData:
    frame_number: int = 0
    timestamp: str = ""
    protocol: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    length: int = 0

    # HTTP字段
    http_method: str = ""
    http_uri: str = ""
    http_host: str = ""
    http_content_type: str = ""
    http_user_agent: str = ""
    http_request_body: bytes = b""
    http_response_code: str = ""
    http_response_body: bytes = b""

    tcp_stream: int = 0

    # 原始数据
    raw_ek_data: Dict[str, Any] = field(default_factory=dict)
    _wrapper: Optional[PacketWrapper] = field(default=None, repr=False)

    @property
    def wrapper(self):
        if self._wrapper is None:
            self._wrapper = PacketWrapper(self.raw_ek_data)
        return self._wrapper


@dataclass
class StreamConfig:
    pcap_path: Optional[str] = None        # PCAP 文件路径 (离线分析)
    interface: Optional[str] = None         # 网卡接口 (实时抓包)
    display_filter: str = ""                # 显示过滤器
    output_format: OutputFormat = OutputFormat.EK
    read_timeout: float = 0.1               # 管道读取超时(秒)
    max_packets: int = 0                    # 最大包数 (0=无限)
    fields: List[str] = field(default_factory=list)  # 自定义字段列表

    decode_as: Dict[str, str] = field(default_factory=dict)

    disable_name_resolution: bool = True
    line_buffered: bool = True


class ProcessManager:

    @staticmethod
    def get_creation_flags():
        if sys.platform == "win32":
            CREATE_NO_WINDOW = 0x08000000
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            return CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
        return 0

    @staticmethod
    def kill_process_tree(process, timeout=5.0):
        if process is None:
            return True

        try:
            if process.poll() is not None:
                return True
        except:
            return True

        pid = process.pid
        logger.debug(f"正在终止进程树 PID={pid}")

        try:
            if sys.platform == "win32":
                try:
                    kill_cmd = ["taskkill", "/F", "/T", "/PID", str(pid)]
                    subprocess.run(
                        kill_cmd,
                        capture_output=True,
                        timeout=timeout,
                        creationflags=0x08000000
                    )
                except subprocess.TimeoutExpired:
                    pass
                except FileNotFoundError:
                    # taskkill不可用，直接terminate
                    try:
                        process.terminate()
                        process.wait(timeout=2.0)
                    except:
                        try:
                            process.kill()
                        except:
                            pass
            else:
                # Unix: 按进程组杀
                try:
                    pgid = os.getpgid(pid)
                    os.killpg(pgid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError, OSError):
                    pass

                # wait before SIGKILL
                try:
                    process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    # 强制 SIGKILL
                    try:
                        pgid = os.getpgid(pid)
                        os.killpg(pgid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError, OSError):
                        pass

            # 确认死了没
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                logger.warning(f"进程 PID={pid} 未能在 {timeout}s 内终止")
                return False

            return True

        except Exception as e:
            logger.debug(f"终止进程树异常: {e}")
            return False

    @staticmethod
    def get_popen_kwargs(config):
        kwargs = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "bufsize": 0,
        }

        if sys.platform == "win32":
            kwargs["creationflags"] = ProcessManager.get_creation_flags()
        else:
            kwargs["start_new_session"] = True

        return kwargs


class StderrMonitor:
    # 后台线程读stderr，碰到致命错误就标记熔断

    ERROR_PATTERNS = {
        "Invalid interface": TsharkInvalidInterfaceError,
        "no such device": TsharkInvalidInterfaceError,
        "doesn't exist": TsharkInvalidInterfaceError,
        "Invalid capture filter": TsharkInvalidFilterError,
        "Invalid display filter": TsharkInvalidFilterError,
        "Display filter": TsharkInvalidFilterError,
        "Syntax error": TsharkInvalidFilterError,
        "Not a valid capture file": TsharkProcessError,
        "Permission denied": TsharkPermissionError,
        "Access is denied": TsharkPermissionError,
        "You don't have permission": TsharkPermissionError,
        "can't be opened": TsharkProcessError,
    }

    def __init__(self, stderr_pipe):
        self._stderr = stderr_pipe
        self._errors: List[str] = []
        self._exception: Optional[TsharkError] = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def _monitor_loop(self):
        try:
            while not self._stop_event.is_set():
                if self._stderr is None:
                    break

                try:
                    line = self._stderr.readline()
                except:
                    break

                if not line:
                    break

                # 二进制readline回来的要decode
                try:
                    line_str = line.decode('utf-8', errors='replace').strip()
                except:
                    continue

                if not line_str:
                    continue

                self._errors.append(line_str)
                logger.debug(f"tshark stderr: {line_str}")

                for pattern, exc_class in self.ERROR_PATTERNS.items():
                    if pattern.lower() in line_str.lower():
                        self._exception = exc_class(line_str)
                        return

        except Exception as e:
            logger.debug(f"Stderr 监控异常: {e}")

    @property
    def has_error(self) -> bool:
        return self._exception is not None

    @property
    def exception(self) -> Optional[TsharkError]:
        return self._exception

    @property
    def all_errors(self) -> List[str]:
        return self._errors.copy()


class PacketParser:

    @staticmethod
    def parse_ek_line(line):
        # tshark的json输出格式有时候会断行，这里做了容错
        try:
            data = json.loads(line)

            # EK有index元数据行，跳过
            if "index" in data:
                return None

            layers = data.get("layers", {})
            if not layers:
                return None

            packet = PacketData()
            packet.raw_ek_data = data

            frame = layers.get("frame", {})
            fn = frame.get("frame_frame_number", [0])
            packet.frame_number = int(fn[0]) if isinstance(fn, list) and fn else 0
            packet.timestamp = PacketParser._get_first(frame, "frame_frame_time", "")
            packet.length = int(PacketParser._get_first(frame, "frame_frame_len", 0))
            protocols = PacketParser._get_first(frame, "frame_frame_protocols", "")
            packet.protocol = protocols.split(":")[-1].upper() if protocols else ""

            ip = layers.get("ip", {})
            packet.src_ip = PacketParser._get_first(ip, "ip_ip_src", "")
            packet.dst_ip = PacketParser._get_first(ip, "ip_ip_dst", "")

            tcp = layers.get("tcp", {})
            if tcp:
                packet.src_port = int(PacketParser._get_first(tcp, "tcp_tcp_srcport", 0))
                packet.dst_port = int(PacketParser._get_first(tcp, "tcp_tcp_dstport", 0))
                packet.tcp_stream = int(PacketParser._get_first(tcp, "tcp_tcp_stream", 0))

            udp = layers.get("udp", {})
            if udp and not tcp:
                packet.src_port = int(PacketParser._get_first(udp, "udp_udp_srcport", 0))
                packet.dst_port = int(PacketParser._get_first(udp, "udp_udp_dstport", 0))

            http = layers.get("http", {})
            if http:
                packet.http_method = PacketParser._get_first(http, "http_http_request_method", "")
                packet.http_uri = PacketParser._get_first(http, "http_http_request_uri", "")
                packet.http_host = PacketParser._get_first(http, "http_http_host", "")
                packet.http_content_type = PacketParser._get_first(http, "http_http_content_type", "")
                packet.http_user_agent = PacketParser._get_first(http, "http_http_user_agent", "")
                packet.http_response_code = PacketParser._get_first(http, "http_http_response_code", "")

                file_data = PacketParser._get_first(http, "http_http_file_data", "")
                if file_data:
                    try:
                        body_bytes = bytes.fromhex(file_data.replace(":", ""))
                    except:
                        body_bytes = file_data.encode('utf-8', errors='ignore')

                    if packet.http_response_code and not packet.http_method:
                        packet.http_response_body = body_bytes
                    else:
                        packet.http_request_body = body_bytes

            return packet

        except json.JSONDecodeError:
            return None
        except Exception as e:
            logger.debug(f"解析 EK 行失败: {e}")
            return None

    @staticmethod
    def _get_first(data, key, default=""):
        value = data.get(key, default)
        if isinstance(value, list) and len(value) > 0:
            return value[0]
        return value if value else default


class TsharkProcessHandler:
    # 核心处理器，用subprocess跑tshark，生成器模式边读边解析边yield

    # 默认搜索路径
    DEFAULT_TSHARK_PATHS = [
        r"E:\internet_safe\wireshark\tshark.exe",
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        r"D:\Program Files\Wireshark\tshark.exe",
        r"D:\Wireshark\tshark.exe",
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
    ]

    def __init__(self, tshark_path=None):
        self._tshark_path = tshark_path or self._find_tshark()
        self._process: Optional[subprocess.Popen] = None
        self._stderr_monitor: Optional[StderrMonitor] = None
        self._is_running = False
        self._stop_requested = False
        self._packet_count = 0

    def _find_tshark(self):
        tshark = shutil.which("tshark")
        if tshark:
            return tshark

        for path in self.DEFAULT_TSHARK_PATHS:
            if os.path.exists(path):
                return path

        raise TsharkNotFoundError(
            "未找到 tshark！请安装 Wireshark: https://www.wireshark.org/download.html"
        )

    def _build_command(self, config):
        cmd = [self._tshark_path]

        if config.pcap_path:
            if ' ' in config.pcap_path and not config.pcap_path.startswith('"'):
                cmd.extend(["-r", config.pcap_path])
            else:
                cmd.extend(["-r", config.pcap_path])
        elif config.interface:
            cmd.extend(["-i", config.interface])
        else:
            raise ValueError("必须指定 pcap_path 或 interface")

        if config.disable_name_resolution:
            cmd.append("-n")
        if config.line_buffered:
            cmd.append("-l")

        if config.display_filter:
            cmd.extend(["-Y", config.display_filter])

        if config.max_packets > 0:
            cmd.extend(["-c", str(config.max_packets)])

        if config.output_format == OutputFormat.EK:
            cmd.extend(["-T", "ek"])
        elif config.output_format == OutputFormat.JSON:
            cmd.extend(["-T", "json"])
        elif config.output_format == OutputFormat.FIELDS:
            cmd.extend(["-T", "fields"])
            for field in config.fields:
                cmd.extend(["-e", field])
            cmd.extend(["-E", "separator=|"])

        for port, protocol in config.decode_as.items():
            cmd.extend(["-d", f"tcp.port=={port},{protocol}"])

        return cmd

    def stream_packets(self, config):
        self._stop_requested = False
        self._packet_count = 0

        cmd = self._build_command(config)
        logger.info(f"启动 tshark: {' '.join(cmd)}")

        popen_kwargs = ProcessManager.get_popen_kwargs(config)

        try:
            self._process = subprocess.Popen(cmd, **popen_kwargs)
            self._is_running = True

            self._stderr_monitor = StderrMonitor(self._process.stderr)
            self._stderr_monitor.start()

            time.sleep(0.05)
            if self._process.poll() is not None:
                if self._stderr_monitor.has_error:
                    raise self._stderr_monitor.exception
                errors = self._stderr_monitor.all_errors
                if errors:
                    raise TsharkProcessError("; ".join(errors))

            first_data_timeout = 5.0
            start_time = time.time()
            got_first_packet = False
            line_count = 0

            while not self._stop_requested:
                if self._stderr_monitor.has_error:
                    raise self._stderr_monitor.exception

                poll_result = self._process.poll()
                if poll_result is not None:
                    break

                if not got_first_packet:
                    elapsed = time.time() - start_time
                    if elapsed >= first_data_timeout:
                        break

                try:
                    line = self._process.stdout.readline()
                except Exception as e:
                    logger.debug(f"读取异常: {e}")
                    break

                if not line:
                    time.sleep(0.05)
                    continue

                line_count += 1

                try:
                    line_str = line.decode('utf-8', errors='replace').strip()
                except:
                    continue

                if not line_str:
                    continue

                packet = PacketParser.parse_ek_line(line_str)

                if packet:
                    if not got_first_packet:
                        got_first_packet = True

                    self._packet_count += 1
                    yield packet

                    if config.max_packets > 0 and self._packet_count >= config.max_packets:
                        break

            # 检查退出码
            if self._process.poll() is not None:
                exit_code = self._process.returncode
                if exit_code != 0 and not self._stop_requested:
                    if self._stderr_monitor.has_error:
                        raise self._stderr_monitor.exception
                    errors = self._stderr_monitor.all_errors
                    if errors:
                        fatal_errors = [e for e in errors if 'warning' not in e.lower()]
                        if fatal_errors:
                            raise TsharkProcessError("; ".join(fatal_errors[:3]))

        finally:
            self._is_running = False
            self.stop()

    def stream_pyshark_compatible(self, config):
        # 直接yield PacketWrapper，可以丢给现有检测器用
        for packet in self.stream_packets(config):
            yield packet.wrapper

    def stop(self):
        self._stop_requested = True

        if self._stderr_monitor:
            self._stderr_monitor.stop()
            self._stderr_monitor = None

        if self._process:
            ProcessManager.kill_process_tree(self._process)

            try:
                if self._process.stdout:
                    self._process.stdout.close()
            except:
                pass

            try:
                if self._process.stderr:
                    self._process.stderr.close()
            except:
                pass

            self._process = None

        self._is_running = False
        logger.debug("TsharkProcessHandler 已停止")

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def tshark_path(self) -> str:
        return self._tshark_path

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False


def stream_http_packets(pcap_path, display_filter="http", tshark_path=None, as_pyshark=False):
    # 快捷函数，读HTTP包
    handler = TsharkProcessHandler(tshark_path)
    config = StreamConfig(
        pcap_path=pcap_path,
        display_filter=display_filter,
        output_format=OutputFormat.EK
    )

    try:
        if as_pyshark:
            yield from handler.stream_pyshark_compatible(config)
        else:
            yield from handler.stream_packets(config)
    finally:
        handler.stop()


def get_protocol_stats(pcap_path, tshark_path=None):
    # tshark -z io,phs 协议统计，返回 (protocol_counts, total, hierarchy)
    handler = TsharkProcessHandler(tshark_path)

    cmd = [
        handler.tshark_path,
        "-r", pcap_path,
        "-q",
        "-z", "io,phs"
    ]

    popen_kwargs = {
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": 120
    }

    if sys.platform == "win32":
        popen_kwargs["creationflags"] = 0x08000000

    result = subprocess.run(cmd, **popen_kwargs)

    protocol_counts = {}
    total = 0
    hierarchy = []
    stack = []

    for line in result.stdout.split('\n'):
        if not line or 'frames:' not in line:
            continue

        stripped = line.lstrip()
        if not stripped:
            continue

        indent = len(line) - len(stripped)

        # 协议名可含空格，按 frames: 定位切分
        frames_pos = stripped.find('frames:')
        if frames_pos < 0:
            continue

        proto_name = stripped[:frames_pos].strip()
        if not proto_name:
            continue

        count = 0
        for part in stripped[frames_pos:].split():
            if part.startswith('frames:'):
                try:
                    count = int(part.replace('frames:', ''))
                except ValueError:
                    pass
                break

        upper_name = proto_name.upper()

        if total == 0 and upper_name in ("FRAME", "ETH"):
            total = count

        if upper_name in ("FRAME", "ETH"):
            stack = [(indent, None)]
            continue

        # DATA 跳过，不重置栈
        if upper_name == "DATA":
            continue

        protocol_counts[upper_name] = count

        node = {"name": upper_name, "count": count, "children": []}

        while stack and stack[-1][0] >= indent:
            stack.pop()

        if stack and stack[-1][1] is not None:
            stack[-1][1]["children"].append(node)
        else:
            hierarchy.append(node)

        stack.append((indent, node))

    if total == 0 and protocol_counts:
        total = max(protocol_counts.values())

    return protocol_counts, total, hierarchy


def build_hierarchy_stats(nodes, total):
    """dict hierarchy → ProtocolStats 层级列表"""
    from models.detection_result import ProtocolStats
    result = []
    for node in sorted(nodes, key=lambda n: -n["count"]):
        pct = (node["count"] / total * 100) if total > 0 else 0
        children = build_hierarchy_stats(node["children"], total) if node["children"] else []
        result.append(ProtocolStats(node["name"], node["count"], pct, children))
    return result


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) < 2:
        print("用法: python tshark_stream.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]

    print(f"\n=== 流式分析 {pcap_file} ===\n")

    print("协议统计:")
    stats, total, hierarchy = get_protocol_stats(pcap_file)
    print(f"  总包数: {total}")
    for proto, count in sorted(stats.items(), key=lambda x: -x[1])[:10]:
        print(f"  {proto}: {count}")

    print("\nHTTP 请求 (PyShark 兼容模式):")
    count = 0
    for pkt in stream_http_packets(pcap_file, as_pyshark=True):
        if pkt.has_layer('http') and pkt.http.request_method:
            print(f"  [{pkt.frame_number}] {pkt.http.request_method} {pkt.http.host}{pkt.http.request_uri}")
            count += 1
            if count >= 20:
                print("  ... (更多省略)")
                break

    print(f"\n分析完成!")
