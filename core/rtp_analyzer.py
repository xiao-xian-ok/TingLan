# rtp_analyzer.py - RTP 音视频流检测与导出

import os
import re
import sys
import struct
import shutil
import logging
import subprocess
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

_working_heuristic: Optional[List[str]] = None

RTP_PAYLOAD_TYPES: Dict[int, Tuple[str, str, int]] = {
    0:  ("PCMU",  "audio", 8000),
    3:  ("GSM",   "audio", 8000),
    4:  ("G723",  "audio", 8000),
    5:  ("DVI4",  "audio", 8000),
    6:  ("DVI4",  "audio", 16000),
    7:  ("LPC",   "audio", 8000),
    8:  ("PCMA",  "audio", 8000),
    9:  ("G722",  "audio", 8000),
    10: ("L16",   "audio", 44100),
    11: ("L16",   "audio", 44100),
    12: ("QCELP", "audio", 8000),
    13: ("CN",    "audio", 8000),
    14: ("MPA",   "audio", 90000),
    15: ("G728",  "audio", 8000),
    16: ("DVI4",  "audio", 11025),
    17: ("DVI4",  "audio", 22050),
    18: ("G729",  "audio", 8000),
    25: ("CelB",  "video", 90000),
    26: ("JPEG",  "video", 90000),
    28: ("nv",    "video", 90000),
    31: ("H261",  "video", 90000),
    32: ("MPV",   "video", 90000),
    33: ("MP2T",  "video", 90000),
    34: ("H263",  "video", 90000),
}

SOX_CODECS = {
    "PCMU": ("-t", "ul", "-r", "8000", "-c", "1"),
    "PCMA": ("-t", "al", "-r", "8000", "-c", "1"),
    "G722": ("-t", "raw", "-r", "16000", "-b", "16", "-c", "1", "-e", "signed-integer"),
    "L16":  ("-t", "raw", "-r", "44100", "-b", "16", "-c", "1", "-e", "signed-integer"),
}

FFMPEG_CODECS = {
    "G723":  ("g723_1", "wav"),
    "G729":  ("g729",   "wav"),
    "GSM":   ("gsm",    "wav"),
    "MPA":   ("mp3",    "mp3"),
    "H261":  ("h261",   "mp4"),
    "H263":  ("h263",   "mp4"),
    "H264":  ("h264",   "mp4"),
    "H265":  ("hevc",   "mp4"),
    "VP8":   ("ivf",    "webm"),
    "VP9":   ("ivf",    "webm"),
    "OPUS":  ("ogg",    "ogg"),
    "AMR":   ("amr",    "wav"),
}

# tshark 显示名 → (标准编码名, 媒体类型, 采样率)
TSHARK_CODEC_MAP: Dict[str, Tuple[str, str, int]] = {
    "g711u":  ("PCMU",  "audio", 8000),
    "g711a":  ("PCMA",  "audio", 8000),
    "pcmu":   ("PCMU",  "audio", 8000),
    "pcma":   ("PCMA",  "audio", 8000),
    "g722":   ("G722",  "audio", 8000),
    "g723":   ("G723",  "audio", 8000),
    "g728":   ("G728",  "audio", 8000),
    "g729":   ("G729",  "audio", 8000),
    "gsm":    ("GSM",   "audio", 8000),
    "l16":    ("L16",   "audio", 44100),
    "mpa":    ("MPA",   "audio", 90000),
    "dvi4":   ("DVI4",  "audio", 8000),
    "lpc":    ("LPC",   "audio", 8000),
    "qcelp":  ("QCELP", "audio", 8000),
    "cn":     ("CN",    "audio", 8000),
    "opus":   ("OPUS",  "audio", 48000),
    "amr":    ("AMR",   "audio", 8000),
    "h261":   ("H261",  "video", 90000),
    "h263":   ("H263",  "video", 90000),
    "h264":   ("H264",  "video", 90000),
    "h265":   ("H265",  "video", 90000),
    "jpeg":   ("JPEG",  "video", 90000),
    "mpv":    ("MPV",   "video", 90000),
    "mp2t":   ("MP2T",  "video", 90000),
    "vp8":    ("VP8",   "video", 90000),
    "vp9":    ("VP9",   "video", 90000),
    "celb":   ("CelB",  "video", 90000),
}

# tshark -z rtp,streams 输出格式：
# start end src_ip port dst_ip port ssrc codec pkts lost (loss%) deltas... jitters... [X]
_RE_RTP_STREAM = re.compile(
    r'^\s*'
    r'[\d.]+\s+[\d.]+\s+'                  # start/end time
    r'([\d.]+|[\da-fA-F:]+)\s+'            # src IP
    r'(\d+)\s+'                            # src port
    r'([\d.]+|[\da-fA-F:]+)\s+'            # dst IP
    r'(\d+)\s+'                            # dst port
    r'(0x[\da-fA-F]+)\s+'                  # SSRC
    r'(\S+)\s+'                            # payload/codec name
    r'(\d+)\s+'                            # packets
    r'(-?\d+)\s+'                          # lost (可为负)
    r'\([-\d.]+%\)\s+'                     # loss %
    r'[\d.]+\s+[\d.]+\s+[\d.]+\s+'        # min/mean/max delta
    r'[\d.]+\s+[\d.]+\s+'                 # min/mean jitter
    r'([\d.]+)',                            # max jitter
    re.MULTILINE
)


def _run_tshark(tshark_path: str, args: List[str], timeout: int = 60) -> str:
    cmd = [tshark_path] + args
    kwargs = {
        "capture_output": True,
        "timeout": timeout,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = 0x08000000
    result = subprocess.run(cmd, **kwargs)
    return result.stdout


def _stream_tshark_payload(cmd: List[str], timeout: int = 300) -> bytes:
    """流式读取 tshark -e rtp.payload 输出，边读边转换 hex"""
    popen_kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "bufsize": 1,
    }
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = 0x08000000

    buf = bytearray()
    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)
        try:
            for raw_line in proc.stdout:
                hex_str = raw_line.decode("utf-8", errors="replace").strip().replace(":", "")
                if hex_str:
                    try:
                        buf.extend(bytes.fromhex(hex_str))
                    except ValueError:
                        pass
        finally:
            proc.stdout.close()
            proc.wait(timeout=10)
    except Exception as e:
        raise RuntimeError(f"tshark 流式读取失败: {e}")

    return bytes(buf)


def _get_heuristic_opts(tshark_path: str) -> List[str]:
    """探测当前 tshark 支持的 RTP 启发式选项"""
    global _working_heuristic
    if _working_heuristic is not None:
        return _working_heuristic

    # 检查 tshark 是否支持 --enable-heuristic（Wireshark 3.0+）
    try:
        kwargs = {
            "capture_output": True,
            "timeout": 10,
            "encoding": "utf-8",
            "errors": "replace",
        }
        if sys.platform == "win32":
            kwargs["creationflags"] = 0x08000000
        result = subprocess.run([tshark_path, "-h"], **kwargs)
        if "--enable-heuristic" in (result.stdout or ""):
            _working_heuristic = ["--enable-heuristic", "rtp_udp"]
            logger.debug("RTP heuristic: --enable-heuristic rtp_udp")
            return _working_heuristic
    except Exception:
        pass

    # 旧版本回退到 preference 方式
    _working_heuristic = ["-o", "rtp.heuristic_rtp:TRUE"]
    logger.debug("RTP heuristic fallback: -o rtp.heuristic_rtp:TRUE")
    return _working_heuristic


def list_rtp_streams(pcap_path: str, tshark_path: str) -> list:
    """用 tshark -z rtp,streams 列出所有 RTP 流"""
    from models.detection_result import RTPStreamInfo

    heuristic = _get_heuristic_opts(tshark_path)
    base_args = ["-r", pcap_path, "-q", "-z", "rtp,streams"]

    try:
        output = _run_tshark(
            tshark_path, base_args + heuristic, timeout=180
        )
    except subprocess.TimeoutExpired:
        logger.warning("RTP 流检测超时")
        return []
    except Exception as e:
        logger.warning(f"RTP 流检测失败: {e}")
        return []

    if not output or "RTP" not in output:
        return []

    streams = []
    for m in _RE_RTP_STREAM.finditer(output):
        src_ip = m.group(1)
        src_port = m.group(2)
        dst_ip = m.group(3)
        dst_port = m.group(4)
        ssrc = m.group(5)
        payload_name = m.group(6)
        packets = int(m.group(7))
        lost = int(m.group(8))
        jitter = float(m.group(9))

        codec_info = TSHARK_CODEC_MAP.get(payload_name.lower())
        if codec_info:
            codec_name, media_type, sample_rate = codec_info
        else:
            codec_name = payload_name
            media_type = "audio"
            sample_rate = 8000

        if media_type == "audio":
            duration = packets * 0.02
        else:
            duration = packets / 30.0

        streams.append(RTPStreamInfo(
            ssrc=ssrc,
            src_addr=f"{src_ip}:{src_port}",
            dst_addr=f"{dst_ip}:{dst_port}",
            payload_type=0,
            codec_name=codec_name,
            media_type=media_type,
            sample_rate=sample_rate,
            packets=packets,
            lost=max(lost, 0),
            max_jitter=jitter,
            duration_sec=round(duration, 1),
            pcap_path=pcap_path,
        ))

    return streams


def parse_sdp_codecs(pcap_path: str, tshark_path: str) -> Dict[int, Tuple[str, str, int]]:
    """从 SDP 解析动态 PT（96-127）到编码名映射"""
    try:
        output = _run_tshark(tshark_path, [
            "-r", pcap_path,
            "-Y", "sdp",
            "-T", "fields",
            "-e", "sdp.media",
            "-e", "sdp.media.format",
            "-e", "sdp.fmtp.configuration",
        ])
    except Exception as e:
        logger.debug(f"SDP 解析失败: {e}")
        return {}

    if not output:
        return {}

    try:
        rtpmap_output = _run_tshark(tshark_path, [
            "-r", pcap_path,
            "-Y", "sdp.media.attr contains rtpmap",
            "-T", "fields",
            "-e", "sdp.fmtp.parameter",
            "-e", "sdp.media.attr",
        ])
    except Exception:
        rtpmap_output = ""

    codec_map: Dict[int, Tuple[str, str, int]] = {}

    rtpmap_re = re.compile(r'rtpmap:(\d+)\s+([^/\s]+)(?:/(\d+))?')
    for line in (rtpmap_output or "").split("\n"):
        for rm in rtpmap_re.finditer(line):
            pt = int(rm.group(1))
            if pt < 96:
                continue
            name = rm.group(2).upper()
            rate = int(rm.group(3)) if rm.group(3) else 8000

            media_type = "video" if name in (
                "H264", "H265", "VP8", "VP9", "AV1", "H261", "H263"
            ) else "audio"

            codec_map[pt] = (name, media_type, rate)

    return codec_map


def export_rtp_stream(
    pcap_path: str,
    tshark_path: str,
    stream_info,
    output_dir: str
) -> str:
    """导出单个 RTP 流，流式读取 tshark 输出"""
    os.makedirs(output_dir, exist_ok=True)

    ssrc = stream_info.ssrc
    codec = stream_info.codec_name.upper()
    base_name = f"rtp_{ssrc}_{codec}"

    heuristic = _get_heuristic_opts(tshark_path)

    cmd = [tshark_path, "-r", pcap_path,
           "-Y", f"rtp.ssrc=={ssrc}",
           "-T", "fields", "-e", "rtp.payload"] + heuristic

    raw_data = _stream_tshark_payload(cmd)

    if not raw_data:
        raise RuntimeError(f"SSRC {ssrc} 无 RTP payload 数据")

    converted = _try_convert(raw_data, codec, stream_info, output_dir, base_name)
    if converted:
        return converted

    raw_path = os.path.join(output_dir, f"{base_name}.raw")
    with open(raw_path, "wb") as f:
        f.write(raw_data)
    return raw_path


def _normalize_ssrc(val: str) -> str:
    """SSRC 归一化为小写 0x 十六进制"""
    s = val.strip()
    if s.lower().startswith("0x"):
        try:
            return hex(int(s, 16))
        except ValueError:
            return s.lower()
    try:
        return hex(int(s))
    except ValueError:
        return s.lower()


def export_rtp_streams_batch(
    pcap_path: str,
    tshark_path: str,
    streams: list,
    output_dir: str,
    progress_cb=None,
    cancel_check=None
) -> Dict[str, str]:
    """批量导出 RTP 流，分批 tshark 调用避免命令行过长"""
    if not streams:
        return {}

    os.makedirs(output_dir, exist_ok=True)
    heuristic = _get_heuristic_opts(tshark_path)

    norm_to_orig: Dict[str, str] = {}
    for s in streams:
        norm = _normalize_ssrc(s.ssrc)
        norm_to_orig.setdefault(norm, s.ssrc)

    unique_ssrcs = list(norm_to_orig.keys())
    buffers: Dict[str, bytearray] = {s: bytearray() for s in unique_ssrcs}

    BATCH_SIZE = 200
    total_batches = (len(unique_ssrcs) + BATCH_SIZE - 1) // BATCH_SIZE
    total_streams = len(streams)

    popen_kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "bufsize": 1,
    }
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = 0x08000000

    for batch_idx in range(total_batches):
        if cancel_check and cancel_check():
            break

        batch = unique_ssrcs[batch_idx * BATCH_SIZE:(batch_idx + 1) * BATCH_SIZE]
        ssrc_filter = " || ".join(f"rtp.ssrc=={s}" for s in batch)
        cmd = [tshark_path, "-r", pcap_path,
               "-Y", ssrc_filter,
               "-T", "fields", "-e", "rtp.ssrc", "-e", "rtp.payload",
               "-E", "separator=\t"] + heuristic

        if progress_cb:
            est = min((batch_idx + 1) * total_streams // total_batches, total_streams)
            progress_cb(est, total_streams, f"提取 {batch_idx + 1}/{total_batches}")

        try:
            proc = subprocess.Popen(cmd, **popen_kwargs)
            try:
                for raw_line in proc.stdout:
                    if cancel_check and cancel_check():
                        proc.kill()
                        break

                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line or '\t' not in line:
                        continue

                    ssrc_val, hex_payload = line.split('\t', 1)
                    norm_ssrc = _normalize_ssrc(ssrc_val)
                    hex_str = hex_payload.strip().replace(":", "")

                    if norm_ssrc in buffers and hex_str:
                        try:
                            buffers[norm_ssrc].extend(bytes.fromhex(hex_str))
                        except ValueError:
                            pass
            finally:
                proc.stdout.close()
                proc.wait(timeout=30)
                if proc.returncode:
                    logger.debug(f"tshark batch {batch_idx} rc={proc.returncode}")
        except Exception as e:
            logger.warning(f"tshark 批次 {batch_idx + 1}/{total_batches} 失败: {e}")

    results: Dict[str, str] = {}

    for i, stream in enumerate(streams):
        if cancel_check and cancel_check():
            break

        ssrc = stream.ssrc
        norm = _normalize_ssrc(ssrc)
        codec = stream.codec_name.upper()
        base_name = f"rtp_{ssrc}_{codec}"

        raw_data = bytes(buffers.get(norm, b""))
        if not raw_data:
            continue

        converted = _try_convert(raw_data, codec, stream, output_dir, base_name)
        if converted:
            results[ssrc] = converted
        else:
            raw_path = os.path.join(output_dir, f"{base_name}.raw")
            with open(raw_path, "wb") as f:
                f.write(raw_data)
            results[ssrc] = raw_path

    buffers.clear()
    return results


def _try_convert(
    raw_data: bytes, codec: str, stream_info, output_dir: str, base_name: str
) -> Optional[str]:
    """尝试转码：纯Python WAV → sox → ffmpeg，成功返回输出路径"""
    wav_fmt = {"PCMU": 0x0007, "PCMA": 0x0006}.get(codec)
    if wav_fmt is not None:
        out_path = os.path.join(output_dir, f"{base_name}.wav")
        try:
            _write_wav(raw_data, out_path, wav_fmt, 8000, 1, 8)
            return out_path
        except Exception as e:
            logger.debug(f"纯Python WAV写入失败: {e}")

    sox_path = shutil.which("sox")
    ffmpeg_path = shutil.which("ffmpeg")

    # sox/ffmpeg 需要磁盘文件作为输入
    raw_path = None

    def _ensure_raw_file():
        nonlocal raw_path
        if raw_path is None:
            raw_path = os.path.join(output_dir, f"{base_name}.raw")
            with open(raw_path, "wb") as f:
                f.write(raw_data)
        return raw_path

    if sox_path and codec in SOX_CODECS:
        out_path = os.path.join(output_dir, f"{base_name}.wav")
        sox_args = list(SOX_CODECS[codec])
        cmd = [sox_path] + sox_args + [_ensure_raw_file(), "-t", "wav", out_path]
        try:
            _run_external(cmd)
            if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
                _cleanup_temp(raw_path)
                return out_path
        except Exception as e:
            logger.debug(f"sox 转码失败: {e}")

    if ffmpeg_path and codec in FFMPEG_CODECS:
        fmt, ext = FFMPEG_CODECS[codec]
        out_path = os.path.join(output_dir, f"{base_name}.{ext}")
        cmd = [ffmpeg_path, "-y", "-f", fmt, "-i", _ensure_raw_file(), out_path]
        try:
            _run_external(cmd)
            if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
                _cleanup_temp(raw_path)
                return out_path
        except Exception as e:
            logger.debug(f"ffmpeg 转码失败: {e}")

    if ffmpeg_path and stream_info.media_type == "audio":
        out_path = os.path.join(output_dir, f"{base_name}.wav")
        rate = stream_info.sample_rate if stream_info.sample_rate > 0 else 8000
        cmd = [
            ffmpeg_path, "-y",
            "-f", "s16le", "-ar", str(rate), "-ac", "1",
            "-i", _ensure_raw_file(), out_path
        ]
        try:
            _run_external(cmd)
            if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
                _cleanup_temp(raw_path)
                return out_path
        except Exception as e:
            logger.debug(f"ffmpeg 通用音频转码失败: {e}")

    _cleanup_temp(raw_path)
    return None


def _write_wav(
    raw_data: bytes, out_path: str,
    audio_format: int, sample_rate: int, channels: int, bits_per_sample: int
):
    """纯 Python 写 WAV（PCMU/PCMA 等非 PCM 格式）"""
    byte_rate = sample_rate * channels * bits_per_sample // 8
    block_align = channels * bits_per_sample // 8
    data_size = len(raw_data)
    fmt_chunk_size = 18  # 非 PCM 需要 cbSize 字段
    file_size = 4 + (8 + fmt_chunk_size) + (8 + 4) + (8 + data_size)

    with open(out_path, "wb") as f:
        f.write(b"RIFF")
        f.write(struct.pack("<I", file_size))
        f.write(b"WAVE")
        f.write(b"fmt ")
        f.write(struct.pack("<I", fmt_chunk_size))
        f.write(struct.pack("<HHIIHH",
            audio_format, channels, sample_rate,
            byte_rate, block_align, bits_per_sample))
        f.write(struct.pack("<H", 0))  # cbSize
        f.write(b"fact")
        f.write(struct.pack("<II", 4, data_size // block_align))
        f.write(b"data")
        f.write(struct.pack("<I", data_size))
        f.write(raw_data)


def _cleanup_temp(path: Optional[str]):
    if path and os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


def _run_external(cmd: List[str], timeout: int = 60):
    kwargs = {
        "capture_output": True,
        "timeout": timeout,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = 0x08000000
    result = subprocess.run(cmd, **kwargs)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace") if isinstance(result.stderr, bytes) else (result.stderr or "")
        raise RuntimeError(f"命令失败 (rc={result.returncode}): {stderr[:200]}")


def get_available_tools() -> Dict[str, Optional[str]]:
    """检测可用的转码工具"""
    return {
        "sox": shutil.which("sox"),
        "ffmpeg": shutil.which("ffmpeg"),
    }
