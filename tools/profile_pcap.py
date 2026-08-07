#!/usr/bin/env python3
"""Profile TShark stages used by TingLan without changing application code."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

try:
    import psutil  # optional; enables CPU/RSS metrics
except Exception:
    psutil = None

SEP = chr(31)
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_tshark(explicit: Optional[str], root: Path) -> Optional[str]:
    candidates: List[Path] = []
    for value in (explicit, os.environ.get("WIRESHARK_PATH")):
        if value:
            path = Path(value).expanduser()
            candidates.append(path / "tshark.exe" if path.is_dir() else path)
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if directory:
            candidates.append(Path(directory) / "tshark.exe")
            candidates.append(Path(directory) / "tshark")
    candidates.extend([
        Path("E:/cyber_safe/wireshark/tshark.exe"),
        Path("E:/internet_safe/wireshark/tshark.exe"),
        Path("C:/Program Files/Wireshark/tshark.exe"),
        Path("C:/Program Files (x86)/Wireshark/tshark.exe"),
    ])
    candidates.append(root / "vendor" / "wireshark" / "tshark.exe")
    for candidate in candidates:
        try:
            if candidate.is_file():
                return str(candidate.resolve())
        except OSError:
            pass
    return None


def kill_tree(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           creationflags=CREATE_NO_WINDOW, timeout=10)
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass


def drain_stderr(stream, state: Dict[str, Any]) -> None:
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            state["bytes"] += len(chunk)
            if len(state["preview"]) < 4096:
                state["preview"] += chunk[:4096 - len(state["preview"])]
    except Exception as exc:
        state["error"] = repr(exc)


def metrics(pid: int):
    if psutil is None:
        return None, None
    try:
        proc = psutil.Process(pid)
        cpu = proc.cpu_times()
        return cpu.user + cpu.system, proc.memory_info().rss
    except Exception:
        return None, None


def run_stage(name: str, command: Sequence[str], cwd: Path, timeout: float,
              count_lines: bool = True) -> Dict[str, Any]:
    started = time.perf_counter()
    state: Dict[str, Any] = {"bytes": 0, "preview": b""}
    stdout_bytes = records = 0
    peak_cpu = 0.0
    peak_rss = 0
    timed_out = False
    launch_error = None
    kwargs: Dict[str, Any] = {
        "cwd": str(cwd), "stdout": subprocess.PIPE, "stderr": subprocess.PIPE,
        "bufsize": 0,
    }
    if os.name == "nt":
        kwargs["creationflags"] = CREATE_NO_WINDOW
    else:
        kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(list(command), **kwargs)
    except Exception as exc:
        process = None
        launch_error = repr(exc)
    stderr_thread = None
    if process is not None and process.stderr is not None:
        stderr_thread = threading.Thread(target=drain_stderr,
                                          args=(process.stderr, state), daemon=True)
        stderr_thread.start()
    if process is not None and process.stdout is not None:
        try:
            while True:
                line = process.stdout.readline()
                if line:
                    stdout_bytes += len(line)
                    if count_lines and line.strip():
                        records += 1
                elif process.poll() is not None:
                    break
                else:
                    time.sleep(0.01)
                cpu, rss = metrics(process.pid)
                if cpu is not None:
                    peak_cpu = max(peak_cpu, cpu)
                if rss is not None:
                    peak_rss = max(peak_rss, rss)
                if timeout > 0 and time.perf_counter() - started >= timeout:
                    timed_out = True
                    kill_tree(process)
                    break
        finally:
            try:
                process.wait(timeout=10)
            except Exception:
                kill_tree(process)
            try:
                process.stdout.close()
            except Exception:
                pass
    if stderr_thread:
        stderr_thread.join(timeout=5)
    if process is not None:
        cpu, rss = metrics(process.pid)
        if cpu is not None:
            peak_cpu = max(peak_cpu, cpu)
        if rss is not None:
            peak_rss = max(peak_rss, rss)
    return {
        "name": name, "command": list(command), "cwd": str(cwd),
        "elapsed_sec": round(time.perf_counter() - started, 3),
        "timeout_sec": timeout if timeout > 0 else None, "timed_out": timed_out,
        "returncode": None if process is None else process.returncode,
        "launch_error": launch_error, "stdout_bytes": stdout_bytes,
        "nonempty_records": records, "stderr_bytes": state["bytes"],
        "stderr_preview": state["preview"].decode("utf-8", "replace").strip(),
        "stderr_drain_error": state.get("error"),
        "peak_rss_mb": round(peak_rss / 1048576, 2) if peak_rss else None,
        "cpu_sec": round(peak_cpu, 3) if peak_cpu else None,
        "metrics_source": "psutil" if psutil is not None else "unavailable",
    }


def fields_cmd(tshark: str, pcap: str, filt: str, fields: Sequence[str],
               count: Optional[int] = None) -> List[str]:
    command = [tshark, "-r", pcap, "-n", "-Y", filt, "-T", "fields"]
    for field in fields:
        command += ["-e", field]
    command += ["-E", f"separator={SEP}", "-E", "quote=n"]
    if count is not None:
        command += ["-c", str(count)]
    return command


def ek_cmd(tshark: str, pcap: str, filt: str, count: Optional[int] = None) -> List[str]:
    command = [tshark, "-r", pcap, "-n", "-Y", filt, "-T", "ek"]
    if count is not None:
        command += ["-c", str(count)]
    return command


def project_scan(root: Path) -> Dict[str, Any]:
    patterns = {
        "subprocess_run": r"\bsubprocess\.run\s*\(",
        "subprocess_popen": r"\bsubprocess\.Popen\s*\(",
        "pyshark_capture": r"\b(?:pyshark\.)?FileCapture\s*\(",
        "read_pcap": r"\bread_pcap\s*\(",
        "stream_packets": r"\bstream_packets\s*\(",
        "analyze_pcap": r"\banalyze_pcap\s*\(",
        "export_objects": r"--export-objects",
    }
    totals = {key: 0 for key in patterns}
    files = {}
    for path in root.rglob("*.py"):
        if any(part in {".git", ".venv", "__pycache__"} for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        counts = {key: len(re.findall(pattern, text)) for key, pattern in patterns.items()}
        if any(counts.values()):
            files[str(path.relative_to(root))] = counts
            for key, value in counts.items():
                totals[key] += value
    return {"totals": totals, "files": files}


def print_table(stages: List[Dict[str, Any]]) -> None:
    print("\nStage results")
    print("name                           sec    records  stdout(MB)  RSS(MB)  CPU(sec) status")
    print("-" * 92)
    for item in stages:
        status = "TIMEOUT" if item["timed_out"] else str(item["returncode"])
        rss = "-" if item["peak_rss_mb"] is None else f"{item['peak_rss_mb']:.1f}"
        cpu = "-" if item["cpu_sec"] is None else f"{item['cpu_sec']:.1f}"
        print(f"{item['name'][:30]:30} {item['elapsed_sec']:7.1f} {item['nonempty_records']:9d} "
              f"{item['stdout_bytes']/1048576:10.1f} {rss:8} {cpu:8} {status}")
        if item["stderr_preview"]:
            print("  stderr:", item["stderr_preview"][:240].replace("\n", " | "))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", nargs="?", default="webone.pcap")
    parser.add_argument("--tshark")
    parser.add_argument("--timeout", type=float, default=900,
                        help="Timeout per stage in seconds; 0 disables it")
    parser.add_argument("--no-timeout", action="store_true",
                        help="Run every stage without an automatic timeout")
    parser.add_argument("--sample-packets", type=int, default=5000)
    parser.add_argument("--full-ek", action="store_true")
    parser.add_argument("--include-response", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()
    pcap = Path(args.pcap).expanduser().resolve()
    root = Path(__file__).resolve().parent.parent
    if not pcap.is_file():
        print(f"PCAP not found: {pcap}", file=sys.stderr)
        return 2
    tshark = find_tshark(args.tshark, root)
    if not tshark:
        print("TShark not found; pass --tshark.", file=sys.stderr)
        return 2
    cwd, pcap_name = pcap.parent, pcap.name
    stage_timeout = 0.0 if args.no_timeout else max(0.0, args.timeout)
    report: Dict[str, Any] = {
        "schema": 1, "started_at": dt.datetime.now().astimezone().isoformat(),
        "host": {"platform": platform.platform(), "python": sys.version,
                 "psutil": psutil is not None},
        "pcap": {"path": str(pcap), "size_bytes": pcap.stat().st_size,
                 "sha256": sha256(pcap)},
        "tshark": {"path": tshark}, "options": vars(args),
        "project_scan": project_scan(root), "stages": [],
    }
    try:
        version = subprocess.run([tshark, "--version"], capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", timeout=20,
                                 creationflags=CREATE_NO_WINDOW)
        report["tshark"]["version"] = (version.stdout or version.stderr).splitlines()[0]
    except Exception as exc:
        report["tshark"]["version_error"] = repr(exc)
    stages: List[Dict[str, Any]] = report["stages"]
    stages.append(run_stage("protocol_hierarchy", [tshark, "-r", pcap_name, "-n", "-q", "-z", "io,phs"], cwd, stage_timeout, False))
    request_fields = ["frame.number", "http.request.method", "http.request.uri", "http.host", "http.content_type", "http.user_agent", "http.file_data", "tcp.stream"]
    stages.append(run_stage("http_request_fields_full", fields_cmd(tshark, pcap_name, "http.request", request_fields), cwd, stage_timeout))
    stages.append(run_stage(f"http_request_ek_sample_{args.sample_packets}", ek_cmd(tshark, pcap_name, "http.request", max(1, args.sample_packets)), cwd, stage_timeout))
    if args.full_ek:
        stages.append(run_stage("http_request_ek_full", ek_cmd(tshark, pcap_name, "http.request"), cwd, stage_timeout))
    if args.include_response:
        response_fields = ["frame.number", "http.response.code", "http.content_type", "http.content_length", "http.file_data", "tcp.stream"]
        stages.append(run_stage("http_response_fields_full", fields_cmd(tshark, pcap_name, "http.response", response_fields), cwd, stage_timeout))
        stages.append(run_stage("http_response_ek_full", ek_cmd(tshark, pcap_name, "http.response"), cwd, stage_timeout))
    stages.append(run_stage("icmp_fields", fields_cmd(tshark, pcap_name, "icmp", ["frame.number", "icmp.type", "icmp.code", "data.data", "ip.src", "ip.dst"]), cwd, stage_timeout))
    stages.append(run_stage("dns_fields", fields_cmd(tshark, pcap_name, "dns", ["frame.number", "dns.qry.name", "dns.qry.type", "dns.txt", "ip.src", "ip.dst"]), cwd, stage_timeout))
    with tempfile.TemporaryDirectory(prefix="tinglan_profile_http_") as temp:
        export_dir = Path(temp)
        stages.append(run_stage("http_export_objects", [tshark, "-r", pcap_name, "-n", "-q", "--export-objects", f"http,{export_dir}"], cwd, stage_timeout, False))
        exported = [{"name": path.name, "size_bytes": path.stat().st_size} for path in export_dir.rglob("*") if path.is_file()]
        report["http_exported_files"] = {"count": len(exported), "total_bytes": sum(item["size_bytes"] for item in exported), "sample": exported[:50]}
    report["finished_at"] = dt.datetime.now().astimezone().isoformat()
    report["sum_stage_wall_sec"] = round(sum(item["elapsed_sec"] for item in stages), 3)
    output = Path(args.output).expanduser().resolve() if args.output else root / f"profile_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print_table(stages)
    print(f"\nJSON report: {output}")
    print(f"TShark: {tshark}")
    print(f"PCAP: {pcap} ({pcap.stat().st_size/1048576:.1f} MiB)")
    print("\nStatic project scan totals:")
    for key, value in report["project_scan"]["totals"].items():
        print(f"  {key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
