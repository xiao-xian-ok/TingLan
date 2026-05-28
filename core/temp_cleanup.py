# -*- coding: utf-8 -*-
"""临时目录清理工具。

听澜在分析过程中会调用 tshark 的 --export-objects,产生 tinglan_http_* 临时目录。
本模块负责清理:
- cleanup_stale_dirs: 启动时清掉 N 小时前的残留(crash 残留兜底)
- cleanup_own_dirs: atexit 时清掉本进程产生的目录
"""
from __future__ import annotations

import glob
import logging
import os
import shutil
import tempfile
import time

logger = logging.getLogger("tinglan.cleanup")

_PREFIX = "tinglan_http_"


def cleanup_stale_dirs(max_age_hours: int = 24) -> int:
    """清掉 tempdir 下所有 tinglan_http_* 中 mtime 老于 N 小时的目录。

    不区分 PID,用于启动时扫掉 crash 残留。
    返回成功清理的目录数。
    """
    cutoff = time.time() - max_age_hours * 3600
    count = 0
    pattern = os.path.join(tempfile.gettempdir(), f"{_PREFIX}*")
    for d in glob.glob(pattern):
        try:
            if os.path.isdir(d) and os.path.getmtime(d) < cutoff:
                shutil.rmtree(d, ignore_errors=True)
                count += 1
        except OSError as e:
            logger.debug("skip %s: %s", d, e)
    if count:
        logger.info("启动清理: 删除 %d 个 24h 前的临时目录", count)
    return count


def cleanup_own_dirs() -> int:
    """清掉本进程产生的 tinglan_http_<pid>_* 目录。atexit 用。"""
    pid = os.getpid()
    count = 0
    pattern = os.path.join(tempfile.gettempdir(), f"{_PREFIX}{pid}_*")
    for d in glob.glob(pattern):
        try:
            shutil.rmtree(d, ignore_errors=True)
            count += 1
        except OSError as e:
            logger.debug("skip %s: %s", d, e)
    if count:
        logger.info("退出清理: 删除 %d 个本进程临时目录", count)
    return count
