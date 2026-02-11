# 服务接口定义

from abc import ABC, abstractmethod
from typing import List, Dict, Callable, Optional, Tuple, Iterator, Generator
from dataclasses import dataclass
from enum import Enum


class AnalysisEventType(Enum):
    """分析事件"""
    PROGRESS = "progress"           # 进度更新
    PACKET = "packet"               # 数据包处理
    DETECTION = "detection"         # 检测结果
    PROTOCOL_FINDING = "protocol"   # 协议发现
    DECODING_RESULT = "decoding"    # 解码结果
    FILE_RECOVERY = "recovery"      # 文件还原
    ERROR = "error"                 # 错误
    COMPLETE = "complete"           # 完成


@dataclass
class AnalysisEvent:
    event_type: AnalysisEventType
    data: any
    progress: int = 0
    message: str = ""


# 回调类型
ProgressCallback = Callable[[int, str], None]
DetectionCallback = Callable[["DetectionResult"], None]
EventCallback = Callable[[AnalysisEvent], None]


class IAnalysisService(ABC):
    """分析服务接口"""

    @abstractmethod
    def analyze_pcap(
        self,
        pcap_path: str,
        options: dict,
        on_progress: Optional[ProgressCallback] = None,
        on_detection: Optional[DetectionCallback] = None
    ) -> "AnalysisSummary":
        """分析PCAP文件"""
        pass

    @abstractmethod
    def extract_http_objects(self, pcap_path: str) -> List["ExtractedFile"]:
        pass

    @abstractmethod
    def get_file_hex_content(self, file_path: str, max_bytes: int = 4096) -> str:
        pass

    @abstractmethod
    def get_packet_detail(self, pcap_path: str, packet_num: int) -> Tuple[str, List[str]]:
        """返回 (hex_dump, protocol_layers)"""
        pass

    @abstractmethod
    def find_tshark(self) -> Optional[str]:
        pass


class IStreamAnalysisService(ABC):
    """流式分析服务接口"""

    @abstractmethod
    def stream_analysis(
        self,
        pcap_path: str,
        options: dict
    ) -> Generator[AnalysisEvent, None, "AnalysisSummary"]:
        """流式分析 - 生成器模式"""
        pass

    @abstractmethod
    def start_stream_analysis(
        self,
        pcap_path: str,
        options: dict,
        on_event: EventCallback
    ) -> "AnalysisHandle":
        """启动流式分析 - 回调模式"""
        pass

    @abstractmethod
    def stop_analysis(self, handle: "AnalysisHandle") -> bool:
        pass


class AnalysisHandle(ABC):
    """分析任务句柄"""

    @property
    @abstractmethod
    def is_running(self) -> bool:
        pass

    @property
    @abstractmethod
    def progress(self) -> int:
        pass

    @property
    @abstractmethod
    def packet_count(self) -> int:
        pass

    @abstractmethod
    def cancel(self) -> None:
        pass

    @abstractmethod
    def wait(self, timeout: float = None) -> "AnalysisSummary":
        """等待完成，超时抛 TimeoutError"""
        pass


class IFullAnalysisService(IAnalysisService, IStreamAnalysisService):
    """同时支持同步和流式"""
    pass
