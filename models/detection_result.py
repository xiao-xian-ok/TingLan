# detection_result.py - 检测结果数据结构

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import uuid


class ThreatLevel(Enum):
    """威胁等级"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def display_name(self) -> str:
        names = {
            "info": "信息",
            "low": "低危",
            "medium": "中危",
            "high": "高危",
            "critical": "严重"
        }
        return names.get(self.value, self.value)

    @property
    def color(self) -> str:
        colors = {
            "info": "#2196F3",
            "low": "#4CAF50",
            "medium": "#FF9800",
            "high": "#F44336",
            "critical": "#9C27B0"
        }
        return colors.get(self.value, "#757575")

    @classmethod
    def from_confidence(cls, confidence: str) -> "ThreatLevel":  # 从置信度转换为威胁等级
        mapping = {
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "none": cls.INFO
        }
        return mapping.get(confidence, cls.MEDIUM)

    @classmethod
    def from_string(cls, level_str: str) -> "ThreatLevel":  # 从字符串转换为威胁等级
        level_str = level_str.lower()
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO
        }
        return mapping.get(level_str, cls.MEDIUM)


class DetectionType(Enum):
    ANTSWORD = "antsword"  # Webshell 工具
    CAIDAO = "caidao"
    BEHINDER = "behinder"
    GODZILLA = "godzilla"
    SQLI = "sqli"  # OWASP Top 10 攻击类型
    XSS = "xss"
    RCE = "rce"
    XXE = "xxe"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    DESERIALIZATION = "deserialization"
    FILE_UPLOAD = "file_upload"
    LFI = "lfi"
    RFI = "rfi"
    LDAP_INJECTION = "ldap_injection"
    SSTI = "ssti"
    ATTACK = "attack"  # 通用攻击类型
    UNKNOWN = "unknown"

    @property
    def display_name(self) -> str:
        names = {
            "antsword": "蚁剑 (AntSword)",
            "caidao": "菜刀 (Caidao)",
            "behinder": "冰蝎 (Behinder)",
            "godzilla": "哥斯拉 (Godzilla)",
            "sqli": "SQL注入",
            "xss": "跨站脚本 (XSS)",
            "rce": "远程代码执行 (RCE)",
            "xxe": "XML外部实体 (XXE)",
            "ssrf": "服务端请求伪造 (SSRF)",
            "path_traversal": "目录穿越",
            "command_injection": "命令注入",
            "deserialization": "反序列化漏洞",
            "file_upload": "恶意文件上传",
            "lfi": "本地文件包含",
            "rfi": "远程文件包含",
            "ldap_injection": "LDAP注入",
            "ssti": "模板注入",
            "attack": "攻击行为",
            "unknown": "未知类型"
        }
        return names.get(self.value, self.value)

    @property
    def is_owasp(self) -> bool:
        return self.value in ['sqli', 'xss', 'rce', 'xxe', 'ssrf',
                              'path_traversal', 'command_injection', 'deserialization',
                              'file_upload', 'lfi', 'rfi', 'ldap_injection', 'ssti',
                              'attack']

    @classmethod
    def from_type_string(cls, type_str: str) -> "DetectionType":
        type_str_lower = type_str.lower()
        if "antsword" in type_str_lower:
            return cls.ANTSWORD
        elif "caidao" in type_str_lower:
            return cls.CAIDAO
        elif "behinder" in type_str_lower:
            return cls.BEHINDER
        elif "godzilla" in type_str_lower:
            return cls.GODZILLA
        elif "sqli" in type_str_lower or "sql" in type_str_lower:
            return cls.SQLI
        elif "xss" in type_str_lower:
            return cls.XSS
        elif "rce" in type_str_lower:
            return cls.RCE
        elif "xxe" in type_str_lower:
            return cls.XXE
        elif "ssrf" in type_str_lower:
            return cls.SSRF
        elif "path_traversal" in type_str_lower or "traversal" in type_str_lower:
            return cls.PATH_TRAVERSAL
        elif "command_injection" in type_str_lower or "cmd" in type_str_lower:
            return cls.COMMAND_INJECTION
        elif "deserialization" in type_str_lower:
            return cls.DESERIALIZATION
        elif "file_upload" in type_str_lower or "upload" in type_str_lower:
            return cls.FILE_UPLOAD
        return cls.UNKNOWN


@dataclass
class IndicatorMatch:
    name: str = ""                # 特征名称
    pattern: str = ""             # 匹配的正则模式
    weight: int = 0               # 权重分值
    matched_text: str = ""        # 匹配到的文本片段
    description: str = ""         # 特征描述


@dataclass
class DecodedPayload:
    param_name: str = ""          # 参数名
    payload_type: str = ""        # 载荷类型(Command/PHP Code等)
    decode_method: str = ""       # 解码方式(Base64/Hex等)
    encoded_sample: str = ""      # 编码样本
    decoded_content: str = ""     # 解码后的内容


@dataclass
class DetectionResult:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    detection_type: DetectionType = DetectionType.UNKNOWN
    threat_level: ThreatLevel = ThreatLevel.MEDIUM

    # 基础信息
    timestamp: str = ""
    method: str = ""
    uri: str = ""
    source_ip: str = ""
    dest_ip: str = ""

    # v2.0 新增: 权重和置信度
    total_weight: int = 0         # 总权重
    confidence: str = "low"       # 置信度: high/medium/low/none

    # 匹配的特征列表
    indicators: List[IndicatorMatch] = field(default_factory=list)
    indicator: str = ""           # 向后兼容: 主要检测指标描述

    # 载荷信息
    payloads: List[DecodedPayload] = field(default_factory=list)
    payload: Optional[Dict[str, Any]] = None  # 向后兼容

    # 响应信息
    response_indicators: List[IndicatorMatch] = field(default_factory=list)
    response_data: Optional[str] = None
    response_sample: str = ""

    # 原始数据
    raw_data: Optional[str] = None
    raw_result: Optional[Dict] = None
    tags: List[str] = field(default_factory=list)

    # v2.1 新增: AST 语义分析结果
    ast_findings: List[Dict] = field(default_factory=list)  # AST 分析发现
    obfuscation_score: float = 0.0  # 混淆评分 0.0-1.0
    semantic_validated: bool = False  # 是否经过语义验证

    # 用于UI显示
    packet_number: int = 0
    tcp_stream: int = -1

    def to_table_row(self) -> List[str]:
        # 特征摘要
        indicator_str = self.indicator
        if not indicator_str and self.indicators:
            indicator_str = ", ".join([i.name for i in self.indicators[:3]])
            if len(self.indicators) > 3:
                indicator_str += f" (+{len(self.indicators) - 3})"

        tags_str = ", ".join(self.tags[:2]) if self.tags else ""
        if len(self.tags) > 2:
            tags_str += f" (+{len(self.tags) - 2})"

        return [
            self.threat_level.display_name,
            self.detection_type.display_name,
            self.method,
            self.uri[:50] + "..." if len(self.uri) > 50 else self.uri,
            indicator_str,
            tags_str,
            f"{self.total_weight}" if self.total_weight > 0 else "",
            self.timestamp
        ]

    @staticmethod
    def table_headers() -> List[str]:
        return ["威胁等级", "类型", "方法", "URI", "检测指标", "攻击标签", "权重", "时间戳"]

    @classmethod
    def from_webshell_result(cls, raw: Dict, detection_type: DetectionType) -> "DetectionResult":
        """从webshell_detect结果创建"""
        confidence = raw.get("confidence", "low")
        threat_level = ThreatLevel.from_confidence(confidence)

        indicators = []
        for ind in raw.get("indicators", []):
            indicators.append(IndicatorMatch(
                name=ind.get("name", ""),
                pattern=ind.get("pattern", ""),
                weight=ind.get("weight", 0),
                matched_text=ind.get("matched_text", ""),
                description=ind.get("description", "")
            ))

        response_indicators = []
        for ind in raw.get("response_indicators", []):
            if isinstance(ind, dict):
                response_indicators.append(IndicatorMatch(
                    name=ind.get("name", ""),
                    pattern=ind.get("pattern", ""),
                    weight=ind.get("weight", 0),
                    description=ind.get("description", "")
                ))
            elif isinstance(ind, str):
                response_indicators.append(IndicatorMatch(name=ind))

        payloads = []
        raw_payloads = raw.get("payloads", {})
        if isinstance(raw_payloads, dict):
            for param_name, payload_info in raw_payloads.items():
                if isinstance(payload_info, dict):
                    payloads.append(DecodedPayload(
                        param_name=param_name,
                        payload_type=payload_info.get("type", ""),
                        decode_method=payload_info.get("method", ""),
                        encoded_sample=payload_info.get("encoded_sample", ""),
                        decoded_content=payload_info.get("decoded", payload_info.get("decoded_content", ""))
                    ))

        indicator_str = ""
        if indicators:
            top_indicators = sorted(indicators, key=lambda x: -x.weight)[:3]
            indicator_str = ", ".join([i.name for i in top_indicators])

        return cls(
            detection_type=detection_type,
            threat_level=threat_level,
            method=raw.get("method", ""),
            uri=raw.get("uri", "") or "",
            total_weight=raw.get("total_weight", 0),
            confidence=confidence,
            indicators=indicators,
            indicator=indicator_str,
            payloads=payloads,
            payload=raw_payloads if raw_payloads else None,
            response_indicators=response_indicators,
            response_data=raw.get("response_sample", ""),
            response_sample=raw.get("response_sample", ""),
            raw_result=raw
        )

    @classmethod
    def from_antsword_result(cls, raw: Dict) -> "DetectionResult":
        # 新格式走通用方法
        if "total_weight" in raw or "confidence" in raw:
            return cls.from_webshell_result(raw, DetectionType.ANTSWORD)

        # 旧格式兼容
        return cls(
            detection_type=DetectionType.ANTSWORD,
            threat_level=ThreatLevel.HIGH,
            method=raw.get("method", ""),
            uri=raw.get("uri", "") or "",
            indicator=raw.get("indicator", ""),
            payload=raw.get("payload"),
            response_data=raw.get("response_body"),
            raw_result=raw
        )

    @classmethod
    def from_caidao_result(cls, raw: Dict) -> "DetectionResult":
        # 新格式走通用方法
        if "total_weight" in raw or "confidence" in raw:
            return cls.from_webshell_result(raw, DetectionType.CAIDAO)

        # 旧格式兼容
        return cls(
            detection_type=DetectionType.CAIDAO,
            threat_level=ThreatLevel.HIGH,
            method=raw.get("method", ""),
            uri=raw.get("uri", "") or "",
            indicator=raw.get("indicator", ""),
            payload=raw.get("payload") or raw.get("z0_decoded"),
            raw_result=raw
        )

    @classmethod
    def from_behinder_result(cls, raw: Dict) -> "DetectionResult":
        return cls.from_webshell_result(raw, DetectionType.BEHINDER)

    @classmethod
    def from_godzilla_result(cls, raw: Dict) -> "DetectionResult":
        return cls.from_webshell_result(raw, DetectionType.GODZILLA)

    @classmethod
    def from_attack_result(
        cls,
        attack_result,
        method: str = "",
        uri: str = "",
        source_ip: str = "",
        dest_ip: str = "",
        timestamp: str = "",
        packet_number: int = 0
    ) -> "DetectionResult":
        """从 AttackDetector.detect() 返回的 dict 创建"""
        # 攻击类型映射
        attack_type_mapping = {
            # AttackType.value
            "sqli": DetectionType.SQLI,
            "xss": DetectionType.XSS,
            "rce": DetectionType.RCE,
            "xxe": DetectionType.XXE,
            "ssrf": DetectionType.SSRF,
            "path_traversal": DetectionType.PATH_TRAVERSAL,
            "command_injection": DetectionType.COMMAND_INJECTION,
            "deserialization": DetectionType.DESERIALIZATION,
            "file_upload": DetectionType.FILE_UPLOAD,
            "lfi": DetectionType.LFI,
            "antsword": DetectionType.ANTSWORD,
            "caidao": DetectionType.CAIDAO,
            "behinder": DetectionType.BEHINDER,
            "godzilla": DetectionType.GODZILLA,
            # 显示名称
            "SQL Injection": DetectionType.SQLI,
            "Cross-Site Scripting": DetectionType.XSS,
            "XML External Entity": DetectionType.XXE,
            "Malicious File Upload": DetectionType.FILE_UPLOAD,
            "Command Injection": DetectionType.COMMAND_INJECTION,
            "Path Traversal": DetectionType.PATH_TRAVERSAL,
            "Server-Side Request Forgery": DetectionType.SSRF,
            "Local File Inclusion": DetectionType.LFI,
            "Remote File Inclusion": DetectionType.RFI,
            "LDAP Injection": DetectionType.LDAP_INJECTION,
            "Server-Side Template Injection": DetectionType.SSTI,
            "Insecure Deserialization": DetectionType.DESERIALIZATION,
            "Remote Code Execution": DetectionType.RCE,
        }

        # 兼容 dict 和 object
        is_dict = isinstance(attack_result, dict)

        detection_type = DetectionType.ATTACK
        if is_dict:
            det_type_str = attack_result.get('detection_type', '')
            detection_type = attack_type_mapping.get(det_type_str, DetectionType.ATTACK)

            # 未匹配时尝试从 indicators 的 pattern_name 推断
            if detection_type == DetectionType.ATTACK and attack_result.get('indicators'):
                for ind in attack_result['indicators']:
                    pattern_name = ind.get('name', '')
                    # pattern_name 格式: "sqli:union_select"
                    if ':' in pattern_name:
                        attack_prefix = pattern_name.split(':')[0]
                        inferred_type = attack_type_mapping.get(attack_prefix)
                        if inferred_type:
                            detection_type = inferred_type
                            break
        else:
            # object 模式 (向后兼容)
            if hasattr(attack_result, 'attack_types') and attack_result.attack_types:
                primary_attack = attack_result.attack_types[0]
                attack_value = primary_attack.value if hasattr(primary_attack, 'value') else str(primary_attack)
                detection_type = attack_type_mapping.get(attack_value, DetectionType.ATTACK)

        # 转换威胁等级
        risk_level_mapping = {
            "critical": ThreatLevel.CRITICAL,
            "high": ThreatLevel.HIGH,
            "medium": ThreatLevel.MEDIUM,
            "low": ThreatLevel.LOW,
            "info": ThreatLevel.INFO,
        }

        if is_dict:
            risk_str = attack_result.get('threat_level', 'medium')
            threat_level = risk_level_mapping.get(risk_str, ThreatLevel.MEDIUM)
        else:
            threat_level = risk_level_mapping.get(
                getattr(attack_result, 'risk_level', 'medium'), ThreatLevel.MEDIUM
            )

        # 转换匹配特征
        indicators = []
        if is_dict:
            for ind in attack_result.get('indicators', []):
                indicators.append(IndicatorMatch(
                    name=ind.get('name', ''),
                    pattern=ind.get('pattern', ''),
                    weight=ind.get('weight', 0),
                    matched_text=ind.get('matched_text', ''),
                    description=ind.get('description', '')
                ))
        else:
            for match in getattr(attack_result, 'matches', []):
                indicators.append(IndicatorMatch(
                    name=match.signature.name,
                    pattern=match.signature.pattern,
                    weight=match.signature.weight,
                    matched_text=match.matched_text,
                    description=match.signature.description
                ))

        # 构建指标描述
        indicator_str = ""
        if indicators:
            top_indicators = sorted(indicators, key=lambda x: -x.weight)[:3]
            indicator_str = ", ".join([i.name for i in top_indicators])

        # 标签
        tags = []
        if is_dict:
            tags = list(attack_result.get('tags', []))

            # 从 indicators 生成攻击类型标签
            attack_type_tags = set()
            for ind in attack_result.get('indicators', []):
                pattern_name = ind.get('name', '')
                if ':' in pattern_name:
                    attack_prefix = pattern_name.split(':')[0]
                    tag_mapping = {
                        'sqli': 'SQL注入',
                        'xss': 'XSS攻击',
                        'rce': '远程代码执行',
                        'xxe': 'XXE攻击',
                        'ssrf': 'SSRF攻击',
                        'path_traversal': '目录穿越',
                        'command_injection': '命令注入',
                        'deserialization': '反序列化',
                        'file_upload': '文件上传',
                    }
                    if attack_prefix in tag_mapping:
                        attack_type_tags.add(tag_mapping[attack_prefix])

            # 追加攻击类型标签
            tags.extend(list(attack_type_tags))
        else:
            for attack_type in getattr(attack_result, 'attack_types', []):
                attack_value = attack_type.value if hasattr(attack_type, 'value') else str(attack_type)
                tags.append(attack_value)

        # 没标签的话用检测类型凑一个
        if not tags and detection_type != DetectionType.ATTACK:
            tags.append(detection_type.display_name)

        # 权重和置信度
        if is_dict:
            total_weight = attack_result.get('total_weight', 0)
            confidence = attack_result.get('confidence', 'none')
            # 补充未传入的字段
            if not method:
                method = attack_result.get('method', '')
            if not uri:
                uri = attack_result.get('uri', '')
            if not source_ip:
                source_ip = attack_result.get('src_ip', '')
            if not dest_ip:
                dest_ip = attack_result.get('dst_ip', '')
            if not timestamp:
                timestamp = attack_result.get('timestamp', '')
            if packet_number == 0:
                packet_number = attack_result.get('frame_number', 0)
            tcp_stream_val = attack_result.get('tcp_stream', -1)
        else:
            total_weight = getattr(attack_result, 'total_weight', 0)
            confidence = getattr(attack_result, 'confidence', 'none')
            tcp_stream_val = -1

        # 原始请求信息
        raw_request = ''
        raw_headers = ''
        raw_body = ''
        response_data_val = ''
        response_sample_val = ''
        if is_dict:
            raw_request = attack_result.get('raw_http_request', '')
            raw_headers = attack_result.get('raw_request_headers', '')
            raw_body = attack_result.get('raw_request_body', '')
            response_data_val = attack_result.get('response_data', '')
            response_sample_val = attack_result.get('response_sample', '')

        return cls(
            detection_type=detection_type,
            threat_level=threat_level,
            timestamp=timestamp,
            method=method,
            uri=uri,
            source_ip=source_ip,
            dest_ip=dest_ip,
            total_weight=total_weight,
            confidence=confidence,
            indicators=indicators,
            indicator=indicator_str,
            tags=tags,
            packet_number=packet_number,
            tcp_stream=tcp_stream_val,
            response_data=response_data_val if response_data_val else None,
            response_sample=response_sample_val,
            raw_data=raw_request if raw_request else None,
            raw_result=dict(attack_result) if is_dict else None,
            ast_findings=attack_result.get('ast_findings', []) if is_dict else [],
            obfuscation_score=attack_result.get('obfuscation_score', 0.0) if is_dict else 0.0,
            semantic_validated=attack_result.get('semantic_validated', False) if is_dict else False,
        )


@dataclass
class ProtocolStats:
    protocol: str
    count: int
    percentage: float = 0.0
    children: List['ProtocolStats'] = field(default_factory=list)

    @property
    def display_text(self) -> str:
        return f"{self.protocol} ({self.count})"

    @property
    def name(self) -> str:
        return self.protocol


@dataclass
class ExtractedFile:
    file_path: str
    file_name: str
    file_type: str
    file_size: int
    source_packet: int = 0          # 关联的 frame number（用于获取原始包）
    content_type: str = ""
    # 以下字段用于懒加载（点击时填充）
    hex_dump: str = ""              # 十六进制 dump
    protocol_layers: List[str] = field(default_factory=list)  # 协议分层信息
    pcap_path: str = ""             # 原始 pcap 文件路径（用于懒加载时查询）


@dataclass
class ProtocolFinding:
    """协议分析发现 (如ICMP隐写检测)"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    protocol: str = ""              # 协议类型: "ICMP", "DNS", "FTP" 等
    finding_type: str = ""          # 发现类型: "hidden_data", "anomaly" 等
    title: str = ""                 # 标题: "TTL序列隐写"
    description: str = ""           # 详细说明
    data: Optional[str] = None      # 提取的原始数据（可能是编码的）
    decoded_data: Optional[str] = None  # 自动解码后的数据
    decode_chain: str = ""          # 解码链，如 "base64 -> hex"
    confidence: float = 0.0         # 置信度 0.0-1.0
    is_flag: bool = False           # 是否疑似FLAG
    raw_values: List[Any] = field(default_factory=list)  # 原始值序列

    @classmethod
    def from_analyzer_finding(cls, finding) -> "ProtocolFinding":
        """从 protocol_analyzer.AnalysisFinding 转换"""
        return cls(
            protocol=finding.protocol.value.upper() if hasattr(finding.protocol, 'value') else str(finding.protocol),
            finding_type=finding.finding_type.value if hasattr(finding.finding_type, 'value') else str(finding.finding_type),
            title=finding.title,
            description=finding.description,
            data=finding.data,
            confidence=finding.confidence,
            is_flag=finding.is_flag,
            raw_values=list(finding.raw_values) if finding.raw_values else []
        )

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'protocol': self.protocol,
            'finding_type': self.finding_type,
            'title': self.title,
            'description': self.description,
            'data': self.data,
            'decoded_data': self.decoded_data,
            'decode_chain': self.decode_chain,
            'confidence': self.confidence,
            'is_flag': self.is_flag,
            'raw_values': self.raw_values
        }

    @property
    def display_title(self) -> str:
        prefix = "⚠ " if self.is_flag else ""
        suffix = " [FLAG]" if self.is_flag else ""
        return f"{prefix}{self.title}{suffix}"

    @property
    def confidence_display(self) -> str:
        if self.confidence >= 0.8:
            return "高"
        elif self.confidence >= 0.5:
            return "中"
        else:
            return "低"


@dataclass
class AutoDecodingResult:
    """自动解码结果"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = ""                    # 来源: "http_param", "payload", "file"
    original_data: str = ""             # 原始数据 (hex或文本)
    final_data: str = ""                # 最终解码数据
    decode_chain: str = ""              # 解码链: "base64 -> gzip -> text"
    total_layers: int = 0               # 解码层数
    is_meaningful: bool = False         # 是否有意义
    confidence: float = 0.0             # 置信度
    detected_type: str = ""             # 检测到的内容类型
    flags_found: List[str] = field(default_factory=list)  # 发现的Flag
    associated_detection_id: str = ""   # 关联的检测结果ID

    @property
    def display_title(self) -> str:
        if self.flags_found:
            return f"[FLAG] {self.decode_chain}"
        return f"{self.decode_chain} ({self.total_layers}层)"

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'source': self.source,
            'original_data': self.original_data[:200] if self.original_data else "",
            'final_data': self.final_data[:500] if self.final_data else "",
            'decode_chain': self.decode_chain,
            'total_layers': self.total_layers,
            'is_meaningful': self.is_meaningful,
            'confidence': self.confidence,
            'detected_type': self.detected_type,
            'flags_found': self.flags_found
        }


@dataclass
class FileRecoveryResult:
    """文件还原结果"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    detected: bool = False              # 是否检测到文件
    extension: str = ""                 # 文件扩展名
    description: str = ""               # 文件描述
    mime_type: str = ""                 # MIME类型
    category: str = ""                  # 文件类别: archive, image, audio, etc.
    confidence: float = 0.0             # 置信度
    size: int = 0                       # 文件大小
    offset: int = 0                     # 在原始数据中的偏移
    source_packet: int = 0              # 来源数据包号
    saved_path: str = ""                # 保存路径 (如果已保存)
    data_preview: str = ""              # 数据预览 (hex)

    @property
    def display_title(self) -> str:
        size_str = self._format_size(self.size)
        return f"{self.description} ({size_str})"

    @staticmethod
    def _format_size(size: int) -> str:
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'detected': self.detected,
            'extension': self.extension,
            'description': self.description,
            'mime_type': self.mime_type,
            'category': self.category,
            'confidence': self.confidence,
            'size': self.size,
            'offset': self.offset,
            'source_packet': self.source_packet,
            'saved_path': self.saved_path
        }


@dataclass
class RTPStreamInfo:
    """RTP 音视频流信息"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ssrc: str = ""
    src_addr: str = ""
    dst_addr: str = ""
    payload_type: int = 0
    codec_name: str = ""
    media_type: str = ""         # "audio" | "video"
    sample_rate: int = 0
    packets: int = 0
    lost: int = 0
    max_jitter: float = 0.0
    duration_sec: float = 0.0
    pcap_path: str = ""

    @property
    def display_title(self) -> str:
        duration = f"{self.duration_sec:.1f}s" if self.duration_sec > 0 else "未知时长"
        return f"{self.codec_name} ({self.media_type}) - {duration}"

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'ssrc': self.ssrc,
            'src_addr': self.src_addr,
            'dst_addr': self.dst_addr,
            'payload_type': self.payload_type,
            'codec_name': self.codec_name,
            'media_type': self.media_type,
            'sample_rate': self.sample_rate,
            'packets': self.packets,
            'lost': self.lost,
            'max_jitter': self.max_jitter,
            'duration_sec': self.duration_sec,
        }


@dataclass
class AttackDetectionInfo:
    """攻击检测结果"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    attack_type: str = ""               # 攻击类型: "SQL Injection", "XSS" 等
    risk_level: str = "info"            # 风险等级: info, low, medium, high, critical
    confidence: str = "low"             # 置信度: low, medium, high
    total_weight: int = 0               # 总权重
    matched_signatures: List[str] = field(default_factory=list)  # 匹配的签名名称
    matched_text: str = ""              # 匹配的文本
    context: str = ""                   # 上下文（包含匹配位置的原始文本）
    source_uri: str = ""                # 来源 URI
    source_packet: int = 0              # 来源数据包号
    source_ip: str = ""                 # 源 IP
    dest_ip: str = ""                   # 目标 IP
    method: str = ""                    # HTTP 方法
    timestamp: str = ""                 # 时间戳
    raw_matches: List[Dict] = field(default_factory=list)  # 原始匹配结果

    @property
    def display_title(self) -> str:
        risk_icon = {
            "critical": "[!!!]",
            "high": "[!!]",
            "medium": "[!]",
            "low": "[.]",
            "info": "[i]"
        }.get(self.risk_level, "")
        return f"{risk_icon} {self.attack_type}"

    @property
    def risk_level_display(self) -> str:
        names = {
            "info": "信息",
            "low": "低危",
            "medium": "中危",
            "high": "高危",
            "critical": "严重"
        }
        return names.get(self.risk_level, self.risk_level)

    @property
    def risk_level_color(self) -> str:
        colors = {
            "info": "#2196F3",
            "low": "#4CAF50",
            "medium": "#FF9800",
            "high": "#F44336",
            "critical": "#9C27B0"
        }
        return colors.get(self.risk_level, "#757575")

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'attack_type': self.attack_type,
            'risk_level': self.risk_level,
            'confidence': self.confidence,
            'total_weight': self.total_weight,
            'matched_signatures': self.matched_signatures,
            'matched_text': self.matched_text[:200] if self.matched_text else "",
            'context': self.context[:500] if self.context else "",
            'source_uri': self.source_uri,
            'source_packet': self.source_packet,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'method': self.method,
            'timestamp': self.timestamp
        }

    @classmethod
    def from_attack_detection_result(cls, result, packet_info: Dict = None) -> "AttackDetectionInfo":
        """从 AttackDetectionResult 创建"""
        packet_info = packet_info or {}

        attack_type = ""
        if result.attack_types:
            first_type = result.attack_types[0]
            attack_type = first_type.value if hasattr(first_type, 'value') else str(first_type)

        matched_signatures = []
        matched_texts = []
        raw_matches = []
        for match in result.matches:
            matched_signatures.append(match.signature.name)
            matched_texts.append(match.matched_text)
            raw_matches.append({
                'name': match.signature.name,
                'pattern': match.signature.pattern,
                'weight': match.signature.weight,
                'matched_text': match.matched_text,
                'description': match.signature.description
            })

        return cls(
            attack_type=attack_type,
            risk_level=result.risk_level,
            confidence=result.confidence,
            total_weight=result.total_weight,
            matched_signatures=matched_signatures,
            matched_text="; ".join(matched_texts[:3]),
            context=packet_info.get('raw_body', ''),
            source_uri=packet_info.get('uri', ''),
            source_packet=packet_info.get('packet_number', 0),
            source_ip=packet_info.get('source_ip', ''),
            dest_ip=packet_info.get('dest_ip', ''),
            method=packet_info.get('method', ''),
            timestamp=packet_info.get('timestamp', ''),
            raw_matches=raw_matches
        )


@dataclass
class AnalysisSummary:
    file_path: str = ""
    total_packets: int = 0
    protocol_stats: List[ProtocolStats] = field(default_factory=list)
    detections: List[DetectionResult] = field(default_factory=list)
    extracted_files: List[ExtractedFile] = field(default_factory=list)
    protocol_findings: List[ProtocolFinding] = field(default_factory=list)  # 协议分析发现
    decoding_results: List[AutoDecodingResult] = field(default_factory=list)  # 自动解码结果
    recovered_files: List[FileRecoveryResult] = field(default_factory=list)
    rtp_streams: List[RTPStreamInfo] = field(default_factory=list)
    attack_detections: List[AttackDetectionInfo] = field(default_factory=list)
    analysis_time: float = 0.0

    # 按置信度统计
    high_confidence_count: int = 0
    medium_confidence_count: int = 0
    low_confidence_count: int = 0

    @property
    def threat_count(self) -> int:
        return len(self.detections)

    @property
    def detection_by_type(self) -> Dict[DetectionType, List[DetectionResult]]:
        grouped = {}
        for det in self.detections:
            if det.detection_type not in grouped:
                grouped[det.detection_type] = []
            grouped[det.detection_type].append(det)
        return grouped

    @property
    def detection_by_confidence(self) -> Dict[str, List[DetectionResult]]:
        grouped = {"high": [], "medium": [], "low": []}
        for det in self.detections:
            conf = det.confidence if det.confidence in grouped else "low"
            grouped[conf].append(det)
        return grouped

    def update_confidence_counts(self):
        by_conf = self.detection_by_confidence
        self.high_confidence_count = len(by_conf["high"])
        self.medium_confidence_count = len(by_conf["medium"])
        self.low_confidence_count = len(by_conf["low"])
