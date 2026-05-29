# tree_model.py - 树模型

from typing import List, Optional, Any
import logging
from PySide6.QtCore import Qt, QAbstractItemModel, QModelIndex
from PySide6.QtGui import QIcon, QColor

logger = logging.getLogger(__name__)

from models.detection_result import (
    AnalysisSummary, DetectionResult, DetectionType, ThreatLevel, ProtocolFinding,
    AutoDecodingResult, FileRecoveryResult, AttackDetectionInfo, RTPStreamInfo
)


class TreeNode:

    def __init__(
        self,
        name: str,
        count: int = 0,
        icon_name: str = "",
        node_type: str = "default",
        parent: Optional["TreeNode"] = None
    ):
        self.name = name
        self.count = count
        self.icon_name = icon_name
        self.node_type = node_type
        self.parent = parent
        self.children: List[TreeNode] = []
        self.payload: Any = None  # 关联的数据(DetectionResult等)
        self._row: int = 0  # 缓存的行索引，避免 list.index() O(n) 扫描

    def appendChild(self, child: "TreeNode"):
        child.parent = self
        child._row = len(self.children)  # O(1) 缓存行号
        self.children.append(child)

    def child(self, row: int) -> Optional["TreeNode"]:
        if 0 <= row < len(self.children):
            return self.children[row]
        return None

    def childCount(self) -> int:
        return len(self.children)

    def row(self) -> int:
        return self._row

    def columnCount(self) -> int:
        return 2  # 名称, 计数

    def data(self, column: int) -> str:
        if column == 0:
            return self.name
        elif column == 1:
            return str(self.count) if self.count > 0 else ""
        return ""


class AnalysisTreeModel(QAbstractItemModel):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.root = TreeNode("Root")
        self._icons = {}

    def buildFromSummary(self, summary: AnalysisSummary):
        """从分析结果构建树"""
        import time as _time
        t0 = _time.time()

        self.beginResetModel()
        self.root = TreeNode("Root")

        # 攻击行为检测节点
        attack_node = TreeNode(
            name="攻击行为检测",
            count=len(summary.detections),
            icon_name="shield_warning",
            node_type="category"
        )
        self.root.appendChild(attack_node)

        # 按检测类型分组
        grouped = summary.detection_by_type

        threat_level_order = {
            ThreatLevel.INFO: 0,
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4
        }

        # 按类型分组
        for dtype, items in grouped.items():
            # 按威胁等级排序
            sorted_items = sorted(items, key=lambda x: threat_level_order.get(x.threat_level, 2))

            type_node = TreeNode(
                name=f"{dtype.display_name} ({len(items)})",
                count=len(items),
                icon_name=f"attack_{dtype.value}",
                node_type="detection_type"
            )
            attack_node.appendChild(type_node)

            for item in sorted_items:
                level_icon = {
                    ThreatLevel.INFO: "[信息]",
                    ThreatLevel.LOW: "[低危]",
                    ThreatLevel.MEDIUM: "[中危]",
                    ThreatLevel.HIGH: "[高危]",
                    ThreatLevel.CRITICAL: "[严重]"
                }.get(item.threat_level, "")

                # 攻击标签
                tags_display = ""
                if item.tags:
                    # 过滤掉内部标签（以 ast:, noise_, json_ 开头的）
                    visible_tags = [t for t in item.tags if not t.startswith(('ast:', 'noise_', 'json_'))]
                    if visible_tags:
                        tags_display = f" [{', '.join(visible_tags[:2])}]"

                uri_display = item.uri[:25] + "..." if len(item.uri) > 25 else item.uri
                item_node = TreeNode(
                    name=f"{level_icon}{tags_display} {item.method} {uri_display}",
                    count=0,
                    icon_name="packet",
                    node_type="detection_item"
                )
                item_node.payload = item
                type_node.appendChild(item_node)
        logger.debug(f"攻击行为检测节点构建完成, 耗时={(_time.time()-t0)*1000:.1f}ms")

        # 协议统计节点
        protocol_node = TreeNode(
            name="协议统计",
            count=summary.total_packets,
            icon_name="protocol",
            node_type="category"
        )
        self.root.appendChild(protocol_node)

        self._build_protocol_children(protocol_node, summary.protocol_stats)

        # 文件提取节点
        if summary.extracted_files:
            extract_node = TreeNode(
                name="文件提取",
                count=len(summary.extracted_files),
                icon_name="file_extract",
                node_type="category"
            )
            self.root.appendChild(extract_node)

            for ef in summary.extracted_files:
                file_node = TreeNode(
                    name=ef.file_name,
                    count=0,
                    icon_name="file",
                    node_type="extracted_file"
                )
                file_node.payload = ef
                extract_node.appendChild(file_node)

        # 协议分析节点
        if summary.protocol_findings:
            analysis_node = TreeNode(
                name="协议分析",
                count=len(summary.protocol_findings),
                icon_name="protocol_analysis",
                node_type="category"
            )
            self.root.appendChild(analysis_node)

            # 按协议类型分组
            grouped_by_protocol = {}
            for finding in summary.protocol_findings:
                proto = finding.protocol
                if proto not in grouped_by_protocol:
                    grouped_by_protocol[proto] = []
                grouped_by_protocol[proto].append(finding)

            for protocol, findings in grouped_by_protocol.items():
                proto_node = TreeNode(
                    name=f"{protocol} ({len(findings)})",
                    count=len(findings),
                    icon_name=f"protocol_{protocol.lower()}",
                    node_type="protocol_analysis_type"
                )
                analysis_node.appendChild(proto_node)

                for finding in findings:
                    finding_node = TreeNode(
                        name=finding.display_title,
                        count=0,
                        icon_name="finding_flag" if finding.is_flag else "finding",
                        node_type="protocol_finding"
                    )
                    finding_node.payload = finding
                    proto_node.appendChild(finding_node)

        # 自动解码结果节点
        if summary.decoding_results:
            decoding_node = TreeNode(
                name="自动解码",
                count=len(summary.decoding_results),
                icon_name="decode",
                node_type="category"
            )
            self.root.appendChild(decoding_node)

            # 按FLAG分组
            flag_results = [r for r in summary.decoding_results if r.flags_found]
            normal_results = [r for r in summary.decoding_results if not r.flags_found]

            if flag_results:
                flag_group = TreeNode(
                    name=f"FLAG发现 ({len(flag_results)})",
                    count=len(flag_results),
                    icon_name="flag",
                    node_type="decoding_type"
                )
                decoding_node.appendChild(flag_group)

                for result in flag_results:
                    result_node = TreeNode(
                        name=result.display_title,
                        count=0,
                        icon_name="flag",
                        node_type="decoding_result"
                    )
                    result_node.payload = result
                    flag_group.appendChild(result_node)

            if normal_results:
                normal_group = TreeNode(
                    name=f"解码结果 ({len(normal_results)})",
                    count=len(normal_results),
                    icon_name="decode",
                    node_type="decoding_type"
                )
                decoding_node.appendChild(normal_group)

                for result in normal_results:
                    result_node = TreeNode(
                        name=result.display_title,
                        count=0,
                        icon_name="decode",
                        node_type="decoding_result"
                    )
                    result_node.payload = result
                    normal_group.appendChild(result_node)

        # 音视频流节点
        if summary.rtp_streams:
            rtp_node = TreeNode(
                name="音视频流",
                count=len(summary.rtp_streams),
                icon_name="media_stream",
                node_type="category"
            )
            self.root.appendChild(rtp_node)

            grouped = {}
            for stream in summary.rtp_streams:
                grouped.setdefault(stream.media_type, []).append(stream)

            type_names = {"audio": "音频流", "video": "视频流"}
            for mtype, streams in grouped.items():
                if not streams:
                    continue
                cat_display = type_names.get(mtype, mtype)
                cat_node = TreeNode(
                    name=f"{cat_display} ({len(streams)})",
                    count=len(streams),
                    icon_name=f"rtp_{mtype}",
                    node_type="rtp_category"
                )
                rtp_node.appendChild(cat_node)

                for stream in streams:
                    stream_node = TreeNode(
                        name=stream.display_title,
                        count=0,
                        icon_name=f"rtp_{mtype}",
                        node_type="rtp_stream"
                    )
                    stream_node.payload = stream
                    cat_node.appendChild(stream_node)

        # 文件还原结果节点
        if summary.recovered_files:
            recovery_node = TreeNode(
                name="文件还原",
                count=len(summary.recovered_files),
                icon_name="file_restore",
                node_type="category"
            )
            self.root.appendChild(recovery_node)

            # 按文件类别分组
            grouped_by_category = {}
            for recovery in summary.recovered_files:
                category = recovery.category or "other"
                if category not in grouped_by_category:
                    grouped_by_category[category] = []
                grouped_by_category[category].append(recovery)

            category_names = {
                "archive": "压缩文件",
                "image": "图像文件",
                "audio": "音频文件",
                "video": "视频文件",
                "document": "文档文件",
                "executable": "可执行文件",
                "database": "数据库文件",
                "security": "密钥/证书",
                "script": "脚本文件",
                "network": "网络数据",
                "other": "其他文件"
            }

            for category, recoveries in grouped_by_category.items():
                category_display = category_names.get(category, category)
                category_node = TreeNode(
                    name=f"{category_display} ({len(recoveries)})",
                    count=len(recoveries),
                    icon_name=f"file_{category}",
                    node_type="recovery_category"
                )
                recovery_node.appendChild(category_node)

                for recovery in recoveries:
                    file_node = TreeNode(
                        name=recovery.display_title,
                        count=0,
                        icon_name=f"file_{recovery.extension}",
                        node_type="recovered_file"
                    )
                    file_node.payload = recovery
                    category_node.appendChild(file_node)

        # 攻击检测结果节点 (合并到攻击行为检测下)
        if summary.attack_detections:
            attack_behavior_node = None
            for child in self.root.children:
                if child.node_type == "category" and "攻击行为检测" in child.name:
                    attack_behavior_node = child
                    break

            if attack_behavior_node:
                risk_level_order = {
                    "info": 0,
                    "low": 1,
                    "medium": 2,
                    "high": 3,
                    "critical": 4
                }

                # 按攻击类型分组
                grouped_by_attack = {}
                for attack in summary.attack_detections:
                    attack_type = attack.attack_type or "Unknown"
                    if attack_type not in grouped_by_attack:
                        grouped_by_attack[attack_type] = []
                    grouped_by_attack[attack_type].append(attack)

                for attack_type, attacks in grouped_by_attack.items():
                    # 按风险等级从低到高排序
                    sorted_attacks = sorted(attacks, key=lambda x: risk_level_order.get(x.risk_level, 2))

                    type_node = TreeNode(
                        name=f"{attack_type} ({len(attacks)})",
                        count=len(attacks),
                        icon_name=f"attack_{attack_type.lower().replace(' ', '_')}",
                        node_type="attack_type"
                    )
                    attack_behavior_node.appendChild(type_node)

                    for attack in sorted_attacks:
                        risk_icon = {
                            "info": "[信息]",
                            "low": "[低危]",
                            "medium": "[中危]",
                            "high": "[高危]",
                            "critical": "[严重]"
                        }.get(attack.risk_level, "")

                        tags_display = ""
                        if attack.matched_signatures:
                            tags_display = f" [{', '.join(attack.matched_signatures[:2])}]"

                        attack_item_node = TreeNode(
                            name=f"{risk_icon}{tags_display} {attack.display_title}",
                            count=0,
                            icon_name="attack_item",
                            node_type="attack_detection_item"
                        )
                        attack_item_node.payload = attack
                        type_node.appendChild(attack_item_node)

                # 更新计数
                attack_behavior_node.count += len(summary.attack_detections)
                attack_behavior_node.name = f"攻击行为检测 ({attack_behavior_node.count})"

        logger.debug(f"TreeModel 节点构建完成, 总耗时={(_time.time()-t0)*1000:.1f}ms")
        self.endResetModel()

    def _build_protocol_children(self, parent_node: TreeNode, stats_list):
        for stat in stats_list:
            node = TreeNode(
                name=stat.protocol,
                count=stat.count,
                icon_name=f"protocol_{stat.protocol.lower()}",
                node_type="protocol"
            )
            node.payload = stat
            parent_node.appendChild(node)
            if stat.children:
                self._build_protocol_children(node, stat.children)

    def addDetection(self, detection: DetectionResult):
        self._addDetectionInternal(detection, emit_signals=True)

    def addDetectionBatch(self, detections: list):
        """批量添加检测结果，只触发一次UI更新"""
        if not detections:
            return

        self.layoutAboutToBeChanged.emit()

        try:
            for detection in detections:
                self._addDetectionInternal(detection, emit_signals=False)
        finally:
            self.layoutChanged.emit()

    def _addDetectionInternal(self, detection: DetectionResult, emit_signals: bool = True):
        # 统一用"攻击行为检测"分类
        category_name = "攻击行为检测"
        category_icon = "shield_warning"

        # 找到或创建分类节点
        category_node = None
        for child in self.root.children:
            if child.node_type == "category" and category_name in child.name:
                category_node = child
                break

        if not category_node:
            category_node = TreeNode(
                name=category_name,
                count=0,
                icon_name=category_icon,
                node_type="category"
            )
            if emit_signals:
                self.beginInsertRows(QModelIndex(), self.root.childCount(), self.root.childCount())
            self.root.appendChild(category_node)
            if emit_signals:
                self.endInsertRows()

        # 找到或创建类型节点
        type_node = None
        for child in category_node.children:
            if child.node_type == "detection_type" and detection.detection_type.display_name in child.name:
                type_node = child
                break

        if not type_node:
            type_node = TreeNode(
                name=detection.detection_type.display_name,
                count=0,
                icon_name=f"attack_{detection.detection_type.value}",
                node_type="detection_type"
            )
            if emit_signals:
                parent_index = self.createIndex(category_node.row(), 0, category_node)
                self.beginInsertRows(parent_index, category_node.childCount(), category_node.childCount())
            category_node.appendChild(type_node)
            if emit_signals:
                self.endInsertRows()

        # 添加检测项（带威胁等级标识和攻击标签）
        level_icon = {
            ThreatLevel.INFO: "[信息]",
            ThreatLevel.LOW: "[低危]",
            ThreatLevel.MEDIUM: "[中危]",
            ThreatLevel.HIGH: "[高危]",
            ThreatLevel.CRITICAL: "[严重]"
        }.get(detection.threat_level, "")

        # 构建攻击标签显示
        tags_display = ""
        if detection.tags:
            visible_tags = [t for t in detection.tags if not t.startswith(('ast:', 'noise_', 'json_'))]
            if visible_tags:
                tags_display = f" [{', '.join(visible_tags[:2])}]"

        uri_display = detection.uri[:25] + "..." if len(detection.uri) > 25 else detection.uri
        item_node = TreeNode(
            name=f"{level_icon}{tags_display} {detection.method} {uri_display}",
            count=0,
            icon_name="packet",
            node_type="detection_item"
        )
        item_node.payload = detection

        if emit_signals:
            parent_index = self.createIndex(type_node.row(), 0, type_node)
            self.beginInsertRows(parent_index, type_node.childCount(), type_node.childCount())
        type_node.appendChild(item_node)
        if emit_signals:
            self.endInsertRows()

        # 更新计数
        type_node.count += 1
        category_node.count += 1

        # 更新名称显示计数
        type_node.name = f"{detection.detection_type.display_name} ({type_node.count})"
        category_node.name = f"{category_name} ({category_node.count})"

        # 通知数据变化
        self.dataChanged.emit(
            self.createIndex(type_node.row(), 0, type_node),
            self.createIndex(type_node.row(), 1, type_node)
        )
        self.dataChanged.emit(
            self.createIndex(category_node.row(), 0, category_node),
            self.createIndex(category_node.row(), 1, category_node)
        )

    def addProtocolFinding(self, finding: ProtocolFinding):
        # 找到或创建协议分析节点
        analysis_node = None
        for child in self.root.children:
            if child.node_type == "category" and "协议分析" in child.name:
                analysis_node = child
                break

        if not analysis_node:
            analysis_node = TreeNode(
                name="协议分析",
                count=0,
                icon_name="protocol_analysis",
                node_type="category"
            )
            self.beginInsertRows(QModelIndex(), self.root.childCount(), self.root.childCount())
            self.root.appendChild(analysis_node)
            self.endInsertRows()

        # 找到或创建协议类型节点
        proto_node = None
        for child in analysis_node.children:
            if child.node_type == "protocol_analysis_type" and finding.protocol in child.name:
                proto_node = child
                break

        if not proto_node:
            proto_node = TreeNode(
                name=f"{finding.protocol} (0)",
                count=0,
                icon_name=f"protocol_{finding.protocol.lower()}",
                node_type="protocol_analysis_type"
            )
            parent_index = self.createIndex(analysis_node.row(), 0, analysis_node)
            self.beginInsertRows(parent_index, analysis_node.childCount(), analysis_node.childCount())
            analysis_node.appendChild(proto_node)
            self.endInsertRows()

        # 添加发现项
        finding_node = TreeNode(
            name=finding.display_title,
            count=0,
            icon_name="finding_flag" if finding.is_flag else "finding",
            node_type="protocol_finding"
        )
        finding_node.payload = finding

        parent_index = self.createIndex(proto_node.row(), 0, proto_node)
        self.beginInsertRows(parent_index, proto_node.childCount(), proto_node.childCount())
        proto_node.appendChild(finding_node)
        self.endInsertRows()

        # 更新计数
        proto_node.count += 1
        analysis_node.count += 1

        # 更新协议类型节点名
        proto_node.name = f"{finding.protocol} ({proto_node.count})"

        # 通知数据变化
        self.dataChanged.emit(
            self.createIndex(proto_node.row(), 0, proto_node),
            self.createIndex(proto_node.row(), 1, proto_node)
        )
        self.dataChanged.emit(
            self.createIndex(analysis_node.row(), 0, analysis_node),
            self.createIndex(analysis_node.row(), 1, analysis_node)
        )

    def addDecodingResult(self, result: AutoDecodingResult):
        # 找到或创建自动解码节点
        decoding_node = None
        for child in self.root.children:
            if child.node_type == "category" and "自动解码" in child.name:
                decoding_node = child
                break

        if not decoding_node:
            decoding_node = TreeNode(
                name="自动解码",
                count=0,
                icon_name="decode",
                node_type="category"
            )
            self.beginInsertRows(QModelIndex(), self.root.childCount(), self.root.childCount())
            self.root.appendChild(decoding_node)
            self.endInsertRows()

        # 根据是否有FLAG选择分组
        group_name = "FLAG发现" if result.flags_found else "解码结果"
        group_node = None
        for child in decoding_node.children:
            if group_name in child.name:
                group_node = child
                break

        if not group_node:
            group_node = TreeNode(
                name=f"{group_name} (0)",
                count=0,
                icon_name="flag" if result.flags_found else "decode",
                node_type="decoding_type"
            )
            parent_index = self.createIndex(decoding_node.row(), 0, decoding_node)
            self.beginInsertRows(parent_index, decoding_node.childCount(), decoding_node.childCount())
            decoding_node.appendChild(group_node)
            self.endInsertRows()

        # 添加结果节点
        result_node = TreeNode(
            name=result.display_title,
            count=0,
            icon_name="flag" if result.flags_found else "decode",
            node_type="decoding_result"
        )
        result_node.payload = result

        parent_index = self.createIndex(group_node.row(), 0, group_node)
        self.beginInsertRows(parent_index, group_node.childCount(), group_node.childCount())
        group_node.appendChild(result_node)
        self.endInsertRows()

        # 更新计数
        group_node.count += 1
        decoding_node.count += 1
        group_node.name = f"{group_name} ({group_node.count})"

        # 通知数据变化
        self.dataChanged.emit(
            self.createIndex(group_node.row(), 0, group_node),
            self.createIndex(group_node.row(), 1, group_node)
        )
        self.dataChanged.emit(
            self.createIndex(decoding_node.row(), 0, decoding_node),
            self.createIndex(decoding_node.row(), 1, decoding_node)
        )

    def addFileRecovery(self, recovery: FileRecoveryResult):
        # 找到或创建文件还原节点
        recovery_root = None
        for child in self.root.children:
            if child.node_type == "category" and "文件还原" in child.name:
                recovery_root = child
                break

        if not recovery_root:
            recovery_root = TreeNode(
                name="文件还原",
                count=0,
                icon_name="file_restore",
                node_type="category"
            )
            self.beginInsertRows(QModelIndex(), self.root.childCount(), self.root.childCount())
            self.root.appendChild(recovery_root)
            self.endInsertRows()

        # 文件类别分组
        category_names = {
            "archive": "压缩文件", "image": "图像文件", "audio": "音频文件",
            "video": "视频文件", "document": "文档文件", "executable": "可执行文件",
            "database": "数据库文件", "security": "密钥/证书", "script": "脚本文件",
            "network": "网络数据", "other": "其他文件"
        }

        category = recovery.category or "other"
        category_display = category_names.get(category, category)

        # 找到或创建类别节点
        category_node = None
        for child in recovery_root.children:
            if category_display in child.name:
                category_node = child
                break

        if not category_node:
            category_node = TreeNode(
                name=f"{category_display} (0)",
                count=0,
                icon_name=f"file_{category}",
                node_type="recovery_category"
            )
            parent_index = self.createIndex(recovery_root.row(), 0, recovery_root)
            self.beginInsertRows(parent_index, recovery_root.childCount(), recovery_root.childCount())
            recovery_root.appendChild(category_node)
            self.endInsertRows()

        # 添加文件节点
        file_node = TreeNode(
            name=recovery.display_title,
            count=0,
            icon_name=f"file_{recovery.extension}",
            node_type="recovered_file"
        )
        file_node.payload = recovery

        parent_index = self.createIndex(category_node.row(), 0, category_node)
        self.beginInsertRows(parent_index, category_node.childCount(), category_node.childCount())
        category_node.appendChild(file_node)
        self.endInsertRows()

        # 更新计数
        category_node.count += 1
        recovery_root.count += 1
        category_node.name = f"{category_display} ({category_node.count})"

        # 通知数据变化
        self.dataChanged.emit(
            self.createIndex(category_node.row(), 0, category_node),
            self.createIndex(category_node.row(), 1, category_node)
        )
        self.dataChanged.emit(
            self.createIndex(recovery_root.row(), 0, recovery_root),
            self.createIndex(recovery_root.row(), 1, recovery_root)
        )

    def addAttackDetection(self, attack: AttackDetectionInfo):
        # 找到或创建攻击行为检测节点
        attack_root = None
        for child in self.root.children:
            if child.node_type == "category" and "攻击行为检测" in child.name:
                attack_root = child
                break

        if not attack_root:
            attack_root = TreeNode(
                name="攻击行为检测",
                count=0,
                icon_name="shield_warning",
                node_type="category"
            )
            self.beginInsertRows(QModelIndex(), self.root.childCount(), self.root.childCount())
            self.root.appendChild(attack_root)
            self.endInsertRows()

        # 攻击类型分组
        attack_type = attack.attack_type or "Unknown"

        # 找到或创建类型节点
        type_node = None
        for child in attack_root.children:
            if attack_type in child.name:
                type_node = child
                break

        if not type_node:
            type_node = TreeNode(
                name=f"{attack_type} (0)",
                count=0,
                icon_name=f"attack_{attack_type.lower().replace(' ', '_')}",
                node_type="attack_type"
            )
            parent_index = self.createIndex(attack_root.row(), 0, attack_root)
            self.beginInsertRows(parent_index, attack_root.childCount(), attack_root.childCount())
            attack_root.appendChild(type_node)
            self.endInsertRows()

        # 添加攻击项节点
        risk_icon = {
            "info": "[信息]",
            "low": "[低危]",
            "medium": "[中危]",
            "high": "[高危]",
            "critical": "[严重]"
        }.get(attack.risk_level, "")

        # 构建攻击标签显示
        tags_display = ""
        if attack.matched_signatures:
            tags_display = f" [{', '.join(attack.matched_signatures[:2])}]"

        attack_item_node = TreeNode(
            name=f"{risk_icon}{tags_display} {attack.display_title}",
            count=0,
            icon_name="attack_item",
            node_type="attack_detection_item"
        )
        attack_item_node.payload = attack

        parent_index = self.createIndex(type_node.row(), 0, type_node)
        self.beginInsertRows(parent_index, type_node.childCount(), type_node.childCount())
        type_node.appendChild(attack_item_node)
        self.endInsertRows()

        # 更新计数
        type_node.count += 1
        attack_root.count += 1
        type_node.name = f"{attack_type} ({type_node.count})"
        attack_root.name = f"攻击行为检测 ({attack_root.count})"

        # 通知数据变化
        self.dataChanged.emit(
            self.createIndex(type_node.row(), 0, type_node),
            self.createIndex(type_node.row(), 1, type_node)
        )
        self.dataChanged.emit(
            self.createIndex(attack_root.row(), 0, attack_root),
            self.createIndex(attack_root.row(), 1, attack_root)
        )

    # QAbstractItemModel 必要方法

    def index(self, row: int, column: int, parent: QModelIndex = QModelIndex()) -> QModelIndex:
        if not self.hasIndex(row, column, parent):
            return QModelIndex()

        if not parent.isValid():
            parent_node = self.root
        else:
            parent_node = parent.internalPointer()

        child_node = parent_node.child(row)
        if child_node:
            return self.createIndex(row, column, child_node)
        return QModelIndex()

    def parent(self, index: QModelIndex) -> QModelIndex:
        if not index.isValid():
            return QModelIndex()

        child_node = index.internalPointer()
        parent_node = child_node.parent

        if parent_node == self.root or parent_node is None:
            return QModelIndex()

        return self.createIndex(parent_node.row(), 0, parent_node)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.column() > 0:
            return 0

        if not parent.isValid():
            parent_node = self.root
        else:
            parent_node = parent.internalPointer()

        return parent_node.childCount()

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 2

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid():
            return None

        if role == Qt.DisplayRole:
            node = index.internalPointer()
            return node.data(index.column())

        if role == Qt.UserRole:
            node = index.internalPointer()
            return node.payload

        if role == Qt.ToolTipRole:
            node = index.internalPointer()
            if node.count > 0:
                return f"{node.name}  ({node.count})"
            return node.name

        if role != Qt.ForegroundRole:
            return None

        # ForegroundRole: 根据节点类型返回颜色
        node = index.internalPointer()
        if node.node_type == "detection_item" and node.payload:
            return QColor(node.payload.threat_level.color)
        elif node.node_type == "protocol_finding" and node.payload:
            if node.payload.is_flag:
                return QColor("#D32F2F")
            else:
                return QColor("#7B1FA2")
        elif node.node_type == "decoding_result" and node.payload:
            if node.payload.flags_found:
                return QColor("#D32F2F")
            else:
                return QColor("#1976D2")
        elif node.node_type == "recovered_file" and node.payload:
            if node.payload.category == "executable":
                return QColor("#FF9800")
            else:
                return QColor("#388E3C")
        elif node.node_type == "attack_detection_item" and node.payload:
            return QColor(node.payload.risk_level_color)

        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlags:
        if not index.isValid():
            return Qt.NoItemFlags
        node = index.internalPointer()
        base_flags = Qt.ItemIsEnabled | Qt.ItemIsSelectable
        # 叶节点标记为永远没有子节点，避免 Qt 反复查询 hasChildren/rowCount
        if node and not node.children:
            base_flags |= Qt.ItemNeverHasChildren
        return base_flags

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> Any:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            if section == 0:
                return "项目"
            elif section == 1:
                return "数量"
        return None
