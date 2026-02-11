# 配色方案

# 主色调
PRIMARY = "#1976D2"  # 主蓝色
PRIMARY_LIGHT = "#E3F2FD"  # 浅蓝色
PRIMARY_DARK = "#0D47A1"  # 深蓝色

# 强调色
ACCENT = "#FFC107"  # 金色/警告色
ACCENT_LIGHT = "#FFF8E1"

# 背景色
BG_PRIMARY = "#FFFFFF"  # 主背景
BG_SECONDARY = "#F5F5F5"  # 次要背景
BG_TERTIARY = "#FAFAFA"  # 三级背景

# 边框色
BORDER = "#E0E0E0"
BORDER_LIGHT = "#F0F0F0"
BORDER_DARK = "#BDBDBD"

# 文字色
TEXT_PRIMARY = "#333333"
TEXT_SECONDARY = "#666666"
TEXT_DISABLED = "#9E9E9E"
TEXT_HINT = "#BDBDBD"

# 威胁等级颜色
THREAT_CRITICAL = "#9C27B0"  # 紫色
THREAT_HIGH = "#F44336"  # 红色
THREAT_MEDIUM = "#FF9800"  # 橙色
THREAT_LOW = "#4CAF50"  # 绿色
THREAT_INFO = "#2196F3"  # 蓝色

# 状态色
SUCCESS = "#4CAF50"
WARNING = "#FF9800"
ERROR = "#F44336"
INFO = "#2196F3"

# 检测类型颜色
DETECTION_ANTSWORD = "#E91E63"
DETECTION_CAIDAO = "#9C27B0"
DETECTION_BEHINDER = "#673AB7"
DETECTION_GODZILLA = "#3F51B5"

# 协议颜色
PROTOCOL_HTTP = "#4CAF50"
PROTOCOL_TCP = "#2196F3"
PROTOCOL_UDP = "#FF9800"
PROTOCOL_ICMP = "#9C27B0"
PROTOCOL_DNS = "#00BCD4"
PROTOCOL_TLS = "#009688"


def get_threat_color(level: str) -> str:
    """获取威胁等级颜色"""
    colors = {
        "critical": THREAT_CRITICAL,
        "high": THREAT_HIGH,
        "medium": THREAT_MEDIUM,
        "low": THREAT_LOW,
        "info": THREAT_INFO
    }
    return colors.get(level.lower(), TEXT_SECONDARY)


def get_protocol_color(protocol: str) -> str:
    """获取协议颜色"""
    colors = {
        "http": PROTOCOL_HTTP,
        "tcp": PROTOCOL_TCP,
        "udp": PROTOCOL_UDP,
        "icmp": PROTOCOL_ICMP,
        "dns": PROTOCOL_DNS,
        "tls": PROTOCOL_TLS
    }
    return colors.get(protocol.lower(), TEXT_SECONDARY)
