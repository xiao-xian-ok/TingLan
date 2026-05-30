# 听澜 (TingLan)

蓝队流量分析工具，主要面向 CTF 比赛里的流量分析题目。

能检测常见的 webshell 流量（蚁剑、菜刀、冰蝎、哥斯拉），也能识别 SQL 注入、XSS、命令注入、文件上传这些攻击。支持DNS 隧道、Cobalt Strike、RTP 音视频、USB HID、TLS/RDP/Redis/SMB/SSH 等协议分析和多层编码payload 自动解密。

制作团队：C404_TL

## 为什么做这个工具

Wireshark 很强，但对刚接触流量分析的人不太友好。很多时候题目里真正有用的内容藏在大量 HTTP 请求、编码参数、协议字段或者传输文件里，手动过滤和检索会花很长时间，尤其是数据包数量一多，定位可疑流量本身就会变成主要成本。

听澜想解决的是这个问题：先把常见的分析动作自动跑一遍，把可疑请求、解码结果、协议发现和提取文件整理出来，让分析者可以直接从结果里继续验证，而不是从一堆包里慢慢翻。

## 功能

- **Webshell 检测**: 蚁剑/菜刀/冰蝎/哥斯拉，结合流量特征、参数解码和 AST 语义校验
- **攻击检测**: SQLi、XSS、RCE、XXE、SSRF、目录穿越、命令注入、反序列化、文件上传等
- **自动解码**: Base64、Hex、URL 编码、Gzip/Zlib、ROT13、Morse 等，支持多层嵌套识别
- **协议分析**: ICMP 隐写、DNS 隧道、FTP、SMTP、MMS、蓝牙、USB、RTP、TLS、RDP、Redis、SMB、SSH
- **Cobalt Strike 分析**: Metadata Cookie 提取、Beacon 会话信息解析、加密 HTTP Body 识别和证据导出
- **文件还原**: 从 HTTP/SMB/TFTP 等流量中提取文件，支持 Magic Number 识别和安全路径清洗
- **MCP 服务**: 提供 `analyze_pcap`、`auto_decode`、`detect_attack`、`extract_files` 等工具给支持 MCP 的客户端调用

## 主要模块

底层解析依赖 TShark/pyshark，听澜负责做流式处理、规则检测、语义判断和结果整理。

- **流式分析模块**: 基于 TShark 按需读取数据包，边读边检测，避免大文件一次性加载到内存里。
- **攻击检测模块**: 对 HTTP 参数、请求体和 URI 做规则匹配、权重打分、上下文判断，用来快速筛出 SQLi、XSS、RCE 等常见攻击。
- **AST 语义分析模块**: 针对 PHP 代码做词法分析、语法树构建和污点追踪。普通正则只能看字符串特征，AST 能进一步判断用户输入是不是流向了 `eval`、`assert`、动态函数调用等危险位置，对混淆 webshell 的判断更稳，也能减少只靠关键字匹配带来的误报。
- **自动解码模块**: 对 URL、Base64、Hex、压缩数据等做多层尝试，适合处理 CTF 里常见的套娃 payload。
- **协议分析模块**: 把 ICMP、DNS、FTP、SMTP、USB、RTP、TLS、RDP、Redis、SMB、SSH 等协议的常见取证点单独封装，方便后续继续扩展。
- **MCP 服务**: 提供一组可以被 AI 客户端直接调用的分析工具，比如 `analyze_pcap`、`auto_decode`、`extract_files`。这样在排查时可以让 AI 直接调用工具读包、解码和整理结果，减少手动来回切换。

## 安装

### 环境要求

- Python 3.8+
- Wireshark (需要 tshark 组件)

### 安装步骤

```bash
# 克隆项目
git clone https://github.com/xiao-xian-ok/TingLan.git
cd TingLan

# 安装依赖
pip install -r requirements.txt
```

**注意**: PySide6 建议使用 `6.6.0`，新版本在部分 Windows 环境里可能有 DLL 加载问题。

如果要做 Cobalt Strike 密钥文件解析，还需要：

```bash
pip install javaobj-py3 cryptography pycryptodome
```

### Wireshark/TShark

需要安装 Wireshark 并确保 `tshark` 可用：

Windows:
- 官网下载安装，记得勾选 TShark 组件
- 安装路径一般是 `C:\Program Files\Wireshark\tshark.exe`

Linux:
```bash
# Debian/Ubuntu
sudo apt install tshark

# CentOS
sudo yum install wireshark-cli
```

macOS:
```bash
brew install wireshark
```

如果程序找不到 TShark，可以把 Wireshark 安装目录加入 `PATH`，或者设置 `WIRESHARK_PATH` 指向 Wireshark 安装目录。

## 使用

### GUI 模式

```bash
python main.py
```

打开后选择 pcap 文件，点开始分析就行。右侧可以查看 payload、响应包、自动解码结果、提取文件和协议发现。

GUI 里还有两个辅助面板：
- **密钥管理**: 保存冰蝎/哥斯拉/AES 密钥，也可以分析 Cobalt Strike Beacon 密钥
- **解码工具**: 手动做 Base64、URL、Hex、ROT13、HTML 实体、Unicode 转义等编码解码

### MCP 模式

```bash
python mcp_server.py
```

MCP 服务的详细用法请查看 `MCP_GUIDE.md`
### 命令行小工具

部分协议模块保留了交互式入口：

```bash
# ICMP 隐写分析
python icmp_analyzer.py

# FTP 文件和凭据分析
python core/ftp_analyzer.py

# DNS 隧道分析
python core/dns_analyzer.py

# Cobalt Strike Metadata/流量解密
python core/CS_analyzer.py

# TLS/RDP/SSH 等协议分析
python core/tls_analyzer.py
python core/rdp_analyzer.py
python core/ssh_analyzer.py
```

## 项目结构

```
TingLan/
├── main.py                    # GUI 启动入口
├── mcp_server.py              # MCP 服务入口
├── MCP_GUIDE.md               # MCP 工具说明
│
├── core/                      # 核心检测和协议分析模块
│   ├── stream_worker.py       # GUI 流式分析流程
│   ├── tshark_stream.py       # TShark 流式读取
│   ├── tshark_fields.py       # TShark 字段分隔和解析
│   ├── attack_detector.py     # OWASP 攻击检测
│   ├── webshell_detect.py     # Webshell 检测和解密
│   ├── ast_engine.py          # PHP AST 语义分析
│   ├── auto_decoder.py        # 自动解码引擎
│   ├── protocol_analyzer.py   # ICMP/DNS/FTP/SMTP/CS/USB/TLS/RDP/Redis/SMB/SSH 等统一协议分析
│   ├── http_reassembly.py     # HTTP 响应体重组和压缩解码
│   ├── file_restorer.py       # 文件类型识别和还原
│   ├── cs_payload_export.py   # Cobalt Strike 加密 payload 证据导出
│   ├── display_safety.py      # 二进制/乱码安全展示
│   └── safe_paths.py          # 导出文件路径安全处理
│
├── services/
│   ├── analysis_service.py    # 分析服务，HTTP 对象智能提取
│   ├── interfaces.py          # 服务接口
│   └── mock_service.py        # Mock 分析服务
│
├── controllers/
│   ├── analysis_controller.py # 旧版分析流程控制
│   └── export_controller.py   # JSON/HTML 报告导出
│
├── models/
│   ├── detection_result.py    # 检测结果、协议发现、解码结果等数据结构
│   ├── tree_model.py          # GUI 树模型
│   └── table_model.py         # GUI 表格模型
│
├── gui/                       # PySide6 界面
│   ├── main_window.py         # 主窗口
│   ├── widgets/               # 结果树、详情表、payload 查看器、图表等控件
│   ├── dialogs/               # 设置、导出、完成提示等对话框
│   └── styles/                # 主题样式
│
└── tests/
    └── test_security_regressions.py # 安全和稳定性回归测试
```

## 检测能力

### Webshell

| 工具 | 检测方式 |
|-----|---------|
| 蚁剑 | `@ini_set`、`eval($_POST)`、gzinflate、随机前缀 Base64 等特征 |
| 菜刀 | 固定 Base64 特征、`z0/z1/z2` 参数、响应体特征 |
| 冰蝎 | AES 加密流量、Session 密钥交换、默认密钥和自定义密钥尝试 |
| 哥斯拉 | ClassLoader 反射、特殊 MD5 响应格式、加密参数识别 |

### 攻击类型

- SQL 注入: UNION SELECT、OR 1=1、SLEEP()、注释符
- XSS: script 标签、事件处理器、javascript 伪协议
- RCE: eval、system、exec、反引号等危险执行
- XXE: ENTITY 声明、外部实体引用
- SSRF: 内网 IP、云元数据地址
- 目录穿越: ../、编码绕过
- 命令注入: 管道符、分号、命令拼接
- 文件上传: 双扩展名、Content-Type 绕过
- LFI/RFI、LDAP 注入、SSTI、反序列化

### 自动解码

支持的编码格式：
- Base64 / Base32 / Base58
- Hex（支持冒号、空格、`0x` 前缀等格式）
- URL 编码
- HTML 实体
- 二进制 / 八进制 / 十进制
- Gzip / Zlib
- ROT13
- Morse 码

遇到多层编码会自动递归解码，比如 `Base64(URL(Base64(flag)))` 这种。

### 协议和取证

- ICMP 隐写: Data 长度、TTL、载荷偏移、序列号
- DNS 隧道: 子域名编码、TXT 指令、Hex/Base64/GB2312 解码
- FTP/SMTP: 登录凭据、文件传输、邮件内容和附件提取
- MMS/蓝牙: MMS 文件数据、OBEX/L2CAP/GATT 数据提取
- USB: HID 键盘输入还原、鼠标轨迹恢复
- RTP: 音视频流统计、SSRC/编码/时长/丢包信息，支持按需导出
- TLS/RDP/SSH: 握手、证书、弱算法、keylog/私钥辅助解密
- Redis/SMB: 命令、认证信息、共享文件提取
- Cobalt Strike: Metadata Cookie、Beacon AES/HMAC 会话密钥、加密 HTTP Body 证据

### 文件还原

程序会先用 TShark 导出 HTTP 对象，再做一次智能过滤：
- 去掉普通 HTML 页面和重复对象
- 优先保留下载文件、图片、压缩包、文档、可执行文件等
- 使用 Magic Number 识别 50+ 种文件格式
- 导出路径会做文件名清洗，避免路径穿越

## 配置

### TShark 路径

程序会自动查找 `tshark`，默认查找路径包括：

```
Windows:
- C:\Program Files\Wireshark\tshark.exe
- C:\Program Files (x86)\Wireshark\tshark.exe
- D:\Program Files\Wireshark\tshark.exe
- D:\Wireshark\tshark.exe

Linux/Mac:
- /usr/bin/tshark
- /usr/local/bin/tshark
- /opt/homebrew/bin/tshark
```

如果不在这些路径里，建议把 TShark 加入 `PATH`，或者设置：

```bash
# Windows PowerShell
$env:WIRESHARK_PATH="C:\Program Files\Wireshark"

# Linux/macOS
export WIRESHARK_PATH=/Applications/Wireshark.app/Contents/MacOS
```

### 输出目录

- `output/cs_payloads/`: Cobalt Strike 加密 HTTP Body 证据
- `output/extracted_files/`: MCP 文件提取结果
- 临时目录 `tinglan_http_*`: GUI HTTP 对象提取缓存
- `logs/mcp.log`: MCP 服务日志

## 依赖

```
PySide6==6.6.0    # GUI 框架
pyshark>=0.6      # pcap 解析
jinja2>=3.1.0     # HTML 报告生成
pyahocorasick     # 快速特征匹配
mcp>=1.0.0        # MCP 服务
pycryptodome      # 冰蝎/哥斯拉/CS 解密
```

可选：

```
javaobj-py3       # 解析 Cobalt Strike .beacon_keys
cryptography      # RSA 私钥加载和 CS Metadata 解密
matplotlib/numpy  # USB 鼠标轨迹绘图
```

## 常见问题

**Q: 启动报 DLL 错误**

A: 多数是 PySide6 版本问题，建议固定到 6.6.0：
```bash
pip uninstall PySide6
pip install PySide6==6.6.0
```

**Q: 找不到 tshark**

A: 安装 Wireshark，确保安装时勾选了 TShark 组件。也可以把 Wireshark 目录加入 `PATH`，或者设置 `WIRESHARK_PATH`。

**Q: 分析大文件很慢**

A: 正常，程序用的是流式处理，不会把整个文件加载到内存。如果文件特别大（几个 G），可以先用 Wireshark 过滤一下再分析。

**Q: Cobalt Strike 只看到加密 Body，看不到明文**

A: 只识别到加密帧时只能导出长度头、密文和 HMAC 证据。要还原明文命令，需要提供 Beacon 会话密钥，或者先用 `.cobaltstrike.beacon_keys` 解出 Metadata 里的 AES/HMAC key。

**Q: 检测结果不准**

A: 这工具主要是用来辅助分析的，不能完全依赖自动检测。建议结合手工分析，特别是遇到免杀、变形 webshell 或非标准协议流量。

## TODO

- [ ] 规则自定义
- [ ] 批量分析
- [ ] 支持更多协议

## License

MIT
