# 听澜 (TingLan)

蓝队流量分析工具，CTF比赛中的流量分析题目。

能检测常见的webshell流量（蚁剑、菜刀、冰蝎、哥斯拉），也能识别SQL注入、XSS、命令注入这些攻击。还有自动解码功能，遇到多层编码的payload可以自动一层层解开。

制作团队：C404_TL

## 功能

- **Webshell检测**: 蚁剑/菜刀/冰蝎/哥斯拉，基于流量特征匹配
- **攻击检测**: SQLi、XSS、RCE、XXE、SSRF、目录穿越、命令注入等
- **自动解码**: Base64、Hex、URL编码、Gzip等，支持多层嵌套自动识别
- **协议分析**: ICMP隐写、FTP文件提取、SMTP邮件分析
- **文件还原**: 从流量中提取传输的文件，支持50+种格式识别

## 安装

### 环境要求

- Python 3.8+
- Wireshark (需要tshark组件)

### 安装步骤

```bash
# 克隆项目
git clone https://github.com/xiao-xian-ok/TingLan.git
cd tinglan

# 安装依赖
pip install -r requirements.txt
```

**注意**: PySide6必须用6.6.0版本，新版本在Windows上有DLL加载问题

### Wireshark/TShark

需要安装Wireshark并确保tshark可用：

Windows:
- 官网下载安装，记得勾选TShark组件
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

## 使用

### GUI模式

```bash
python main.py
```

打开后选择pcap文件，点开始分析就行。

### 命令行

单独跑webshell检测：
```bash
python core/webshell_detect.py
```

ICMP隐写分析：
```bash
python icmp_analyzer.py
```

FTP文件提取：
```bash
python core/ftp_analyzer.py
```

## 项目结构

```
tinglan/
├── main.py                 # 程序入口
├── mcp_server.py           # MCP服务（给Claude用的）
│
├── core/                   # 核心检测模块
│   ├── webshell_detect.py  # webshell检测（蚁剑/菜刀/冰蝎/哥斯拉）
│   ├── attack_detector.py  # OWASP攻击检测
│   ├── auto_decoder.py     # 自动解码引擎
│   ├── protocol_analyzer.py # 协议分析（ICMP隐写等）
│   ├── entropy_analyzer.py # 信息熵分析
│   ├── file_restorer.py    # 文件类型识别和还原
│   ├── tshark_stream.py    # tshark流式处理
│   ├── ftp_analyzer.py     # FTP分析
│   └── SMTP_analyzer.py    # 邮件分析
│
├── services/
│   └── analysis_service.py # 分析服务，HTTP对象提取
│
├── controllers/
│   ├── analysis_controller.py  # 分析流程控制
│   └── export_controller.py    # 报告导出
│
├── models/
│   └── detection_result.py # 检测结果数据结构
│
├── gui/                    # 界面
│   ├── main_window.py      # 主窗口
│   ├── widgets/            # 各种控件
│   └── dialogs/            # 对话框
│
└── tests/                  # 测试
```

## 检测能力

### Webshell

| 工具 | 检测方式 |
|-----|---------|
| 蚁剑 | `@ini_set`、`eval($_POST)`、gzinflate等特征 |
| 菜刀 | Base64编码的固定特征 `QGluaV9zZXQ` |
| 冰蝎 | AES加密流量、openssl_decrypt、Session密钥交换 |
| 哥斯拉 | ClassLoader反射、特殊的MD5响应格式 |

### 攻击类型

- SQL注入: UNION SELECT、OR 1=1、SLEEP()、注释符
- XSS: script标签、事件处理器、javascript伪协议
- RCE: eval、system、exec等危险函数
- XXE: ENTITY声明、外部实体引用
- SSRF: 内网IP、云元数据地址
- 目录穿越: ../、编码绕过
- 命令注入: 管道符、分号、反引号
- 文件上传: 双扩展名、Content-Type绕过

### 自动解码

支持的编码格式：
- Base64 / Base32 / Base58
- Hex（支持多种分隔符：冒号、空格、0x前缀）
- URL编码
- HTML实体
- 二进制 / 八进制 / 十进制
- Gzip / Zlib
- ROT13
- Morse码

遇到多层编码会自动递归解码，比如 `Base64(URL(Base64(flag)))` 这种。

### 隐写检测

ICMP隐写：
- Data长度作为字节值
- TTL值编码
- 二进制编码（TTL 32/64表示0/1）
- 序列号隐写

## 配置

### TShark路径

程序会自动查找tshark，如果找不到可以手动指定：

修改 `services/analysis_service.py` 中的 `find_tshark()` 函数，添加你的路径。

默认查找路径：
```
Windows:
- C:\Program Files\Wireshark\tshark.exe
- C:\Program Files (x86)\Wireshark\tshark.exe

Linux/Mac:
- /usr/bin/tshark
- /usr/local/bin/tshark
```

## 依赖

```
PySide6==6.6.0    # GUI框架，必须用这个版本
pyshark           # pcap解析
jinja2            # HTML报告生成
pycryptodome      # 冰蝎/哥斯拉解密（可选）
```

## 常见问题

**Q: 启动报DLL错误**

A: PySide6版本问题，必须用6.6.0：
```bash
pip uninstall PySide6
pip install PySide6==6.6.0
```

**Q: 找不到tshark**

A: 安装Wireshark，确保安装时勾选了TShark组件。

**Q: 分析大文件很慢**

A: 正常，程序用的是流式处理，不会把整个文件加载到内存。如果文件特别大（几个G），可以先用Wireshark过滤一下再分析。

**Q: 检测结果不准**

A: 这工具主要是用来辅助分析的，不能完全依赖自动检测。建议结合手工分析，特别是遇到免杀或变形的webshell。

## TODO

- [ ] DNS隧道检测
- [ ] 更多协议支持
- [ ] 规则自定义
- [ ] 批量分析

## License

MIT

