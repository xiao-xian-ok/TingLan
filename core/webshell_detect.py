# webshell_detect.py
# webshell流量检测 - 蚁剑/菜刀/冰蝎/哥斯拉
# 特征匹配+权重打分，分数过线就告警

import re
import base64
import logging
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import unquote

from http_formatter import burp_format_request, hex_to_string
from statistical_analyzer import StatisticalAnalyzer, StatisticalConfig

logger = logging.getLogger(__name__)


class DetectionConfig:

    # 蚁剑特征
    ANTSWORD_INDICATORS = [
        {'pattern': r'@ini_set\s*\(\s*["\']display_errors["\']', 'weight': 90, 'name': 'php_ini_set'},  # 禁用错误显示
        {'pattern': r'@set_time_limit\s*\(\s*0\s*\)', 'weight': 70, 'name': 'set_time_limit'},  # 无限执行时间

        {'pattern': r'@error_reporting\s*\(\s*0\s*\)', 'weight': 60, 'name': 'error_reporting'},  # 禁用错误报告
        {'pattern': r'eval\s*\(\s*[\$@]', 'weight': 50, 'name': 'eval_var'},  # eval执行变量
        {'pattern': r'assert\s*\(\s*[\$@]', 'weight': 50, 'name': 'assert_var'},  # assert执行变量
        {'pattern': r'create_function\s*\(', 'weight': 55, 'name': 'create_function'},  # 动态创建函数
        {'pattern': r'preg_replace\s*\([^)]*["\'][^"\']*\/[^\/]*e', 'weight': 60, 'name': 'preg_replace_e'},  # /e修饰符代码执行
        {'pattern': r'gzinflate\s*\(', 'weight': 45, 'name': 'gzinflate'},  # gzip解压混淆
        {'pattern': r'gzuncompress\s*\(', 'weight': 45, 'name': 'gzuncompress'},
        {'pattern': r'str_rot13\s*\(', 'weight': 40, 'name': 'str_rot13'},  # ROT13编码
        {'pattern': r'base64_decode\s*\([^)]*\)', 'weight': 40, 'name': 'base64_decode'},

        {'pattern': r'call_user_func', 'weight': 35, 'name': 'call_user_func'},  # 回调函数执行
        {'pattern': r'call_user_func_array', 'weight': 35, 'name': 'call_user_func_array'},
        {'pattern': r'_0x[a-fA-F0-9]{4,}', 'weight': 30, 'name': 'obfuscated_var'},  # 混淆变量名
        {'pattern': r'chr\s*\(\s*\d+\s*\)', 'weight': 25, 'name': 'chr_obfuscation'},  # chr()字符混淆
        {'pattern': r'\$_POST\s*\[', 'weight': 20, 'name': 'post_access'},
        {'pattern': r'\$_GET\s*\[', 'weight': 20, 'name': 'get_access'},
        {'pattern': r'\$_REQUEST\s*\[', 'weight': 20, 'name': 'request_access'},
        {'pattern': r'\$_COOKIE\s*\[', 'weight': 15, 'name': 'cookie_access'},
        {'pattern': r'array_map\s*\(\s*[\'"]', 'weight': 30, 'name': 'array_map_callback'},  # 回调执行
        {'pattern': r'array_filter\s*\(\s*[^,]+,\s*[\'"]', 'weight': 30, 'name': 'array_filter_callback'},
        {'pattern': r'usort\s*\(\s*[^,]+,\s*[\'"]', 'weight': 30, 'name': 'usort_callback'},
    ]

    # 菜刀特征
    CAIDAO_INDICATORS = [
        {'pattern': r'[a-zA-Z_]\w*=QGluaV9zZXQ', 'weight': 95, 'name': 'caidao_ini_b64'},  # 固定Base64(@ini_set编码)
        {'pattern': r'z\d+=.*base64_decode', 'weight': 80, 'name': 'caidao_z_base64'},  # z参数+base64_decode

        {'pattern': r'action=\w+&[a-zA-Z]\d+=', 'weight': 70, 'name': 'caidao_action_pattern'},  # action参数模式
        {'pattern': r'z\d+=[\w\+/=]{50,}', 'weight': 60, 'name': 'caidao_z_long_b64'},  # z参数长Base64值
    ]

    # 冰蝎特征
    BEHINDER_INDICATORS = [
        # PHP Shell代码
        {'pattern': r'openssl_decrypt\s*\(', 'weight': 70, 'name': 'openssl_decrypt'},  # AES解密
        {'pattern': r'AES-128-CBC', 'weight': 60, 'name': 'aes_128_cbc'},
        {'pattern': r'class\s+\w+\s*\{\s*function\s+__construct\s*\(\s*\)', 'weight': 50, 'name': 'behinder_class_pattern'},

        # 冰蝎4 PHP固定代码
        {'pattern': r'eval\s*\(\s*\$post\s*\)', 'weight': 85, 'name': 'behinder4_eval_post'},  # eval($post)
        {'pattern': r'\$post\s*=\s*Decrypt\s*\(', 'weight': 90, 'name': 'behinder4_decrypt_post'},  # $post=Decrypt(
        {'pattern': r'Decrypt\s*\(\s*file_get_contents\s*\(\s*["\']php://input["\']', 'weight': 95, 'name': 'behinder4_php_input_decrypt'},  # Decrypt(file_get_contents("php://input"))
        {'pattern': r'@error_reporting\s*\(\s*0\s*\)\s*;', 'weight': 60, 'name': 'behinder4_error_reporting'},

        # JSP Shell
        {'pattern': r'new\s+ReflectionClass', 'weight': 45, 'name': 'reflection_class'},
        {'pattern': r'defineClass\s*\(', 'weight': 50, 'name': 'define_class'},  # 动态定义类
        {'pattern': r'javax\.crypto\.Cipher', 'weight': 55, 'name': 'java_cipher'},
        {'pattern': r'getRuntime\s*\(\s*\)\s*\.exec', 'weight': 65, 'name': 'runtime_exec'},  # Java命令执行

        # 冰蝎v3/v4
        {'pattern': r'session_start\s*\(\s*\)', 'weight': 30, 'name': 'session_start'},  # v3密钥交换
        {'pattern': r'\$_SESSION\s*\[\s*[\'"][^\'"]+[\'"]\s*\]', 'weight': 25, 'name': 'session_access'},

        # 冰蝎解密后常见模式
        {'pattern': r'@error_reporting\s*\(\s*0\s*\).*openssl', 'weight': 75, 'name': 'behinder_php_shell', 'flags': re.DOTALL},
        {'pattern': r'function\s+\w+\s*\(\s*\$\w+\s*\)\s*\{.*return.*openssl', 'weight': 70, 'name': 'behinder_decrypt_func', 'flags': re.DOTALL},
        {'pattern': r'base64_decode\s*\(\s*\$_POST', 'weight': 55, 'name': 'base64_decode_post'},
        {'pattern': r'\$post\s*=\s*file_get_contents\s*\(\s*[\'"]php://input[\'"]\s*\)', 'weight': 60, 'name': 'php_input'},

        # 冰蝎命令执行
        {'pattern': r'methodBody\s*=', 'weight': 45, 'name': 'method_body_var'},
        {'pattern': r'currentPath\s*=', 'weight': 40, 'name': 'current_path_var'},
        {'pattern': r'execCommand', 'weight': 55, 'name': 'exec_command_func'},
        {'pattern': r'fileOperation', 'weight': 50, 'name': 'file_operation_func'},
    ]

    # 冰蝎4首包 - 默认密钥时首次请求的固定Base64模式
    BEHINDER4_FIRST_REQUEST_PATTERNS = [
        'dFAXQV1LORcHRQtLRlwMAhwFTAg/M',  # 解密后为: @error_reporting(0);
        'dFAXQV1LORcHRQ',  # 前缀匹配
    ]

    # 冰蝎流量层 - 检测加密流量本身
    BEHINDER_TRAFFIC_PATTERNS = {
        'pure_base64_body': {
            'weight': 45,
        },  # 纯Base64请求体
        'high_entropy_body': {
            'weight': 40,
        },  # 高熵值(加密数据)
        'aes_block_aligned': {
            'weight': 35,
        },  # Content-Length是16的倍数
        'no_readable_params': {
            'weight': 30,
        },  # 无可读参数名
        'encrypted_response': {
            'weight': 40,
        },  # 响应体也是加密的
        'response_base64': {
            'weight': 35,
        },  # 响应体Base64
        'post_to_php': {
            'weight': 20,
        },
        'small_uri_large_body': {
            'weight': 25,
        },  # 短URI+大请求体
        'behinder_v3_handshake': {
            'weight': 60,
        },  # v3密钥协商
        'repeated_encrypted_pattern': {
            'weight': 50,
        },  # 重复加密通信
    }

    # 哥斯拉特征
    GODZILLA_INDICATORS = [
        {'pattern': r'run\s*\(\s*\$_POST\s*\[\s*[\'"][^\'"]+[\'"]\s*\]\s*\)', 'weight': 80, 'name': 'godzilla_run_post'},  # run($POST)模式
        {'pattern': r'class\s+\w+\s*extends\s+ClassLoader', 'weight': 75, 'name': 'godzilla_classloader'},  # JSP类加载器
        {'pattern': r'methodBody\s*=', 'weight': 60, 'name': 'godzilla_method_body'},

        {'pattern': r'session_start\s*\(\s*\)\s*;.*\$_SESSION', 'weight': 40, 'name': 'godzilla_session', 'flags': re.DOTALL},  # 会话管理
        {'pattern': r'E\s*\(\s*\$_POST\s*\[', 'weight': 55, 'name': 'godzilla_e_post'},  # E()函数调用

        # 哥斯拉PHP shell
        {'pattern': r'@session_start\s*\(\s*\)\s*;', 'weight': 35, 'name': 'godzilla_session_start'},
        {'pattern': r'\$key\s*=\s*@?\$_SESSION\s*\[', 'weight': 50, 'name': 'godzilla_session_key'},  # session密钥获取
        {'pattern': r'@ini_set\s*\(\s*["\']display_errors["\']', 'weight': 40, 'name': 'godzilla_ini_set'},
    ]

    # 哥斯拉流量层
    GODZILLA_TRAFFIC_PATTERNS = {
        'java_user_agent': {
            'weight': 40,
        },  # Java默认UA
        'jdk_accept': {
            'weight': 35,
        },  # JDK默认Accept头
        'cookie_trailing_semicolon': {
            'weight': 60,
        },  # Cookie末尾分号(强特征)
        'godzilla_response_format': {
            'weight': 90,
        },  # md5前16位+base64+md5后16位
        'large_base64_body': {
            'weight': 35,
        },  # 大型Base64请求体(初始化)
        'raw_encrypted_body': {
            'weight': 40,
        },  # 原始加密请求体
    }

    # 哥斯拉响应体正则 - Java版大写MD5，PHP版小写
    GODZILLA_RESPONSE_PATTERN = re.compile(
        r'^([0-9a-fA-F]{16})([\w+/]{4,}=?=?)([0-9a-fA-F]{16})$'
    )

    # 响应包
    RESPONSE_INDICATORS = [
        # 蚁剑响应
        {'pattern': r'\[S\].*?\[E\]', 'weight': 85, 'name': 'antsword_marker', 'flags': re.DOTALL},  # [S][E]标记
        {'pattern': r'->\./', 'weight': 60, 'name': 'path_marker'},  # 路径标记

        # 菜刀响应
        {'pattern': r'X@Y', 'weight': 70, 'name': 'caidao_xay_marker'},  # X@Y标记
        {'pattern': r'->\|', 'weight': 65, 'name': 'caidao_path_prefix'},  # ->|路径前缀
        {'pattern': r'\|\|[^|]+\|\|', 'weight': 50, 'name': 'caidao_delimiter'},  # ||分隔符

        # 命令执行回显
        {'pattern': r'uid=\d+\([^)]+\)\s+gid=\d+', 'weight': 80, 'name': 'id_command_output'},  # Linux id输出
        {'pattern': r'Windows IP Configuration', 'weight': 75, 'name': 'ipconfig_output'},
        {'pattern': r'Directory of [C-Z]:\\', 'weight': 75, 'name': 'dir_command_output'},
        {'pattern': r'total\s+\d+.*?drwx', 'weight': 70, 'name': 'ls_command_output', 'flags': re.DOTALL},
        {'pattern': r'(root|admin|www-data):[x*]:\d+:\d+:', 'weight': 75, 'name': 'etc_passwd_output'},  # /etc/passwd
        {'pattern': r'\[boot loader\]', 'weight': 65, 'name': 'boot_ini_output'},

        # 错误信息(权重低，容易误报)
        {'pattern': r'(Parse error|Fatal error|Warning):\s+.+\s+in\s+.+\s+on line\s+\d+', 'weight': 35, 'name': 'php_error'},
    ]

    # HTTP请求特征
    REQUEST_INDICATORS = [
        {'pattern': r'X-Forwarded-For:\s*127\.0\.0\.1', 'weight': 25, 'name': 'xff_localhost'},  # XFF伪造
        {'pattern': r'application/x-www-form-urlencoded.*charset\s*=\s*utf-8', 'weight': 15, 'name': 'form_utf8'},
    ]

    # 可疑参数名
    SUSPICIOUS_PARAM_PATTERNS = [
        (r'^_0x[a-fA-F0-9]+$', 35, 'obfuscated_param', '混淆参数名(_0x开头)'),
        (r'^[a-z]{1,2}\d{1,2}$', 20, 'short_indexed_param', '短参数名(如z0,a1)'),
        (r'^ant[_-]?', 40, 'ant_prefix', 'ant前缀参数'),
        (r'^(cmd|exec|shell|payload|code)$', 30, 'dangerous_param_name', '危险参数名'),
        (r'^[a-f0-9]{32}$', 25, 'md5_param_name', 'MD5格式参数名'),
    ]

    DETECTION_THRESHOLD = 60
    HIGH_CONFIDENCE_THRESHOLD = 100
    MEDIUM_CONFIDENCE_THRESHOLD = 75
    SUSPICIOUS_THRESHOLD = 30

    # 统计学阈值
    STATISTICAL_THRESHOLDS = {
        'entropy': {
            'high': 5.5,
            'medium': 4.5,
            'normal_max': 4.0,
        },
        'special_char_ratio': {
            'high': 0.4,
            'medium': 0.25,
            'normal_max': 0.15,
        },
        'non_printable_ratio': {
            'high': 0.3,
            'medium': 0.1,
        },
        'base64_length': {
            'large': 5000,
            'medium': 1000,
            'small': 200,
        },
    }

    # 参数名白名单
    PARAM_NAME_WHITELIST = {
        'password', 'passwd', 'pass', 'pwd', 'token', 'csrf', 'csrftoken',
        'session', 'sessionid', 'auth', 'key', 'secret', 'api_key', 'apikey',
        'username', 'user', 'login', 'email', 'phone', 'mobile',
        'callback', 'jsonp', 'format', 'type', 'action', 'method',
        'page', 'size', 'limit', 'offset', 'sort', 'order',
        'id', 'uid', 'pid', 'cid', 'tid', 'fid',
        'name', 'title', 'content', 'body', 'text', 'message', 'msg',
        'file', 'path', 'url', 'src', 'href', 'link',
        'time', 'date', 'timestamp', 'created', 'updated',
        'status', 'state', 'code', 'result', 'error',
        'data', 'info', 'list', 'items', 'records',
        'q', 's', 'search', 'query', 'keyword', 'keywords',
        'v', 'version', 'lang', 'language', 'locale',
        '_', '__', '_t', '_r', 'r', 't', 'n',
    }

    # URI白名单
    URI_WHITELIST_PATTERNS = [
        r'/api/v\d+/',           # API版本路径
        r'/static/',             # 静态资源
        r'/assets/',             # 资源目录
        r'\.(css|js|png|jpg|gif|ico|woff|ttf|svg)(\?|$)',  # 静态文件
    ]

    # 编码
    BASE64_PREFIX_LENGTHS = [0, 2, 3, 4, 5, 6, 8, 10]
    MAX_URL_DECODE_ITERATIONS = 3

    # 参数限制
    MAX_PARAM_NAME_LENGTH = 128
    MIN_PARAM_VALUE_LENGTH = 4
    MAX_PARAM_VALUE_LENGTH = 100000

    SUPPORTED_METHODS = {'POST', 'PUT', 'PATCH'}

    # 冰蝎/哥斯拉解密密钥
    BEHINDER_DEFAULT_KEYS = [
        b'e45e329feb5d925b',  # md5("rebeyond")[:16] 默认
        b'1234567890123456',
        b'0123456789abcdef',
        b'abcdef0123456789',

        b'password12345678',
        b'admin12345678901',
        b'root123456789012',
        b'test123456789012',
        b'shell12345678901',
        b'behinder12345678',
        b'webshell12345678',
        b'hackme1234567890',
        b'secretkey1234567',

        b'xc3x4rs5xyzw6789',
        b'bx4ut56rs3xyzabc',

        # MD5前16位
        b'5f4dcc3b5aa765d6',  # password
        b'21232f297a57a5a7',  # admin
        b'63a9f0ea7bb98050',  # root
        b'098f6bcd4621d373',  # test
        b'c4ca4238a0b92382',  # 1
        b'c81e728d9d4c2f63',  # 2
        b'e10adc3949ba59ab',  # 123456
        b'd41d8cd98f00b204',  # 空串
        b'827ccb0eea8a706c',  # 12345
        b'25d55ad283aa400a',  # 12345678
        b'fcea920f7412b5da',  # password123
        b'0192023a7bbd7324',  # administrator
        b'7c4a8d09ca3762af',  # 123456789

        b'aaaaaaaaaaaaaaaa',
        b'0000000000000000',
        b'ffffffffffffffff',
        b'key1234567890123',
        b'pass123456789012',
        b'adminadminadmina',
        b'rootrootrootroot',
    ]

    # 哥斯拉密钥(XOR加密)
    GODZILLA_DEFAULT_KEYS = [
        'key',
        'pass',
        '3c6e0b8a9c15224a',
        'password',
        'admin',
        'root',
        'shell',
        'test',
        '123456',
        'godzilla',
        'webshell',
        'hack',
        'secret',
        '5f4dcc3b5aa765d6',  # password
        '21232f297a57a5a7',  # admin
        'e10adc3949ba59ab',  # 123456
        'a', 'b', 'c', 'x', 'y', 'z',
        '1', '2', '3',
    ]


def try_decrypt_behinder(encrypted_data: str, custom_keys: List[bytes] = None) -> Optional[Dict]:
    """尝试用常见密钥AES解密冰蝎流量"""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except ImportError:
        # 没有安装pycryptodome，尝试简单方式
        return _try_decrypt_behinder_simple(encrypted_data)

    try:
        # Base64解码
        if not encrypted_data:
            return None

        clean_data = encrypted_data.strip()

        try:
            cipher_data = base64.b64decode(clean_data)
        except Exception:
            return None

        if len(cipher_data) < 16:
            return None

        # 自定义密钥优先
        keys_to_try = []
        if custom_keys:
            keys_to_try.extend(custom_keys)
        keys_to_try.extend(DetectionConfig.BEHINDER_DEFAULT_KEYS)

        for key in keys_to_try:
            try:
                for iv in [key, b'\x00' * 16]:
                    try:
                        cipher = AES.new(key, AES.MODE_CBC, iv)
                        decrypted = cipher.decrypt(cipher_data)
                        try:
                            decrypted = unpad(decrypted, AES.block_size)
                        except Exception:
                            pass

                        try:
                            decrypted_str = decrypted.decode('utf-8', errors='strict')
                        except UnicodeDecodeError:
                            decrypted_str = decrypted.decode('utf-8', errors='ignore')

                        if _is_valid_decrypted(decrypted_str):
                            return {
                                'decrypted': decrypted_str,
                                'key': key.decode('utf-8', errors='ignore'),
                                'method': 'AES-128-CBC'
                            }
                    except Exception:
                        continue
            except Exception:
                continue

    except Exception as e:
        logger.debug(f"冰蝎解密异常: {e}")

    return None


def _try_decrypt_behinder_simple(encrypted_data: str) -> Optional[Dict]:
    """没装pycryptodome时的简单解密尝试"""
    try:
        # 多层Base64解码
        data = encrypted_data
        for _ in range(3):
            try:
                decoded = base64.b64decode(data)
                try:
                    decoded_str = decoded.decode('utf-8', errors='strict')
                except UnicodeDecodeError:
                    decoded_str = decoded.decode('utf-8', errors='ignore')
                if _is_valid_decrypted(decoded_str):
                    return {
                        'decrypted': decoded_str,
                        'key': 'base64',
                        'method': 'Base64'
                    }
                data = decoded_str
            except Exception:
                break
    except Exception:
        pass
    return None


def try_decrypt_godzilla(encrypted_data: str, pass_keys: List[str] = None) -> Optional[Dict]:
    """尝试用常见密钥XOR解密哥斯拉流量"""
    if not encrypted_data:
        return None

    # 自定义密钥优先
    keys_to_try = []
    if pass_keys:
        keys_to_try.extend(pass_keys)
    keys_to_try.extend(DetectionConfig.GODZILLA_DEFAULT_KEYS)

    for key in keys_to_try:
        if not key:
            continue

        try:
            # 解密流程: base64_decode -> XOR(key)
            try:
                decoded = base64.b64decode(encrypted_data)
            except Exception:
                decoded = encrypted_data.encode('utf-8', errors='ignore')

            # XOR解密
            key_bytes = key.encode('utf-8') if isinstance(key, str) else key
            decrypted_bytes = bytearray()

            for i, b in enumerate(decoded):
                decrypted_bytes.append(b ^ key_bytes[i % len(key_bytes)])

            try:
                decrypted_str = decrypted_bytes.decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                decrypted_str = bytes(decrypted_bytes).decode('utf-8', errors='ignore')

            if _is_valid_decrypted(decrypted_str):
                return {
                    'decrypted': decrypted_str,
                    'key': key,
                    'method': 'XOR+Base64'
                }

            # 双重编码
            try:
                double_decoded = base64.b64decode(decrypted_str)
                try:
                    double_str = double_decoded.decode('utf-8', errors='strict')
                except UnicodeDecodeError:
                    double_str = double_decoded.decode('utf-8', errors='ignore')
                if _is_valid_decrypted(double_str):
                    return {
                        'decrypted': double_str,
                        'key': key,
                        'method': 'XOR+Double-Base64'
                    }
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"哥斯拉解密尝试失败(key={key}): {e}")
            continue

    # 尝试纯Base64解码
    try:
        decoded = base64.b64decode(encrypted_data)
        try:
            decoded_str = decoded.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            decoded_str = decoded.decode('utf-8', errors='ignore')
        if _is_valid_decrypted(decoded_str):
            return {
                'decrypted': decoded_str,
                'key': 'none',
                'method': 'Base64'
            }
    except Exception:
        pass

    return None


def _is_valid_decrypted(text: str) -> bool:
    """检查解密结果是否可读"""
    if not text or len(text) < 5:
        return False

    # 计算ASCII可打印字符比例
    ascii_printable = 0
    non_ascii = 0
    control_chars = 0

    for c in text:
        code = ord(c)
        if 32 <= code <= 126:
            ascii_printable += 1
        elif code in (9, 10, 13):
            ascii_printable += 1
        elif code < 32:
            control_chars += 1
        else:
            non_ascii += 1

    total = len(text)
    ascii_ratio = ascii_printable / total
    non_ascii_ratio = non_ascii / total
    control_ratio = control_chars / total

    # 包含PHP/Shell关键字且ASCII比例够高的
    if ascii_ratio > 0.80 and non_ascii_ratio < 0.05 and control_ratio < 0.05:
        keywords = ['eval', 'exec', 'system', 'shell', 'cmd', 'base64', 'php',
                    'class', 'function', 'return', 'echo', 'print', '<?', '?>',
                    'error_reporting', 'ini_set', 'assert', 'preg_replace',
                    'file_get_contents', 'file_put_contents', 'fopen', 'fwrite']
        text_lower = text.lower()
        for kw in keywords:
            if kw in text_lower:
                return True

    # 解密后的代码基本都是ASCII
    if ascii_ratio > 0.95 and non_ascii_ratio < 0.03 and control_ratio < 0.02:
        return True

    return False


def extract_raw_payload(request_body: str) -> str:
    """提取请求载荷用于显示"""
    if not request_body:
        return ""

    # URL解码
    decoded = safe_url_decode(request_body)

    # 如果太长，截断
    if len(decoded) > 2000:
        return decoded[:2000] + "\n... (truncated)"

    return decoded


def safe_decode(data: Any, encoding: str = 'utf-8') -> Optional[str]:
    """bytes/其他类型安全转str"""
    if data is None:
        return None
    if isinstance(data, bytes):
        return data.decode(encoding, errors='ignore')
    return str(data)


def safe_hex_to_string(hex_data: Any) -> Optional[str]:
    """十六进制转字符串"""
    if hex_data is None:
        return None
    try:
        result = hex_to_string(hex_data)
        return result if result else None
    except Exception as e:
        logger.debug(f"Hex转换失败: {e}")
        return None


def safe_url_decode(data: str, max_iterations: int = None) -> str:
    """URL解码，支持多层嵌套"""
    if not data:
        return data

    if max_iterations is None:
        max_iterations = DetectionConfig.MAX_URL_DECODE_ITERATIONS

    try:
        decoded = data
        for _ in range(max_iterations):
            new_decoded = unquote(decoded)
            if new_decoded == decoded:
                break
            decoded = new_decoded
        return decoded
    except Exception as e:
        logger.debug(f"URL解码失败: {e}")
        return data


def is_valid_base64_relaxed(s: str) -> bool:
    """宽松Base64格式验证，支持无padding和URL安全变体"""
    if not s or len(s) < 4:
        return False

    # 清理和标准化
    s = s.strip()
    s = s.replace('-', '+').replace('_', '/')
    s = re.sub(r'\s', '', s)

    if not re.match(r'^[A-Za-z0-9+/]*=*$', s):
        return False

    # 补齐padding
    padding_needed = (4 - len(s) % 4) % 4
    s_padded = s + '=' * padding_needed

    try:
        base64.b64decode(s_padded, validate=True)
        return True
    except Exception:
        return False


def try_base64_decode(s: str) -> Optional[str]:
    """Base64解码，支持无padding和URL安全"""
    if not s or len(s) < 4:
        return None
    try:
        s = s.strip()
        s = s.replace('-', '+').replace('_', '/')
        s = re.sub(r'\s', '', s)

        # 补齐padding
        padding_needed = (4 - len(s) % 4) % 4
        s_padded = s + '=' * padding_needed

        decoded = base64.b64decode(s_padded)
        try:
            return decoded.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            decoded_str = decoded.decode('utf-8', errors='ignore')
            if len(decoded_str) < len(decoded) * 0.8:
                return None
            return decoded_str
    except Exception:
        return None


def try_base64_decode_with_prefix(value: str, prefix_lengths: List[int] = None) -> List[Dict]:
    """跳过不同长度前缀尝试Base64解码，蚁剑会在Base64前加随机前缀"""
    if prefix_lengths is None:
        prefix_lengths = DetectionConfig.BASE64_PREFIX_LENGTHS

    results = []
    for prefix_len in prefix_lengths:
        if len(value) <= prefix_len + 4:  # 至少需要4个字符的base64
            continue

        candidate = value[prefix_len:]
        decoded = try_base64_decode(candidate)

        if decoded and is_meaningful_content(decoded):
            results.append({
                'prefix_len': prefix_len,
                'prefix': value[:prefix_len] if prefix_len > 0 else '',
                'decoded': decoded
            })

    return results


def try_hex_decode(s: str) -> Optional[str]:
    """十六进制字符串解码"""
    if not s:
        return None

    # 清理分隔符
    s_clean = re.sub(r'[:\s-]', '', s)

    # 验证格式
    if not re.match(r'^[0-9a-fA-F]+$', s_clean):
        return None
    if len(s_clean) % 2 != 0:
        return None
    if len(s_clean) < 4:
        return None

    try:
        decoded = bytes.fromhex(s_clean)
        try:
            return decoded.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            decoded_str = decoded.decode('utf-8', errors='ignore')
            if len(decoded_str) < len(decoded) * 0.8:
                return None
            return decoded_str
    except Exception:
        return None


def is_meaningful_content(content: str) -> bool:
    """判断解码内容是否有意义(过滤乱码)"""
    if not content or len(content.strip()) < 3:
        return False

    # 计算可打印字符比例
    printable_count = sum(1 for c in content if 32 <= ord(c) <= 126 or c in '\r\n\t')
    ratio = printable_count / len(content) if len(content) > 0 else 0

    if ratio < 0.65:
        return False

    # 有意义的关键词列表
    meaningful_keywords = [
        # 系统命令
        'cd ', 'ls', 'dir', 'cat ', 'echo', 'whoami', 'pwd', 'type ',
        'net ', 'ipconfig', 'ifconfig', 'ping ', 'curl ', 'wget ',
        'chmod', 'chown', 'mkdir', 'rmdir', 'cp ', 'mv ', 'rm ',
        'ps ', 'kill', 'top', 'df ', 'du ', 'grep', 'find ',
        # 代码特征
        '<?php', '<%', 'function', 'class ', 'import ', 'require',
        'include', 'eval', 'exec', 'system', 'shell_exec', 'passthru',
        # SQL关键词
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE',
        'UNION', 'DROP', 'CREATE', 'ALTER', 'TRUNCATE',
        # 文件路径特征
        '/', '\\', '.php', '.asp', '.jsp', '.txt', '.log', '.conf',
        '/etc/', '/var/', '/tmp/', 'C:\\', 'D:\\',
        # 其他
        'cmd', 'shell', 'popen', 'proc_open',
    ]

    content_lower = content.lower()
    has_keyword = any(kw.lower() in content_lower for kw in meaningful_keywords)

    return has_keyword or ratio > 0.85


def is_valid_param_name(key: str) -> bool:
    """过滤明显无效的参数名"""
    if not key:
        return False
    if len(key) > DetectionConfig.MAX_PARAM_NAME_LENGTH:
        return False

    # multipart分隔符
    if key.startswith('-----'):
        return False

    # 无效模式
    invalid_patterns = [
        r'^[\s;"\'\(\)\{\}<>=]+$',  # 纯特殊字符
        r'Content-Disposition',
        r'Content-Type',
        r'boundary=',
    ]

    for pattern in invalid_patterns:
        if re.search(pattern, key, re.IGNORECASE):
            return False

    return True


def identify_payload_type(param_name: str, decoded_content: str) -> str:
    """根据解码内容判断payload用途"""
    if not decoded_content:
        return 'Unknown'

    dc = decoded_content.lower()

    # 命令执行模式
    cmd_patterns = [
        (r'^\s*cd\s+[\'"]?[/\\]', 'Command (cd)'),
        (r'\b(whoami|id|pwd|hostname)\b', 'Command (Info Gathering)'),
        (r'\b(ls|dir|find|type|cat|head|tail)\s', 'Command (File Listing)'),
        (r'\b(net\s+user|ipconfig|ifconfig|netstat)\b', 'Command (Network)'),
        (r'echo\s*\[S\]|echo\s*\[E\]', 'Command (AntSword Marker)'),
        (r'\b(rm|del|rmdir|mkdir|mv|cp|copy)\s', 'Command (File Operation)'),
        (r'\b(wget|curl|nc|ncat)\s', 'Command (Download/Connect)'),
        (r'\b(chmod|chown|chgrp)\s', 'Command (Permission)'),
    ]

    for pattern, ptype in cmd_patterns:
        if re.search(pattern, dc, re.IGNORECASE):
            return ptype

    # 路径
    if re.search(r'^[a-zA-Z]:\\|^/', decoded_content.strip()):
        return 'Argument (Path)'

    # PHP代码
    if re.search(r'<\?php|\$_|function\s+\w+\s*\(|class\s+\w+', dc):
        return 'PHP Code'

    # ASP代码
    if re.search(r'<%|response\.write|request\.form|server\.mappath', dc):
        return 'ASP Code'

    # JSP代码
    if re.search(r'<%@|request\.getParameter|runtime\.exec|processbuilder', dc):
        return 'JSP Code'

    return 'Argument (Data)'


def pair_http_requests_responses(packets: List) -> List[Dict]:
    """把同一会话的请求和响应配对，用(src/dst IP+端口+TCP流ID)做key"""
    paired_packets = []
    request_queue = {}

    for packet in packets:
        if not hasattr(packet, 'http'):
            continue

        http_layer = packet.http

        src_ip = getattr(packet.ip, 'src', None) if hasattr(packet, 'ip') else None
        dst_ip = getattr(packet.ip, 'dst', None) if hasattr(packet, 'ip') else None
        src_port = getattr(packet.tcp, 'srcport', None) if hasattr(packet, 'tcp') else None
        dst_port = getattr(packet.tcp, 'dstport', None) if hasattr(packet, 'tcp') else None
        stream_id = getattr(packet.tcp, 'stream', None) if hasattr(packet, 'tcp') else None

        if hasattr(http_layer, 'request_method'):  # 请求包
            key = (src_ip, dst_ip, src_port, dst_port, stream_id)
            request_queue[key] = {'packet': packet, 'response': None}
        else:  # 响应包
            key = (dst_ip, src_ip, dst_port, src_port, stream_id)
            if key in request_queue:
                request_queue[key]['response'] = packet

    paired_packets = list(request_queue.values())
    return paired_packets


def _get_request_body(http_layer) -> Optional[str]:
    """从HTTP层取请求体"""
    if not hasattr(http_layer, 'file_data'):
        return None

    request_body = safe_decode(http_layer.file_data)
    hex_converted = safe_hex_to_string(http_layer.file_data)
    if hex_converted:
        request_body = hex_converted

    return request_body


def _get_response_body(response_packet) -> Optional[str]:
    """从响应包取响应体"""
    if not response_packet or not hasattr(response_packet, 'http'):
        return None

    http_layer = response_packet.http
    if not hasattr(http_layer, 'file_data'):
        return None

    response_body = safe_decode(http_layer.file_data)
    hex_converted = safe_hex_to_string(http_layer.file_data)
    if hex_converted:
        response_body = hex_converted

    return response_body


def _is_readable_text(text: str) -> bool:
    """检查文本是否可读，用于响应显示判断"""
    if not text or len(text) < 5:
        return True

    ascii_printable = 0
    non_ascii = 0
    control_chars = 0

    for c in text:
        code = ord(c)
        if 32 <= code <= 126:
            ascii_printable += 1
        elif code in (9, 10, 13):
            ascii_printable += 1
        elif code < 32:
            control_chars += 1
        else:
            non_ascii += 1

    total = len(text)
    ascii_ratio = ascii_printable / total
    non_ascii_ratio = non_ascii / total
    control_ratio = control_chars / total

    # ASCII可打印超过90%就算可读
    return ascii_ratio > 0.90 and non_ascii_ratio < 0.05 and control_ratio < 0.05


def format_response_for_display(response_body: str) -> str:
    """格式化响应体，乱码就返回提示"""
    if not response_body:
        return ""

    if _is_readable_text(response_body):
        return response_body

    # 不可读，返回提示
    return f"[加密/二进制数据, 长度: {len(response_body)} 字节]"


def parse_request_params(body_str: str) -> Dict[str, str]:
    """解析HTTP请求参数，支持urlencoded和multipart"""
    params = {}

    if not body_str:
        return params

    # 检测是否是multipart
    is_multipart = ('Content-Disposition: form-data' in body_str or
                    re.search(r'^------', body_str, re.MULTILINE))

    if is_multipart:
        # multipart解析
        multipart_pattern = re.compile(
            r'name="([^"]+)"(?:[^\r\n]*)\r?\n\r?\n(.*?)(?=\r?\n------|\Z)',
            re.DOTALL
        )
        matches = multipart_pattern.findall(body_str)
        for key, val in matches:
            key = key.strip()
            val = val.strip()
            if is_valid_param_name(key):
                params[key] = val
    else:
        # URL编码表单解析
        pairs = re.split(r'&(?![^=]*;)', body_str)  # 避免分割URL编码中的&
        for pair in pairs:
            if '=' in pair:
                key, val = pair.split('=', 1)
                key = key.strip()
                if is_valid_param_name(key):
                    params[key] = val

    return params


def analyze_params(params: Dict[str, str]) -> Dict[str, Dict]:
    """对每个参数尝试多种解码(URL/Base64/Hex/双层)，识别payload"""
    decoded_payloads = {}

    for key, val in params.items():
        # 跳过太短或太长的值
        if len(val) < DetectionConfig.MIN_PARAM_VALUE_LENGTH:
            continue
        if len(val) > DetectionConfig.MAX_PARAM_VALUE_LENGTH:
            continue

        val_clean = val.strip()

        # 蚁剑核心特征直接明文匹配
        if re.search(r'@ini_set\s*\(\s*["\']display_errors', val_clean):
            decoded_payloads[key] = {
                'type': 'PHP_Code (Shell Core)',
                'method': 'Plaintext',
                'content': 'AntSword Shell Signature Detected',
                'sample': val_clean[:200]
            }
            continue

        # 尝试各种解码
        decoded_content = None
        decode_method = None

        # URL解码
        url_decoded = safe_url_decode(val_clean)

        # Base64解码(多前缀)
        base64_results = try_base64_decode_with_prefix(url_decoded)
        if base64_results:
            best = min(base64_results, key=lambda x: x['prefix_len'])
            decoded_content = best['decoded']
            if best['prefix_len'] > 0:
                decode_method = f"Base64 (prefix={best['prefix_len']}, value='{best['prefix']}')"
            else:
                decode_method = "Base64"

        # 十六进制解码
        if not decoded_content:
            hex_decoded = try_hex_decode(url_decoded)
            if hex_decoded and is_meaningful_content(hex_decoded):
                decoded_content = hex_decoded
                decode_method = "Hex"

        # 双层Base64
        if not decoded_content and base64_results:
            for br in base64_results:
                inner_decoded = try_base64_decode(br['decoded'])
                if inner_decoded and is_meaningful_content(inner_decoded):
                    decoded_content = inner_decoded
                    decode_method = "Double Base64"
                    break

        # 保存结果
        if decoded_content:
            param_type = identify_payload_type(key, decoded_content)
            decoded_payloads[key] = {
                'type': param_type,
                'method': decode_method,
                'encoded_sample': val_clean[:50] + '...' if len(val_clean) > 50 else val_clean,
                'decoded': decoded_content[:500] if len(decoded_content) > 500 else decoded_content
            }

    return decoded_payloads


class FeatureMatcher:
    """特征匹配引擎"""

    @staticmethod
    def match_indicators(content: str, indicators: List[Dict]) -> Tuple[List[Dict], int]:
        """匹配特征列表，返回(匹配结果, 总权重)"""
        if not content:
            return [], 0

        matches = []
        total_weight = 0
        matched_names = set()

        for indicator in indicators:
            pattern = indicator['pattern']
            name = indicator['name']
            flags = indicator.get('flags', 0)

            # 跳过已匹配的
            if name in matched_names:
                continue

            try:
                match = re.search(pattern, content, flags | re.IGNORECASE)
                if match:
                    matches.append({
                        'name': name,
                        'pattern': pattern,
                        'weight': indicator['weight'],
                        'matched_text': match.group(0)[:50],
                        'description': indicator.get('description', '')
                    })
                    total_weight += indicator['weight']
                    matched_names.add(name)
            except re.error as e:
                logger.warning(f"正则表达式错误 [{pattern}]: {e}")

        return matches, total_weight

    @staticmethod
    def check_suspicious_params(params: Dict[str, str]) -> List[Dict]:
        """检查可疑参数名"""
        suspicious = []

        for name, value in params.items():
            name_lower = name.lower()

            # 跳过白名单
            if name_lower in DetectionConfig.PARAM_NAME_WHITELIST:
                continue

            for pattern, weight, desc, description in DetectionConfig.SUSPICIOUS_PARAM_PATTERNS:
                if re.match(pattern, name, re.IGNORECASE):
                    suspicious.append({
                        'param_name': name,
                        'pattern': pattern,
                        'weight': weight,
                        'name': desc,
                        'description': description
                    })
                    break  # 每个参数只匹配一个模式

        return suspicious

    @staticmethod
    def calculate_confidence(total_weight: int, include_suspicious: bool = True) -> str:
        """根据总权重算置信度: high/medium/low/suspicious/none"""
        if total_weight >= DetectionConfig.HIGH_CONFIDENCE_THRESHOLD:
            return 'high'
        elif total_weight >= DetectionConfig.MEDIUM_CONFIDENCE_THRESHOLD:
            return 'medium'
        elif total_weight >= DetectionConfig.DETECTION_THRESHOLD:
            return 'low'
        elif include_suspicious and total_weight >= DetectionConfig.SUSPICIOUS_THRESHOLD:
            return 'suspicious'
        else:
            return 'none'


class WebShellDetector:
    """WebShell检测器，支持蚁剑/菜刀/冰蝎/哥斯拉"""

    def __init__(self):
        self.matcher = FeatureMatcher()
        self.stat_analyzer = StatisticalAnalyzer()
        self._behinder_keys = {}  # {uri: [extracted_keys]}
        self._behinder_sessions = {}
        self._godzilla_sessions = {}

        self._custom_behinder_keys: List[bytes] = []
        self._custom_godzilla_keys: List[str] = []

        # AST分析默认关闭，按需开启
        self.ast_engine = None
        self._ast_enabled = False

    def enable_ast(self, enabled: bool = True):
        """启用/禁用AST语义分析"""
        if enabled and self.ast_engine is None:
            try:
                try:
                    from ast_engine import PHPASTEngine
                except ImportError:
                    from core.ast_engine import PHPASTEngine
                self.ast_engine = PHPASTEngine()
                self._ast_enabled = True
                logger.info("AST 语义分析引擎已启用")
            except ImportError as e:
                logger.warning(f"AST 引擎不可用: {e}")
                self._ast_enabled = False
        else:
            self._ast_enabled = enabled

    def set_behinder_keys(self, keys: List[str]):
        """设置冰蝎自定义密钥"""
        self._custom_behinder_keys = []
        for key in keys:
            if isinstance(key, str):
                key_bytes = key.encode('utf-8')[:16].ljust(16, b'\x00')
                self._custom_behinder_keys.append(key_bytes)
            elif isinstance(key, bytes):
                self._custom_behinder_keys.append(key[:16].ljust(16, b'\x00'))
        logger.info(f"已设置 {len(self._custom_behinder_keys)} 个冰蝎自定义密钥")

    def set_godzilla_keys(self, keys: List[str]):
        """设置哥斯拉自定义密钥"""
        self._custom_godzilla_keys = list(keys)
        logger.info(f"已设置 {len(self._custom_godzilla_keys)} 个哥斯拉自定义密钥")

    def detect(self, packets: List, tools: List[str] = None, show_all_suspicious: bool = True) -> Dict:
        """统一检测入口，同一请求只保留权重最高的结果"""
        if tools is None:
            tools = ['antsword', 'caidao', 'behinder', 'godzilla']

        results = {
            'antsword': [],
            'caidao': [],
            'behinder': [],
            'godzilla': [],
            'suspicious': [],      # 统计学分析检测到的可疑流量
            'timeline': [],        # 完整攻击时间线
            'summary': {
                'total_detections': 0,
                'high_confidence': 0,
                'medium_confidence': 0,
                'low_confidence': 0,
                'suspicious_confidence': 0
            }
        }

        # 配对请求和响应
        paired_packets = pair_http_requests_responses(packets)

        # 冰蝎密钥协商检测(先扫一遍)
        if 'behinder' in tools:
            self._scan_behinder_handshakes(paired_packets)

        # 哥斯拉会话扫描(先扫一遍)
        if 'godzilla' in tools:
            self._scan_godzilla_sessions(paired_packets)

        # 已检测到的请求(去重用)
        detected_requests = {}

        packet_index = 0

        # 对每个包对进行检测
        for pkt_pair in paired_packets:
            packet = pkt_pair.get('packet')
            if not packet or not hasattr(packet, 'http'):
                continue

            packet_index += 1

            # 获取请求标识
            http_layer = packet.http
            method = getattr(http_layer, 'request_method', '') or ''
            uri = getattr(http_layer, 'request_full_uri', '') or ''
            request_key = (method, uri)

            # 收集检测结果
            all_detections = []

            if 'antsword' in tools:
                result = self._detect_antsword(pkt_pair, include_suspicious=show_all_suspicious)
                if result:
                    result['packet_index'] = packet_index
                    all_detections.append(('antsword', result))

            if 'caidao' in tools:
                result = self._detect_caidao(pkt_pair, include_suspicious=show_all_suspicious)
                if result:
                    result['packet_index'] = packet_index
                    all_detections.append(('caidao', result))

            if 'behinder' in tools:
                result = self._detect_behinder(pkt_pair, include_suspicious=show_all_suspicious)
                if result:
                    result['packet_index'] = packet_index
                    all_detections.append(('behinder', result))

            if 'godzilla' in tools:
                result = self._detect_godzilla(pkt_pair, include_suspicious=show_all_suspicious)
                if result:
                    result['packet_index'] = packet_index
                    all_detections.append(('godzilla', result))

            # 如果没有工具检测到，进行统计学分析
            if not all_detections and show_all_suspicious:
                stat_result = self._detect_statistical(pkt_pair)
                if stat_result:
                    stat_result['packet_index'] = packet_index
                    all_detections.append(('suspicious', stat_result))

            # 去重：取权重最高的
            if all_detections:
                # 按权重排序取最高
                all_detections.sort(key=lambda x: x[1].get('total_weight', 0), reverse=True)
                best_tool, best_result = all_detections[0]

                # 检查是否已经检测过同一请求
                if request_key in detected_requests:
                    prev_tool, prev_weight = detected_requests[request_key]
                    # 如果新的权重更高，替换旧的
                    if best_result.get('total_weight', 0) > prev_weight:
                        # 从旧工具结果中移除
                        results[prev_tool] = [
                            r for r in results[prev_tool]
                            if not (r.get('method') == method and r.get('uri') == uri)
                        ]
                        # 添加到新工具结果
                        results[best_tool].append(best_result)
                        detected_requests[request_key] = (best_tool, best_result.get('total_weight', 0))
                else:
                    # 新请求，直接添加
                    results[best_tool].append(best_result)
                    detected_requests[request_key] = (best_tool, best_result.get('total_weight', 0))

                # 添加到时间线
                results['timeline'].append({
                    'packet_index': packet_index,
                    'tool': best_tool,
                    'confidence': best_result.get('confidence', 'none'),
                    'weight': best_result.get('total_weight', 0),
                    'method': method,
                    'uri': uri,
                    'type': best_result.get('type', 'UNKNOWN')
                })

        # 按包序号排序时间线
        results['timeline'].sort(key=lambda x: x['packet_index'])

        # 统计
        for tool_name in ['antsword', 'caidao', 'behinder', 'godzilla', 'suspicious']:
            for result in results[tool_name]:
                results['summary']['total_detections'] += 1
                confidence = result.get('confidence', 'suspicious')
                if confidence in ['high', 'medium', 'low', 'suspicious']:
                    results['summary'][f'{confidence}_confidence'] += 1

        return results

    def _detect_antsword(self, pkt_pair: Dict, include_suspicious: bool = False) -> Optional[Dict]:
        """检测蚁剑"""
        packet = pkt_pair.get('packet')
        response_packet = pkt_pair.get('response')

        if not packet or not hasattr(packet, 'http'):
            return None

        try:
            http_layer = packet.http
            request_method = getattr(http_layer, 'request_method', None)
            request_uri = getattr(http_layer, 'request_full_uri', None)

            # 获取请求体和响应体
            request_body = _get_request_body(http_layer)
            response_body = _get_response_body(response_packet)

            # 初始化结果
            result = {
                'type': 'ANTSWORD_DETECTED',
                'method': request_method,
                'uri': request_uri,
                'indicators': [],
                'total_weight': 0,
                'confidence': 'none',
                'payloads': {},
                'raw_request_body': '',
                'response_indicators': []
            }

            # 请求包检测
            if request_body and request_method in DetectionConfig.SUPPORTED_METHODS:
                decoded_body = safe_url_decode(request_body)
                result['raw_request_body'] = extract_raw_payload(decoded_body)

                # 蚁剑特征匹配
                matches, weight = self.matcher.match_indicators(
                    decoded_body, DetectionConfig.ANTSWORD_INDICATORS)
                result['indicators'].extend(matches)
                result['total_weight'] += weight

                # 拆参数
                params = parse_request_params(decoded_body)

                # 可疑参数名
                suspicious = self.matcher.check_suspicious_params(params)
                for sp in suspicious:
                    result['indicators'].append(sp)
                    result['total_weight'] += sp['weight']

                # 解码参数值
                decoded_payloads = analyze_params(params)
                if decoded_payloads:
                    result['payloads'] = decoded_payloads
                    # 根据payload类型加权
                    for key, info in decoded_payloads.items():
                        ptype = info.get('type', '')
                        if 'Command' in ptype:
                            result['total_weight'] += 25
                        elif 'Code' in ptype:
                            result['total_weight'] += 20
                        else:
                            result['total_weight'] += 10

                    # AST分析减少误报
                    ast_adjustment = self._apply_ast_validation(result, decoded_payloads, 'AntSword')
                    result['total_weight'] += ast_adjustment

            # 响应包检测
            if response_body:
                resp_matches, resp_weight = self.matcher.match_indicators(
                    response_body, DetectionConfig.RESPONSE_INDICATORS)
                result['response_indicators'].extend(resp_matches)
                result['total_weight'] += resp_weight

                if resp_matches:
                    result['response_sample'] = format_response_for_display(response_body[:500])

            # 计算置信度
            result['confidence'] = self.matcher.calculate_confidence(result['total_weight'], include_suspicious)

            if result['confidence'] != 'none':
                logger.debug(f"[蚁剑] 置信度:{result['confidence']} 权重:{result['total_weight']} URI:{request_uri}")
                try:
                    burp_format_request(packet, http_layer)
                except Exception:
                    pass
                return result

            return None

        except Exception as e:
            logger.error(f"蚁剑检测异常: {e}", exc_info=True)
            return None

    def _detect_caidao(self, pkt_pair: Dict, include_suspicious: bool = False) -> Optional[Dict]:
        """检测菜刀"""
        packet = pkt_pair.get('packet')
        response_packet = pkt_pair.get('response')

        if not packet or not hasattr(packet, 'http'):
            return None

        try:
            http_layer = packet.http
            request_method = getattr(http_layer, 'request_method', None)
            request_uri = getattr(http_layer, 'request_full_uri', None)

            request_body = _get_request_body(http_layer)
            response_body = _get_response_body(response_packet)

            result = {
                'type': 'CAIDAO_DETECTED',
                'method': request_method,
                'uri': request_uri,
                'indicators': [],
                'total_weight': 0,
                'confidence': 'none',
                'payloads': {},
                'raw_request_body': '',
                'response_indicators': []
            }

            if request_body:
                decoded_body = safe_url_decode(request_body)
                result['raw_request_body'] = extract_raw_payload(decoded_body)

                # 菜刀专用特征
                matches, weight = self.matcher.match_indicators(
                    decoded_body, DetectionConfig.CAIDAO_INDICATORS)
                result['indicators'].extend(matches)
                result['total_weight'] += weight

                # 拆参数
                params = parse_request_params(decoded_body)

                # 提取z参数(z0包含@ini_set签名)
                z_pattern = r'([a-zA-Z_]\w*)=(QGluaV9zZXQ[A-Za-z0-9+/]*=*)'
                z_matches = re.findall(z_pattern, decoded_body)
                for param_name, b64_value in z_matches:
                    decoded = try_base64_decode(b64_value)
                    if decoded:
                        result['payloads'][param_name] = {
                            'type': 'PHP Code (Shell Core)',
                            'method': 'Base64',
                            'encoded_sample': b64_value[:50] + '...' if len(b64_value) > 50 else b64_value,
                            'decoded': decoded[:500],
                            'is_ini_signature': '@ini_set' in decoded
                        }
                        result['total_weight'] += 30

                # 解码所有参数(包括z1, z2等)
                decoded_payloads = analyze_params(params)
                for param_name, info in decoded_payloads.items():
                    # 跳过已处理的z0参数
                    if param_name in result['payloads']:
                        continue
                    result['payloads'][param_name] = info
                    # 根据payload类型加权
                    ptype = info.get('type', '')
                    if 'Command' in ptype:
                        result['total_weight'] += 20
                    elif 'Path' in ptype:
                        result['total_weight'] += 10

                # 通用PHP特征(权重减半)
                php_matches, php_weight = self.matcher.match_indicators(
                    decoded_body, DetectionConfig.ANTSWORD_INDICATORS)
                for m in php_matches:
                    m['weight'] = m['weight'] // 2
                result['indicators'].extend(php_matches)
                result['total_weight'] += php_weight // 2

                # AST分析
                if result['payloads']:
                    ast_adjustment = self._apply_ast_validation(result, result['payloads'], 'Caidao')
                    result['total_weight'] += ast_adjustment

            # 响应检测
            if response_body:
                resp_matches, resp_weight = self.matcher.match_indicators(
                    response_body, DetectionConfig.RESPONSE_INDICATORS)
                result['response_indicators'].extend(resp_matches)
                result['total_weight'] += resp_weight
                result['response_sample'] = format_response_for_display(response_body[:500])

            result['confidence'] = self.matcher.calculate_confidence(result['total_weight'], include_suspicious)

            if result['confidence'] != 'none':
                logger.debug(f"[菜刀] 置信度:{result['confidence']} 权重:{result['total_weight']} URI:{request_uri}")
                return result

            return None

        except Exception as e:
            logger.error(f"菜刀检测异常: {e}", exc_info=True)
            return None

    # 冰蝎密钥协商检测

    def _scan_behinder_handshakes(self, paired_packets: List[Dict]):
        """扫描冰蝎密钥协商握手包，提取AES密钥"""
        for pkt_pair in paired_packets:
            packet = pkt_pair.get('packet')
            response_packet = pkt_pair.get('response')

            if not packet or not hasattr(packet, 'http'):
                continue

            try:
                http_layer = packet.http
                method = getattr(http_layer, 'request_method', '') or ''
                uri = getattr(http_layer, 'request_full_uri', '') or ''

                # 检查是否是PHP/JSP/ASP文件
                uri_lower = uri.lower()
                if not re.search(r'\.(php|jsp|aspx?|jspx?)\b', uri_lower):
                    continue

                # 获取响应
                response_body = _get_response_body(response_packet)
                if not response_body:
                    continue

                # 冰蝎v3密钥协商通常是 GET 请求
                # 冰蝎v4也可能是POST请求带特定参数
                is_potential_handshake = False

                if method == 'GET':
                    # GET请求到shell文件 - 典型的v3密钥协商
                    is_potential_handshake = True
                elif method == 'POST':
                    # POST请求但响应很短（可能是密钥响应）
                    if len(response_body.strip()) <= 50:
                        is_potential_handshake = True
                    # 或者请求体为空/很短（初始探测）
                    request_body = _get_request_body(http_layer)
                    if not request_body or len(request_body.strip()) < 32:
                        is_potential_handshake = True

                if not is_potential_handshake:
                    continue

                # 提取可能的密钥
                extracted_key = self._extract_behinder_key(response_body)
                if extracted_key:
                    # 存储密钥，关联到URI
                    uri_base = uri.split('?')[0]
                    if uri_base not in self._behinder_keys:
                        self._behinder_keys[uri_base] = []
                    if extracted_key not in self._behinder_keys[uri_base]:
                        self._behinder_keys[uri_base].append(extracted_key)
                        logger.debug(f"[冰蝎] 提取到密钥: {extracted_key.hex()[:16]}... URI: {uri_base}")

            except Exception as e:
                logger.debug(f"冰蝎握手扫描异常: {e}")
                continue

    def _extract_behinder_key(self, response_body: str) -> Optional[bytes]:
        """从响应中提取冰蝎密钥(16字节/Base64/Hex/JSON)"""
        if not response_body:
            return None

        body = response_body.strip()

        # 跳过HTML响应
        if body.startswith('<') and ('<!DOCTYPE' in body or '<html' in body.lower()):
            return None

        # 正好16字节
        if len(body) == 16:
            try:
                return body.encode('latin-1')
            except Exception:
                pass

        # Base64编码的16字节密钥
        if 20 <= len(body) <= 30 and self._is_pure_base64(body):
            try:
                decoded = base64.b64decode(body)
                if len(decoded) == 16:
                    return decoded
            except Exception:
                pass

        # 32字符十六进制
        if len(body) == 32 and re.match(r'^[a-fA-F0-9]+$', body):
            try:
                return bytes.fromhex(body)
            except Exception:
                pass

        # 短响应体中提取
        if len(body) < 50:
            # 提取16字节Base64
            clean = re.sub(r'[^A-Za-z0-9+/=]', '', body)
            if 20 <= len(clean) <= 30:
                try:
                    decoded = base64.b64decode(clean)
                    if len(decoded) == 16:
                        return decoded
                except Exception:
                    pass

            # 提取32字符hex
            hex_match = re.search(r'[a-fA-F0-9]{32}', body)
            if hex_match:
                try:
                    return bytes.fromhex(hex_match.group(0))
                except Exception:
                    pass

        # JSON响应中的密钥(v4)
        if len(body) < 200 and (body.startswith('{') or body.startswith('[')):
            try:
                import json
                data = json.loads(body)
                # 查找可能的密钥字段
                key_fields = ['key', 'k', 'secret', 'token', 'data']
                if isinstance(data, dict):
                    for field in key_fields:
                        if field in data:
                            val = data[field]
                            if isinstance(val, str):
                                # 尝试解析该字段
                                if len(val) == 16:
                                    return val.encode('latin-1')
                                elif len(val) == 32 and re.match(r'^[a-fA-F0-9]+$', val):
                                    return bytes.fromhex(val)
                                elif 20 <= len(val) <= 30:
                                    try:
                                        decoded = base64.b64decode(val)
                                        if len(decoded) == 16:
                                            return decoded
                                    except Exception:
                                        pass
            except Exception:
                pass

        # 响应体本身经过Base64编码
        if 20 <= len(body) <= 50:
            try:
                decoded = base64.b64decode(body)
                if len(decoded) == 16:
                    return decoded
                # 或者解码后是32字符hex
                if len(decoded) == 32:
                    decoded_str = decoded.decode('utf-8', errors='ignore')
                    if re.match(r'^[a-fA-F0-9]+$', decoded_str):
                        return bytes.fromhex(decoded_str)
            except Exception:
                pass

        return None

    def _get_behinder_keys_for_uri(self, uri: str) -> List[bytes]:
        """获取URI关联的冰蝎密钥(自定义+提取到的+默认)"""
        keys = []
        uri_base = uri.split('?')[0] if uri else ''

        if self._custom_behinder_keys:
            keys.extend(self._custom_behinder_keys)

        if uri_base in self._behinder_keys:
            keys.extend(self._behinder_keys[uri_base])

        keys.extend(DetectionConfig.BEHINDER_DEFAULT_KEYS)

        return keys

    def _detect_behinder(self, pkt_pair: Dict, include_suspicious: bool = False) -> Optional[Dict]:
        """检测冰蝎，多维度流量特征分析"""
        packet = pkt_pair.get('packet')
        response_packet = pkt_pair.get('response')

        if not packet or not hasattr(packet, 'http'):
            return None

        try:
            http_layer = packet.http
            request_method = getattr(http_layer, 'request_method', None)
            request_uri = getattr(http_layer, 'request_full_uri', None) or ''

            # 冰蝎主要使用POST
            if request_method not in ('POST', 'PUT'):
                return None

            request_body = _get_request_body(http_layer)
            response_body = _get_response_body(response_packet)

            result = {
                'type': 'BEHINDER_DETECTED',
                'method': request_method,
                'uri': request_uri,
                'indicators': [],
                'total_weight': 0,
                'confidence': 'none',
                'payloads': {},
                'raw_request_body': '',
                'response_indicators': []
            }

            if not request_body or len(request_body.strip()) < 16:
                return None

            decoded_body = safe_url_decode(request_body)
            body_stripped = decoded_body.strip()
            result['raw_request_body'] = extract_raw_payload(decoded_body)

            # 冰蝎4首包模式检测
            for pattern in DetectionConfig.BEHINDER4_FIRST_REQUEST_PATTERNS:
                if body_stripped.startswith(pattern) or pattern in body_stripped:
                    result['indicators'].append({
                        'name': 'behinder4_first_request',
                        'weight': 90,
                        'description': '冰蝎4默认密钥首包特征(解密为@error_reporting(0);)',
                        'matched_text': body_stripped[:50] + '...'
                    })
                    result['total_weight'] += 90
                    break

            # 冰蝎内容特征匹配
            matches, weight = self.matcher.match_indicators(
                decoded_body, DetectionConfig.BEHINDER_INDICATORS)
            result['indicators'].extend(matches)
            result['total_weight'] += weight

            # 流量层特征分析

            # 纯Base64?
            is_pure_base64 = self._is_pure_base64(body_stripped)
            if is_pure_base64:
                result['indicators'].append({
                    'name': 'pure_base64_body',
                    'weight': 45,
                    'description': '纯Base64请求体(无参数分隔符)',
                    'matched_text': body_stripped[:50] + '...'
                })
                result['total_weight'] += 45

            # 熵值检测
            body_entropy = self._calculate_entropy(body_stripped)
            if body_entropy > 4.5:
                ent_weight = 40 if body_entropy > 5.5 else 25
                result['indicators'].append({
                    'name': 'high_entropy_body',
                    'weight': ent_weight,
                    'description': f'高熵值请求体(entropy={body_entropy:.2f}, 加密数据特征)',
                    'matched_text': f'entropy={body_entropy:.2f}'
                })
                result['total_weight'] += ent_weight

            # AES块对齐检查
            if is_pure_base64:
                try:
                    raw_bytes = base64.b64decode(body_stripped)
                    if len(raw_bytes) >= 16 and len(raw_bytes) % 16 == 0:
                        result['indicators'].append({
                            'name': 'aes_block_aligned',
                            'weight': 35,
                            'description': f'数据长度{len(raw_bytes)}字节, 是16的倍数(AES块对齐)',
                            'matched_text': f'len={len(raw_bytes)}, blocks={len(raw_bytes)//16}'
                        })
                        result['total_weight'] += 35
                except Exception:
                    pass

            # 无可读参数?
            has_form_params = '&' in body_stripped and '=' in body_stripped
            if not has_form_params and len(body_stripped) > 32:
                result['indicators'].append({
                    'name': 'no_readable_params',
                    'weight': 30,
                    'description': '无可读参数名(加密流量特征)',
                    'matched_text': 'no & or = delimiters'
                })
                result['total_weight'] += 30

            # URI是否指向脚本
            uri_lower = request_uri.lower()
            if re.search(r'\.(php|jsp|aspx?|jspx?)\b', uri_lower):
                result['indicators'].append({
                    'name': 'post_to_php',
                    'weight': 20,
                    'description': f'POST请求到脚本文件',
                    'matched_text': request_uri.split('?')[0][-30:]
                })
                result['total_weight'] += 20

            # 短URI+大Body
            uri_path = request_uri.split('?')[0] if request_uri else ''
            if len(uri_path) < 50 and len(body_stripped) > 200:
                result['indicators'].append({
                    'name': 'small_uri_large_body',
                    'weight': 25,
                    'description': f'短URI({len(uri_path)}字符)+大请求体({len(body_stripped)}字符)',
                    'matched_text': f'uri_len={len(uri_path)}, body_len={len(body_stripped)}'
                })
                result['total_weight'] += 25

            # HTTP头特征
            behinder_header_weight = self._check_behinder_headers(http_layer)
            if behinder_header_weight > 0:
                result['indicators'].append({
                    'name': 'behinder_headers',
                    'weight': behinder_header_weight,
                    'description': '冰蝎HTTP头特征',
                    'matched_text': 'suspicious headers combination'
                })
                result['total_weight'] += behinder_header_weight

            # 尝试AES解密
            uri_keys = self._get_behinder_keys_for_uri(request_uri)
            uri_base = request_uri.split('?')[0] if request_uri else ''

            # 检测到密钥协商握手
            if uri_base in self._behinder_keys:
                extracted_keys_count = len(self._behinder_keys[uri_base])
                result['indicators'].append({
                    'name': 'behinder_v3_handshake',
                    'weight': 60,
                    'description': f'检测到冰蝎密钥协商(提取到{extracted_keys_count}个密钥)',
                    'matched_text': f'{extracted_keys_count} keys extracted from handshake'
                })
                result['total_weight'] += 60

            if is_pure_base64 or (not has_form_params and len(body_stripped) > 32):
                decrypt_data = body_stripped
                decrypt_result = try_decrypt_behinder(decrypt_data, uri_keys)
                if decrypt_result:
                    result['payloads']['body'] = {
                        'type': 'Encrypted Command',
                        'method': decrypt_result['method'],
                        'encoded_sample': decrypt_data[:50] + '...',
                        'decoded': decrypt_result['decrypted'][:500],
                        'key_used': decrypt_result['key']
                    }
                    # 解密成功是强指标
                    result['indicators'].append({
                        'name': 'behinder_decrypt_success',
                        'weight': 80,
                        'description': f'成功用默认密钥解密(key={decrypt_result["key"][:8]}...)',
                        'matched_text': decrypt_result['decrypted'][:50]
                    })
                    result['total_weight'] += 80
                else:
                    # 无法解密，保留原始数据
                    if is_pure_base64 and body_entropy > 5.0:
                        result['payloads']['body'] = {
                            'type': 'Encrypted Data (AES)',
                            'method': 'AES-128-CBC (无法解密)',
                            'raw_data': decrypt_data[:200] + ('...' if len(decrypt_data) > 200 else ''),
                            'note': '原始加密数据，需要正确的shell密钥才能解密'
                        }
            else:
                # 有参数形式的请求体，逐参数尝试
                params = parse_request_params(decoded_body)
                for param_name, param_value in params.items():
                    if len(param_value) > 20 and self._is_pure_base64(param_value.strip()):
                        decrypt_result = try_decrypt_behinder(param_value, uri_keys)
                        if decrypt_result:
                            result['payloads'][param_name] = {
                                'type': 'Encrypted Command',
                                'method': decrypt_result['method'],
                                'encoded_sample': param_value[:50] + '...',
                                'decoded': decrypt_result['decrypted'][:500],
                                'key_used': decrypt_result['key']
                            }
                            result['indicators'].append({
                                'name': 'behinder_decrypt_success',
                                'weight': 80,
                                'description': f'参数{param_name}解密成功',
                                'matched_text': decrypt_result['decrypted'][:50]
                            })
                            result['total_weight'] += 80

            # 响应包分析
            if response_body:
                resp_body_stripped = response_body.strip()

                # 检查响应是否加密
                resp_is_base64 = self._is_pure_base64(resp_body_stripped)
                resp_entropy = self._calculate_entropy(resp_body_stripped) if len(resp_body_stripped) > 16 else 0

                if resp_is_base64 and resp_entropy > 4.5:
                    result['indicators'].append({
                        'name': 'encrypted_response',
                        'weight': 40,
                        'description': f'响应体也是加密数据(entropy={resp_entropy:.2f})',
                        'matched_text': resp_body_stripped[:50] + '...'
                    })
                    result['total_weight'] += 40

                    # 双向加密 = 强指标
                    if is_pure_base64:
                        result['indicators'].append({
                            'name': 'bidirectional_encrypted',
                            'weight': 30,
                            'description': '双向加密通信(请求+响应均为加密数据)',
                            'matched_text': 'bidirectional encryption detected'
                        })
                        result['total_weight'] += 30
                elif resp_is_base64 and len(resp_body_stripped) > 32:
                    result['indicators'].append({
                        'name': 'response_base64',
                        'weight': 25,
                        'description': '响应体为Base64格式',
                        'matched_text': resp_body_stripped[:50] + '...'
                    })
                    result['total_weight'] += 25

                # 通用响应特征
                resp_matches, resp_weight = self.matcher.match_indicators(
                    response_body, DetectionConfig.RESPONSE_INDICATORS)
                result['response_indicators'] = resp_matches
                result['total_weight'] += resp_weight
                result['response_sample'] = format_response_for_display(response_body[:500])

            # AST分析
            if result['payloads']:
                ast_adjustment = self._apply_ast_validation(result, result['payloads'], 'Behinder')
                result['total_weight'] += ast_adjustment

            # 计算置信度
            result['confidence'] = self.matcher.calculate_confidence(result['total_weight'], include_suspicious)

            if result['confidence'] != 'none':
                logger.debug(f"[冰蝎] 置信度:{result['confidence']} 权重:{result['total_weight']} URI:{request_uri}")
                return result

            return None

        except Exception as e:
            logger.error(f"冰蝎检测异常: {e}", exc_info=True)
            return None

    # 冰蝎辅助函数

    @staticmethod
    def _is_pure_base64(data: str) -> bool:
        """检查是否纯Base64"""
        if not data or len(data) < 32:
            return False

        if '&' in data and '=' in data:
            if data.count('&') >= 1 and data.count('=') >= 2:
                return False

        clean = re.sub(r'\s', '', data)

        if not re.match(r'^[A-Za-z0-9+/=]+$', clean):
            return False

        # 验证Base64解码
        try:
            decoded = base64.b64decode(clean)
            return len(decoded) >= 16
        except Exception:
            return False

    @staticmethod
    def _calculate_entropy(data: str) -> float:
        """Shannon信息熵，加密数据>5.0，正常文本<4.5"""
        import math

        if not data:
            return 0.0

        freq = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1

        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    @staticmethod
    def _check_behinder_headers(http_layer) -> int:
        """检查冰蝎HTTP头特征"""
        weight = 0
        matched_features = 0

        # Content-Type检查
        content_type = getattr(http_layer, 'content_type', '') or ''

        # 冰蝎v3/v4 常用Content-Type
        if 'application/x-www-form-urlencoded' in content_type:
            weight += 10
            matched_features += 1

        # 冰蝎v4有时使用 application/octet-stream
        if 'application/octet-stream' in content_type:
            weight += 15
            matched_features += 1

        # 冰蝎4特征Accept头
        accept = getattr(http_layer, 'accept', '') or ''
        # 冰蝎4典型Accept头
        if 'application/json' in accept and 'text/javascript' in accept:
            weight += 25
            matched_features += 1
        elif accept == '*/*' or 'text/html' in accept:
            weight += 5

        # Accept-Language
        accept_language = getattr(http_layer, 'accept_language', '') or ''
        if 'zh-CN' in accept_language and 'en-US' in accept_language:
            weight += 15
            matched_features += 1

        # Accept-Encoding
        accept_encoding = getattr(http_layer, 'accept_encoding', '') or ''
        # 单独的gzip比较可疑
        if accept_encoding == 'gzip' or accept_encoding.strip() == 'gzip':
            weight += 15  # 单独的gzip是可疑的
            matched_features += 1
        elif 'gzip' in accept_encoding:
            weight += 5

        # Connection: Keep-Alive
        connection = getattr(http_layer, 'connection', '') or ''
        if 'keep-alive' in connection.lower():
            weight += 10
            matched_features += 1

        # Content-Length
        content_length = getattr(http_layer, 'content_length', '') or ''
        try:
            cl_value = int(content_length)
            if cl_value > 5000:
                weight += 20  # 非常大的请求体
                matched_features += 1
            elif cl_value > 2000:
                weight += 15
                matched_features += 1
            elif cl_value > 1000:
                weight += 10
                matched_features += 1
        except (ValueError, TypeError):
            pass

        # User-Agent
        user_agent = getattr(http_layer, 'user_agent', '') or ''
        behinder_uas = [
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'Mozilla/4.0 (compatible; MSIE 8.0;',
            'Mozilla/5.0 (Linux; U; Android 2.2;',
        ]
        for ua in behinder_uas:
            if ua in user_agent:
                weight += 20
                matched_features += 1
                break

        # Pragma/Cache-Control
        pragma = getattr(http_layer, 'pragma', '') or ''
        cache_control = getattr(http_layer, 'cache_control', '') or ''
        if 'no-cache' in pragma or 'no-cache' in cache_control:
            weight += 5

        # 多特征组合加权
        if matched_features >= 4:
            weight += 30  # 多特征组合强指标
        elif matched_features >= 3:
            weight += 15

        return weight

    # 哥斯拉会话扫描

    def _scan_godzilla_sessions(self, paired_packets: List[Dict]):
        """扫描哥斯拉响应特征(md5前16位+base64+md5后16位)"""
        for pkt_pair in paired_packets:
            packet = pkt_pair.get('packet')
            response_packet = pkt_pair.get('response')

            if not packet or not hasattr(packet, 'http'):
                continue

            try:
                http_layer = packet.http
                uri = getattr(http_layer, 'request_full_uri', '') or ''

                # 获取响应
                response_body = _get_response_body(response_packet)
                if not response_body:
                    continue

                uri_base = uri.split('?')[0]

                # 检查响应是否符合哥斯拉格式
                godzilla_resp = self._check_godzilla_response(response_body.strip())
                if godzilla_resp:
                    if uri_base not in self._godzilla_sessions:
                        self._godzilla_sessions[uri_base] = {
                            'has_godzilla_response': True,
                            'response_count': 0
                        }
                    self._godzilla_sessions[uri_base]['response_count'] += 1
                    logger.debug(f"[哥斯拉] 检测到特征响应 URI: {uri_base}")

            except Exception as e:
                logger.debug(f"哥斯拉会话扫描异常: {e}")
                continue

    def _is_godzilla_session(self, uri: str) -> bool:
        """检查URI是否已被标记为哥斯拉会话"""
        uri_base = uri.split('?')[0] if uri else ''
        return uri_base in self._godzilla_sessions

    def _detect_godzilla(self, pkt_pair: Dict, include_suspicious: bool = False) -> Optional[Dict]:
        """检测哥斯拉"""
        packet = pkt_pair.get('packet')
        response_packet = pkt_pair.get('response')

        if not packet or not hasattr(packet, 'http'):
            return None

        try:
            http_layer = packet.http
            request_method = getattr(http_layer, 'request_method', None)
            request_uri = getattr(http_layer, 'request_full_uri', None)

            request_body = _get_request_body(http_layer)
            response_body = _get_response_body(response_packet)

            result = {
                'type': 'GODZILLA_DETECTED',
                'method': request_method,
                'uri': request_uri,
                'indicators': [],
                'total_weight': 0,
                'confidence': 'none',
                'payloads': {},
                'raw_request_body': '',
                'response_indicators': []
            }

            # HTTP头特征
            header_weight = self._check_godzilla_headers(http_layer)
            if header_weight > 0:
                result['indicators'].append({
                    'name': 'godzilla_headers',
                    'weight': header_weight,
                    'description': '哥斯拉HTTP头特征',
                    'matched_text': 'Godzilla header patterns detected'
                })
                result['total_weight'] += header_weight

            # 已知哥斯拉会话加权
            if self._is_godzilla_session(request_uri):
                session_info = self._godzilla_sessions.get(request_uri.split('?')[0], {})
                resp_count = session_info.get('response_count', 0)
                result['indicators'].append({
                    'name': 'godzilla_known_session',
                    'weight': 50,
                    'description': f'已知哥斯拉会话(检测到{resp_count}个特征响应)',
                    'matched_text': f'{resp_count} Godzilla responses detected'
                })
                result['total_weight'] += 50

            # 请求体检测
            if request_body:
                decoded_body = safe_url_decode(request_body)
                body_stripped = decoded_body.strip()
                result['raw_request_body'] = extract_raw_payload(decoded_body)

                # 代码特征匹配
                matches, weight = self.matcher.match_indicators(
                    decoded_body, DetectionConfig.GODZILLA_INDICATORS)
                result['indicators'].extend(matches)
                result['total_weight'] += weight

                # 纯Base64请求体
                is_pure_base64 = self._is_pure_base64(body_stripped)
                if is_pure_base64:
                    body_len = len(body_stripped)
                    # 哥斯拉初始化请求通常较大
                    if body_len > 5000:
                        result['indicators'].append({
                            'name': 'godzilla_init_request',
                            'weight': 45,
                            'description': f'大型Base64请求体(可能是哥斯拉初始化, {body_len}字符)',
                            'matched_text': body_stripped[:50] + '...'
                        })
                        result['total_weight'] += 45
                    elif body_len > 500:
                        result['indicators'].append({
                            'name': 'godzilla_base64_body',
                            'weight': 30,
                            'description': f'Base64请求体({body_len}字符)',
                            'matched_text': body_stripped[:50] + '...'
                        })
                        result['total_weight'] += 30

                # 原始加密raw数据(大量不可见字符)
                content_type = getattr(http_layer, 'content_type', '') or ''
                if 'multipart/form-data' not in content_type.lower():
                    non_printable_ratio = self._calculate_non_printable_ratio(body_stripped)
                    if non_printable_ratio > 0.3 and len(body_stripped) > 100:
                        result['indicators'].append({
                            'name': 'godzilla_raw_encrypted',
                            'weight': 40,
                            'description': f'原始加密数据(不可见字符比例: {non_printable_ratio:.1%})',
                            'matched_text': f'{non_printable_ratio:.1%} non-printable chars'
                        })
                        result['total_weight'] += 40

                # 尝试解密哥斯拉载荷
                params = parse_request_params(decoded_body)
                for param_name, param_value in params.items():
                    if len(param_value) > 20:
                        decrypt_result = try_decrypt_godzilla(param_value, self._custom_godzilla_keys)
                        if decrypt_result:
                            result['payloads'][param_name] = {
                                'type': 'Encrypted Command',
                                'method': decrypt_result['method'],
                                'encoded_sample': param_value[:50] + '...' if len(param_value) > 50 else param_value,
                                'decoded': decrypt_result['decrypted'][:500],
                                'key_used': decrypt_result['key']
                            }
                            result['total_weight'] += 30  # 解密成功加权

                # 无参数时整体作为加密数据
                if not params and len(body_stripped) > 20:
                    decrypt_result = try_decrypt_godzilla(body_stripped, self._custom_godzilla_keys)
                    if decrypt_result:
                        result['payloads']['body'] = {
                            'type': 'Encrypted Command',
                            'method': decrypt_result['method'],
                            'encoded_sample': body_stripped[:50] + '...',
                            'decoded': decrypt_result['decrypted'][:500],
                            'key_used': decrypt_result['key']
                        }
                        result['total_weight'] += 30

            # 响应体检测(强特征)
            if response_body:
                resp_stripped = response_body.strip()

                # 哥斯拉响应格式
                godzilla_resp_match = self._check_godzilla_response(resp_stripped)
                if godzilla_resp_match:
                    result['indicators'].append({
                        'name': 'godzilla_response_format',
                        'weight': 90,
                        'description': '哥斯拉响应格式: md5前16位+base64+md5后16位',
                        'matched_text': f"前缀:{godzilla_resp_match['prefix']}, 后缀:{godzilla_resp_match['suffix']}"
                    })
                    result['total_weight'] += 90
                    result['response_sample'] = format_response_for_display(resp_stripped[:500])

                    # 解码中间的base64数据
                    if godzilla_resp_match['base64_data']:
                        try:
                            decoded_resp = base64.b64decode(godzilla_resp_match['base64_data'])
                            decoded_str = decoded_resp.decode('utf-8', errors='strict')
                            if _is_valid_decrypted(decoded_str):
                                result['payloads']['response'] = {
                                    'type': 'Godzilla Response',
                                    'method': 'md5+base64+md5',
                                    'encoded_sample': resp_stripped[:100],
                                    'decoded': decoded_str[:500]
                                }
                            else:
                                result['payloads']['response'] = {
                                    'type': 'Godzilla Response (Encrypted)',
                                    'method': 'md5+base64+md5',
                                    'raw_data': godzilla_resp_match['base64_data'][:100] + '...',
                                    'note': '响应数据可能经过二次加密'
                                }
                        except UnicodeDecodeError:
                            result['payloads']['response'] = {
                                'type': 'Godzilla Response (Binary)',
                                'method': 'md5+base64+md5',
                                'raw_data': godzilla_resp_match['base64_data'][:100] + '...',
                                'note': '响应数据为二进制格式'
                            }
                        except Exception:
                            pass

                # 通用响应特征
                resp_matches, resp_weight = self.matcher.match_indicators(
                    response_body, DetectionConfig.RESPONSE_INDICATORS)
                result['response_indicators'].extend(resp_matches)
                result['total_weight'] += resp_weight

                if not result.get('response_sample'):
                    result['response_sample'] = format_response_for_display(response_body[:500])

            # AST分析
            if result['payloads']:
                ast_adjustment = self._apply_ast_validation(result, result['payloads'], 'Godzilla')
                result['total_weight'] += ast_adjustment

            # 计算置信度
            result['confidence'] = self.matcher.calculate_confidence(result['total_weight'], include_suspicious)

            if result['confidence'] != 'none':
                logger.debug(f"[哥斯拉] 置信度:{result['confidence']} 权重:{result['total_weight']} URI:{request_uri}")
                return result

            return None

        except Exception as e:
            logger.error(f"哥斯拉检测异常: {e}", exc_info=True)
            return None

    # 哥斯拉辅助函数

    @staticmethod
    def _check_godzilla_headers(http_layer) -> int:
        """检查哥斯拉HTTP头特征(Java UA/JDK Accept/Cookie末尾分号)"""
        weight = 0
        matched_features = 0

        # User-Agent - Java默认UA
        user_agent = getattr(http_layer, 'user_agent', '') or ''
        if re.match(r'^Java/\d+\.\d+', user_agent):
            weight += 40
            matched_features += 1
        elif 'Java/' in user_agent:
            weight += 30
            matched_features += 1

        # Accept头
        accept = getattr(http_layer, 'accept', '') or ''
        jdk_accept_patterns = [
            r'text/html.*image/gif.*image/jpeg.*\*.*q=\.2',
            r'\*;\s*q=\.2.*\*/\*;\s*q=\.2',
            r'image/gif.*image/jpeg.*\*;',
        ]
        for pattern in jdk_accept_patterns:
            if re.search(pattern, accept, re.IGNORECASE):
                weight += 35
                matched_features += 1
                break

        # Cookie末尾分号(强特征)
        cookie = getattr(http_layer, 'cookie', '') or ''
        if cookie and cookie.rstrip().endswith(';'):
            weight += 60
            matched_features += 1

        # Content-Type
        content_type = getattr(http_layer, 'content_type', '') or ''
        if 'application/x-www-form-urlencoded' in content_type:
            weight += 10
            matched_features += 1
        elif 'application/octet-stream' in content_type:
            weight += 15
            matched_features += 1

        # Connection
        connection = getattr(http_layer, 'connection', '') or ''
        if 'keep-alive' in connection.lower():
            weight += 5

        # 组合特征加权
        if matched_features >= 3:
            weight += 25
        elif matched_features >= 2:
            weight += 10

        return weight

    @staticmethod
    def _check_godzilla_response(response_body: str) -> Optional[Dict]:
        """检查哥斯拉响应格式: md5前16位 + base64 + md5后16位"""
        if not response_body or len(response_body) < 36:
            return None

        body = response_body.strip()

        pattern = re.compile(
            r'^([0-9a-fA-F]{16})([\w+/]+={0,2})([0-9a-fA-F]{16})$'
        )
        match = pattern.match(body)

        if match:
            prefix = match.group(1)
            base64_data = match.group(2)
            suffix = match.group(3)

            # 验证中间是有效的base64
            try:
                base64.b64decode(base64_data)
                return {
                    'prefix': prefix,
                    'base64_data': base64_data,
                    'suffix': suffix
                }
            except Exception:
                pass

        # 尝试更宽松的匹配(可能有换行)
        body_clean = re.sub(r'\s', '', body)
        match = pattern.match(body_clean)

        if match:
            prefix = match.group(1)
            base64_data = match.group(2)
            suffix = match.group(3)

            try:
                base64.b64decode(base64_data)
                return {
                    'prefix': prefix,
                    'base64_data': base64_data,
                    'suffix': suffix
                }
            except Exception:
                pass

        return None

    @staticmethod
    def _calculate_non_printable_ratio(data: str) -> float:
        """不可见字符比例"""
        if not data:
            return 0.0

        non_printable = sum(1 for c in data if ord(c) < 32 or ord(c) > 126)
        return non_printable / len(data)

    def _apply_ast_validation(self, result: Dict, payloads: Dict, tool_name: str = '') -> int:
        """AST语义分析验证，检查污点传播和危险函数调用"""
        # AST 未启用
        if not self._ast_enabled or not self.ast_engine:
            return 0

        if not payloads:
            return 0

        total_adjustment = 0
        ast_analysis_results = []

        MAX_PAYLOADS = 3
        MAX_CODE_LENGTH = 5000
        payload_count = 0

        for param_name, payload_info in payloads.items():
            if payload_count >= MAX_PAYLOADS:
                break

            # 获取解码后的内容
            decoded_content = ''
            if isinstance(payload_info, dict):
                decoded_content = (
                    payload_info.get('decoded', '') or
                    payload_info.get('decoded_content', '') or
                    payload_info.get('decrypted', '')
                )
            elif isinstance(payload_info, str):
                decoded_content = payload_info

            # 跳过太短或太长的
            if not decoded_content or len(decoded_content) < 15:
                continue
            if len(decoded_content) > MAX_CODE_LENGTH:
                logger.debug(f"[{tool_name}][AST] 跳过过长代码 ({len(decoded_content)} > {MAX_CODE_LENGTH})")
                continue

            # 是否像PHP
            if not self._looks_like_php(decoded_content):
                continue

            payload_count += 1

            try:
                ast_result = self.ast_engine.analyze(decoded_content)

                if ast_result.findings or ast_result.dangerous_calls:
                    ast_analysis_results.append({
                        'param': param_name,
                        'obfuscation_score': ast_result.obfuscation_score,
                        'is_likely_webshell': ast_result.is_likely_webshell,
                        'dangerous_calls': [
                            {
                                'func': c.function_name,
                                'tainted': c.is_tainted,
                                'severity': c.severity
                            }
                            for c in ast_result.dangerous_calls
                        ],
                        'findings_count': len(ast_result.findings)
                    })

                total_adjustment += ast_result.confidence_adjustment

                for finding in ast_result.findings[:5]:
                    result['indicators'].append({
                        'name': f'ast_{finding.type}',
                        'weight': finding.severity,
                        'pattern': '',
                        'matched_text': finding.code_context[:50] if finding.code_context else '',
                        'description': f'[AST] {finding.description}'
                    })

                if ast_result.is_likely_webshell:
                    result['indicators'].append({
                        'name': 'ast_webshell_confirmed',
                        'weight': 40,
                        'pattern': '',
                        'matched_text': param_name,
                        'description': '[AST] 语义分析确认: 存在污点数据流入危险函数'
                    })
                    total_adjustment += 40

                logger.debug(
                    f"[{tool_name}][AST] 参数 {param_name}: "
                    f"调整={ast_result.confidence_adjustment}, "
                    f"危险调用={len(ast_result.dangerous_calls)}, "
                    f"混淆评分={ast_result.obfuscation_score:.2f}"
                )

            except Exception as e:
                logger.debug(f"[{tool_name}][AST] 分析异常 ({param_name}): {e}")
                continue

        # 存储AST分析结果
        if ast_analysis_results:
            result['ast_analysis'] = {
                'enabled': True,
                'results': ast_analysis_results,
                'total_adjustment': total_adjustment
            }

        return total_adjustment

    @staticmethod
    def _looks_like_php(content: str) -> bool:
        """快速判断是否像PHP代码"""
        if '<?php' in content.lower() or '<?=' in content:
            return True

        has_variable = '$' in content
        has_function_call = bool(re.search(r'\w+\s*\(', content))
        has_semicolon = ';' in content

        score = sum([has_variable, has_function_call, has_semicolon])
        return score >= 2

    # 统计学特征检测

    def _detect_statistical(self, pkt_pair: Dict) -> Optional[Dict]:
        """统计学特征检测，用于检测高度混淆/加密的免杀流量"""
        packet = pkt_pair.get('packet')
        response_packet = pkt_pair.get('response')

        if not packet or not hasattr(packet, 'http'):
            return None

        try:
            http_layer = packet.http
            request_method = getattr(http_layer, 'request_method', None)
            request_uri = getattr(http_layer, 'request_full_uri', None)

            # 只分析POST/PUT请求
            if request_method not in ('POST', 'PUT'):
                return None

            request_body = _get_request_body(http_layer)
            response_body = _get_response_body(response_packet)

            result = {
                'type': 'STATISTICAL_ANOMALY',
                'method': request_method,
                'uri': request_uri,
                'indicators': [],
                'total_weight': 0,
                'confidence': 'none',
                'payloads': {},
                'raw_request_body': '',
                'response_indicators': [],
                'statistical_analysis': {}
            }

            if not request_body or len(request_body.strip()) < 30:
                return None

            decoded_body = safe_url_decode(request_body)
            body_stripped = decoded_body.strip()
            result['raw_request_body'] = extract_raw_payload(decoded_body)

            # 排除multipart/form-data（文件上传）
            content_type = getattr(http_layer, 'content_type', '') or ''
            if 'multipart/form-data' in content_type.lower():
                return None

            # 统计学分析
            stat_result = self.stat_analyzer.analyze_http_body(body_stripped, content_type)
            result['statistical_analysis'] = stat_result
            result['indicators'].extend(stat_result.get('indicators', []))
            result['total_weight'] += stat_result.get('total_weight', 0)

            # 检查URI是否指向脚本文件
            uri_lower = (request_uri or '').lower()
            if re.search(r'\.(php|jsp|aspx?|jspx?|asp)\b', uri_lower):
                result['indicators'].append({
                    'name': 'post_to_script',
                    'weight': 15,
                    'description': 'POST请求到脚本文件',
                    'matched_text': request_uri.split('?')[0][-40:] if request_uri else ''
                })
                result['total_weight'] += 15

            # 响应体统计学分析
            if response_body and len(response_body.strip()) > 30:
                resp_stat = self.stat_analyzer.analyze(response_body.strip())
                if resp_stat.get('total_weight', 0) >= 30:
                    for ind in resp_stat.get('indicators', []):
                        ind['name'] = 'response_' + ind['name']
                        ind['description'] = '响应体: ' + ind['description']
                    result['response_indicators'].extend(resp_stat.get('indicators', []))
                    result['total_weight'] += resp_stat.get('total_weight', 0) // 2  # 响应体权重减半
                result['response_sample'] = format_response_for_display(response_body[:500])

            # 计算置信度
            if result['total_weight'] >= StatisticalConfig.HIGH_CONFIDENCE_THRESHOLD:
                result['confidence'] = 'high'
            elif result['total_weight'] >= StatisticalConfig.SUSPICIOUS_THRESHOLD:
                result['confidence'] = 'medium'
            elif result['total_weight'] >= StatisticalConfig.DETECTION_THRESHOLD:
                result['confidence'] = 'suspicious'
            else:
                result['confidence'] = 'none'

            # 只返回有意义的结果
            if result['confidence'] != 'none':
                logger.debug(f"[统计学] 置信度:{result['confidence']} 权重:{result['total_weight']} URI:{request_uri}")
                return result

            return None

        except Exception as e:
            logger.error(f"统计学检测异常: {e}", exc_info=True)
            return None


# 兼容旧接口

def antsword_php(packet_or_packets) -> List[Dict]:
    """蚁剑检测(兼容旧接口)"""
    detector = WebShellDetector()

    if isinstance(packet_or_packets, list):
        results = detector.detect(packet_or_packets, ['antsword'])
        return results['antsword']

    # 单个包
    pkt_pair = packet_or_packets if isinstance(packet_or_packets, dict) else {'packet': packet_or_packets, 'response': None}
    result = detector._detect_antsword(pkt_pair)
    return [result] if result else []


def caidao(packet_or_packets) -> List[Dict]:
    """菜刀检测(兼容旧接口)"""
    detector = WebShellDetector()

    if isinstance(packet_or_packets, list):
        results = detector.detect(packet_or_packets, ['caidao'])
        return results['caidao']

    pkt_pair = packet_or_packets if isinstance(packet_or_packets, dict) else {'packet': packet_or_packets, 'response': None}
    result = detector._detect_caidao(pkt_pair)
    return [result] if result else []


def detect_webshell(packets, tools=None) -> Dict:
    """统一检测入口(兼容旧接口)"""
    detector = WebShellDetector()
    return detector.detect(packets, tools)


def antsword_payload(body_str: str) -> Optional[Dict]:
    """提取蚁剑payload(兼容旧接口)"""
    if not body_str:
        return None

    try:
        params = parse_request_params(safe_url_decode(body_str))
        decoded_payloads = analyze_params(params)

        password_param = None
        command_param = None

        for key, info in decoded_payloads.items():
            if info.get('type') == 'PHP_Code (Shell Core)':
                password_param = key
            elif 'Command' in info.get('type', ''):
                command_param = key

        return {
            'payloads': decoded_payloads,
            'password_param': password_param,
            'command_param': command_param
        } if decoded_payloads else None

    except Exception as e:
        logger.error(f"提取payload异常: {e}")
        return None


def antsword_response(response_str: str) -> Optional[Dict]:
    """检测蚁剑响应(兼容旧接口)"""
    if not response_str:
        return None

    matches, weight = FeatureMatcher.match_indicators(
        response_str, DetectionConfig.RESPONSE_INDICATORS)

    if matches:
        return {
            'indicators': [m['name'] for m in matches],
            'weight': weight,
            'sample': response_str[:200],
            'details': matches
        }
    return None

# 其他旧接口
def is_valid_base64(s):
    return is_valid_base64_relaxed(s)

def try_b64_decode(s):
    return try_base64_decode(s)

def is_hex_string(s):
    if not s:
        return False
    s_clean = re.sub(r'[:\s-]', '', s)
    return bool(re.match(r'^[0-9a-fA-F]+$', s_clean)) and len(s_clean) >= 4

def is_valid_decoded_content(content):
    return is_meaningful_content(content)

def identify_parameter_type(param_name, decoded_content):
    return identify_payload_type(param_name, decoded_content)

def caidao_decode(z_value):
    if not z_value:
        return None
    decoded = try_base64_decode(z_value)
    if decoded:
        return {
            'method': 'Base64',
            'decoded_content': decoded[:500],
            'is_ini_signature': '@ini_set' in decoded
        }
    return {'error': 'Base64解码失败'}

def caidao_payload_decode(body_str):
    if not body_str:
        return None
    decoded_payloads = []
    url_parts = re.findall(r'(?:[^&\s]+=)?[^&\s]*%[0-9A-Fa-f]{2}[^&\s]*', body_str)
    for part in url_parts:
        url_decoded = safe_url_decode(part)
        b64_matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', url_decoded)
        for b64 in b64_matches:
            decoded = try_base64_decode(b64)
            if decoded and is_meaningful_content(decoded):
                decoded_payloads.append({
                    'url_encoded_sample': part[:50],
                    'base64_encoded': b64[:50],
                    'decoded_content': decoded[:200]
                })
    return decoded_payloads if decoded_payloads else None

def extract_response_data_from_packet(http_layer):
    if not http_layer:
        return None
    if hasattr(http_layer, 'file_data'):
        temp_data = http_layer.file_data
        if ":" in str(temp_data):
            raw_hex = str(temp_data).replace(':', '')
            return try_hex_decode(raw_hex)
        return safe_decode(temp_data)
    return None
