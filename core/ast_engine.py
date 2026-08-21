# ast_engine.py - PHP AST引擎
# 词法分析 + 语法分析 + 污点追踪

import re
import base64
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any, Union

try:
    from core.semantic_decoder import (
        DecodeBudget, OBFUSCATION_DECODERS, decode_by_name, is_decoder,
        looks_like_code as decoded_looks_like_code,
    )
except ImportError:  # 允许脚本方式直接跑
    try:
        from semantic_decoder import (
            DecodeBudget, OBFUSCATION_DECODERS, decode_by_name, is_decoder,
            looks_like_code as decoded_looks_like_code,
        )
    except ImportError:
        DecodeBudget = None
        OBFUSCATION_DECODERS = frozenset()

        def decode_by_name(*_a, **_kw):
            class _Fail:
                ok = False
                output = ""
                method = ""
                reason = "decoder_unavailable"
                truncated = False
            return _Fail()

        def is_decoder(_name):
            return False

        def decoded_looks_like_code(_text):
            return False


class TokenType(Enum):
    STRING = auto()
    VARIABLE = auto()
    FUNCTION = auto()
    OPERATOR = auto()
    NUMBER = auto()
    KEYWORD = auto()
    IDENTIFIER = auto()
    WHITESPACE = auto()
    COMMENT = auto()
    PHP_TAG = auto()
    EOF = auto()


class NodeType(Enum):
    PROGRAM = auto()
    CALL = auto()
    ASSIGNMENT = auto()
    CONCAT = auto()
    VARIABLE = auto()
    LITERAL = auto()
    ARRAY_ACCESS = auto()
    BINARY_OP = auto()
    VARIABLE_VARIABLE = auto()    # $$var
    DYNAMIC_CALL = auto()         # $func()
    SUPERGLOBAL = auto()          # $_POST, $_GET
    EXPRESSION = auto()
    UNARY_OP = auto()
    TERNARY = auto()
    STATEMENT = auto()


# 数据类

@dataclass
class Token:
    type: TokenType
    value: str
    line: int = 1
    column: int = 0

    def __repr__(self):
        return f"Token({self.type.name}, {self.value!r})"


@dataclass
class ASTNode:
    type: NodeType
    value: Any = None
    children: List['ASTNode'] = field(default_factory=list)
    line: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self):
        return f"ASTNode({self.type.name}, {self.value!r}, children={len(self.children)})"


@dataclass
class TaintInfo:
    """污点从哪来的，怎么传播的"""
    source: str
    propagation_chain: List[str] = field(default_factory=list)
    is_user_controlled: bool = True

    def __repr__(self):
        return f"Taint({self.source})"


@dataclass
class DangerousCallInfo:
    """记录一次危险函数调用"""
    function_name: str
    arguments: List[str] = field(default_factory=list)
    is_tainted: bool = False
    taint_info: Optional[TaintInfo] = None
    resolved_name: Optional[str] = None   # 动态调用解析后的名称
    obfuscation_method: Optional[str] = None
    severity: int = 50
    # 这次调用是在第几层解码之后才看见的（0 = 原文里直接可见）
    nesting_depth: int = 0
    # 走到它经过的解码链，如 ['base64_decode', 'gzinflate']
    decode_chain: List[str] = field(default_factory=list)


@dataclass
class SemanticFinding:
    type: str
    severity: int = 50
    description: str = ""
    code_context: str = ""
    taint_chain: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'type': self.type,
            'severity': self.severity,
            'description': self.description,
            'code_context': self.code_context,
            'taint_chain': self.taint_chain
        }


@dataclass
class ASTAnalysisResult:
    findings: List[SemanticFinding] = field(default_factory=list)
    dangerous_calls: List[DangerousCallInfo] = field(default_factory=list)
    taint_sources: Set[str] = field(default_factory=set)
    obfuscation_score: float = 0.0
    is_likely_webshell: bool = False
    confidence_adjustment: int = 0
    # 这段代码是不是走攻击者可控通道进来的（请求体/请求参数）。
    # 它与 DangerousCallInfo.is_tainted 是**两个不同的维度**，别混：
    #   is_tainted     = 函数的**参数**能回溯到 $_GET/$_POST 等超全局
    #   external_taint = **代码本身**是攻击者投递的
    # 详见 SemanticAnalyzer.analyze 的 external_taint 参数说明。
    external_taint: bool = False
    # 语义解码闭环的产出：解开过哪些层、有没有撞到预算上限。
    # 撞到上限**必须**能说出来 —— "没看"和"看了没事"是两个结论。
    decode_chains: List[List[str]] = field(default_factory=list)
    decode_notes: List[str] = field(default_factory=list)
    max_decode_depth_reached: int = 0

    def to_dict(self) -> Dict:
        return {
            'findings': [f.to_dict() for f in self.findings],
            'dangerous_calls': [
                {
                    'function': c.function_name,
                    'is_tainted': c.is_tainted,
                    'severity': c.severity,
                    'obfuscation': c.obfuscation_method,
                    'nesting_depth': c.nesting_depth,
                    'decode_chain': c.decode_chain
                }
                for c in self.dangerous_calls
            ],
            'taint_sources': list(self.taint_sources),
            'obfuscation_score': self.obfuscation_score,
            'is_likely_webshell': self.is_likely_webshell,
            'confidence_adjustment': self.confidence_adjustment,
            'external_taint': self.external_taint,
            'decode_chains': self.decode_chains,
            'decode_notes': self.decode_notes,
            'max_decode_depth_reached': self.max_decode_depth_reached
        }


class PHPTokenizer:
    """PHP词法分析，把代码拆成token流"""

    # PHP 关键字
    KEYWORDS = {
        'if', 'else', 'elseif', 'while', 'for', 'foreach', 'do',
        'switch', 'case', 'default', 'break', 'continue', 'return',
        'function', 'class', 'new', 'public', 'private', 'protected',
        'static', 'const', 'global', 'echo', 'print', 'exit', 'die',
        'include', 'include_once', 'require', 'require_once',
        'true', 'false', 'null', 'and', 'or', 'xor', 'as', 'instanceof'
    }

    # 超全局变量
    SUPERGLOBALS = {
        '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SESSION',
        '$_FILES', '$_SERVER', '$_ENV', '$GLOBALS',
        '$HTTP_GET_VARS', '$HTTP_POST_VARS', '$HTTP_RAW_POST_DATA'
    }

    def __init__(self):
        self._pos = 0
        self._line = 1
        self._column = 0
        self._code = ""
        self._length = 0

    def tokenize(self, code: str) -> List[Token]:
        """把PHP代码切成token列表"""
        self._code = code
        self._pos = 0
        self._line = 1
        self._column = 0
        self._length = len(code)

        tokens = []

        while self._pos < self._length:
            token = self._next_token()
            if token:
                if token.type not in (TokenType.WHITESPACE, TokenType.COMMENT):
                    tokens.append(token)

        tokens.append(Token(TokenType.EOF, "", self._line, self._column))
        return tokens

    def _next_token(self) -> Optional[Token]:
        if self._pos >= self._length:
            return None

        ch = self._code[self._pos]

        if ch in ' \t\n\r':
            return self._read_whitespace()

        if ch == '<' and self._peek(1) == '?':
            return self._read_php_tag()

        if ch == '?' and self._peek(1) == '>':
            self._pos += 2
            return Token(TokenType.PHP_TAG, "?>", self._line, self._column - 2)

        if ch == '/' and self._peek(1) in ('/', '*'):
            return self._read_comment()

        if ch in '"\'':
            return self._read_string(ch)

        if ch == '<' and self._peek(1) == '<' and self._peek(2) == '<':
            return self._read_heredoc()

        if ch == '$':
            return self._read_variable()

        if ch.isdigit() or (ch == '.' and self._peek(1) and self._peek(1).isdigit()):
            return self._read_number()

        if ch.isalpha() or ch == '_':
            return self._read_identifier()

        return self._read_operator()

    def _peek(self, offset: int = 1) -> Optional[str]:
        pos = self._pos + offset
        if pos < self._length:
            return self._code[pos]
        return None

    def _advance(self) -> str:
        ch = self._code[self._pos]
        self._pos += 1
        if ch == '\n':
            self._line += 1
            self._column = 0
        else:
            self._column += 1
        return ch

    def _read_whitespace(self) -> Token:
        """跳过空白，不需要构建值"""
        start_line = self._line
        start_col = self._column
        start_pos = self._pos

        while self._pos < self._length and self._code[self._pos] in ' \t\n\r':
            ch = self._code[self._pos]
            self._pos += 1
            if ch == '\n':
                self._line += 1
                self._column = 0
            else:
                self._column += 1

        return Token(TokenType.WHITESPACE, self._code[start_pos:self._pos], start_line, start_col)

    def _read_php_tag(self) -> Token:
        start_col = self._column
        tag_start = self._pos

        # <?php 或 <?=
        self._advance()
        self._advance()

        if self._pos < self._length:
            if self._code[self._pos] == '=':
                self._advance()
            elif self._code[self._pos:self._pos+3].lower() == 'php':
                self._advance()
                self._advance()
                self._advance()

        return Token(TokenType.PHP_TAG, self._code[tag_start:self._pos], self._line, start_col)

    def _read_comment(self) -> Token:
        start_line = self._line
        start_col = self._column
        chars = []

        self._advance()  # 第一个 /
        second = self._advance()
        chars.append('/')
        chars.append(second)

        if second == '/':
            # 单行注释，切片快速跳过
            line_start = self._pos
            while self._pos < self._length and self._code[self._pos] != '\n':
                self._pos += 1
                self._column += 1
            chars.append(self._code[line_start:self._pos])
        else:
            # 多行注释
            while self._pos < self._length:
                ch = self._advance()
                chars.append(ch)
                if ch == '*' and self._pos < self._length and self._code[self._pos] == '/':
                    chars.append(self._advance())
                    break

        return Token(TokenType.COMMENT, ''.join(chars), start_line, start_col)

    def _read_string(self, quote: str) -> Token:
        start_line = self._line
        start_col = self._column
        chars = []

        self._advance()  # 开始引号

        while self._pos < self._length:
            ch = self._code[self._pos]

            if ch == '\\' and self._pos + 1 < self._length:
                chars.append(self._advance())
                chars.append(self._advance())
            elif ch == quote:
                self._advance()
                break
            else:
                chars.append(self._advance())

        return Token(TokenType.STRING, ''.join(chars), start_line, start_col)

    def _read_heredoc(self) -> Token:
        """处理heredoc/nowdoc语法"""
        start_line = self._line
        start_col = self._column

        # 跳过 <<<
        self._advance()
        self._advance()
        self._advance()

        identifier = ""
        is_nowdoc = False

        while self._pos < self._length and self._code[self._pos] in ' \t':
            self._advance()

        # nowdoc用单引号包标识符
        if self._pos < self._length and self._code[self._pos] == "'":
            is_nowdoc = True
            self._advance()

        while self._pos < self._length and (self._code[self._pos].isalnum() or self._code[self._pos] == '_'):
            identifier += self._advance()

        if is_nowdoc and self._pos < self._length and self._code[self._pos] == "'":
            self._advance()

        # 跳到下一行
        while self._pos < self._length and self._code[self._pos] != '\n':
            self._advance()
        if self._pos < self._length:
            self._advance()

        # 读内容直到结束标识符
        value = ""
        while self._pos < self._length:
            line_start = self._pos

            line = ""
            while self._pos < self._length and self._code[self._pos] != '\n':
                line += self._code[self._pos]
                self._pos += 1

            stripped = line.strip().rstrip(';')
            if stripped == identifier:
                break

            value += line
            if self._pos < self._length:
                value += '\n'
                self._pos += 1
                self._line += 1

        return Token(TokenType.STRING, value, start_line, start_col)

    def _read_variable(self) -> Token:
        start_line = self._line
        start_col = self._column
        chars = []

        chars.append(self._advance())  # $

        # $$var
        if self._pos < self._length and self._code[self._pos] == '$':
            chars.append(self._advance())

        # ${...} 语法
        if self._pos < self._length and self._code[self._pos] == '{':
            chars.append(self._advance())
            brace_count = 1
            while self._pos < self._length and brace_count > 0:
                ch = self._code[self._pos]
                if ch == '{':
                    brace_count += 1
                elif ch == '}':
                    brace_count -= 1
                chars.append(self._advance())
            return Token(TokenType.VARIABLE, ''.join(chars), start_line, start_col)

        # 切片读变量名
        name_start = self._pos
        while self._pos < self._length:
            ch = self._code[self._pos]
            if ch.isalnum() or ch == '_':
                self._pos += 1
                self._column += 1
            else:
                break
        if self._pos > name_start:
            chars.append(self._code[name_start:self._pos])

        return Token(TokenType.VARIABLE, ''.join(chars), start_line, start_col)

    def _read_number(self) -> Token:
        start_line = self._line
        start_col = self._column
        num_start = self._pos

        # 十六进制
        if self._code[self._pos] == '0' and self._peek(1) in ('x', 'X'):
            self._pos += 2  # 0x
            self._column += 2
            while self._pos < self._length and self._code[self._pos] in '0123456789abcdefABCDEF':
                self._pos += 1
                self._column += 1
            return Token(TokenType.NUMBER, self._code[num_start:self._pos], start_line, start_col)

        has_dot = False
        while self._pos < self._length:
            ch = self._code[self._pos]
            if ch.isdigit():
                self._pos += 1
                self._column += 1
            elif ch == '.' and not has_dot:
                has_dot = True
                self._pos += 1
                self._column += 1
            elif ch in 'eE':
                self._pos += 1
                self._column += 1
                if self._pos < self._length and self._code[self._pos] in '+-':
                    self._pos += 1
                    self._column += 1
            else:
                break

        return Token(TokenType.NUMBER, self._code[num_start:self._pos], start_line, start_col)

    def _read_identifier(self) -> Token:
        start_line = self._line
        start_col = self._column
        id_start = self._pos

        while self._pos < self._length:
            ch = self._code[self._pos]
            if ch.isalnum() or ch == '_':
                self._pos += 1
                self._column += 1
            else:
                break

        value = self._code[id_start:self._pos]

        if value.lower() in self.KEYWORDS:
            return Token(TokenType.KEYWORD, value, start_line, start_col)

        return Token(TokenType.IDENTIFIER, value, start_line, start_col)

    def _read_operator(self) -> Token:
        start_col = self._column
        ch = self._advance()

        # 双字符运算符
        if self._pos < self._length:
            next_ch = self._code[self._pos]
            two_char = ch + next_ch

            if two_char in ('==', '!=', '<=', '>=', '&&', '||', '..', '->', '=>',
                           '++', '--', '+=', '-=', '*=', '/=', '.=', '??', '::'):
                self._advance()
                # 三字符
                if self._pos < self._length:
                    three_char = two_char + self._code[self._pos]
                    if three_char in ('===', '!==', '<=>'):
                        self._advance()
                        return Token(TokenType.OPERATOR, three_char, self._line, start_col)
                return Token(TokenType.OPERATOR, two_char, self._line, start_col)

        return Token(TokenType.OPERATOR, ch, self._line, start_col)


# AST构建器

class PHPASTBuilder:
    """从token列表建AST，只关心webshell相关的结构"""

    def __init__(self):
        self._tokens: List[Token] = []
        self._pos = 0
        self._length = 0
        # 本文件里定义过的用户函数：函数名(小写) -> 参数名列表。
        # 语义分析器靠它做保守污点传播（见 SemanticAnalyzer._is_tainted_impl）。
        self.user_functions: Dict[str, List[str]] = {}

    def build(self, tokens: List[Token]) -> ASTNode:
        """从token列表构建AST"""
        self._tokens = tokens
        self._pos = 0
        self._length = len(tokens)
        self.user_functions = {}

        root = ASTNode(NodeType.PROGRAM, children=[])
        max_iterations = self._length * 2  # 安全上限，防死循环

        iterations = 0
        while not self._is_at_end():
            iterations += 1
            if iterations > max_iterations:
                break
            try:
                stmt = self._parse_statement()
                if stmt:
                    root.children.append(stmt)
                else:
                    # 跳过 { } 之类识别不了的token
                    self._advance()
            except Exception:
                self._advance()

        self._collect_user_function_signatures()

        return root

    def _collect_user_function_signatures(self) -> None:
        """从 token 流里找 `function name(...)` 定义，收集 函数名 -> 参数名。

        解析器把 `function foo($a, $b) {...}` 拆成零散语句（'function' 退化成
        LITERAL，调用名解析成 CALL），AST 上区分不了"定义"和"调用"，所以在
        token 层识别：KEYWORD 'function' -> IDENTIFIER 函数名 -> (参数)。

        只记**有名字**的函数；匿名函数（function(...) 后没有标识符）跳过。
        """
        tokens = self._tokens
        n = len(tokens)
        i = 0
        while i < n:
            if tokens[i].type == TokenType.KEYWORD and tokens[i].value.lower() == 'function':
                j = i + 1
                # 引用返回：function &name(...)
                if j < n and tokens[j].type == TokenType.OPERATOR and tokens[j].value == '&':
                    j += 1
                name = None
                if j < n and tokens[j].type == TokenType.IDENTIFIER:
                    name = tokens[j].value
                    j += 1
                if name and j < n and tokens[j].value == '(':
                    params = []
                    j += 1
                    while j < n and tokens[j].value != ')':
                        if tokens[j].type == TokenType.VARIABLE:
                            params.append(tokens[j].value)
                        j += 1
                    self.user_functions[name.lower()] = params
            i += 1

    def _current(self) -> Token:
        if self._pos < self._length:
            return self._tokens[self._pos]
        return Token(TokenType.EOF, "")

    def _peek(self, offset: int = 1) -> Token:
        pos = self._pos + offset
        if pos < self._length:
            return self._tokens[pos]
        return Token(TokenType.EOF, "")

    def _advance(self) -> Token:
        token = self._current()
        if not self._is_at_end():
            self._pos += 1
        return token

    def _is_at_end(self) -> bool:
        return self._current().type == TokenType.EOF

    def _check(self, *types: TokenType) -> bool:
        return self._current().type in types

    def _check_value(self, value: str) -> bool:
        return self._current().value == value

    def _match(self, *types: TokenType) -> bool:
        if self._check(*types):
            self._advance()
            return True
        return False

    def _match_value(self, value: str) -> bool:
        if self._check_value(value):
            self._advance()
            return True
        return False

    def _parse_statement(self) -> Optional[ASTNode]:
        # 跳过PHP标签和分号
        if self._check(TokenType.PHP_TAG):
            self._advance()
            return None

        if self._check_value(';'):
            self._advance()
            return None

        expr = self._parse_expression()
        if expr:
            self._match_value(';')
            return ASTNode(NodeType.STATEMENT, children=[expr])

        return None

    def _parse_expression(self) -> Optional[ASTNode]:
        return self._parse_assignment()

    def _parse_assignment(self) -> Optional[ASTNode]:
        left = self._parse_ternary()

        if left and self._check(TokenType.OPERATOR):
            op = self._current().value
            if op in ('=', '.=', '+=', '-=', '*=', '/='):
                self._advance()
                right = self._parse_assignment()
                if right:
                    return ASTNode(
                        NodeType.ASSIGNMENT,
                        value=op,
                        children=[left, right],
                        line=left.line
                    )

        return left

    def _parse_ternary(self) -> Optional[ASTNode]:
        condition = self._parse_logical_or()

        if condition and self._check_value('?'):
            self._advance()
            then_expr = self._parse_expression()
            self._match_value(':')
            else_expr = self._parse_expression()
            return ASTNode(
                NodeType.TERNARY,
                children=[condition, then_expr, else_expr] if then_expr and else_expr else [condition]
            )

        return condition

    def _parse_logical_or(self) -> Optional[ASTNode]:
        left = self._parse_logical_and()

        while left and self._check_value('||'):
            op = self._advance().value
            right = self._parse_logical_and()
            if right:
                left = ASTNode(NodeType.BINARY_OP, value=op, children=[left, right])

        return left

    def _parse_logical_and(self) -> Optional[ASTNode]:
        left = self._parse_concat()

        while left and self._check_value('&&'):
            op = self._advance().value
            right = self._parse_concat()
            if right:
                left = ASTNode(NodeType.BINARY_OP, value=op, children=[left, right])

        return left

    def _parse_concat(self) -> Optional[ASTNode]:
        left = self._parse_comparison()

        while left and self._check_value('.'):
            self._advance()
            right = self._parse_comparison()
            if right:
                left = ASTNode(NodeType.CONCAT, children=[left, right])

        return left

    def _parse_comparison(self) -> Optional[ASTNode]:
        left = self._parse_additive()

        if left and self._check(TokenType.OPERATOR):
            op = self._current().value
            if op in ('==', '!=', '===', '!==', '<', '>', '<=', '>=', '<=>'):
                self._advance()
                right = self._parse_additive()
                if right:
                    return ASTNode(NodeType.BINARY_OP, value=op, children=[left, right])

        return left

    def _parse_additive(self) -> Optional[ASTNode]:
        left = self._parse_multiplicative()

        while left and self._check(TokenType.OPERATOR):
            op = self._current().value
            if op in ('+', '-'):
                self._advance()
                right = self._parse_multiplicative()
                if right:
                    left = ASTNode(NodeType.BINARY_OP, value=op, children=[left, right])
            else:
                break

        return left

    def _parse_multiplicative(self) -> Optional[ASTNode]:
        left = self._parse_unary()

        while left and self._check(TokenType.OPERATOR):
            op = self._current().value
            if op in ('*', '/', '%'):
                self._advance()
                right = self._parse_unary()
                if right:
                    left = ASTNode(NodeType.BINARY_OP, value=op, children=[left, right])
            else:
                break

        return left

    def _parse_unary(self) -> Optional[ASTNode]:
        if self._check(TokenType.OPERATOR):
            op = self._current().value
            if op in ('@', '!', '-', '+', '~'):
                self._advance()
                operand = self._parse_unary()
                if operand:
                    return ASTNode(NodeType.UNARY_OP, value=op, children=[operand])

        return self._parse_postfix()

    def _parse_postfix(self) -> Optional[ASTNode]:
        """处理函数调用、数组访问、->方法"""
        expr = self._parse_primary()

        while expr:
            if self._check_value('('):
                self._advance()
                args = self._parse_arguments()
                self._match_value(')')

                # 变量调用 vs 普通调用
                if expr.type == NodeType.VARIABLE:
                    expr = ASTNode(
                        NodeType.DYNAMIC_CALL,
                        value=expr.value,
                        children=args,
                        line=expr.line
                    )
                else:
                    expr = ASTNode(
                        NodeType.CALL,
                        value=expr.value if expr.type == NodeType.LITERAL else None,
                        children=[expr] + args if expr.type != NodeType.LITERAL else args,
                        line=expr.line,
                        metadata={'callee': expr}
                    )

            # 数组访问
            elif self._check_value('['):
                self._advance()
                index = self._parse_expression()
                self._match_value(']')
                if index:
                    expr = ASTNode(
                        NodeType.ARRAY_ACCESS,
                        children=[expr, index],
                        line=expr.line
                    )

            # -> 访问
            elif self._check_value('->'):
                self._advance()
                member = self._parse_primary()
                if member:
                    if self._check_value('('):
                        self._advance()
                        args = self._parse_arguments()
                        self._match_value(')')
                        expr = ASTNode(
                            NodeType.CALL,
                            value=member.value,
                            children=[expr] + args,
                            metadata={'is_method': True}
                        )
                    else:
                        expr = ASTNode(
                            NodeType.ARRAY_ACCESS,
                            children=[expr, member],
                            metadata={'is_property': True}
                        )
            else:
                break

        return expr

    def _parse_primary(self) -> Optional[ASTNode]:
        token = self._current()

        if token.type == TokenType.STRING:
            self._advance()
            return ASTNode(NodeType.LITERAL, value=token.value, line=token.line)

        if token.type == TokenType.NUMBER:
            self._advance()
            return ASTNode(NodeType.LITERAL, value=token.value, line=token.line)

        if token.type == TokenType.VARIABLE:
            self._advance()
            value = token.value

            # 超全局变量
            base_var = value.split('[')[0].split('{')[0]
            if base_var in PHPTokenizer.SUPERGLOBALS:
                return ASTNode(NodeType.SUPERGLOBAL, value=value, line=token.line)

            # $$var
            if value.startswith('$$'):
                return ASTNode(NodeType.VARIABLE_VARIABLE, value=value, line=token.line)

            # ${...}
            if value.startswith('${'):
                return ASTNode(NodeType.VARIABLE_VARIABLE, value=value, line=token.line)

            return ASTNode(NodeType.VARIABLE, value=value, line=token.line)

        # 标识符当函数名
        if token.type == TokenType.IDENTIFIER:
            self._advance()
            return ASTNode(NodeType.LITERAL, value=token.value, line=token.line)

        if token.type == TokenType.KEYWORD:
            self._advance()
            # include/require/echo这些当函数调用处理
            if token.value.lower() in ('include', 'include_once', 'require', 'require_once', 'echo', 'print', 'exit', 'die'):
                arg = self._parse_expression()
                return ASTNode(
                    NodeType.CALL,
                    value=token.value.lower(),
                    children=[arg] if arg else [],
                    line=token.line
                )
            return ASTNode(NodeType.LITERAL, value=token.value, line=token.line)

        if self._check_value('('):
            self._advance()
            expr = self._parse_expression()
            self._match_value(')')
            return expr

        if self._check_value('[') or (token.type == TokenType.IDENTIFIER and token.value.lower() == 'array'):
            return self._parse_array()

        return None

    def _parse_arguments(self) -> List[ASTNode]:
        args = []

        if self._check_value(')'):
            return args

        arg = self._parse_expression()
        if arg:
            args.append(arg)

        while self._check_value(','):
            self._advance()
            arg = self._parse_expression()
            if arg:
                args.append(arg)

        return args

    def _parse_array(self) -> Optional[ASTNode]:
        if self._check_value('['):
            self._advance()
            elements = []
            while not self._check_value(']') and not self._is_at_end():
                elem = self._parse_expression()
                if elem:
                    elements.append(elem)
                if not self._match_value(','):
                    break
            self._match_value(']')
            return ASTNode(NodeType.LITERAL, value=elements, metadata={'is_array': True})

        if self._current().value.lower() == 'array':
            self._advance()
            self._match_value('(')
            elements = []
            while not self._check_value(')') and not self._is_at_end():
                elem = self._parse_expression()
                if elem:
                    elements.append(elem)
                if not self._match_value(','):
                    break
            self._match_value(')')
            return ASTNode(NodeType.LITERAL, value=elements, metadata={'is_array': True})

        return None

    def resolve_concat(self, node: ASTNode) -> Optional[str]:
        """尝试把拼接还原成完整字符串，如 "sys"."tem" -> "system" """
        if node.type == NodeType.LITERAL:
            return str(node.value) if node.value is not None else None

        if node.type == NodeType.CONCAT and len(node.children) == 2:
            left = self.resolve_concat(node.children[0])
            right = self.resolve_concat(node.children[1])
            if left is not None and right is not None:
                return left + right

        return None


class SemanticAnalyzer:
    """遍历AST做污点追踪和混淆检测"""

    # 攻击者投递的代码里，这个严重度以上的 sink 即使参数是硬编码，
    # 本身也构成指控 —— 正常业务不会在 HTTP 请求体里投递 eval/system 调用。
    # 40 分档的 file_get_contents/fopen 不在此列：那些在正常代码里太常见，
    # 只免罚不加分。
    EXTERNAL_TAINT_SINK_FLOOR = 90

    # 字符串变换函数静态求值的最大嵌套深度。变换链每层都消耗一个调用节点，
    # 恶意深嵌套（strtolower(strtolower(...))) 靠它兜底，不会把栈走穿。
    TRANSFORM_EVAL_MAX_DEPTH = 8

    # 污点来源
    TAINT_SOURCES = {
        '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES',
        '$_SERVER', '$_ENV', '$GLOBALS',
        '$HTTP_GET_VARS', '$HTTP_POST_VARS', '$HTTP_RAW_POST_DATA'
    }

    # 危险sink，值是严重程度
    DANGEROUS_SINKS = {
        'eval': 100,
        'assert': 90,
        'create_function': 85,
        'preg_replace': 70,  # /e修饰符
        'call_user_func': 75,
        'call_user_func_array': 75,
        'array_map': 60,
        'array_filter': 60,
        'usort': 55,
        'uasort': 55,

        'system': 100,
        'exec': 100,
        'shell_exec': 100,
        'passthru': 100,
        'popen': 90,
        'proc_open': 90,
        'pcntl_exec': 95,

        'include': 80,
        'include_once': 80,
        'require': 80,
        'require_once': 80,
        'file_put_contents': 70,
        'fwrite': 60,
        'fputs': 60,
        'file_get_contents': 40,
        'fopen': 40,
        'readfile': 40,

        'unserialize': 80,
    }

    # 污点传播函数（输入脏了输出也脏）
    TAINT_PROPAGATORS = {
        'base64_decode', 'base64_encode',
        'str_rot13', 'gzinflate', 'gzuncompress', 'gzdecode', 'gzencode',
        'urldecode', 'rawurldecode', 'urlencode',
        'substr', 'str_replace', 'preg_replace', 'str_ireplace',
        'implode', 'join', 'explode', 'split',
        'trim', 'ltrim', 'rtrim', 'strtolower', 'strtoupper',
        'sprintf', 'printf', 'vsprintf',
        'chr', 'ord', 'pack', 'unpack',
        'strrev', 'str_repeat', 'str_pad',
        'htmlspecialchars_decode', 'html_entity_decode',
        'hex2bin', 'bin2hex',
        'json_decode', 'json_encode',
        'serialize',
    }

    def __init__(self):
        self._tainted_vars: Dict[str, TaintInfo] = {}
        self._var_values: Dict[str, Any] = {}  # 变量值追踪
        self._findings: List[SemanticFinding] = []
        self._dangerous_calls: List[DangerousCallInfo] = []
        self._obfuscation_indicators: List[str] = []
        self._ast_builder = PHPASTBuilder()
        self._external_taint = False
        self._decode_budget = None
        self._decode_depth = 0
        self._decode_chains: List[List[str]] = []
        self._max_depth_reached = 0
        self._decoded_seen: Set[int] = set()
        self._decoded_vars: Dict[str, Tuple[str, List[str]]] = {}

    def analyze(self, ast: ASTNode, external_taint: bool = False,
                decode_budget: Optional["DecodeBudget"] = None,
                decode_depth: int = 0,
                decoded_seen: Optional[Set[int]] = None) -> ASTAnalysisResult:
        """分析AST，跑污点追踪+混淆检测

        external_taint —— 这段代码是不是走**攻击者可控通道**进来的。

        污点分析本来是**源码审计**模型：假设扫的是磁盘上一个 PHP 文件，
        文件本身可信，$_GET/$_POST 是唯一不可信入口，所以"危险函数的参数
        追不到超全局"确实说明它无害。

        但听澜读的是**流量**。请求体里的一段 PHP 代码，整体就是攻击者写下
        并投递过来的 —— 外层污点在协议层已经成立，再要求载荷内部出现
        $_POST 是重复举证。实测后果（修这个 bug 前）：

            system("whoami")                          -> -50
            eval(base64_decode("<硬编码的 system('id')>")) -> -50
            echo file_get_contents("config.php")      -> -50

        三条全是"已经打进来了"的行为，全被倒扣，足以把冰蝎/哥斯拉解密成功
        的家族锚点分数吃干净。

        所以方向必须区分：
          请求侧 (external_taint=True)  代码是攻击者投递的 -> 不倒扣
          响应侧 (external_taint=False) 可能是服务器回显自己的源码 -> 保留降权

        注意这里**不去改 DangerousCallInfo.is_tainted**。is_tainted 的含义是
        "该调用的**参数**用户可控"，硬编码参数就是不可控，改它等于在报告里
        伪造证据链（会写成"用户输入流入危险函数"，而实际参数是字面量）。
        取证工具不能这么干，所以另开 external_taint 这一维，证据也另开
        attacker_delivered_sink 这个 finding 类型，如实描述。

        decode_budget / decode_depth —— 语义解码闭环用，见
        `_resolve_encoded_literal` 和 `_try_decode_and_recurse`。外部调用方
        一般不用传，递归时由引擎自己往下带。
        """
        self._tainted_vars = {}
        self._var_values = {}
        self._findings = []
        self._dangerous_calls = []
        self._obfuscation_indicators = []
        self._taint_cache = {}  # _is_tainted结果缓存
        self._external_taint = bool(external_taint)
        self._decode_depth = decode_depth
        self._decode_chains = []
        self._max_depth_reached = decode_depth
        self._decoded_seen = decoded_seen if decoded_seen is not None else set()
        self._decoded_vars = {}
        if decode_budget is not None:
            self._decode_budget = decode_budget
        elif DecodeBudget is not None:
            self._decode_budget = DecodeBudget()
        else:
            self._decode_budget = None

        self._visit(ast)

        if self._external_taint:
            self._emit_external_taint_findings()

        obfuscation_score = self._calculate_obfuscation_score()
        confidence_adjustment = self._calculate_confidence_adjustment()
        is_likely_webshell = self._is_likely_webshell()

        notes = list(self._decode_budget.exhausted) if self._decode_budget else []

        return ASTAnalysisResult(
            findings=self._findings,
            dangerous_calls=self._dangerous_calls,
            taint_sources=set(self._tainted_vars.keys()),
            obfuscation_score=obfuscation_score,
            is_likely_webshell=is_likely_webshell,
            confidence_adjustment=confidence_adjustment,
            external_taint=self._external_taint,
            decode_chains=self._decode_chains,
            decode_notes=notes,
            max_decode_depth_reached=self._max_depth_reached
        )

    def _external_taint_sinks(self) -> List[DangerousCallInfo]:
        """攻击者投递的代码里，参数硬编码但本身就够格立案的高危调用"""
        return [
            c for c in self._dangerous_calls
            if not c.is_tainted and c.severity >= self.EXTERNAL_TAINT_SINK_FLOOR
        ]

    # ------------------------------------------------------------ 语义解码闭环

    def _static_string_of(self, node: ASTNode, _depth: int = 0) -> Optional[str]:
        """把节点求值成静态字符串（不解码，只求值）

        管三种：字面量、字符串拼接、以及**值已知的变量**。第三种是必要的 ——
        `$x = "c3lz..."; eval(base64_decode($x));` 这种把编码串先存进变量的
        写法在真实样本里比直接内联更常见。

        外加第四种：**字符串变换函数**的静态求值（`str_replace('u','s','auuert')`
        这类），由 `_static_eval_transform` 提供。解码器不在这里 —— 那是
        `_resolve_encoded_literal` 的职责，避免一条串被解两遍。
        """
        if node is None:
            return None

        if node.type == NodeType.LITERAL:
            if isinstance(node.value, str):
                return node.value
            return None

        if node.type == NodeType.CONCAT:
            parts = []
            for child in node.children:
                piece = self._static_string_of(child, _depth)
                if piece is None:
                    return None
                parts.append(piece)
            return ''.join(parts) if parts else None

        if node.type == NodeType.VARIABLE:
            value = self._var_values.get(node.value)
            return value if isinstance(value, str) else None

        if node.type == NodeType.CALL:
            return self._static_eval_transform(node, _depth + 1)

        return None

    def _resolve_static_text(self, node: ASTNode, _depth: int = 0) -> Optional[str]:
        """把节点求值成静态字符串（解码增强版）。

        `_static_string_of` 之上叠加解码链：字面量 / 拼接 / 已知变量 / 变换函数
        / 解码器全认。call_user_func 的函数名实参就用它还原 —— 攻击者拼函数名
        的每种手法在这都有对应的求值路径。
        """
        if node is None or _depth > self.TRANSFORM_EVAL_MAX_DEPTH:
            return None

        base = self._static_string_of(node, _depth)
        if base is not None:
            return base

        if node.type == NodeType.CALL:
            decoded, _chain = self._resolve_encoded_literal(node)
            if decoded is not None:
                return decoded

        return None

    def _static_eval_transform(self, node: ASTNode, _depth: int = 0) -> Optional[str]:
        """静态求值**字符串变换函数**，如 str_replace('u','s','auuert') -> 'assert'。

        覆盖一类纯字符串变换（无副作用、无随机性）：替换、大小写、反转、取子串、
        chr、trim 族、重复。参数必须能静态求值（字面量/拼接/已知变量/嵌套变换/
        解码链），任何一个求不出来就整体返回 None —— 宁可不知道，也不硬猜。
        深度有上限，防止恶意深嵌套把栈走穿。
        """
        if node is None or _depth > self.TRANSFORM_EVAL_MAX_DEPTH:
            return None
        if node.type != NodeType.CALL:
            return None

        name = (node.value or '').lower()
        args = node.children

        def arg_text(index: int) -> Optional[str]:
            if index >= len(args):
                return None
            return self._resolve_static_text(args[index], _depth + 1)

        def arg_int(index: int) -> Optional[int]:
            text = arg_text(index)
            if text is None:
                return None
            try:
                return int(str(text), 0)
            except ValueError:
                return None

        if name in ('str_replace', 'str_ireplace') and len(args) >= 3:
            search, repl, subject = arg_text(0), arg_text(1), arg_text(2)
            if search is None or repl is None or subject is None:
                return None
            if search == '':
                return subject
            if name == 'str_replace':
                return subject.replace(search, repl)
            return re.sub(re.escape(search), repl, subject, flags=re.IGNORECASE)

        if name == 'strtolower' and args:
            text = arg_text(0)
            return text.lower() if text is not None else None

        if name == 'strtoupper' and args:
            text = arg_text(0)
            return text.upper() if text is not None else None

        if name == 'strrev' and args:
            text = arg_text(0)
            return text[::-1] if text is not None else None

        if name == 'substr' and len(args) >= 2:
            text = arg_text(0)
            start = arg_int(1)
            if text is None or start is None:
                return None
            if len(args) >= 3:
                length = arg_int(2)
                if length is None:
                    return None
                return text[start:start + length]
            return text[start:]

        if name == 'chr' and args:
            code = arg_int(0)
            if code is None or not 0 <= code <= 0x10FFFF:
                return None
            return chr(code)

        if name in ('trim', 'ltrim', 'rtrim') and args:
            text = arg_text(0)
            if text is None:
                return None
            if name == 'trim':
                return text.strip()
            if name == 'ltrim':
                return text.lstrip()
            return text.rstrip()

        if name == 'str_repeat' and len(args) >= 2:
            text = arg_text(0)
            count = arg_int(1)
            if text is None or count is None or count < 0 or count > 1000:
                return None
            result = text * count
            return result if len(result) <= 64 * 1024 else None

        return None

    def _resolve_encoded_literal(
        self, node: ASTNode, _depth: int = 0
    ) -> Tuple[Optional[str], List[str]]:
        """把 base64_decode("...") 这类**解码函数调用链**求值成明文

        返回 (明文, 解码链)。没有经过任何解码器时返回 (None, [])，这样调用方
        能区分"这是个普通字符串"和"这是解开一层之后的内容"。

        为什么解码方式不用猜：语法树已经写着 `gzinflate(base64_decode(x))`，
        解码链就是函数名本身。通用解码器只能看字节形状去猜，实测会把
        `gzdeflate+base64` 判成 base85 解出乱码；这里没有这个问题。
        """
        if node is None or self._decode_budget is None:
            return None, []

        # 语法嵌套的深度也要收口，否则 a(b(c(d(...)))) 能把栈走穿
        if _depth > self._decode_budget.max_depth:
            self._decode_budget.note_exhausted(
                f"nested_call_depth:{self._decode_budget.max_depth}")
            return None, []

        if node.type != NodeType.CALL:
            return None, []

        func_name = node.value
        if not isinstance(func_name, str) or not is_decoder(func_name):
            return None, []

        if not node.children:
            return None, []

        # pack("H*", $data) 的编码串在第二个实参上；其余解码器都在第一个
        arg = node.children[0]
        if func_name.lower() == 'pack' and len(node.children) >= 2:
            arg = node.children[1]

        # 先看内层还是不是解码调用，是就先把内层解开（自然形成解码链）
        inner_text, inner_chain = self._resolve_encoded_literal(arg, _depth + 1)
        if inner_text is None:
            inner_text = self._static_string_of(arg)
            inner_chain = []

        if inner_text is None:
            return None, []

        result = decode_by_name(func_name, inner_text, self._decode_budget)
        if not result.ok:
            return None, []

        return result.output, inner_chain + [func_name.lower()]

    def _try_decode_and_recurse(self, node: ASTNode, sink_name: str,
                                severity: int) -> None:
        """sink 的实参是编码字面量时，解开它再递归建一次 AST

        这是"eval 里到底装了什么"这个问题的答案。修之前两头都看不见：AST 只
        看到 eval 的参数是个字符串，解码器看到整段是可打印的 PHP 源码不动它。

        sink 套编码套 sink 是**正常代码不会有的形状**，所以内层一旦发现危险
        调用，就直接定性，不再要求污点链。
        """
        if self._decode_budget is None:
            return
        if self._decode_depth >= self._decode_budget.max_depth:
            self._decode_budget.note_exhausted(
                f"max_depth:{self._decode_budget.max_depth}")
            return

        for arg in node.children:
            decoded, chain = self._resolve_encoded_literal(arg)
            if decoded is None or not chain:
                # 参数是变量时，看它有没有在别处被解码过：
                #   $c = base64_decode("..."); eval($c);
                # 这个形态比直接内联更常见，不接上等于闭环少了一半。
                if arg is not None and arg.type == NodeType.VARIABLE:
                    stored = self._decoded_vars.get(arg.value)
                    if stored:
                        decoded, chain = stored
            if decoded is None or not chain:
                continue

            # 解出来跟解之前一样 -> 死循环，停
            fingerprint = hash(decoded)
            if fingerprint in self._decoded_seen:
                continue
            self._decoded_seen.add(fingerprint)

            chain_text = ' -> '.join(chain)
            self._decode_chains.append(chain)

            # 用到编码函数本身就是混淆信号
            if any(c in OBFUSCATION_DECODERS for c in chain):
                self._obfuscation_indicators.append(f"encoded_literal:{chain_text}")

            if not decoded_looks_like_code(decoded):
                # 解出来不像代码就别往下钻了（图片/证书/序列化数据）。
                # 但这一层解码本身仍然记着 —— 它是混淆证据。
                continue

            sub_result = self._analyze_decoded(decoded)
            if sub_result is None:
                continue

            self._merge_decoded_result(sub_result, sink_name, chain, severity)

    def _analyze_decoded(self, code: str) -> Optional[ASTAnalysisResult]:
        """对解出来的明文再跑一次完整分析（新分析器，共享预算）"""
        try:
            sub = SemanticAnalyzer()
            sub._ast_builder = self._ast_builder
            tokens = self._ast_builder_tokenize(code)
            if tokens is None:
                return None
            sub_ast = self._ast_builder.build(tokens)
            return sub.analyze(
                sub_ast,
                external_taint=self._external_taint,
                decode_budget=self._decode_budget,
                decode_depth=self._decode_depth + 1,
                decoded_seen=self._decoded_seen,
            )
        except Exception:
            return None

    def _ast_builder_tokenize(self, code: str) -> Optional[List[Token]]:
        try:
            cleaned = re.sub(r'<\?php\s*', '', code, flags=re.IGNORECASE)
            cleaned = re.sub(r'<\?=?\s*', '', cleaned)
            cleaned = re.sub(r'\?>\s*$', '', cleaned)
            return PHPTokenizer().tokenize(cleaned.strip())
        except Exception:
            return None

    def _merge_decoded_result(self, sub: ASTAnalysisResult, sink_name: str,
                              chain: List[str], severity: int) -> None:
        """把内层结果并进外层，并标清它是从哪条解码链里挖出来的"""
        chain_text = ' -> '.join(chain)
        self._max_depth_reached = max(
            self._max_depth_reached, sub.max_decode_depth_reached,
            self._decode_depth + 1)
        self._decode_chains.extend(sub.decode_chains)

        for call in sub.dangerous_calls:
            call.nesting_depth = max(call.nesting_depth, self._decode_depth + 1)
            call.decode_chain = chain + call.decode_chain
            if not call.obfuscation_method:
                call.obfuscation_method = f"encoded_literal:{chain_text}"
            self._dangerous_calls.append(call)

        for finding in sub.findings:
            self._findings.append(finding)

        if sub.dangerous_calls:
            inner = sub.dangerous_calls[0]
            # sink 套编码套 sink。正常代码不会长这样，直接给满格严重度。
            self._findings.append(SemanticFinding(
                type='decoded_sink',
                severity=max(severity, inner.severity, 90),
                description=(
                    f"{sink_name}() 的参数经 {chain_text} 解码后是可执行代码，"
                    f"其中调用了 {inner.function_name}()"
                ),
                code_context=(
                    f"{sink_name}({chain_text}(...)) → "
                    f"{inner.function_name}({', '.join(inner.arguments[:2])})"
                )
            ))
            self._obfuscation_indicators.append(f"decoded_sink:{sink_name}")

    def _emit_external_taint_findings(self) -> None:
        for call in self._external_taint_sinks():
            args = ', '.join(call.arguments[:3])
            self._findings.append(SemanticFinding(
                type='attacker_delivered_sink',
                severity=call.severity,
                description=(
                    f"攻击者投递的代码中直接调用危险函数 {call.function_name}()"
                    f"（参数为硬编码，非参数注入）"
                ),
                code_context=f"{call.function_name}({args})"
            ))

    def _visit(self, node: ASTNode) -> None:
        if node is None:
            return

        # 按节点类型分派
        if node.type == NodeType.ASSIGNMENT:
            self._visit_assignment(node)
        elif node.type == NodeType.CALL:
            self._visit_call(node)
        elif node.type == NodeType.DYNAMIC_CALL:
            self._visit_dynamic_call(node)
        elif node.type == NodeType.VARIABLE_VARIABLE:
            self._visit_variable_variable(node)
        elif node.type == NodeType.CONCAT:
            self._visit_concat(node)

        for child in node.children:
            if isinstance(child, ASTNode):
                self._visit(child)

    def _visit_assignment(self, node: ASTNode) -> None:
        if len(node.children) < 2:
            return

        left = node.children[0]
        right = node.children[1]

        if left.type == NodeType.VARIABLE:
            var_name = left.value

            is_tainted, taint_info = self._is_tainted(right)

            if is_tainted:
                # 传播污点
                self._tainted_vars[var_name] = TaintInfo(
                    source=taint_info.source if taint_info else "unknown",
                    propagation_chain=(taint_info.propagation_chain if taint_info else []) + [var_name]
                )
            else:
                # 被新值覆盖就不算脏了
                if var_name in self._tainted_vars:
                    del self._tainted_vars[var_name]

            # 追踪变量值。解码链要**先**试 —— 它同时能给出"这个值是解开一层
            # 得到的"以及解码链本身，后面 `eval($x)` 那边要靠这个接上闭环。
            decoded, chain = self._resolve_encoded_literal(right)
            if decoded is not None and chain:
                self._var_values[var_name] = decoded
                self._decoded_vars[var_name] = (decoded, chain)
            else:
                resolved_value = self._try_resolve_value(right)
                if resolved_value is not None:
                    self._var_values[var_name] = resolved_value

    def _visit_call(self, node: ASTNode) -> None:
        func_name = node.value
        if func_name is None and node.metadata.get('callee'):
            callee = node.metadata['callee']
            if callee.type == NodeType.LITERAL:
                func_name = str(callee.value)

        if func_name is None:
            # $_GET['f']() 这种"函数名本身用户可控"的调用：解析器建不出名字
            # （callee 是 ARRAY_ACCESS），但 callee 表达式脏本身就是一条证据
            # —— 一句话木马的经典写法，`$_GET['f']($_POST['x'])`。
            if node.metadata.get('callee'):
                callee_tainted, callee_taint = self._is_tainted(node.metadata['callee'])
                if callee_tainted:
                    self._findings.append(SemanticFinding(
                        type='suspicious_dynamic_call',
                        severity=60,
                        description='动态函数调用使用了用户可控的函数名',
                        code_context=self._node_to_string(node),
                        taint_chain=callee_taint.propagation_chain if callee_taint else []
                    ))
            return

        func_name_lower = func_name.lower()

        # call_user_func / call_user_func_array 的第一个实参是函数名。静态求值
        # 还原它（字面量/拼接/已知变量/变换函数/解码链），命中危险函数就按
        # "间接调用危险函数"立案 —— 不再重复记一条裸的 call_user_func，
        # 同一个事实记两遍会污染信心分。
        if (func_name_lower in ('call_user_func', 'call_user_func_array')
                and node.children):
            callee_name = self._resolve_static_text(node.children[0])
            if callee_name and callee_name.lower() in self.DANGEROUS_SINKS:
                self._record_indirect_dangerous_call(node, callee_name)
                return

        if func_name_lower in self.DANGEROUS_SINKS:
            severity = self.DANGEROUS_SINKS[func_name_lower]

            # 看参数有没有被污染
            is_tainted = False
            taint_info = None
            for arg in node.children:
                arg_tainted, arg_taint = self._is_tainted(arg)
                if arg_tainted:
                    is_tainted = True
                    taint_info = arg_taint
                    break

            call_info = DangerousCallInfo(
                function_name=func_name_lower,
                arguments=[self._node_to_string(arg) for arg in node.children],
                is_tainted=is_tainted,
                taint_info=taint_info,
                severity=severity
            )
            self._dangerous_calls.append(call_info)

            if is_tainted:
                self._findings.append(SemanticFinding(
                    type='tainted_sink',
                    severity=severity,
                    description=f"危险函数 {func_name}() 使用了用户可控输入",
                    code_context=f"{func_name}({', '.join(call_info.arguments[:3])})",
                    taint_chain=taint_info.propagation_chain if taint_info else []
                ))

            # 参数是编码字面量的话，解开再看一层 —— "eval 里装了什么"
            self._try_decode_and_recurse(node, func_name_lower, severity)

    def _record_indirect_dangerous_call(self, node: ASTNode, callee: str) -> None:
        """call_user_func(静态求值出的危险函数名, ...) 按"直接调用"立案。

        与 `$f()` 动态调用（_visit_dynamic_call）同族，只是函数名藏在
        call_user_func 的第一个实参里。还原出名字后：
          - 危险调用记成还原后的名字（resolved_name 可追溯），obfuscation 记
            call_user_func_dynamic，方便报告区分"间接调用"；
          - 参数仍是那批参数，污点判定照旧 —— 参数脏就 is_tainted=True。
        """
        resolved_lower = callee.lower()

        is_tainted = False
        taint_info = None
        for arg in node.children:
            arg_tainted, arg_taint = self._is_tainted(arg)
            if arg_tainted:
                is_tainted = True
                taint_info = arg_taint
                break

        call_info = DangerousCallInfo(
            function_name=resolved_lower,
            arguments=[self._node_to_string(arg) for arg in node.children],
            is_tainted=is_tainted,
            taint_info=taint_info,
            resolved_name=callee,
            obfuscation_method='call_user_func_dynamic',
            severity=self.DANGEROUS_SINKS[resolved_lower]
        )
        self._dangerous_calls.append(call_info)
        self._obfuscation_indicators.append(
            f"call_user_func_dynamic:{resolved_lower}")

        self._findings.append(SemanticFinding(
            type='obfuscated_dangerous_call',
            severity=95,
            description=f"call_user_func 间接调用危险函数 {callee}()",
            code_context=self._node_to_string(node),
            taint_chain=taint_info.propagation_chain if taint_info else []
        ))

        # 参数是编码字面量的话，解开再看一层 —— "assert 里装了什么"
        self._try_decode_and_recurse(node, resolved_lower, call_info.severity)

    def _visit_dynamic_call(self, node: ASTNode) -> None:
        """$func() 这种动态调用"""
        var_name = node.value
        self._obfuscation_indicators.append(f"dynamic_call:{var_name}")

        # 试着解析变量值看看调的是啥
        resolved_name = self._var_values.get(var_name)
        if resolved_name and isinstance(resolved_name, str):
            resolved_lower = resolved_name.lower()

            if resolved_lower in self.DANGEROUS_SINKS:
                is_tainted = False
                taint_info = None
                for arg in node.children:
                    arg_tainted, arg_taint = self._is_tainted(arg)
                    if arg_tainted:
                        is_tainted = True
                        taint_info = arg_taint
                        break

                call_info = DangerousCallInfo(
                    function_name=resolved_lower,
                    arguments=[self._node_to_string(arg) for arg in node.children],
                    is_tainted=is_tainted,
                    taint_info=taint_info,
                    resolved_name=resolved_name,
                    obfuscation_method='dynamic_variable',
                    severity=self.DANGEROUS_SINKS[resolved_lower]
                )
                self._dangerous_calls.append(call_info)

                self._findings.append(SemanticFinding(
                    type='obfuscated_dangerous_call',
                    severity=95,
                    description=f"通过变量函数调用危险函数 {resolved_name}()",
                    code_context=f"{var_name}() → {resolved_name}()",
                    taint_chain=taint_info.propagation_chain if taint_info else []
                ))
        else:
            # 解析不出来，但还是可疑
            is_tainted = any(self._is_tainted(arg)[0] for arg in node.children)
            if is_tainted:
                self._findings.append(SemanticFinding(
                    type='suspicious_dynamic_call',
                    severity=60,
                    description=f"动态函数调用 {var_name}() 使用了用户输入",
                    code_context=f"{var_name}(...)"
                ))

    def _visit_variable_variable(self, node: ASTNode) -> None:
        """$$var 和 ${expr} 这种"""
        self._obfuscation_indicators.append(f"variable_variable:{node.value}")

        # ${} 可能是混淆的超全局变量
        if node.value and node.value.startswith('${'):
            inner = node.value[2:-1] if node.value.endswith('}') else node.value[2:]

            # 检查是否是超全局变量混淆，比如 ${"_P"."OST"} -> $_POST
            if '"' in inner or "'" in inner:
                resolved = self._try_resolve_string_expr(inner)
                if resolved:
                    full_var = '$' + resolved
                    for superglobal in self.TAINT_SOURCES:
                        if superglobal.replace('$', '') in resolved:
                            self._findings.append(SemanticFinding(
                                type='obfuscated_superglobal',
                                severity=80,
                                description=f"混淆的超全局变量访问: {node.value} → {full_var}",
                                code_context=node.value
                            ))
                            self._tainted_vars[node.value] = TaintInfo(
                                source=full_var,
                                propagation_chain=[full_var]
                            )
                            break

    def _visit_concat(self, node: ASTNode) -> None:
        resolved = self._ast_builder.resolve_concat(node)
        if resolved:
            # 看有没有拼出危险函数名
            resolved_lower = resolved.lower()
            if resolved_lower in self.DANGEROUS_SINKS:
                self._obfuscation_indicators.append(f"concat_dangerous:{resolved}")
                self._findings.append(SemanticFinding(
                    type='obfuscated_function_name',
                    severity=85,
                    description=f"通过字符串拼接构造危险函数名: {resolved}",
                    code_context=self._node_to_string(node)
                ))

    def _is_tainted(self, node: ASTNode) -> Tuple[bool, Optional[TaintInfo]]:
        """检查节点是否被污染，带缓存"""
        if node is None:
            return False, None

        node_id = id(node)
        if node_id in self._taint_cache:
            return self._taint_cache[node_id]

        result = self._is_tainted_impl(node)
        self._taint_cache[node_id] = result
        return result

    def _is_tainted_impl(self, node: ASTNode) -> Tuple[bool, Optional[TaintInfo]]:
        if node.type == NodeType.SUPERGLOBAL:
            source = node.value.split('[')[0] if '[' in str(node.value) else node.value
            return True, TaintInfo(source=source, propagation_chain=[source])

        if node.type == NodeType.VARIABLE:
            var_name = node.value
            if var_name in self._tainted_vars:
                return True, self._tainted_vars[var_name]
            base_var = var_name.split('[')[0]
            if base_var in self.TAINT_SOURCES:
                return True, TaintInfo(source=base_var, propagation_chain=[base_var])

        if node.type == NodeType.VARIABLE_VARIABLE:
            if node.value in self._tainted_vars:
                return True, self._tainted_vars[node.value]

        if node.type == NodeType.ARRAY_ACCESS and node.children:
            return self._is_tainted(node.children[0])

        # 污点传播：调用传播函数时参数脏了输出也脏
        if node.type == NodeType.CALL:
            func_name = node.value
            func_name_lower = func_name.lower() if func_name else ''
            if func_name_lower in self.TAINT_PROPAGATORS:
                for arg in node.children:
                    is_tainted, taint_info = self._is_tainted(arg)
                    if is_tainted:
                        return True, taint_info

            # 用户自定义函数（同一份代码里定义过的）：参数脏 -> 返回值脏。
            # 我们没有函数体语义，拿不到"参数经过清洗/只用了一部分"这类信息，
            # 所以取保守方向 —— 宁可多报也不放跑（攻击者可控的上限就是漏洞）。
            # 只认签名表里的名字，内置函数不在表里，行为不被这层改变。
            user_funcs = getattr(self._ast_builder, 'user_functions', None) or {}
            if func_name_lower in user_funcs:
                for arg in node.children:
                    is_tainted, taint_info = self._is_tainted(arg)
                    if is_tainted:
                        return True, TaintInfo(
                            source=taint_info.source if taint_info else 'user_function',
                            propagation_chain=(taint_info.propagation_chain or [])
                                              + [func_name_lower]
                        )

        # 拼接中有脏数据，结果也脏
        if node.type == NodeType.CONCAT:
            for child in node.children:
                is_tainted, taint_info = self._is_tainted(child)
                if is_tainted:
                    return True, taint_info

        # 其他表达式类型只检查直接子节点
        if node.type in (NodeType.BINARY_OP, NodeType.EXPRESSION, NodeType.UNARY_OP, NodeType.TERNARY):
            for child in node.children:
                if isinstance(child, ASTNode):
                    is_tainted, taint_info = self._is_tainted(child)
                    if is_tainted:
                        return True, taint_info

        return False, None

    def _try_resolve_value(self, node: ASTNode) -> Optional[Any]:
        """尝试静态求值"""
        if node is None:
            return None

        if node.type == NodeType.LITERAL:
            return node.value

        if node.type == NodeType.CONCAT:
            return self._ast_builder.resolve_concat(node)

        if node.type == NodeType.CALL:
            # 这里原来自带一份**简化版**的 base64_decode / str_rot13 求值：
            # 只认这两个函数、无预算约束、`.decode('utf-8', errors='ignore')`
            # 会把二进制中间层打烂、而且不记解码链。它还有个更隐蔽的后果 ——
            # 它先于语义解码闭环返回非 None，把 `$c = base64_decode("...")`
            # 的解码链吃掉，导致后面 `eval($c)` 那边拿不到"这是解码来的"。
            #
            # 统一委托给 _resolve_encoded_literal：覆盖全部解码器、共享预算、
            # 二进制无损往返、解码链可追溯。一处实现，不再分叉。
            decoded, chain = self._resolve_encoded_literal(node)
            if decoded is not None and chain:
                return decoded

            # 解码链之后试字符串变换函数：str_replace('u','s','auuert')
            # -> 'assert'。这样 `$f = str_replace(...)` 存进 _var_values，
            # 后面的 `$f()` 动态调用和 call_user_func 还原都能用上。
            return self._static_eval_transform(node, 0)

        return None

    def _try_resolve_string_expr(self, expr: str) -> Optional[str]:
        """解析简单的字符串拼接，如 "_P"."OST" """
        parts = []
        current = ""
        in_string = False
        string_char = None

        for ch in expr:
            if not in_string:
                if ch in '"\'':
                    in_string = True
                    string_char = ch
                elif ch == '.':
                    continue
                elif ch in ' \t':
                    continue
            else:
                if ch == string_char:
                    parts.append(current)
                    current = ""
                    in_string = False
                else:
                    current += ch

        if parts:
            return ''.join(parts)
        return None

    def _node_to_string(self, node: ASTNode) -> str:
        if node is None:
            return ""

        if node.type == NodeType.LITERAL:
            return str(node.value) if node.value is not None else ""

        if node.type == NodeType.VARIABLE:
            return node.value or ""

        if node.type == NodeType.SUPERGLOBAL:
            return node.value or ""

        if node.type == NodeType.CONCAT:
            parts = [self._node_to_string(c) for c in node.children]
            return ' . '.join(parts)

        if node.type == NodeType.ARRAY_ACCESS:
            if len(node.children) >= 2:
                return f"{self._node_to_string(node.children[0])}[{self._node_to_string(node.children[1])}]"

        if node.type == NodeType.CALL:
            args = ', '.join(self._node_to_string(c) for c in node.children)
            return f"{node.value}({args})"

        return f"<{node.type.name}>"

    def _calculate_obfuscation_score(self) -> float:
        score = 0.0
        indicators = self._obfuscation_indicators

        dynamic_calls = sum(1 for i in indicators if i.startswith('dynamic_call:'))
        score += min(dynamic_calls * 0.2, 0.4)

        var_vars = sum(1 for i in indicators if i.startswith('variable_variable:'))
        score += min(var_vars * 0.15, 0.3)

        concat_dangerous = sum(1 for i in indicators if i.startswith('concat_dangerous:'))
        score += min(concat_dangerous * 0.25, 0.4)

        indirect_calls = sum(1 for i in indicators
                             if i.startswith('call_user_func_dynamic:'))
        score += min(indirect_calls * 0.25, 0.4)

        obfuscation_findings = [f for f in self._findings if 'obfuscated' in f.type]
        score += min(len(obfuscation_findings) * 0.1, 0.3)

        return min(score, 1.0)

    def _calculate_confidence_adjustment(self) -> int:
        adjustment = 0

        for call in self._dangerous_calls:
            if call.is_tainted:
                adjustment += call.severity // 2
            elif not self._external_taint:
                # 响应侧才罚。请求侧的代码本身就是攻击者投递的，
                # 参数硬编码不构成"无害"的证据（见 analyze 的 docstring）。
                adjustment -= 20

        if self._obfuscation_indicators:
            adjustment += len(self._obfuscation_indicators) * 10

        for finding in self._findings:
            # attacker_delivered_sink 单独计分，不走这条通用加权，
            # 免得同一个事实被 finding 和下面的 external 分支算两遍。
            if finding.type == 'attacker_delivered_sink':
                continue
            if finding.severity >= 80:
                adjustment += 15
            elif finding.severity >= 60:
                adjustment += 10

        if self._external_taint:
            # 攻击者投递的高危 sink：给正分，但明显低于"参数可控"那档
            # (severity // 2)，保持"有污点链的证据更强"这个序关系。
            for call in self._external_taint_sinks():
                adjustment += call.severity // 4
        elif not self._tainted_vars and self._dangerous_calls:
            # 无污点+有危险函数 → 降低分数（仅响应侧）
            untainted_calls = [c for c in self._dangerous_calls if not c.is_tainted]
            adjustment -= len(untainted_calls) * 30

        return adjustment

    def _is_likely_webshell(self) -> bool:
        # 有污染数据流入危险函数
        tainted_dangerous = any(c.is_tainted for c in self._dangerous_calls)
        if tainted_dangerous:
            return True

        # sink 的参数解码后还是可执行代码，且里面又有 sink。
        # 这个形状在正常代码里不存在，不需要污点链佐证。
        if any(f.type == 'decoded_sink' for f in self._findings):
            return True

        # 攻击者投递的代码里出现 eval/system 这一档的调用。参数是不是硬编码
        # 不影响定性 —— 正常业务不会往 HTTP 请求体里塞这种调用。
        if self._external_taint and self._external_taint_sinks():
            return True

        # 高混淆 + 有危险调用
        if self._calculate_obfuscation_score() > 0.5 and self._dangerous_calls:
            return True

        high_severity = sum(1 for f in self._findings if f.severity >= 70)
        if high_severity >= 2:
            return True

        return False


# 主引擎

class PHPASTEngine:
    """主入口，串起tokenizer -> ast builder -> semantic analyzer"""

    # 一次过分析的长度上限。这以内保持污点追踪的完整保真度（赋值和 sink
    # 在同一棵树里）。给到 256KB 是因为真实 webshell 载荷解码后基本都在这
    # 之内，窗口化是给异常大的载荷兜底用的，不是常规路径。
    DIRECT_LIMIT = 256 * 1024
    # 超过上限后的滑动窗口。重叠区要足够放下一段完整的 "赋值 + 调用"，
    # 否则跨窗口的污点链会断。
    WINDOW_SIZE = 64 * 1024
    WINDOW_OVERLAP = 8 * 1024

    def __init__(self):
        self.tokenizer = PHPTokenizer()
        self.ast_builder = PHPASTBuilder()
        self.semantic_analyzer = SemanticAnalyzer()
        # 共享ast builder实例
        self.semantic_analyzer._ast_builder = self.ast_builder

    def analyze(self, code: str, external_taint: bool = False,
                decode_budget: Optional["DecodeBudget"] = None) -> ASTAnalysisResult:
        if not code or len(code.strip()) < 3:
            return ASTAnalysisResult(external_taint=external_taint)

        try:
            code = self._preprocess(code)
            tokens = self.tokenizer.tokenize(code)
            ast = self.ast_builder.build(tokens)
            result = self.semantic_analyzer.analyze(
                ast, external_taint=external_taint, decode_budget=decode_budget)
            return result

        except Exception as e:
            return ASTAnalysisResult(external_taint=external_taint)

    def analyze_windowed(self, code: str,
                         external_taint: bool = False) -> Tuple[ASTAnalysisResult, bool]:
        """超长代码的兜底分析路径，返回 (结果, 是否走了窗口)。

        为什么不是"太长就跳过"：长度是攻击者可控的。把 webshell 填充到
        阈值以上就能让语义分析整个消失，那是一键绕过（这个 bug 在
        attack_detector 里出现过一次，commit d144e93 修掉；webshell_detect
        里的复制品由本方法替换）。

        窗口化确实会损失跨窗口的污点链，所以只在 DIRECT_LIMIT 以上才启用，
        并且重叠区给得比较宽。调用方拿到 True 时应当留痕，让报告能说清
        "这一条是分段分析的，可能不完整"，而不是假装看全了。
        """
        if not code or len(code.strip()) < 3:
            return ASTAnalysisResult(external_taint=external_taint), False

        if len(code) <= self.DIRECT_LIMIT:
            return self.analyze(code, external_taint=external_taint), False

        merged = ASTAnalysisResult(external_taint=external_taint)
        seen_findings = set()
        seen_calls = set()
        adjustments = []

        # 解码预算按**整条载荷**算一份，所有窗口共用。给每个窗口各发一份的话，
        # 总开销会随窗口数线性膨胀 —— 一段 10MB 的载荷能开出 150 个窗口。
        budget = DecodeBudget() if DecodeBudget is not None else None

        step = max(self.WINDOW_SIZE - self.WINDOW_OVERLAP, 1)
        for start in range(0, len(code), step):
            window = code[start:start + self.WINDOW_SIZE]
            if len(window.strip()) < 3:
                continue
            part = self.analyze(window, external_taint=external_taint,
                                decode_budget=budget)

            for finding in part.findings:
                key = (finding.type, finding.severity, finding.code_context)
                if key in seen_findings:
                    continue
                seen_findings.add(key)
                merged.findings.append(finding)

            for call in part.dangerous_calls:
                key = (call.function_name, call.is_tainted, tuple(call.arguments))
                if key in seen_calls:
                    continue
                seen_calls.add(key)
                merged.dangerous_calls.append(call)

            merged.taint_sources |= part.taint_sources
            merged.obfuscation_score = max(
                merged.obfuscation_score, part.obfuscation_score)
            merged.is_likely_webshell = (
                merged.is_likely_webshell or part.is_likely_webshell)
            merged.max_decode_depth_reached = max(
                merged.max_decode_depth_reached, part.max_decode_depth_reached)
            for chain in part.decode_chains:
                if chain not in merged.decode_chains:
                    merged.decode_chains.append(chain)
            adjustments.append(part.confidence_adjustment)

            if start + self.WINDOW_SIZE >= len(code):
                break

        if budget is not None:
            merged.decode_notes = list(budget.exhausted)

        # 取最有指控力的那个窗口，而不是求和 —— 求和会随窗口数线性放大分数。
        # 全为负时 max 取到惩罚最轻的那个，方向上偏保守（宁可少扣分）。
        merged.confidence_adjustment = max(adjustments) if adjustments else 0
        return merged, True

    def validate_detection(
        self,
        code: str,
        regex_indicators: List[Dict],
        regex_weight: int
    ) -> Tuple[bool, int, str]:
        """用AST语义分析来验证/调整正则检测的结果"""
        result = self.analyze(code)

        adjusted_weight = regex_weight + result.confidence_adjustment

        if result.is_likely_webshell:
            return True, max(adjusted_weight, regex_weight), "ast_confirmed"

        # AST没发现污点流入危险函数，降低权重
        if regex_weight >= 60 and not result.dangerous_calls:
            return False, min(adjusted_weight, 30), "no_dangerous_calls"

        if regex_weight >= 60 and not any(c.is_tainted for c in result.dangerous_calls):
            return False, min(adjusted_weight, 40), "no_taint_propagation"

        if result.obfuscation_score > 0.3:
            return True, adjusted_weight + 20, "obfuscation_detected"

        return adjusted_weight >= 60, adjusted_weight, "ast_adjusted"

    def _preprocess(self, code: str) -> str:
        # 清理PHP标签和BOM
        code = re.sub(r'<\?php\s*', '', code, flags=re.IGNORECASE)
        code = re.sub(r'<\?=?\s*', '', code)
        code = re.sub(r'\?>\s*$', '', code)

        if code.startswith('\ufeff'):
            code = code[1:]

        return code.strip()


def analyze_php_code(code: str, external_taint: bool = False) -> ASTAnalysisResult:
    engine = PHPASTEngine()
    return engine.analyze(code, external_taint=external_taint)


def is_webshell(code: str, external_taint: bool = False) -> bool:
    result = analyze_php_code(code, external_taint=external_taint)
    return result.is_likely_webshell


def get_dangerous_calls(code: str) -> List[DangerousCallInfo]:
    result = analyze_php_code(code)
    return result.dangerous_calls
