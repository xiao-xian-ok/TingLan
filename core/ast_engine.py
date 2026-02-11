# ast_engine.py - PHP AST引擎
# 词法分析 + 语法分析 + 污点追踪

import re
import base64
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any, Union


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

    def to_dict(self) -> Dict:
        return {
            'findings': [f.to_dict() for f in self.findings],
            'dangerous_calls': [
                {
                    'function': c.function_name,
                    'is_tainted': c.is_tainted,
                    'severity': c.severity,
                    'obfuscation': c.obfuscation_method
                }
                for c in self.dangerous_calls
            ],
            'taint_sources': list(self.taint_sources),
            'obfuscation_score': self.obfuscation_score,
            'is_likely_webshell': self.is_likely_webshell,
            'confidence_adjustment': self.confidence_adjustment
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

    def build(self, tokens: List[Token]) -> ASTNode:
        """从token列表构建AST"""
        self._tokens = tokens
        self._pos = 0
        self._length = len(tokens)

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

        return root

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

    def analyze(self, ast: ASTNode) -> ASTAnalysisResult:
        """分析AST，跑污点追踪+混淆检测"""
        self._tainted_vars = {}
        self._var_values = {}
        self._findings = []
        self._dangerous_calls = []
        self._obfuscation_indicators = []
        self._taint_cache = {}  # _is_tainted结果缓存

        self._visit(ast)

        obfuscation_score = self._calculate_obfuscation_score()
        confidence_adjustment = self._calculate_confidence_adjustment()
        is_likely_webshell = self._is_likely_webshell()

        return ASTAnalysisResult(
            findings=self._findings,
            dangerous_calls=self._dangerous_calls,
            taint_sources=set(self._tainted_vars.keys()),
            obfuscation_score=obfuscation_score,
            is_likely_webshell=is_likely_webshell,
            confidence_adjustment=confidence_adjustment
        )

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

            # 追踪变量值
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
            return

        func_name_lower = func_name.lower()

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
            if func_name and func_name.lower() in self.TAINT_PROPAGATORS:
                for arg in node.children:
                    is_tainted, taint_info = self._is_tainted(arg)
                    if is_tainted:
                        return True, taint_info

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
            func_name = node.value
            if func_name and func_name.lower() == 'base64_decode':
                if node.children:
                    arg_value = self._try_resolve_value(node.children[0])
                    if arg_value and isinstance(arg_value, str):
                        try:
                            decoded = base64.b64decode(arg_value).decode('utf-8', errors='ignore')
                            return decoded
                        except Exception:
                            pass

            if func_name and func_name.lower() == 'str_rot13':
                if node.children:
                    arg_value = self._try_resolve_value(node.children[0])
                    if arg_value and isinstance(arg_value, str):
                        import codecs
                        return codecs.decode(arg_value, 'rot_13')

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

        obfuscation_findings = [f for f in self._findings if 'obfuscated' in f.type]
        score += min(len(obfuscation_findings) * 0.1, 0.3)

        return min(score, 1.0)

    def _calculate_confidence_adjustment(self) -> int:
        adjustment = 0

        for call in self._dangerous_calls:
            if call.is_tainted:
                adjustment += call.severity // 2
            else:
                adjustment -= 20

        if self._obfuscation_indicators:
            adjustment += len(self._obfuscation_indicators) * 10

        for finding in self._findings:
            if finding.severity >= 80:
                adjustment += 15
            elif finding.severity >= 60:
                adjustment += 10

        # 无污点+有危险函数 → 降低分数
        if not self._tainted_vars and self._dangerous_calls:
            untainted_calls = [c for c in self._dangerous_calls if not c.is_tainted]
            adjustment -= len(untainted_calls) * 30

        return adjustment

    def _is_likely_webshell(self) -> bool:
        # 有污染数据流入危险函数
        tainted_dangerous = any(c.is_tainted for c in self._dangerous_calls)
        if tainted_dangerous:
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

    def __init__(self):
        self.tokenizer = PHPTokenizer()
        self.ast_builder = PHPASTBuilder()
        self.semantic_analyzer = SemanticAnalyzer()
        # 共享ast builder实例
        self.semantic_analyzer._ast_builder = self.ast_builder

    def analyze(self, code: str) -> ASTAnalysisResult:
        if not code or len(code.strip()) < 3:
            return ASTAnalysisResult()

        try:
            code = self._preprocess(code)
            tokens = self.tokenizer.tokenize(code)
            ast = self.ast_builder.build(tokens)
            result = self.semantic_analyzer.analyze(ast)
            return result

        except Exception as e:
            return ASTAnalysisResult()

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


def analyze_php_code(code: str) -> ASTAnalysisResult:
    engine = PHPASTEngine()
    return engine.analyze(code)


def is_webshell(code: str) -> bool:
    result = analyze_php_code(code)
    return result.is_likely_webshell


def get_dangerous_calls(code: str) -> List[DangerousCallInfo]:
    result = analyze_php_code(code)
    return result.dangerous_calls
