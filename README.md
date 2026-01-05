# mcp-GraphQL

> **Model-assisted Cyber Penetration for GraphQL**
> 一个轻量级、AI 驱动的 GraphQL 自动化漏洞探测工具。利用大语言模型（LLM）智能分析 Schema，自动构造并验证 SSRF、RCE、信息泄露等漏洞。

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## 🔍 功能特性

- ✅ 自动 GraphQL 指纹识别（支持 100+ 常见路径）
- ✅ 内省（Introspection）泄露检测与 Schema 获取
- ✅ **完整内省查询**：获取所有类型、枚举、输入类型、接口信息
- ✅ Mutation & Query 参数自动提取与风险分析
- ✅ **AI 驱动**：大模型生成 SSRF/RCE/SQLi/信息泄露 Payload
- ✅ **智能 Fuzzing**：AI 分析响应并迭代优化 Payload（默认启用，3 轮迭代）
- ✅ **智能字段处理**：使用 `__typename` 避免猜测字段错误
- ✅ **多维度 RCE 检测**：时间盲注 + 回显检测（whoami/id）+ OAST 外连
- ✅ 自动漏洞验证（OAST + 时间盲注 + 关键词匹配）
- ✅ **自动错误修复**：GraphQL 语法错误自动修复与重试
- ✅ **HTML 报告生成**：精美的漏洞报告，支持 HTML/JSON/Markdown 格式
- ✅ **认证支持**：自定义 Headers、Cookies、认证文件
- ✅ **代理支持**：HTTP/HTTPS/SOCKS5 代理，方便与 Burp Suite 联动
- ✅ 清晰的控制台彩色输出
- ✅ 支持多种 LLM（Qwen、Ollama/Llama3）

## 🚀 快速开始

### 1. 环境要求

- Python 3.8+
- pip 包管理器

### 2. 安装依赖

```bash
git clone https://github.com/yourusername/GraphQL-MCP.git
cd GraphQL-MCP
pip install -r requirements.txt
```

### 3. 配置 LLM API

#### 方式一：使用阿里云 Qwen（推荐）

1. 访问 [阿里云 DashScope](https://dashscope.aliyun.com) 获取免费 API Key
2. 设置环境变量：

```bash
# Windows
set DASHSCOPE_API_KEY=your_api_key_here

# Linux/macOS
export DASHSCOPE_API_KEY=your_api_key_here
```

或直接在命令行使用 `--api-key` 参数。

#### 方式二：使用本地 Ollama（离线）

```bash
# 安装 Ollama
# https://ollama.ai

# 启动 Ollama 服务
ollama serve

# 下载 Llama3 模型
ollama pull llama3
```

### 4. 运行扫描

```bash
# 最简单用法：直接启用 AI Fuzz 模式（默认 3 轮迭代）
python mcp-graphql.py --url https://target.com

# 使用 Qwen（默认）
python mcp-graphql.py --url https://target.com --oast-domain yourid.oastify.com

# 使用本地 Llama3
python mcp-graphql.py --url https://target.com --model llama3

# 跳过 LLM，仅做基础扫描
python mcp-graphql.py --url https://target.com --skip-llm

# 禁用 AI Fuzz，使用传统单次生成模式
python mcp-graphql.py --url https://target.com --no-fuzz

# 自定义迭代次数
python mcp-graphql.py --url https://target.com --max-iterations 5

# 保存报告（支持 .html, .json, .md 格式）
python mcp-graphql.py --url https://target.com --output report.html
```

![img](image.png)

![img](image2.png)

### 5. 查看结果

- 控制台会实时显示扫描进度和发现的漏洞
- **自动生成 HTML 报告**（默认 `report.html`），包含漏洞详情和 AI 分析
- 对于 SSRF 漏洞，需要手动检查 OAST 平台（如 [Interact.sh](https://interact.sh) 或 [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator)）是否有回连

## ⚙️ 参数说明

| 参数              | 说明                                       | 默认值                  |
| ----------------- | ------------------------------------------ | ----------------------- |
| `--url`           | 目标基础 URL（必填）                       | -                       |
| `--oast-domain`   | OAST 域名（用于 SSRF 检测）                | example.oastify.com     |
| `--model`         | LLM 模型：`qwen` 或 `llama3`/其他 Ollama   | qwen                    |
| `--api-key`       | Qwen API Key（也可用环境变量）             | -                       |
| `--timeout`       | 请求超时时间（秒）                         | 10                      |
| `--llm-timeout`   | LLM API 调用超时时间（秒）                 | 60                      |
| `--output`, `-o`  | 输出报告文件（.json, .md 或 .html）        | report.html             |
| `--skip-llm`      | 跳过 LLM 分析，仅做基础扫描                | false                   |
| `--no-fuzz`       | 禁用智能 AI Fuzzing（默认启用）            | false                   |
| `--max-iterations`| 智能 Fuzzing 最大迭代次数                  | 3                       |
| `--header`, `-H`  | 添加自定义 Header（可多次使用）            | -                       |
| `--cookie`, `-c`  | 添加 Cookie（可多次使用）                  | -                       |
| `--auth-file`     | 从 JSON 文件加载认证信息                   | -                       |
| `--proxy`, `-x`   | 设置代理（http/https/socks5）              | -                       |

## 🔐 认证与代理

### 使用 Header 认证

```bash
# Bearer Token
python mcp-graphql.py --url https://target.com -H "Authorization: Bearer eyJhbG..."

# API Key
python mcp-graphql.py --url https://target.com -H "X-API-Key: your-api-key"

# 多个 Header
python mcp-graphql.py --url https://target.com -H "Authorization: Bearer xxx" -H "X-Custom: value"
```

### 使用 Cookie 认证

```bash
# 单个 Cookie
python mcp-graphql.py --url https://target.com -c "session=abc123"

# 多个 Cookie
python mcp-graphql.py --url https://target.com -c "session=abc123" -c "token=xyz789"
```

### 使用认证文件

创建 `auth.json` 文件：

```json
{
  "headers": {
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "X-API-Key": "your-api-key"
  },
  "cookies": {
    "session": "abc123",
    "token": "xyz789"
  }
}
```

```bash
python mcp-graphql.py --url https://target.com --auth-file auth.json
```

### 使用代理

```bash
# HTTP 代理（Burp Suite）
python mcp-graphql.py --url https://target.com --proxy http://127.0.0.1:8080

# HTTPS 代理
python mcp-graphql.py --url https://target.com -x https://127.0.0.1:8080

# SOCKS5 代理
python mcp-graphql.py --url https://target.com -x socks5://127.0.0.1:1080

# 组合使用（认证 + 代理）
python mcp-graphql.py --url https://target.com -H "Authorization: Bearer xxx" -x http://127.0.0.1:8080
```

## 🧠 工作原理

```mermaid
graph LR
A[Target URL] --> B(探测 GraphQL 端点)
B --> C{内省可用?}
C -->|Yes| D[提取 Mutations & Queries]
D --> E[分析参数风险]
E --> F[LLM 生成 Payload]
F --> G[发送 Payload]
G --> H[验证漏洞]
H --> I[生成报告]
```

### 扫描流程

1. **指纹识别**：自动探测 `/graphql`、`/api/graphql` 等常见路径
2. **Schema 获取**：发送 Introspection Query 获取完整 Schema
3. **参数分析**：提取 Mutation/Query 参数，基于命名推断风险类型
4. **AI 分析**：将 Schema 信息传给 LLM，生成针对性 Payload
5. **漏洞验证**：
   - **SSRF**：使用 OAST 域名，检查是否回连
   - **RCE**：多维度检测
     - 时间盲注：测量响应时间（`sleep 5` > 4s 判定为阳性）
     - 回显检测：检测 `whoami`、`id`、`uname -a` 等命令输出
     - OAST 外连：`curl`、`nslookup` 回连检测
   - **SQLi**：检查响应中是否包含 SQL 错误信息
   - **信息泄露**：匹配响应中的敏感关键词（password、token 等）
6. **报告生成**：输出彩色控制台报告，可选保存为 JSON/Markdown

## 📊 示例输出

```
  ███╗   ███╗ ██████╗██████╗        ██████╗ ██████╗  █████╗ ██████╗ ██╗  ██╗ ██████╗ ██╗
  ████╗ ████║██╔════╝██╔══██╗      ██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██║  ██║██╔═══██╗██║
  ██╔████╔██║██║     ██████╔╝█████╗██║  ███╗██████╔╝███████║██████╔╝███████║██║   ██║██║
  ██║╚██╔╝██║██║     ██╔═══╝ ╚════╝██║   ██║██╔══██╗██╔══██║██╔═══╝ ██╔══██║██║▄▄ ██║██║
  ██║ ╚═╝ ██║╚██████╗██║           ╚██████╔╝██║  ██║██║  ██║██║     ██║  ██║╚██████╔╝███████╗
  ╚═╝     ╚═╝ ╚═════╝╚═╝            ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚══▀▀═╝ ╚══════╝

  Model-assisted Cyber Penetration for GraphQL
  AI 驱动的 GraphQL 自动化漏洞探测工具
  [!] 仅用于授权渗透测试

[*] 正在探测 GraphQL 端点: https://target.com
[+] 发现 GraphQL 端点: https://target.com/graphql
[*] 正在获取 GraphQL Schema (Introspection)...
[+] 成功获取 Schema
[*] 发现 5 个 Mutations
[*] 发现 12 个 Queries

============================================================
Schema 分析结果
============================================================

Mutations:
  - importPaste [风险: ssrf, path_traversal]
      host: String (ssrf)
      port: Int
      path: String (ssrf, path_traversal)
  - executeCommand [风险: rce]
      cmd: String (rce)

[*] 正在调用 Qwen API 生成 Payload...
[+] LLM Payload 生成成功

============================================================
漏洞验证
============================================================

[*] 测试 Payload #1 [SSRF]
  mutation { importPaste(host: "abc.oastify.com", port: 80, path: "/") { result } }
[!] SSRF Payload 已发送，请检查 OAST 平台

[*] 测试 Payload #2 [RCE]
  mutation { executeCommand(cmd: "sleep 5") { output } }
[VULN] RCE: 响应时间 5.12s，可能存在命令注入!

============================================================
漏洞扫描报告
============================================================

发现 1 个潜在漏洞:

[漏洞 #1]
  类型: RCE
  详情: 响应时间 5.12s，可能存在命令注入
  Payload: mutation { executeCommand(cmd: "sleep 5") { output } }

[提醒] 请检查 OAST 平台 (abc.oastify.com) 确认 SSRF 漏洞
```

## 🎯 测试目标

以下是一些公开的 GraphQL 测试环境：

- [DVGA (Damn Vulnerable GraphQL Application)](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application)
- [GraphQL Voyager Demo](https://apis.guru/graphql-voyager/)
- 你自己搭建的测试环境

**注意**：请勿对未授权目标使用本工具！

## 🛠 高级用法

### 自定义 OAST 平台

```bash
# 使用 Interact.sh
curl https://interact.sh/register  # 获取你的域名
python mcp-graphql.py --url https://target.com --oast-domain xxxxx.oastify.com

# 使用 Burp Collaborator
python mcp-graphql.py --url https://target.com --oast-domain xxxxx.burpcollaborator.net
```

### 批量扫描

```bash
#!/bin/bash
for url in $(cat targets.txt); do
  python mcp-graphql.py --url $url --output reports/${url//\//_}.json
done
```

## ⚠️ 注意事项

### 潜在风险

使用本工具进行扫描可能对目标系统造成以下影响：

1. **服务中断**：DoS 测试 Payload 可能导致目标服务响应缓慢或崩溃
2. **数据污染**：XSS、SQL 注入等 Payload 可能在数据库中写入测试数据
3. **日志告警**：大量异常请求可能触发目标系统的安全告警和 WAF 拦截
4. **资源消耗**：批量查询和深度递归查询可能消耗目标服务器资源
5. **账户封禁**：频繁的异常请求可能导致 IP 或账户被封禁

### 使用建议

- ✅ 仅在获得明确书面授权后使用
- ✅ 优先在测试/沙箱环境中进行测试
- ✅ 使用 `--proxy` 参数配合 Burp Suite 手动审查 Payload
- ✅ 控制扫描频率，避免对目标造成过大压力
- ✅ 测试完成后清理测试数据
- ❌ 切勿对生产环境进行未授权测试
- ❌ 切勿对第三方系统进行未授权扫描

## 🛡 免责声明

**本工具仅用于授权渗透测试、安全研究和教育目的。**

### 法律声明

1. **授权要求**：使用本工具前，您必须获得目标系统所有者的明确书面授权
2. **合法用途**：本工具仅供以下场景使用：
   - 企业内部安全测试
   - 授权的渗透测试项目
   - CTF 比赛和安全研究
   - 个人搭建的测试环境
3. **禁止滥用**：严禁将本工具用于任何非法活动，包括但不限于：
   - 未经授权访问计算机系统
   - 破坏或干扰网络服务
   - 窃取、篡改或删除数据
   - 任何违反当地法律法规的行为

### 责任限制

- **使用者责任**：使用者需对使用本工具的所有行为承担全部法律责任
- **作者免责**：工具作者不对任何因使用或滥用本工具而导致的直接或间接损害承担责任
- **无担保**：本工具按"原样"提供，不提供任何明示或暗示的担保

### 合规要求

使用本工具时，请确保遵守：
- 《中华人民共和国网络安全法》
- 《中华人民共和国刑法》相关条款
- 当地适用的计算机犯罪法律
- 目标组织的安全政策和服务条款

**下载、安装或使用本工具即表示您已阅读、理解并同意以上条款。**

---

**⭐ 如果这个项目对你有帮助，请给个 Star！**
