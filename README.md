### 简介

一个轻量的局域网文本/文件互传工具。运行后自动开启服务端监听，同时进入交互式 REPL，可发送文本或文件，支持别名切换目标与来源 IP 白名单。

### 环境要求

- Python 3.8 及以上（Windows/macOS/Linux 均可）
- 局域网可达，且接收端防火墙放行所用端口（默认 50080/TCP）

### 安装与启动

1) 克隆或下载本项目后，直接运行：
```bash
python3 lan_transfer.py
```
- Windows 可在 PowerShell 中运行：
```powershell
python .\lan_transfer.py
```

2) 程序会：
- 后台启动服务端监听（默认 `0.0.0.0:50080`，保存目录 `received`）
- 在前台进入 REPL 交互（命令行模式）

3) 配置文件（可选）：
- 程序会自动尝试加载以下任一路径：
  - 工作目录：`lan_config.json`
  - 或用户目录：`~/.lan_transfer.json`
- 也可显式指定：
```bash
python3 lan_transfer.py --config /absolute/path/to/lan_config.json
```

### 配置说明（JSON）

示例：
```json
{
  "bind_host": "0.0.0.0",
  "default_port": 50080,
  "save_dir": "received",
  "encryption_key": "your_secret_password_here",
  "allow_sources": [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "127.0.0.1"
  ],
  "aliases": {
    "pc1": "192.168.1.10",
    "pc2": "192.168.1.11",
    "server": "192.168.1.100"
  },
  "default_target": "server"
}
```
- **bind_host**: 服务端绑定地址（默认 `0.0.0.0`）
- **default_port**: 服务端/客户端默认端口（默认 `50080`）
- **save_dir**: 接收文件保存目录
- **encryption_key**: 加密密钥（可选），启用后所有传输内容将被加密
- **allow_sources**: 允许来源 IP 白名单，支持单 IP 与 CIDR（留空表示不限制）
- **aliases**: 发送目标别名映射，REPL 中通过别名选择目标
- **default_target**: 默认发送目标的别名（可选）

### REPL 命令

- **text**: 切换为发送文本模式；随后输入的每一行会作为文本发送
- **file**: 切换为发送文件模式；随后输入的每一行会被当作文件路径并发送（显示进度）
- **sendto+别名**、**sendto 别名** 或 **sendto别名**: 切换发送对象（从配置的 `aliases` 中解析）
- **targets**: 查看所有可用别名
- **show**: 显示当前模式/目标/端口
- **help**: 显示帮助
- **exit**: 退出程序

提示：若未设置目标，先用 `sendto+别名`（或 `sendto 别名` / `sendto别名`）选择，或在配置中设置 `default_target`。

### 运行示例

1) 机器 A（接收端 + 交互）
```bash
python3 lan_transfer.py
# 首次运行会显示配置加载、服务端监听信息
```

2) 机器 B（发送端 + 交互）
```bash
python3 lan_transfer.py
targets
sendto+server
text
你好，局域网！
file
/path/to/file.png
```

### 文件传输进度

- 发送端与接收端均会以进度条显示进度、速率（B/s, KB/s, MB/s 等）

### 常见问题与注意事项

- **防火墙**: 首次运行可能弹窗请求放行；如被拦截，手动允许 `python` 进程在本地网络通信
- **端口占用**: 默认端口为 50080，可在配置中调整 `default_port`
- **权限**: 目标保存目录不可写会导致接收失败；修改 `save_dir` 或赋予权限
- **字符集**: 终端需支持 UTF-8 才能正确显示中文

### 加密功能

- **标准库实现**: 本工具使用 Python 标准库（`hashlib`, `secrets`, `hmac`, `base64`）实现加密功能，无需安装第三方库
- **加密算法**: 使用基于 HMAC-SHA256 和 XOR 的加密方案，每次加密都会生成随机 IV
- **配置启用**: 在配置文件中添加 `encryption_key` 字段即可启用加密
- **兼容性**: 加密功能向后兼容，未配置密钥时仍可正常使用（不加密）

### 跨平台说明

- 本工具基于 Python 标准库实现，适用于 **Windows / macOS / Linux**
- Windows 使用 PowerShell/CMD 即可运行；macOS/Linux 使用终端运行
- 若需在公网上使用，请自行加一层隧道或加密（如 SSH 转发/TLS），本工具默认不加密、不鉴权


