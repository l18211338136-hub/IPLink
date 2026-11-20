# IPLink Windows 部署与配置指南

本文档说明如何在 **Windows（AMD64 / x86_64）** 环境下编译、部署并配置 IPLink 服务端与客户端。

---

## 1. 编译与获取二进制文件

IPLink 使用纯 Go 标准库编写，无外部运行时依赖，可直接编译为单文件 `.exe` 程序。

### 方式一：在 Linux / WSL 中交叉编译（推荐）

在项目根目录执行：

```bash
# 编译全平台产物（包含 Windows amd64）
make build-all
```

或单独编译 Windows 版本：

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/iplink-server-windows-amd64.exe ./cmd/server
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/iplink-client-windows-amd64.exe ./cmd/client
```

### 方式二：在 Windows 本机直接编译

若 Windows 已安装 Go（1.26+），在 PowerShell 中进入项目目录执行：

```powershell
mkdir bin -Force
go build -o bin\iplink-server.exe .\cmd\server
go build -o bin\iplink-client.exe .\cmd\client
```

| 文件 | 适用端 | 说明 |
|---|---|---|
| `iplink-server-windows-amd64.exe` | Windows 服务端 | 控制面、TCP/UDP 隧道监听、HTTP 反向代理、NAT 探测与 Relay 中继 |
| `iplink-client-windows-amd64.exe` | Windows 客户端 | 内网服务接入、心跳保活、自动重连与流量转发 |

> 配置文件（`server.json` / `client.json`）与 `.exe` 分离存放，修改配置后重启对应进程即可生效。

---

### 1.1 生成认证密钥（IPLINK_TOKEN）

`IPLINK_TOKEN` 可自行设定任意非空字符串（底层作为 `HMAC-SHA256` 签名密钥），只需保证**服务端与所有客户端完全一致**。

在 **PowerShell** 中生成 64 位随机十六进制密钥：

```powershell
-join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })
```

两种写入方式任选其一：
- **环境变量注入（推荐）**：`server.json` / `client.json` 中保持 `"token": "${IPLINK_TOKEN}"`，启动前设置环境变量 `$env:IPLINK_TOKEN` 或写入系统环境变量。
- **直接写入 JSON**：将 `"${IPLINK_TOKEN}"` 替换为生成的密钥字符串（若自定义密码，请避免包含 `$` 符号，以免被环境变量解析器误展开）。

---

## 2. 客户端部署（Windows 内网主机，常见场景）

假设你希望将 Windows 本机或局域网的服务（例如本地 Ollama `11434`、Web 服务、远程桌面等）通过公网服务端暴露出去。

### 2.1 准备目录与配置文件

在 PowerShell 中创建目录（例如 `C:\iplink`），将 `iplink-client-windows-amd64.exe` 重命名为 `iplink-client.exe` 放入其中，并创建 `C:\iplink\client.json`：

```powershell
New-Item -ItemType Directory -Path C:\iplink -Force
```

示例 `C:\iplink\client.json`（以穿透本机 Ollama `11434` 端口为例）：

```json
{
  "client": {
    "id": "windows-lan-01"
  },
  "server": {
    "address": "203.0.113.10",
    "port": 29000,
    "relay_port": 29001,
    "nat_port": 29002
  },
  "security": {
    "tls_enabled": false,
    "tls_insecure_skip_verify": false,
    "token": "${IPLINK_TOKEN}",
    "allowed_targets": [
      "127.0.0.1:11434"
    ]
  },
  "network": {
    "enable_tcp": true,
    "enable_udp": false,
    "enable_p2p": true
  },
  "reconnect": {
    "enabled": true,
    "max_attempts": 0,
    "interval_seconds": 5
  },
  "tunnels": [
    {
      "name": "ollama",
      "protocol": "tcp",
      "local_addr": "127.0.0.1:11434",
      "remote_addr": "0.0.0.0:11434"
    }
  ],
  "logging": {
    "level": "info",
    "format": "text"
  }
}
```

**关键配置说明**：
- `client.id`：客户端唯一标识；同一 `id` 重连会替换旧会话。
- `server.address`：**必须填写服务端公网纯 IP**，不能填写域名。
- `security.allowed_targets`：内网访问白名单，建议按需收敛到具体 `IP:Port`（如 `127.0.0.1:11434` 或 `192.168.1.0/24:*`）。
- `tunnels`：支持同时配置多条 `tcp` / `udp` / `http` 隧道。

### 2.2 前台启动与测试

在 PowerShell 中执行：

```powershell
cd C:\iplink
$env:IPLINK_TOKEN = "替换为与服务端一致的密钥"
.\iplink-client.exe connect --config C:\iplink\client.json
```

看到 `connected to IPLink server` 和 `tunnel registered` 日志即表示连接并注册成功。

---

## 3. 服务端部署（Windows 公网服务器，可选）

如果服务端也部署在 Windows Server 上，步骤如下：

### 3.1 准备配置文件 `C:\iplink\server.json`

```json
{
  "server": {
    "listen_ip": "0.0.0.0",
    "control_port": 29000,
    "relay_port": 29001,
    "nat_port": 29002,
    "http_proxy_port": 28080
  },
  "security": {
    "tls_enabled": false,
    "tls_cert_file": "",
    "tls_key_file": "",
    "token": "${IPLINK_TOKEN}"
  },
  "relay": {
    "enabled": true,
    "max_sessions": 1000,
    "max_bytes_per_sec": 0
  },
  "logging": {
    "level": "info",
    "format": "json"
  }
}
```

### 3.2 放行 Windows 防火墙端口

以**管理员身份**运行 PowerShell，放行服务端所需端口：

```powershell
New-NetFirewallRule -DisplayName "IPLink Control"    -Direction Inbound -Protocol TCP -LocalPort 29000 -Action Allow
New-NetFirewallRule -DisplayName "IPLink Relay"      -Direction Inbound -Protocol UDP -LocalPort 29001 -Action Allow
New-NetFirewallRule -DisplayName "IPLink NAT"        -Direction Inbound -Protocol UDP -LocalPort 29002 -Action Allow
New-NetFirewallRule -DisplayName "IPLink HTTP Proxy" -Direction Inbound -Protocol TCP -LocalPort 28080 -Action Allow
# 若客户端穿透了其他端口（如 11434），需同步放行对应端口：
# New-NetFirewallRule -DisplayName "IPLink Ollama" -Direction Inbound -Protocol TCP -LocalPort 11434 -Action Allow
```

> 若服务器位于阿里云、腾讯云、AWS 等云平台，还需同步在云厂商控制台的**安全组**中放行对应端口。

### 3.3 启动服务端

```powershell
cd C:\iplink
$env:IPLINK_TOKEN = "替换为你的强随机密钥"
.\iplink-server.exe start --config C:\iplink\server.json
```

---

## 4. 后台常驻与开机自启

### 方式一：使用 NSSM 注册为 Windows 系统服务（推荐）

[NSSM](https://nssm.cc/) 可以将任意 `.exe` 托管为标准 Windows 服务，支持崩溃自动重启与日志输出。

以托管客户端为例（**管理员 PowerShell**）：

```powershell
# 1. 安装服务
nssm install IPLinkClient "C:\iplink\iplink-client.exe"
nssm set IPLinkClient AppParameters "connect --config C:\iplink\client.json"
nssm set IPLinkClient AppDirectory "C:\iplink"

# 2. 注入环境变量（若 JSON 中直接写了密钥可跳过此行）
nssm set IPLinkClient AppEnvironmentExtra "IPLINK_TOKEN=替换为你的密钥"

# 3. 配置日志输出（可选，便于排查）
nssm set IPLinkClient AppStdout "C:\iplink\client.log"
nssm set IPLinkClient AppStderr "C:\iplink\client-err.log"

# 4. 启动服务并设为开机自启
nssm set IPLinkClient Start SERVICE_AUTO_START
nssm start IPLinkClient
```

常用服务管理命令：

```powershell
nssm status IPLinkClient
nssm restart IPLinkClient
nssm stop IPLinkClient
```

> 若要托管服务端，将程序与参数分别替换为 `C:\iplink\iplink-server.exe` 和 `start --config C:\iplink\server.json` 即可。

### 方式二：使用 Windows 任务计划程序（无需第三方工具）

如果已经在 JSON 中写死了 `token`（或已在 Windows **系统环境变量** 中添加了 `IPLINK_TOKEN`），可以直接在**管理员 PowerShell** 中创建一个开机自启任务：

```powershell
$action = New-ScheduledTaskAction -Execute "C:\iplink\iplink-client.exe" -Argument "connect --config C:\iplink\client.json" -WorkingDirectory "C:\iplink"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "IPLinkClient" -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest
Start-ScheduledTask -TaskName "IPLinkClient"
```

---

## 5. 常用运维与排查命令

```powershell
# 校验配置文件语法与必填字段
.\iplink-client.exe status --config C:\iplink\client.json
.\iplink-server.exe status --config C:\iplink\server.json

# 查看当前在线客户端
.\iplink-client.exe peers --config C:\iplink\client.json

# 测试服务端控制端口是否可达
Test-NetConnection -ComputerName 203.0.113.10 -Port 29000
```

### 常见问题

1. **提示 `security.token is required`**：检查是否设置了 `$env:IPLINK_TOKEN`（注意：`setx` 设置的环境变量需**新开一个终端窗口**或重启服务后才生效）。
2. **提示 `authentication failed`**：检查客户端与服务端的 `IPLINK_TOKEN` 是否一致，以及两端系统时间差是否在 60 秒以内（可在 Windows 上同步时间）。
3. **提示 `target ... is not permitted by allowed_targets policy`**：`local_addr` 未在客户端 `security.allowed_targets` 中放行。
4. **外部无法访问穿透端口**：确认服务端防火墙及云服务器安全组已放行对应的 `remote_addr` 端口，且目标本地服务（如 Ollama）已在客户端本机正常监听。
