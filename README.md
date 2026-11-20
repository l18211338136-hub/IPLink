# IPLink

**IPLink** 是一个使用 Go 语言开发的轻量级、跨平台 **Pure IP Network Tunneling System（纯 IP 内网穿透系统）**。

## 核心特性

- **纯 IP 通信**：不依赖 DNS 域名，直接使用 IP 地址与端口建立连接。
- **Client / Server 分离架构**：服务端负责控制面协调、隧道监听与 Relay 中继；客户端负责内网服务映射与转发。
- **TCP / UDP 内网穿透**：支持将内网 TCP 服务（HTTP、SSH、数据库等）和 UDP 服务映射到服务端端口。
- **Direct First + Relay Fallback**：支持 UDP NAT 公网地址发现与 UDP Hole Punching，打洞失败时自动回退至 Server Relay 中继。
- **安全认证与权限控制**：
  - Challenge-Response HMAC-SHA256 身份认证（不传输明文 Token，防重放）。
  - 可选 TLS 1.3 加密传输。
  - `allowed_targets` 目标地址白名单，防止被滥用为开放代理。
- **自动重连与优雅退出**：支持心跳保活、断线自动重连、上下文取消与资源回收。

## 目录结构

```text
IPLink/
├── cmd/
│   ├── client/main.go          # 客户端 CLI 入口
│   └── server/main.go          # 服务端 CLI 入口
├── internal/
│   ├── client/service/         # 客户端核心控制、隧道转发、P2P/Relay 协调
│   ├── server/
│   │   ├── service/            # 服务端控制面、TCP/UDP 隧道监听与转发
│   │   └── session/            # 会话生命周期与心跳超时管理
│   ├── protocol/               # 帧编解码、消息定义、JSON/二进制 Codec
│   ├── transport/tcp/          # TCP / TLS 1.3 传输封装
│   ├── nat/                    # UDP NAT 公网地址发现与打洞
│   ├── relay/manager/          # UDP Relay 会话管理与转发
│   ├── security/               # HMAC-SHA256 认证、TLS 1.3、目标白名单
│   ├── config/                 # JSON 配置加载、环境变量展开与校验
│   ├── logger/                 # 基于 slog 的结构化日志
│   └── metrics/                # 运行时原子指标统计
├── pkg/protocol/               # 公共协议头与消息类型定义
├── configs/                    # 配置示例
├── docs/architecture/decisions/# 架构决策记录 (ADR)
└── test/integration/           # 端到端集成测试
```

## 快速开始

### 1. 编译

```bash
go build -o bin/iplink-server ./cmd/server
go build -o bin/iplink-client ./cmd/client
```

### 2. 配置与启动服务端

复制并修改 `configs/server.json.example` 为 `configs/server.json`，设置环境变量 `IPLINK_TOKEN`：

```bash
export IPLINK_TOKEN="your-strong-secret-token"
./bin/iplink-server start --config configs/server.json
```

### 3. 配置与启动客户端

复制并修改 `configs/client.json.example` 为 `configs/client.json`：

```bash
export IPLINK_TOKEN="your-strong-secret-token"
./bin/iplink-client connect --config configs/client.json
```

或使用单条命令行快速创建隧道：

```bash
./bin/iplink-client tunnel tcp --config configs/client.json --local 127.0.0.1:8080 --remote 0.0.0.0:18080
./bin/iplink-client tunnel udp --config configs/client.json --local 127.0.0.1:5353 --remote 0.0.0.0:15353
```

## 测试

```bash
go vet ./...
go test -v ./...
```
