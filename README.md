# IPLink

**IPLink** 是一个使用 Go 语言开发的轻量级、跨平台 **Pure IP Network Tunneling System（纯 IP 内网穿透系统）**。

> 协议版本 2：UDP 通道全面加密，与 v1 客户端不兼容（v1 帧会被服务端直接拒绝），升级时请两端同步。

## 核心特性

- **纯 IP 通信**：不依赖 DNS 域名，直接使用 IP 地址与端口建立连接。
- **Client / Server 分离架构**：服务端负责控制面协调、隧道监听与 Relay 中继；客户端负责内网服务映射与转发。
- **TCP / UDP 内网穿透**：支持将内网 TCP 服务（HTTP、SSH、数据库等）和 UDP 服务映射到服务端端口。
- **Direct First + Relay Fallback**：支持 UDP NAT 公网地址发现与 UDP Hole Punching，打洞失败时自动回退至 Server Relay 中继；两端都会建立可收发的通道，Relay 会话由服务端自动通知对端加入。
- **安全认证与权限控制**：
  - Challenge-Response HMAC-SHA256 身份认证（不传输明文 Token，防重放）。
  - 全链路加密：控制面走 TLS 1.3；启用 TLS 后 HTTP 代理与指标端点也升级为 HTTPS。
  - UDP 数据报加密：NAT 发现、P2P 打洞与通道、Relay 转发载荷均用 token 派生的 AES-256-GCM 密钥加密（每包随机 nonce，防重放/篡改），零外部依赖。
  - `allowed_targets` 目标地址白名单，防止被滥用为开放代理。
- **半开连接检测**：客户端连续 3 个心跳周期（默认 60s）收不到 PONG 即主动断开并重连，避免链路单向中断时的"假在线"。
- **出口限速**：Relay 的 `relay.max_bytes_per_sec` 令牌桶限流（<=0 不限速），超速率的数据报直接丢弃。
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

### 4. 验证 P2P / Relay 通道

两端都连上服务端后，在任一端执行：

```bash
./bin/iplink-client peer ping client-b --config configs/client.json
```

输出包含实际通道模式（`p2p` 或 `relay`）和往返时延。对端会自动应答并注册反向通道。

> 注意：在本机（localhost）验证时，NAT 反射地址等于本地地址，打洞必然成功，只能验证协议链路；NAT 穿越能力需要在两台位于不同 NAT 后的机器上验证。

### 5. 查看服务端能力与运行状态

```bash
./bin/iplink-client info --config configs/client.json
```

客户端在认证时会自动获取服务端实际启用的服务（Relay / NAT / HTTP 代理）及其绑定端口，并据此决定 NAT 探测与 Relay 回退策略——不必再依赖两端配置一致，端口 0 动态分配也能正确识别。`info` 命令还会返回在线客户端数、隧道数、流量和 P2P 成功率等运行时指标。

### 6. 指标导出

服务端默认在 `29100` 端口暴露运行时指标（可通过 `metrics.port` 修改，设为 `0` 动态分配；`metrics.enabled=false` 关闭）：

```bash
curl http://<server-ip>:29100/metrics        # Prometheus 文本格式
curl http://<server-ip>:29100/metrics/json   # JSON 格式
```

包含在线客户端、活跃会话/隧道、Relay 会话、P2P 尝试/成功数及成功率、累积收发字节数。`iplink-client info` 的能力列表里也会显示指标端口，无需两端配置一致。

### 7. 配置开关说明

- **客户端 `network.enable_tcp` / `enable_udp`**：为 `false` 时跳过对应协议的隧道注册（HTTP 隧道归入 TCP），不影响其它隧道与连接本身。
- **服务端 `security.allowed_targets`**：显式配置后，服务端会对客户端注册的每个 `local_addr` 做白名单校验（支持 IP / CIDR / 端口，如 `10.0.0.0/8:8080`），防止服务端被当作开放代理。留空则不限制，保持内网任意目标转发的兼容性。
- **服务端 `relay.max_bytes_per_sec`**：Relay 出口字节速率上限，超出的 UDP 数据报会被丢弃；`0` 或负数表示不限速。
- **服务端 `metrics.enabled` / `metrics.port`**：内置指标端点开关与端口（默认 `29100`），端口需与其它服务端口互不相同，`0` 表示动态分配。

## 测试

```bash
go vet ./...
go test -v ./...
```
