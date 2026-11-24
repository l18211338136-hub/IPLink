# IPLink

**IPLink** 是一个使用 Go 语言开发的轻量级、跨平台 **Pure IP Network Tunneling System（纯 IP 内网穿透系统）**。

> 协议版本 3：UDP 通道全面加密，且 Relay 会话使用随机 ID + 每会话 HMAC token；与 v2 及更早客户端不兼容（旧帧会被服务端直接拒绝），升级时请两端同步。

## 核心特性

- **纯 IP 通信**：不依赖 DNS 域名，直接使用 IP 地址与端口建立连接。
- **Client / Server 分离架构**：服务端负责控制面协调、隧道监听与 Relay 中继；客户端负责内网服务映射与转发。
- **TCP / UDP 内网穿透**：支持将内网 TCP 服务（HTTP、SSH、数据库等）和 UDP 服务映射到服务端端口。
- **Direct First + Relay Fallback**：支持持久 UDP NAT 公网地址发现、同局域网直连候选地址与 UDP Hole Punching，打洞失败时自动回退至 Server Relay 中继；两端都会建立可收发的通道，Relay 会话由服务端自动通知对端加入。
- **P2P 可靠流多路复用（`internal/p2p`）**：在加密 UDP P2P/Relay 通道之上提供可靠有序流复用，内置 RFC 6298 自适应 SRTT/RTO、3 次重复 ACK 快速重传、有序重传与 2 MB UDP 内核收发缓冲。
- **独立 P2P 远程桌面与文件传输客户端（`rdp/`）**：控制端与被控端共用单个 `iplink-rdp.exe`，支持系统 `mstsc` 转发、免 Windows 3389 内置同屏远控与断点续传 P2P 文件传输。
- **安全认证与权限控制**：
  - Challenge-Response HMAC-SHA256 身份认证（不传输明文 Token，防重放）。
  - 全链路加密：控制面走 TLS 1.3；启用 TLS 后 HTTP 代理与指标端点也升级为 HTTPS。
  - UDP 数据报加密：NAT 发现、P2P 打洞与通道、Relay 转发载荷均用 token 派生的 AES-256-GCM 密钥加密（每包随机 nonce，防重放/篡改），零外部依赖。
  - Relay 会话隔离：会话 ID 随机生成，每个会话下发独立 token 并对每个数据报做 HMAC 校验，其他客户端无法枚举或注入会话。
  - UDP 回程目标校验：客户端只能回包到服务端实际观测到的对端地址，防止 `allowed_targets` 被绕过或用作反射放大器。
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
│   ├── p2p/                    # 基于 UDP 的可靠流多路复用（Mux / Stream）
│   ├── relay/manager/          # UDP Relay 会话管理与转发
│   ├── security/               # HMAC-SHA256 认证、TLS 1.3、目标白名单
│   ├── config/                 # JSON 配置加载、环境变量展开与校验
│   ├── logger/                 # 基于 slog 的结构化日志
│   └── metrics/                # 运行时原子指标统计
├── desktop/                    # 桌面端 GUI 客户端（Wails）
├── rdp/                        # 独立 P2P 远程桌面与文件传输客户端（Wails）
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

服务端默认在 `127.0.0.1:29100` 暴露运行时指标（仅本机可访问），可通过 `metrics.listen_ip` / `metrics.port` 修改，端口设为 `0` 动态分配，`metrics.enabled=false` 关闭。默认配置无需鉴权——因为只绑 loopback。

**要将指标端点暴露到非本机地址，必须设置 `metrics.token`**（否则配置校验会拒绝启动）。设置后请求默认只接受 Bearer header：

```bash
curl -H "Authorization: Bearer <token>" http://<server-ip>:29100/metrics
```

`?token=<token>` 查询参数默认被拒绝，避免 token 进入访问日志与浏览器历史。仅当旧版 Prometheus 必须使用 `params` 时，才显式设置 `metrics.allow_query_token: true` 开启兼容模式。

Prometheus 抓取配置示例：

```yaml
scrape_configs:
  - job_name: iplink
    static_configs:
      - targets: ['<server-ip>:29100']
    authorization:
      credentials: <token>
```

生产环境建议保持 `listen_ip` 为 loopback 并用反向代理 + 访问控制对外提供，或开启 `tls_enabled` 让指标端点一并走 HTTPS。

包含在线客户端、活跃会话/隧道、Relay 会话、P2P 尝试/成功数及成功率、累积收发字节数。此外还有**隧道级统计**：每条隧道的活跃连接数、收发字节数，Prometheus 输出带 `tunnel_id` / `protocol` 标签（如 `iplink_tunnel_active_conns{tunnel_id="tun-1",protocol="tcp"}`），JSON 输出在 `tunnels` 数组。

三种查询入口共享同一份运行时快照：

- `GET /metrics` — Prometheus 文本（含隧道级指标）
- `iplink-client info --config configs/client.json` — 连到服务端查询，打印能力 + 全局指标 + 隧道明细
- `iplink-server status --config configs/server.json` — 本机查询 metrics 端点，服务端未运行时会给出提示而非报错（动态端口 `0` 时跳过）

### 7. 配置开关说明

- **客户端 `network.enable_tcp` / `enable_udp`**：为 `false` 时跳过对应协议的隧道注册（HTTP 隧道归入 TCP），不影响其它隧道与连接本身。
- **服务端 `security.allowed_targets`**：服务端始终对客户端注册的每个 `local_addr` 做白名单校验（支持 IP / CIDR / 端口，如 `10.0.0.0/8:8080`）。留空时默认仅允许 loopback（`127.0.0.1:*`、`[::1]:*`），与客户端默认策略一致；需要任意目标时必须显式配置 `"*:*"`。
- **服务端 `relay.max_bytes_per_sec`**：Relay 出口字节速率上限，超出的 UDP 数据报会被丢弃；`0` 或负数表示不限速。
- **服务端 `metrics.enabled` / `metrics.port` / `metrics.listen_ip` / `metrics.token` / `metrics.allow_query_token`**：内置指标端点开关、端口（默认 `29100`）、监听 IP（默认 `127.0.0.1`）、访问 token 与查询参数兼容开关（默认 `false`）。端口需与其它服务端口互不相同，`0` 表示动态分配；监听非 loopback 地址时 `token` 必填，请求默认只接受 `Authorization: Bearer`。

## 桌面客户端与安装

`desktop/` 是独立的 Go module，使用 Wails 将前端嵌入单个 Windows 可执行文件（GUI 子系统，无控制台窗口）。

- **首次运行向导**：首次启动（或配置中服务端地址为空）时自动弹出快速设置，引导填写服务端 IP、端口、客户端 ID、Token 与本地目标白名单；保存后写入用户配置目录 `%APPDATA%\IPLink\client.json`，之后可在主界面修改。
- **编译**：`cd desktop && bash build.sh`（脚本自定位路径，不再依赖个人目录）。产物 `bin/iplink-desktop.exe`。
- **Windows 安装包（NSIS）**：
  ```bash
  # 先构建 exe，再生成 setup.exe
  cd desktop && bash build.sh
  cd installer && makensis /DIPLINK_EXE=..\..\bin\iplink-desktop.exe install.nsi
  # 产物：bin/IPLink-Setup.exe（安装到 %LOCALAPPDATA%\Programs\IPLink，含开始菜单/桌面快捷方式与卸载项）
  ```

## P2P 远程桌面与文件传输客户端（`rdp/`）

`rdp/` 是独立的 Go module（Wails 桌面应用），控制端与被控端共用同一个 `bin/iplink-rdp.exe`，**无需修改服务端**即可通过 IPLink 的 P2P / Relay 通道进行远程控制与文件传输。

- **每次启动唯一 Client ID**：自动基于本机非回环网卡 MAC 哈希 + 随机数生成 `rdp-<mac6>-<rand6>`，多台设备或多开实例互不冲突；配置保存在 `%APPDATA%\IPLink\rdp.json`。
- **内置同屏远控（P2P 免 3389）**：
  - 零第三方依赖，不依赖 Windows 远程桌面服务（3389），支持 Windows 家庭版与同屏协作；勾选「允许被同屏远控」即自动在 `127.0.0.1:29389` 就绪。
  - **高性能抓屏与渲染**：64×64 精细分块 + 2D 脏矩形聚类合并、多核并行 JPEG 编码、原始 BGRA 零拷贝比对、自适应画质背压，以及静止 250ms 后自动补发高清帧（动时流畅、停时高清）。
  - **双流分离与防卡死**：画面流（`msgRoleVideo`）与键鼠输入流（`msgRoleInput`）独立复用互不阻塞；画面流抖动时前端自动恢复并支持一键「刷新画面」；被控端自动追踪并在断连时释放所有按住的鼠标/键盘修饰键，防止卡键。
  - **便捷操控**：支持一键将本机剪贴板文本粘贴到远端（完整支持中文/密码）、快捷发送 `Win` / `显示桌面` / `任务管理器` 等系统组合键。
- **系统远程桌面模式（`mstsc`）**：仍支持通过 P2P / Relay 转发目标 `127.0.0.1:3389` 并自动拉起 Windows 自带 `mstsc.exe`。
- **P2P 文件传输（支持断点续传）**：
  - 使用独立文件流（`msgRoleFile`），按 `256 KB` 流式分块收发，不阻塞画面与键鼠操作。
  - 基于文件内容指纹（文件名 + 大小 + 首尾 64 KB SHA-256）与 `.iplinkpart` 临时断点文件，支持网络闪断自动重试续传及跨重启手动续传，传输完成后自动重命名保存到 `下载\IPLink\` 目录（界面支持一键打开接收目录）。
- **编译（Windows 64 位）**：
  ```powershell
  cd rdp
  $env:GOOS="windows"; $env:GOARCH="amd64"
  go build -tags desktop,production -ldflags="-H windowsgui -s -w" -o ..\bin\iplink-rdp.exe .
  ```

## 测试

```bash
go vet ./...
go test -v ./...
cd rdp && go vet ./... && go test -v ./...
```
