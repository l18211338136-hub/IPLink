# IPLink Ubuntu 部署与配置指南

本文档说明如何在 **Ubuntu（AMD64 / x86_64）** 环境下部署并配置 IPLink 服务端与客户端。

---

## 1. 打包产物说明

已通过 `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` 静态编译生成两个无外部运行时依赖的独立二进制文件（位于项目 `bin/` 目录）：

| 文件 | 适用端 | 大小 | 说明 |
|---|---|---|---|
| `bin/iplink-server` | 公网 Ubuntu 服务端 | ~7.0 MB | 控制面、TCP/UDP 隧道监听、HTTP 反向代理、NAT 探测与 Relay 中继 |
| `bin/iplink-client` | 内网 Ubuntu 客户端 | ~5.1 MB | 内网服务接入、心跳保活、自动重连与流量转发 |

> 配置文件（`server.json` / `client.json`）**未打包**在二进制内，部署时放在机器外部目录即可，修改后重启对应进程即生效。

### 1.1 生成认证密钥（IPLINK_TOKEN）

`IPLINK_TOKEN` 没有固定格式，可自行设定任意非空字符串（底层作为 `HMAC-SHA256` 签名密钥），只需保证**服务端与客户端完全一致**。推荐在 Ubuntu 上生成高强度随机纯字母数字密钥：

```bash
# 方式一：使用 openssl 生成 64 位十六进制随机密钥（推荐）
openssl rand -hex 32

# 方式二：若无 openssl，使用 /dev/urandom 生成 48 位随机字符
tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 48; echo
```

两种写入方式任选其一：
- **环境变量注入（推荐）**：`server.json` / `client.json` 中保持 `"token": "${IPLINK_TOKEN}"`，将密钥写入 `/etc/iplink/server.env` 与 `/etc/iplink/client.env`。
- **直接写入 JSON**：将 `"${IPLINK_TOKEN}"` 替换为生成的密钥字符串（若自定义密码，请避免包含 `$` 符号，以免被环境变量解析器误展开）。

---

## 2. 服务端部署（公网 Ubuntu）

### 2.1 安装二进制与配置文件

```bash
# 1. 创建程序与配置目录
sudo mkdir -p /etc/iplink

# 2. 复制二进制到系统路径并赋予执行权限
sudo cp bin/iplink-server /usr/local/bin/iplink-server
sudo chmod +x /usr/local/bin/iplink-server

# 3. 复制配置模板为正式配置
sudo cp configs/server.json.example /etc/iplink/server.json
```

### 2.2 编辑服务端配置（`/etc/iplink/server.json`）

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

**关键字段说明**：
- `server.control_port`：客户端控制连接端口（TCP）。
- `server.relay_port`：P2P 失败时的中继端口（UDP）。
- `server.nat_port`：NAT 公网地址探测端口（UDP）。
- `server.http_proxy_port`：单端口 HTTP 反向代理入口端口（TCP）。设为 `0` 表示关闭 HTTP 反向代理。
- `security.token`：认证密钥，推荐通过环境变量 `${IPLINK_TOKEN}` 注入，客户端与服务端必须一致。
- `security.tls_enabled`：若启用 TLS 1.3，需同时配置 `tls_cert_file` 和 `tls_key_file` 证书路径。

### 2.3 放行防火墙与云服务器安全组

```bash
# 若服务器开启了 ufw 防火墙
sudo ufw allow 29000/tcp
sudo ufw allow 29001/udp
sudo ufw allow 29002/udp
sudo ufw allow 28080/tcp
# 若使用了额外 TCP/UDP 端口穿透（如 18080），需同步放行对应端口
```

### 2.4 使用 systemd 后台托管（推荐）

1. 创建环境变量文件 `/etc/iplink/
`（设置强密码并限制权限）：

```bash
echo 'IPLINK_TOKEN=替换为你的强随机密钥' | sudo tee /etc/iplink/server.env
sudo chmod 600 /etc/iplink/server.env
```

2. 安装并启动 systemd 服务（仓库已提供模板 `deployments/systemd/iplink-server.service`）：

```bash
sudo cp deployments/systemd/iplink-server.service /etc/systemd/system/iplink-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now iplink-server

# 查看运行状态与实时日志
sudo systemctl status iplink-server
sudo journalctl -u iplink-server -f
```

> 也可直接前台调试运行：`IPLINK_TOKEN="你的密钥" /usr/local/bin/iplink-server start --config /etc/iplink/server.json`

---

## 3. 客户端部署（内网 Ubuntu）

### 3.1 安装二进制与配置文件

```bash
sudo mkdir -p /etc/iplink
sudo cp bin/iplink-client /usr/local/bin/iplink-client
sudo chmod +x /usr/local/bin/iplink-client
sudo cp configs/client.json.example /etc/iplink/client.json
```

### 3.2 编辑客户端配置（`/etc/iplink/client.json`）

```json
{
  "client": {
    "id": "ubuntu-lan-01"
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
      "127.0.0.1:*",
      "192.168.1.0/24:*"
    ]
  },
  "network": {
    "enable_tcp": true,
    "enable_udp": true,
    "enable_p2p": true
  },
  "reconnect": {
    "enabled": true,
    "max_attempts": 0,
    "interval_seconds": 5
  },
  "tunnels": [
    {
      "name": "web-app1",
      "protocol": "http",
      "local_addr": "127.0.0.1:3000",
      "http_path": "/app1",
      "strip_prefix": true
    },
    {
      "name": "lan-grafana",
      "protocol": "http",
      "local_addr": "192.168.1.50:3000",
      "http_path": "/grafana",
      "strip_prefix": false
    },
    {
      "name": "ssh-forward",
      "protocol": "tcp",
      "local_addr": "127.0.0.1:22",
      "remote_addr": "0.0.0.0:10022"
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
- `server.address`：**必须填写服务端公网纯 IP**，禁止填写域名。
- `security.allowed_targets`：内网访问白名单。默认仅允许 `127.0.0.1:*` 和 `[::1]:*`；若需穿透局域网其他主机（如 `192.168.1.50:3000`），必须将对应 IP 或 CIDR 网段加入此列表。
- `tunnels`：支持同时配置多条隧道：
  - **HTTP 反向代理（`protocol: "http"`）**：共用服务端 `http_proxy_port`（如 `28080`），通过 `http_path` 区分不同应用。`strip_prefix: true` 会剥离前缀后转发给后端（例如 `/app1/api` -> `/api`）。
  - **TCP/UDP 端口穿透（`protocol: "tcp"` 或 `"udp"`）**：需指定 `remote_addr`（服务端监听的 `IP:Port`）。

### 3.3 使用 systemd 后台托管（推荐）

```bash
echo 'IPLINK_TOKEN=与服务端一致的密钥' | sudo tee /etc/iplink/client.env
sudo chmod 600 /etc/iplink/client.env

sudo cp deployments/systemd/iplink-client.service /etc/systemd/system/iplink-client.service
sudo systemctl daemon-reload
sudo systemctl enable --now iplink-client

sudo systemctl status iplink-client
sudo journalctl -u iplink-client -f
```

---

## 4. 常用运维与排查命令

```bash
# 校验配置是否正确
iplink-server status --config /etc/iplink/server.json
iplink-client status --config /etc/iplink/client.json

# 查看当前在线客户端（需在已配置 client.json 的机器上执行）
iplink-client peers --config /etc/iplink/client.json

# 修改配置后重启生效
sudo systemctl restart iplink-client
```

### 常见问题

1. **提示 `authentication failed`**：检查客户端与服务端的 `IPLINK_TOKEN` 是否一致，以及两台 Ubuntu 的系统时间差是否在 60 秒以内（防重放校验要求时间窗在 60s 内）。
2. **提示 `target ... is not permitted by allowed_targets policy`**：`local_addr` 使用了局域网 IP 但未在客户端 `security.allowed_targets` 中放行。
3. **外部无法访问 `remote_addr` 或 `http_proxy_port`**：检查云服务器安全组及 Ubuntu `ufw` 是否放行对应端口。
4. **修改 `client.json` 后未生效**：当前版本在启动时加载配置，修改后请执行 `sudo systemctl restart iplink-client`。
