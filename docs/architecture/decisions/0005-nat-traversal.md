# ADR 0005 & 0006: NAT Traversal & Relay Fallback

- **背景**：对称型 NAT 与严格防火墙下 UDP 打洞可能失败，Relay 是系统可靠性的必要兜底。
- **最终决定**：
  1. 服务端提供 UDP NAT 反射端口用于发现公网 `IP:Port`。
  2. `ConnectPeer` 采用 Direct First 策略尝试 UDP Hole Punching，超时或失败时自动申请 Server Relay 会话并透明切换为 Relay 转发。
  3. Relay 管理器限制最大会话数并定期清理空闲会话。
- **影响范围**：`internal/nat/`、`internal/relay/manager/`、`internal/client/service`。
