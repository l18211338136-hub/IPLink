# ADR 0002: Control & Data Plane Separation

- **背景**：内网穿透系统需同时处理会话管理、心跳、NAT 协调与高并发字节流转发。
- **方案**：控制面负责认证、心跳、隧道注册、Peer 协调与 Relay 分配；数据面负责 TCP 字节流多路复用转发、UDP 数据报转发及 Relay 转发。
- **最终决定**：控制连接上的并发流通过独立的 `ConnID` 通道与有界发送队列解耦，避免慢速连接阻塞整个控制面。
- **影响范围**：`internal/server/service`、`internal/client/service`。
