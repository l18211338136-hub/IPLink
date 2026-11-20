# ADR 0003: Transport & Framing Protocol

- **背景**：TCP 是字节流协议，单次 `Read` 不保证读取完整消息。
- **最终决定**：采用 26 字节大端序固定帧头（Version、Type、Flags、Length、RequestID、SessionID）+ 载荷，强制校验 `MaxFramePayloadSize`（1 MiB）以防止恶意超大包导致内存耗尽。TCP 数据帧使用二进制 `ConnID + Payload` 编码减少序列化开销。
- **影响范围**：`pkg/protocol`、`internal/protocol/`。
