# Roadmap（开发前拆分）

## M0：骨架与接口稳定
- Core/Adapters/Bindings 目录结构稳定
- 完成 API/配置/错误/重试/签名文档与规格

## M1：master MVP
- 异步写入 + 聚合 + 压缩
- TLS 请求构建 + V4 签名 + 基础错误解析
- RetryPolicy（指数退避 + 抖动）与可重试判定
- 基础指标接口

## M2：master 完整
- 上下文查询（可选）
- 更完善的限流与背压策略
- 性能优化与长稳保障

## M3：persistent MVP
- ring file + checkpoint 落盘与恢复
- uuid-range ack 推进与清理
- 单线程发送约束与多进程路径策略（由绑定层提供）
