# 测试计划（开发前）

## 单元测试
- 配置默认值与参数校验
- 批次聚合触发条件（count/bytes/timeout）
- 重试判定（HTTP/网络错误映射）
- 签名 canonicalization 与 header 生成

## 集成测试
- 真实服务端联调：成功/429/5xx/签名错误
- 超时与网络异常注入：EOF/ECONNRESET/ETIMEDOUT

## 可靠性测试（persistent）
- 崩溃恢复：写入后 kill -9，重启重放未 ack 数据
- checkpoint 滚动与损坏恢复：截断 idx 文件后恢复行为
- ring file 滚动与清理：超过 maxFileSize/maxFileCount 行为

## 性能与资源
- 写入吞吐（20w logs/s 量级目标）
- CPU/内存占用基线
- 长稳：持续运行 24h，验证泄漏与队列增长
