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

## 真实环境完整性验证（persistent）
- baseline：正常发送后服务端精确条数校验，重复 recover 不得重放
- crash_before_send：入盘后、发送前崩溃，重启 recover 后服务端应补齐且无重复
- partial_send_then_crash：部分发送成功后崩溃，重启 recover 后服务端应补齐且无重复
- timeout_then_recover：网络失败或超时后崩溃，重启 recover 后服务端应补齐且无重复
- terminal_auth_drop：鉴权终态失败时应被 durable ack 为 drop，后续 recover 不得重放
- quota_reject_new：以 `persistent_max_records` 打满模拟本地持久化空间耗尽，验证 overflow policy 与最终服务端精确条数
- checkpoint_corruption：人为破坏 `checkpoint` 文件后 recover，验证 checkpoint 损坏恢复路径
- stale_takeover：同一路径 active owner 阻止第二个进程打开，owner stale 后允许 takeover 并恢复未发送数据
- 待补：真实文件系统 `ENOSPC`、checkpoint 半写以外的 manifest 损坏、跨宿主多语言共享路径联动

## 下一阶段真实环境场景规划（persistent）
- P0 `segment_tail_corruption`：在仅落盘未发送时破坏 active segment 尾部，验证 repair 后可恢复剩余完整记录
- P0 `checkpoint_after_partial_ack`：部分发送成功并 durable ack 后再破坏 checkpoint，验证重复发送上界
- P0 `real_enospc`：在真实小容量挂载点或限额目录下压满磁盘，验证 append 失败、恢复与 reclaim 路径
- P1 `manifest_corruption`：破坏 `manifest` 后重启，验证 format/version/store 元数据恢复策略
- P1 `takeover_after_owner_crash`：owner 在 heartbeat 正常阶段崩溃，验证 stale 窗口后 takeover 恢复与旧 owner fencing
- P1 `lease_live_conflict`：active owner 存活时第二进程反复抢占，验证 fail-fast 与日志不重复
- P1 `persistent_block_timeout`：overflow policy 为 `block` 时验证阻塞时间、错误码与最终恢复结果
- P2 `android_process_derivation`：Android 多进程默认派生路径与 shared path lease 语义联测
- P2 `jni_recover_path`：Android/JNI 实际接入 persistent 后验证宿主重启恢复
- P2 `multi_binding_shared_path`：不同绑定层共享同一路径时的 owner/lease 语义联测

## 当前评审口径
- 已通过真实环境验证的“空间耗尽”是 SDK quota 饱和，不是操作系统磁盘真正写满
- 已通过真实环境验证的 checkpoint 损坏恢复，当前策略是回退到零 checkpoint 并优先保完整性；若损坏发生在部分 ack 之后，后续需要额外场景验证重复发送上界
- `stale_takeover` 当前按 at-least-once 语义评审，验收重点是 `unique_seq` 完整性；若服务端因重试歧义产生重复写入，会单独记录 `duplicates`

## 真实环境 Benchmark 规划（persistent）
- `steady_state_limit`：persistent 开启、真实服务端发送、批量参数调优后做 rate sweep，找到“服务端精确收齐且 producer 无 fail”的最高稳定速率
- `recover_drain_limit`：先离线落盘，再 recover 回灌真实服务端，测恢复吞吐上限
- `low_latency_mode`：`flush_interval_ms=0`、`log_count_per_package=1`，测低延迟配置下的上限
- `batched_mode`：`flush_interval_ms=1000`、`log_count_per_package=1024`，测吞吐优先配置下的上限
- `hash_key_mode`：固定 `hash_key` 与无 `hash_key` 分别测一轮，观察单 key 串行约束对上限的影响

## 2026-04-10 实测归档摘要
- 真实环境 steady-state benchmark 入口：`tools/persistent_real_bench.sh --mode steady`
- 真实环境 recover benchmark 入口：`tools/persistent_real_bench.sh --mode recover`
- bench 评审口径统一看窗口速率和排空阶段：
  - `PERSISTENT_REAL_PROGRESS phase=steady|recover|drain`
  - 窗口吞吐：`enqueue_lps`、`success_lps`、`enqueue_bytes_ps`、`send_bytes_ps`
  - 累计吞吐：`enqueue_lps_avg`、`success_lps_avg`
  - durable 状态：`acked_log_id`、`active_segment_id`、`current_segments/current_records/current_bytes`
  - 结论必须区分“steady 生产速率”和“drain 排空速率”，不能只看最终平均值
- 本轮归档目录：
  - steady: `build-persistent-real/bench-results/20260410-143440/`
  - recover: `build-persistent-real/bench-results/20260410-143730/`
- 本轮 stable steady 结果：
  - `rate=50`、`100`、`200`、`300` 在 `wait_ms=120000` 下均通过
  - `rate=300` 样本：`add_ok=1266`、`unique_seq=1266`、`close_rc=0`、`producer_lps=14.55`、`end_to_end_lps=14.07`
  - 结合 `rate=200` 样本看，当前真实 steady-state 吞吐平台约在 `14~16 logs/s`
- 本轮 stable recover 结果：
  - `records=1000` 样本通过，`unique_seq=1000`、`close_rc=0`、`recover_lps=14.93`、`end_to_end_lps=14.29`
- 本轮 benchmark 开发过程中已确认并修复的两个问题：
  - 成功回调逐条打印会干扰高压跑数，已通过 demo 开关在 benchmark 模式下静音
  - 查询工具原先仅看前 `1000` 条，导致高压样本误报未收齐，现已改为带 `Offset` 的分页查询

## 归档要求
- 每个真实环境场景或 benchmark 至少记录：场景名、配置、命令、run_id、开始/结束时间、通过条件、服务端最终 `unique_seq`/`duplicates`
- benchmark 额外记录：producer 侧 `add_ok/success/fail/close_rc`、服务端精确条数、producer 用时、query 用时、计算出的 logs/s
- 原始 stdout/stderr 建议归档到构建目录下的独立时间戳目录，便于评审回放
- 评审结论以“通过条件是否满足”为准，不以单次局部日志片段替代

## 性能与资源
- 写入吞吐（20w logs/s 量级目标）
- CPU/内存占用基线
- 长稳：持续运行 24h，验证泄漏与队列增长
