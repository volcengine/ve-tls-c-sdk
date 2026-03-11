# persistent 落盘语义规范

## 目标
在 master 能力基础上增加落盘队列与断点续传，保证 At Least Once。

## 文件布局
- ring file：`${persistentFilePath}_%03d` 多文件滚动
- checkpoint：`${persistentFilePath}.idx` 追加写入

## 数据记录格式
- item header：magic_code + log_uuid + log_size + preserved
- 数据体：紧随 header 的日志字节

## 写入流程
- 写入前检查容量：maxPersistentFileCount * maxPersistentFileSize 与 maxPersistentLogCount 双重上限
- write header + body 到 ring file
- 更新 now_file_offset/now_log_uuid 与 in_buffer_log_offsets
- 首次写入后保存 checkpoint

## ack 语义
- 发送完成回调带 uuid 范围（startId/endId）
- 成功或丢弃时推进 start_log_uuid/start_file_offset
- 保存 checkpoint 并清理 ring file 区间

## 恢复流程
- 读取最后一个完整 checkpoint
- 从 start offset 顺序读 header + body 并回放未 ack 数据
- 检测 magic、uuid 跳跃、log_size 合法性
- 回放成功后更新 checkpoint

## 线程模型
- 启用 persistent 时强制单线程发送
