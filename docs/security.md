# 安全规范

本页说明接入和排障时的安全边界。漏洞报告流程见仓库根目录 [SECURITY.md](../SECURITY.md)。

## 机密信息

- 不要把 AK/SK、security token、真实 endpoint 配置文件提交到仓库。
- 不要在日志、回调、metrics 或崩溃上报里输出 AK/SK、security token、完整 Authorization header。
- 不要输出完整请求体。确实需要排查字段问题时，只记录脱敏后的少量样本。
- `.local/` 和 `tools/real_demo.env` 已在 `.gitignore` 中，真实配置建议放在这些路径下。

SDK-owned 的静态/动态凭证副本、发送线程缓存和已签名 header 缓冲区会在释放或
归还对象池前清零。credentials provider 返回值仍归调用方所有，调用方应按自己的
所有权合同清理原始凭证内存。

## 传输安全

- 真实网络发送使用 HTTPS。
- `tls_verify_peer` 和 `tls_verify_host` 默认开启。生产环境不要关闭。
- 使用自定义 CA 时，通过 `ca_cert_path` 指定证书路径。
- 代理配置应由部署环境控制，不要把带账号密码的代理地址写入公开配置。

## Persistent 目录

- Persistent 目录会保存待发送日志。日志里如果有敏感字段，磁盘上也会保存这些字段。
- 目录权限建议只允许当前进程用户读写。
- 多租户机器上不要把 persistent 目录放在所有用户可读的位置。
- 清理 persistent 目录前确认 backlog 是否已经补发；直接删除会丢失未处理日志。

## HTTP 调试

`http_debug` 会输出更多传输细节，只适合本地排查。生产环境不要开启；如果必须开启，先确认日志系统会脱敏。
