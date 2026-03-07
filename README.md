# ve-tls-c-sdk

面向多端与 IoT 的 TLS Producer C Core。以 master 为能力基线，按场景派生 live/bricks/persistent 分支。

## 目标
- 统一落盘语义与恢复行为，保证 At Least Once
- 可裁剪、低资源占用、跨平台适配
- 保持稳定 API，便于 JNI/FFI 接入

## 分支策略
| 分支 | 状态 | 功能优势 | 建议使用场景 |
| --- | --- | --- | --- |
| master | 可用 | 低依赖、高性能、资源占用小 | Linux 服务器、嵌入式 Linux |
| live | 可用 | 功能与 master 等价，支持更多平台 | Windows、Mac、Android、iOS |
| bricks | 可用 | 极致精简、体积极小 | 资源极小场景，例如 RTOS |
| persistent | 可用 | 在 master 基础上增加落盘缓存，限制单线程发送 | Android、iOS |

## 目录结构
```
core/          核心能力
adapters/      平台适配层
bindings/      平台绑定
tests/         测试
tools/         工具与脚本
docs/          文档
```

## 构建
```
cmake -S . -B build
cmake --build build
```

## 接口示例
```
ve_tls_config cfg;
ve_tls_config_init(&cfg);
ve_tls_producer * p = ve_tls_producer_create(&cfg);
ve_tls_producer_destroy(p);
```
