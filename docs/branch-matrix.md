# 分支能力矩阵

| 分支 | 状态 | 功能优势 | 建议使用场景 |
| --- | --- | --- | --- |
| master | 可用 | 低依赖、高性能、资源占用小 | Linux 服务器、嵌入式 Linux |
| live | 可用 | 功能与 master 等价，支持更多平台 | Windows、Mac、Android、iOS |
| bricks | 可用 | 极致精简、体积极小 | 资源极小场景，例如 RTOS |
| persistent | 可用 | 在 master 基础上增加落盘缓存，限制单线程发送 | Android、iOS |

## 分支差异边界
- master 作为能力基线，所有新能力先进入 master
- live 仅扩展平台编译支持，不新增语义差异
- bricks 只做能力裁剪与资源优化，不修改协议与语义
- persistent 增加落盘队列与断点续传，并强制单线程发送
