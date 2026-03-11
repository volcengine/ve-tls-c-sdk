# 接口草案（C Core）

## 初始化与生命周期
- ve_tls_config_init
- ve_tls_producer_create
- ve_tls_producer_destroy

## 发送与回调
- ve_tls_producer_set_send_done
- ve_tls_producer_add_log_raw
- ve_tls_producer_add_log_kv

## 持久化与恢复（persistent）
- ve_tls_producer_recover
- ve_tls_producer_set_persistent

## 动态配置
- ve_tls_producer_update_config
- ve_tls_producer_flush
