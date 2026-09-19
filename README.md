# monitor

## 特性

- 实时监控：秒级实时数据展示
- 轻量高效：Rust 语言构建，低资源占用，极简高效
- 自托管：完全掌控数据隐私，部署简单
- 通知：离线与恢复、流量、到期与登录提醒，推送到 Telegram 或自定义 Webhook，消息模板可在面板里改
- 告警：CPU / 内存 / 硬盘持续超阈值，独立的一套渠道与按节点静音，只在状态变化时推送

## 组成

| 仓库 | 说明 |
|---|---|
| [monitor](https://github.com/monitor-probe/monitor) | hub：后台、API、公开页宿主 |
| [agent](https://github.com/monitor-probe/agent) | Linux agent |
| [monitor-theme-default](https://github.com/monitor-probe/monitor-theme-default) | 内置默认主题 |

```
agent (Linux)  ──WebSocket / JSON-RPC 2.0──▶  hub (axum + SQLite)  ──▶  后台 + 状态页
```

## 反向代理

面板与 agent 令牌都应只经 TLS 反代暴露。hub 默认只信任**本机**（loopback）送来的
`X-Forwarded-For`：反代与 hub 同机时不需要任何配置，`install-hub.sh` 生成的 systemd
单元（`--listen 127.0.0.1:PORT`）与 nginx 配置正是这种形态，客户端的真实地址照常出现在
登录限流与节点列表里。

反代在**另一台主机或容器**里时，必须显式指名它，否则它的 `X-Forwarded-For` 会被忽略，
该反代后面所有请求会被当成同一个调用方限流：

```sh
monitor-hub --trusted-proxy 172.18.0.0/16    # 可重复，接受单个地址或 CIDR
```

这里刻意不按网段猜。曾经只要来源是私网地址就采信该头，而 `--listen` 默认又是通配地址，
于是同一网段里的任何机器都能直连端口、逐请求伪造一个客户端地址，绕过登录失败锁定去猜
管理口令。loopback 始终在信任列表里且无法移除：本机进程本来就能直接读数据库，而一个
不再被信任的本地反代会让所有人一起被锁在外面。

`--listen` 默认 `[::]:28080`（通配）。前面有反代时请用 `--listen 127.0.0.1:PORT`，让这个
端口不再能被直接访问——`X-Forwarded-Proto` 与 `X-Forwarded-For` 都只对反代这一个入口有意
义，端口本身可直连时两者都能被调用方自己写。
