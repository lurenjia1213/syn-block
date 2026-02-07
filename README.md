# syn\_block

基于 eBPF/XDP 的流量过滤工具，专为 frps 服务器设计，用于缓解 SYN Flood 攻击并防止内网穿透服务的 IP 误封。

## ⚠️ 警告 (Disclaimer)

​**本程序目前处于实验阶段**，可能存在 Bug。请务必小心使用，谨慎用于生产环境。

> 本人这一年都会很忙

> 所有代码均为GPL，请遵循许可协议

## 📖 项目简介

本程序旨在运行于 frps（服务端）机器上，通过 eBPF XDP技术过滤部分恶意攻击流量。

### 🎯 设计初衷与背景

在使用阿里云等云服务器作为 frps 节点进行内网穿透和 SSH 转发时，经常面临以下痛点：

1. ​**SSHD 限制**：被转发的目标机器（内网机器）上的 SSHD 服务往往不支持（或无法配置）通过 Proxy Protocol 获取真实客户端 IP。
2. ​**IP 混淆**：在 frp 隧道下，所有流量的源 IP 在目标机器看来都是 frpc 节点的 IP
3. ​**误封禁**：当 frps 遭遇公网扫描或 SYN Flood 攻击并转发给内网时，内网机器的 SSHD 会检测到大量来自 frpc 的失败尝试，从而通过 Fail2Ban 等机制将 frpc 的 IP 拉黑，导致正常服务中断。

​**本程序的作用**：在 frps 服务器入口处直接识别并阻断恶意攻击流量，避免这些流量进入 frp 转发链路，从而保护后端 SSHD 不触发封禁机制。

## 🚀 用法说明 (Usage)

### 运行参数

```
cargo run --release -- \
  --iface <网卡名> \
  --ports <端口列表> \
  --window-secs <统计窗口秒数> \
  --threshold <阻断阈值> \
  --block-secs <阻断时长>
  --rst                  # 当丢包时发送 TCP RST 以更快终止连接（可选）

```

### 参数详解

|**参数**|**说明**|**示例**|
| ------| --------------------------------| ------|
|​`--iface`|指定监听的网卡接口名称|​`eth0`|
|​`--ports`|需要监控的端口列表（逗号分隔）|​`22,80,443`|
|​`--window-secs`|流量统计的时间窗口（秒）|​`5`|
|​`--threshold`|触发阻断的连接数阈值|​`100`|
|​`--block-secs`|阻断生效的时长（秒）|​`60`|
|​`--rst`|加上此参数时发送rst，而非丢包|

#### 我咋用的
```
除了被保护端口外，我还额外监控了几个我不会使用的端口
当这些端口被扫描，则会拉黑源ip 6分钟
对被拉黑的ip，发送rst，假装端口未开放
```


### 日志控制

通过环境变量 `RUST_LOG` 控制日志级别：

- 可选等级：`off`​, `error`​, `warn`​, `info`​, `debug`​, `trace`

示例：

```
RUST_LOG=info cargo run --release -- ...

```

退出程序：使用 `Ctrl + C`。

## 🛠️ 构建与开发 (Build & Development)

### 前置要求 (Prerequisites)

1. ​**Rust Toolchain (Stable)** ​: `rustup toolchain install stable`
2. ​**Rust Toolchain (Nightly)** ​: `rustup toolchain install nightly --component rust-src`
3. ​**bpf-linker**​: `cargo install bpf-linker`​ (macOS 上需加 `--no-default-features`)
4.  **(Cross-compile)**  Target: `rustup target add ${ARCH}-unknown-linux-musl`
5.  **(Cross-compile)**  LLVM: e.g., `brew install llvm` (macOS)
6.  **(Cross-compile)**  C Toolchain: e.g., `brew install filosottile/musl-cross/musl-cross` (macOS)

### 编译与运行 (Build & Run)

使用标准 cargo 命令即可，构建脚本会自动处理 eBPF 程序：

```
cargo build
cargo check
cargo build --release
cargo run --release

```

