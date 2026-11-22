# NetStat TProxy

Android Root 透明代理（TProxy）一体化方案：**KernelSU / Magisk 持久化守护模块（`flclash-helper` + `FlClashCore`） + 隐匿包名版 FlClash 前端（`NetStat` / `com.kestrel.netstat.app`）**。

---

## 核心特性

1. **进程分离 & 无弹窗权限架构**
   - `flclash-helper` 开机自启常驻 `127.0.0.1:47890`，基于内核 `/proc/net/tcp` + `/data/system/packages.list` 校验调用方 Socket UID，仅放行授权前端包名与 `uid=0`，**App 内无需请求 `su` 弹窗**。
   - `FlClashCore -daemon` 以独立持久化 TCP 守护运行，首帧强制 SHA-256 常量时间 Token 鉴权；**划掉或强杀 App 前端不断网**，重开后无缝回连恢复计时与流量面板。

2. **TProxy 策略路由 & 防 DNS / IPv6 / WebRTC 泄露**
   - 使用高 4 位 fwmark 掩码 `0x08000000/0x0f000000`（路由表 `233`）保留 Android `netd` 原生标记；出站防环标记 `0x09000000`（`routing-mark: 150994944`）。
   - `FlClashCore` 强制开启 `dns.listen: 127.0.0.1:1053`，`iptables -t nat OUTPUT 1` 插入 `FLCLASH_DNS` 抢先接管 `:53`（可与既有 `AdGuardHome` 共存，关闭代理自动还原），并拦截非 Core 的 `:853` DoT 迫使其回落 Clash Fake-IP。
   - 国内外分流防 ECS 泄露：未覆写时默认采用 `nameserver: 1.1.1.1 / 8.8.8.8` DoH 经代理隧道解析，`geosite:cn`、`direct-nameserver` 与 `proxy-server-nameserver` 保留 `223.5.5.5 / 119.29.29.29`。
   - IPv6 防护：未开启 IPv6 代理时，`ip6tables` 拦截非本地/非 `fe80::` 全局 IPv6 出站（保留 VoLTE/IMS），并临时禁用 `wlan0` IPv6 消除 WebRTC 公网 IPv6 地址泄露。

3. **代理出口自动联动地区与时区伪装（33 国预设）**
   - 监听 FlClash 原生出口探测（`outboundIpProbeProvider`）与后端 `/tproxy/start` 异步探针联动：开启代理或切换节点时，自动按真实出口国家及**城市级时区**（支持区分美/加/澳/俄等多时区国家）同步调整 SIM 运营商（`gsm.*` 多卡槽）、系统语言区域（`persist.sys.locale` / `ro.*`）与系统时区（`cmd time_zone_detector`）。
   - 支持 **工具 → 地区与时区伪装** 面板独立开关与手动固定地区，关闭代理自动还原真机原生基线。

4. **包名与名称隐匿**
   - 前端发布包名为 `com.kestrel.netstat.app`，应用与快捷磁贴名称为 **`NetStat`**，可与原版 FlClash 共存并规避常见包名关键词扫描。

---

## 目录结构

- `root_helper/`：Go 编写的 ARM64 Root 守护程序 `flclash-helper`（TProxy 规则管理、Core 生命周期、UID 鉴权、地区/时区管理与出口探测）。
- `ksu_module/`：KernelSU / Magisk 模块模板（`module.prop`、`service.sh`、`customize.sh`、`uninstall.sh`）。
- `app_src/`：基于 FlClash 修改的 Flutter / Android 前端与 `FlClashCore` Go 守护补丁。

---

## 安装与使用

1. 从本仓库 [Releases](https://github.com/syh0119/netstat-tproxy/releases) 下载：
   - `FlClash_TProxy_KSU.zip`：在 KernelSU / Magisk 中刷入后重启（或执行模块目录 `service.sh`）。
   - `NetStat_arm64.apk`：直接安装 **`NetStat`**（`com.kestrel.netstat.app`）。
2. 打开 **NetStat**，导入你的订阅配置并点击 **启动**。
3. 可在 **工具 → 地区与时区伪装** 中配置自动跟随或手动锁定伪装国家与时区。

---

## 编译说明

```bash
# 1. 编译 Root Helper (Linux ARM64)
cd root_helper
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../ksu_module/bin/flclash-helper .

# 2. 编译 FlClashCore Daemon (Linux ARM64)
cd ../app_src/core
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -tags with_gvisor -ldflags="-s -w" -o ../../ksu_module/bin/FlClashCore ./cmd/core

# 3. 编译 Android ARM64 APK
cd ..
flutter build apk --release --target-platform android-arm64 --split-per-abi --dart-define=APP_ENV=stable
```

## 致谢与协议

- 上游核心与界面基于开源项目 FlClash 及 Clash.Meta（mihomo），遵循 GPL-3.0 协议。
