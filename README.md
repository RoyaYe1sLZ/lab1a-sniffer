# 网络嗅探器 · 实验 1A

一个面向 macOS 的图形化网络嗅探器，使用 Python、PySide6 和系统 libpcap 实现。

项目支持实时抓包、分层协议解析、协议过滤、PCAP 文件读写，以及 TCP 流追踪和本机进程关联。通过数据包列表、协议树、原始字节和连接时序，观察网络通信过程。

仓库地址：https://github.com/RoyaYe1sLZ/lab1a-sniffer

## 功能概览

| 模块 | 功能 |
| --- | --- |
| 实时抓包 | 枚举网络接口，开始和停止抓包，显示运行状态与错误信息 |
| 数据包列表 | 展示序号、时间、源地址、目的地址、协议、长度和摘要 |
| 协议解析 | Ethernet、IPv4、IPv6、TCP、UDP、ICMP、ICMPv6、明文 HTTP/1.x |
| 协议详情 | 分层展示协议字段，选中字段时高亮对应原始字节 |
| 原始数据 | 十六进制与 ASCII 视图，支持展开完整数据 |
| 抓包过滤 | 支持 libpcap BPF 表达式 |
| 显示过滤 | 按协议、TCP 连接或已关联进程筛选已有数据 |
| TCP 流追踪 | 按双方 IP 和端口归组，展示双向统计、握手与关闭状态 |
| 方向时序 | 展示相对时间、收发方向、TCP 标志、序列号和确认号 |
| 进程关联 | 实时采样本机 TCP 套接字，关联进程名与 PID |
| 文件操作 | 保存全部缓存数据为经典 PCAP，打开 PCAP 离线分析 |
| 资源控制 | 有界队列、缓存容量限制、本地丢弃计数和可获得的内核丢包统计 |

界面采用浅色主题，包含“数据包”和“TCP 流与进程”两个工作页。

## 技术实现

- **Python 3.13**：应用逻辑、线程调度和协议解析。
- **PySide6 / Qt Widgets**：图形界面与事件处理。
- **ctypes + libpcap**：调用系统抓包接口。
- **lsof / ps**：采集当前用户可见的 TCP 套接字及进程身份信息。
- **pytest**：解析、文件、生命周期和 GUI 交互测试。

抓包直接调用 libpcap；协议字段由项目中的 Python 代码解析，没有使用现成协议解析库。

主要验证环境为 macOS arm64。锁定依赖包括：

- PySide6-Essentials 6.12.0
- shiboken6 6.12.0
- pytest 9.2.0

具体依赖以 `pyproject.toml` 和 `uv.lock` 为准。

## 环境要求

- macOS
- Python 3.13，版本范围为 `>=3.13,<3.14`
- 系统 libpcap
- 实时抓包所需的 `/dev/bpf*` 访问权限

离线打开 PCAP 不需要实时抓包权限。

如果程序提示无法打开接口，应检查网络接口状态和 BPF 设备权限。程序不会自动修改系统权限。

## 安装与启动

### 使用 uv

在已安装 uv 的环境中执行：

```bash
git clone https://github.com/RoyaYe1sLZ/lab1a-sniffer.git
cd lab1a-sniffer
uv sync --locked
uv run python -m lab1a_sniffer gui
```

### 使用 Python 虚拟环境

也可以使用 Python 3.13 创建虚拟环境：

```bash
git clone https://github.com/RoyaYe1sLZ/lab1a-sniffer.git
cd lab1a-sniffer

python3.13 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m lab1a_sniffer gui
```

使用 uv 可以按 `uv.lock` 安装锁定版本；直接使用 pip 时，依赖按 `pyproject.toml` 中的版本范围安装。

### 在 PyCharm 中运行

创建一个 Python 运行配置：

| 配置项 | 内容 |
| --- | --- |
| 运行方式 | 模块名称 |
| 模块名 | `lab1a_sniffer` |
| 参数 | `gui` |
| 工作目录 | 项目根目录 |
| Python 解释器 | 项目中的 `.venv/bin/python` |

请使用模块方式启动，直接运行 `src/lab1a_sniffer/__main__.py` 可能导致相对导入错误。

## 基本使用

### 实时抓包

1. 选择网络接口。
2. 根据需要输入“抓包过滤 · BPF”，留空表示不设置抓包过滤。
3. 点击“开始抓包”。
4. 产生需要观察的网络流量。
5. 点击数据包查看协议字段及原始字节。
6. 点击“停止抓包”后，可继续分析或保存。

### 网络接口选择

| 接口 | 常见用途 |
| --- | --- |
| `en0` 等物理接口 | 观察 Wi-Fi 或以太网通信 |
| `lo0` | 观察本机回环通信，例如 `127.0.0.1` 和 `::1` |
| `utunN` | 观察 VPN、代理 TUN 等虚拟隧道中的流量 |

接口名称与用途取决于实际机器，`en0` 不保证始终代表 Wi-Fi。

启用代理或 VPN 后，应用连接可能经过 `utunN`。物理接口与隧道接口看到的地址、端口和封装可能不同，应根据实际路由选择接口。

### 两种协议过滤

**抓包过滤**在开始抓包前设置，决定哪些包进入程序，例如：

```text
tcp
udp
ip
ip6
icmp or icmp6
tcp port 443
host 192.0.2.1 and tcp
```

未被捕获的数据无法通过后续显示过滤恢复。

**显示过滤**只改变当前列表，不删除缓存数据。支持：

```text
全部、HTTP、TCP、UDP、IPv4、IPv6、ICMP、ICMPv6
```

显示匹配会检查完整协议封装关系。例如，一个 IPv4/TCP/HTTP 包能够同时匹配 IPv4、TCP 和 HTTP。

HTTP 根据载荷内容识别，不将端口 80 直接等同于 HTTP。

### TCP 流追踪

进入“TCP 流与进程”页，可以查看：

- 连接两端的 IP 和端口。
- 双向包数、帧字节数和捕获载荷字节数。
- 观测到的握手与关闭状态。
- 连接观测时长及握手观测时长。
- 数据包方向、相对时间、TCP 标志、Seq 和 Ack。

选择连接后：

- 点击“仅看所选连接”，筛出该连接的数据包。
- 双击时序行，跳回对应的原始数据包。
- 在数据包页点击“追踪 TCP 流”，打开当前包所属的连接。
- 点击“取消连接过滤”，恢复全部连接范围。

连接过滤与协议显示过滤共同生效，原始包序号保持不变。

“已见三次握手”等状态表示抓包中的观测结果，不代表系统此刻仍保持该连接。

### 进程关联

实时抓包时，可开启“实时关联本机进程”。

程序约每秒查询一次当前用户可见的 TCP 套接字，使用完整的双方 IP、端口以及相近时间匹配连接。

匹配成功后：

1. “进程线索”列显示进程名和 PID。
2. 在顶部进程下拉框中选择具体进程。
3. 查看该进程已关联的连接。
4. 点击“查看该进程已关联 TCP 包”，集中查看对应数据包。

进程下拉框只包含本次抓包中已经匹配成功的进程，并非系统全部进程列表。

进程关联属于套接字快照线索，存在以下限制：

- 短连接可能在两次采样之间结束。
- 权限限制、地址映射和代理转发可能导致匹配失败。
- 应用可能通过辅助进程联网。
- 回环连接可能同时关联客户端和服务端进程。
- 不能保证覆盖某个进程的全部网络活动。

### PCAP 保存与打开

点击“打开 PCAP”可以离线浏览文件，实时和离线数据使用相同的协议解析入口。

点击“保存全部”会导出全部缓存数据，不受协议、连接或进程显示过滤影响。实时抓包需要先停止再保存。

当前支持微秒精度的经典 PCAP 2.4，不支持 PCAPNG 和纳秒精度 PCAP。

经典 PCAP 不保存进程名和 PID。因此，保存后重新打开文件，可以重建 TCP 流，但无法恢复此前采集的进程关联信息。

## 离线样本

仓库提供：

```text
samples/protocols.pcap
```

包含五个人工构造的独立报文：

- IPv4/TCP/HTTP 请求
- IPv4/TCP/HTTP 响应
- IPv6/UDP
- IPv4/ICMP Echo Request
- IPv6/ICMPv6 Echo Request

可以直接在 GUI 中打开，体验协议过滤、分层解析和原始字节查看。

这些样本用于验证解析和显示，不是包含完整握手的 TCP 会话。

## 命令行功能

以下示例从项目根目录运行。

列出接口：

```bash
uv run python -m lab1a_sniffer interfaces
```

抓包 10 秒，显示协议详情并保存：

```bash
mkdir -p artifacts

uv run python -m lab1a_sniffer capture \
  -i en0 \
  -f 'tcp or udp' \
  -t 10 \
  --details \
  -w artifacts/capture.pcap
```

执行真实抓包及协议字段自检：

```bash
uv run python -m lab1a_sniffer selfcheck \
  --analyze \
  --physical-interface en0 \
  --output-dir artifacts/selfcheck
```

接口名称需要根据实际机器调整。

## 项目结构

```text
.
├── src/lab1a_sniffer/
│   ├── __main__.py          # 模块启动入口
│   ├── cli.py               # 命令行入口
│   ├── _ffi.py              # libpcap C 接口与结构体声明
│   ├── pcap.py              # 网卡枚举、实时/离线读取和 PCAP 写入
│   ├── capture.py           # 抓包线程、有界队列和停止控制
│   ├── models.py            # 原始包、协议层和字段等数据模型
│   ├── parser.py            # 分层协议解析
│   ├── flows.py             # TCP 流索引、分代和统计
│   ├── processes.py         # 本机进程与套接字快照
│   ├── storage.py           # 离线加载与缓存预算
│   ├── gui.py               # 主窗口及交互
│   ├── gui_controller.py    # 实时抓包与 GUI 调度
│   ├── gui_files.py         # 后台文件任务
│   ├── gui_processes.py     # 异步进程采样
│   ├── gui_models.py        # 数据包模型和显示过滤
│   ├── gui_flows.py         # TCP 流、进程与方向时序界面
│   ├── gui_theme.py         # 集中管理的界面主题
│   └── gui_widgets.py       # 协议标签、开关、图标等组件
├── tests/                   # 自动化测试
├── scripts/                 # 原生 GUI 验收脚本
├── samples/                 # 合成 PCAP 样本
├── docs/                    # 实现说明与验收记录
├── pyproject.toml
└── uv.lock
```

实时数据的主要处理流程：

```text
网络接口
  ↓
libpcap / BPF
  ↓
后台抓包线程复制原始字节
  ↓
有界队列
  ↓
GUI 主线程分批取包、解析协议
  ↓
缓存与 TCP 流索引
  ↓
协议 / 连接 / 进程显示过滤
  ↓
数据包列表、协议树、字节视图与方向时序
```

文件读取和进程采样分别在后台工作线程执行，结果交给 GUI 主线程更新。

## 测试与验收

使用 uv 安装开发依赖后运行：

```bash
uv sync --locked
uv run python -m pytest
```

启用真实网卡测试：

```bash
uv run python -m pytest --run-live --physical-interface en0
```

原生 GUI 验收：

```bash
uv run python scripts/gui_smoke.py
uv run python scripts/gui_files_smoke.py
uv run python scripts/gui_flows_smoke.py
```

截至 2026 年 11 月 12 日的验收记录：

- 全套测试：181 项通过。
- 原生实时抓包验收：14 项通过。
- 原生过滤与文件验收：22 项通过。
- TCP 流与进程关联验收：18 项通过。
- 实际窗口已检查 980 和 1320 像素宽度布局。

文件验收脚本使用受控路径替代系统文件选择面板，原生文件选择面板需手动检查。

## 已知限制

- 当前主要面向 macOS，未完成 Windows/Linux 适配。
- HTTP 仅分析单个 TCP 载荷中可见的明文 HTTP/1.x 起始行和头字段。
- 未实现 TCP 字节流重组、IP 分片重组和 HTTP 消息体完整还原。
- 未实现 HTTPS 解密，以及 TLS、HTTP/2、QUIC 等协议的专门解析。
- 校验和字段仅展示，不验证其正确性。
- TCP 流统计包含重传包，载荷统计不是去重后的应用数据量。
- 缺包、乱序及未捕获新 SYN 的端口复用可能影响连接分代判断。
- 默认缓存上限为 20000 个包和 128 MiB 保守解析对象预算；该预算不等于整个进程 RSS。
- TCP 索引另设最多 2048 条流和 20000 个 TCP 包行号的上限。
- 尚未进行高速网络压力测试。

## 进一步阅读

- [TCP 流追踪与进程关联说明](docs/加分项说明.md)
- [加分项验收记录](docs/加分项验收记录.md)
- [UI 改版说明](docs/UI改版说明.md)
- [过滤与 PCAP 文件说明](docs/阶段4说明.md)
- [合成样本说明](samples/说明.md)

`docs/` 中的阶段说明记录各阶段的实现过程；早期阶段中的“尚未实现”描述应结合后续阶段文档阅读。
