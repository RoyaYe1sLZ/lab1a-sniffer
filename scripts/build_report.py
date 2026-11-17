"""早期基础版报告生成脚本（保留供开发记录参考）。

内容停留在基础功能阶段，不包含后续 TCP 流追踪和进程关联。
最终报告位于 docs/实验报告/，应使用 Typora 打开 Markdown 并导出 PDF；
请勿使用本脚本覆盖最终报告。运行本脚本另需 reportlab 和 Pillow。
"""

import argparse
from datetime import datetime
from html import escape
import json
from pathlib import Path
import subprocess
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image,
    KeepTogether,
)

ROOT = Path(__file__).resolve().parents[1]
NAVY = colors.HexColor("#20354d")
TEAL = colors.HexColor("#167b83")
GRAY = colors.HexColor("#66768a")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    stable = json.loads((ROOT / "artifacts/final/stability/stability.json").read_text())
    gui = json.loads((ROOT / "artifacts/stage4/gui-files-smoke.json").read_text())
    if not stable["passed"] or not gui["passed"]:
        raise RuntimeError("验收尚未通过，不能生成完成版报告。")
    pdfmetrics.registerFont(TTFont("Chinese", "/System/Library/Fonts/STHeiti Light.ttc", subfontIndex=0))
    styles = {
        "title": ParagraphStyle("title", fontName="Chinese", fontSize=24, leading=34, textColor=NAVY, spaceAfter=12),
        "h1": ParagraphStyle("h1", fontName="Chinese", fontSize=17, leading=25, textColor=NAVY, spaceAfter=14),
        "h2": ParagraphStyle("h2", fontName="Chinese", fontSize=12, leading=19, textColor=TEAL, spaceBefore=9, spaceAfter=6),
        "body": ParagraphStyle("body", fontName="Chinese", fontSize=10.3, leading=17.5, spaceAfter=9, wordWrap="CJK"),
        "small": ParagraphStyle("small", fontName="Chinese", fontSize=8.4, leading=13, textColor=GRAY, spaceAfter=6, wordWrap="CJK"),
        "cell": ParagraphStyle("cell", fontName="Chinese", fontSize=9, leading=14, wordWrap="CJK"),
        "head": ParagraphStyle("head", fontName="Chinese", fontSize=9, leading=14, textColor=colors.white, wordWrap="CJK"),
        "code": ParagraphStyle("code", fontName="Chinese", fontSize=8.5, leading=13, backColor=colors.HexColor("#f1f5f8"), borderPadding=8, spaceAfter=12, wordWrap="CJK"),
    }
    story = []
    def p(text, style="body"):
        story.append(Paragraph(text, styles[style]))
    def heading(title):
        p(title, "h1")
    def sub(title):
        p(title, "h2")
    def table(rows, widths):
        data = [[Paragraph(escape(str(value)), styles["head" if i == 0 else "cell"]) for value in row]
                for i, row in enumerate(rows)]
        result = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        result.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f7fa")]),
            ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 9),
            ("LINEBELOW", (0, -1), (-1, -1), .4, colors.HexColor("#d7e0ea")),
        ]))
        story.append(result)
        story.append(Spacer(1, 11))
    def page():
        story.append(PageBreak())
    def screenshot(path, caption, width=490):
        from PIL import Image as PILImage
        with PILImage.open(path) as image:
            w, h = image.size
        story.append(Image(str(path), width=width, height=width * h / w))
        p(caption, "small")

    now = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y年%m月%d日")
    revision = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True).strip()
    name, student_id = metadata["name"], metadata["student_id"]
    repo = metadata.get("repository_url", "")
    repo_verified = bool(metadata.get("repository_verified"))
    width = 490
    p("软件与系统安全实验报告", "small")
    p("实验 1A 网络嗅探器\n设计与实现".replace("\n", "<br/>"), "title")
    p("macOS 图形界面抓包与分层协议分析", "h2")
    table([["项目", "信息"], ["姓名", name], ["学号", student_id], ["日期", now],
           ["运行平台", "macOS 26.6 / Apple Silicon arm64"], ["本地版本", revision]], [90, 400])
    if repo_verified:
        p(f'代码仓库：<link href="{escape(repo, quote=True)}" color="#167b83">{escape(repo)}</link>')
    else:
        p("代码仓库尚待 GitHub 发布完成。此版本供核对内容，公开链接确认后重新生成提交版。")
    sub("实验结果")
    p("本实验实现了带 GUI 的网络嗅探器：使用 libpcap 实时捕获原始数据，在 Python 中自行解析协议，"
      "通过 Qt 界面呈现数据包、协议字段及原始字节，并支持抓包过滤、协议显示过滤和经典 PCAP 文件读写。"
      "实时与离线数据共用解析入口。过滤只改变可见列表，保存包含全部缓存数据。")
    p(f"全套 {metadata.get('test_count',156)} 项测试通过；两组原生窗口验收分别通过 14 项、22 项检查。"
      f"连续抓包 {stable['seconds_elapsed']:.2f} 秒，生成并捕获 {stable['captured_packets']:,} 个本机 UDP 包，"
      "未记录到程序队列或内核丢包，导出再打开的数据逐包一致。")
    p("本实现面向课程实验与常规本机流量观察。未实现 TCP 流重组、HTTPS 解密或进程关联，亦不将此次负载测试解释为高速网络性能保证。", "small")
    page()

    heading("1 实验目标与功能对应")
    p("根据课程讲义，实验 1A 要求设计并实现带 GUI 的网络嗅探器。NPS 抓包是必需功能；协议分析和跨层协议过滤是完成质量的重要组成。"
      "流追踪等加分方向未纳入本次基础版。")
    table([["要求或交付目标", "实现", "验证方式"],
           ["真实数据包捕获", "libpcap 枚举接口并读取 en0 / lo0", "带随机标记的真实本机流量"],
           ["图形化交互", "接口选择、启停、包列表、协议树、HEX/ASCII", "Qt 自动化与 Cocoa 窗口验收"],
           ["协议分析", "Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP / HTTP", "独立样本、真实流量及 tcpdump"],
           ["协议过滤", "BPF 抓包过滤与按解析层匹配的显示过滤", "HTTP 也匹配 TCP/IP，实时增量过滤"],
           ["文件保存与复查", "经典 PCAP 打开与全量导出", "过滤后导出、逐字段及字节往返"],
           ["稳定性", "有界队列、缓存预算、可中断生命周期", "五分钟抓包、失败及关闭路径测试"]], [105, 225, 160])
    sub("技术选型")
    p("应用使用 Python 3.13 和 PySide6 Qt Widgets。Python 通过标准库 ctypes 调用 macOS 系统 libpcap，"
      "无需编译自定义 C++ 模块。协议分析由项目代码完成，不使用 Scapy 或 Wireshark 的解析器代替核心实现。"
      "Qt 采用模型与视图分离的表格，按需生成可见单元格内容。")
    table([["组件", "验证版本", "职责"], ["Python", "3.13.17", "业务逻辑、解析、线程调度"],
           ["PySide6 Essentials / Qt", "6.12.0", "QtCore / QtGui / QtWidgets"],
           ["系统 libpcap", "1.10.1", "抓包、BPF、PCAP 读写"], ["pytest", "9.2.0", "解析、资源与 GUI 自动化测试"]], [175, 90, 225])
    p("环境使用项目独立 .venv，uv.lock 锁定依赖。原生库和 GUI 目标平台限定为 64 位 macOS。")
    page()

    heading("2 总体结构与线程模型")
    table([["层次", "主要模块", "职责"], ["原生接口", "_ffi.py / pcap.py", "C ABI、网卡、原始包复制、句柄与文件"],
           ["捕获服务", "capture.py", "工作线程、有界队列、停止标志与统计"],
           ["解析数据", "models.py / parser.py", "不可变原始包、协议层、字段与提示"],
           ["数据存储", "storage.py / gui_models.py", "缓存预算、离线导入、源模型与过滤代理"],
           ["交互调度", "gui_controller.py / gui_files.py", "Qt 定时轮询、后台文件任务与结果交接"],
           ["呈现", "gui.py / formatting.py", "窗口、包选择、协议树、字节关联与 CLI"]], [85, 185, 220])
    sub("实时数据流")
    p("网卡/BPF → libpcap 工作线程 → 复制为 RawPacket → 有界队列 → Qt 控制器分批读取 → "
      "parse_packet → 全部缓存源模型 → 协议过滤代理 → 列表与详情。")
    p("RawPacket 保存整数秒与微秒时间戳、线上长度、链路类型和独立的 bytes。ParsedPacket 引用原始包，"
      "同时提供源/目的地址和端口、摘要、协议层、字段位置及解析提示。字段偏移均相对原始包起点。")
    sub("线程与生命周期")
    p("抓包句柄仅由创建它的工作线程读取、查询统计和关闭。GUI 不直接关闭原生句柄，而是设置停止事件。"
      "句柄处于非阻塞模式，单次等待读取就绪最多 50 ms。Qt 主线程每 50 ms 取最多 128 个包，"
      "初始化和停止期间仍处理界面事件。关闭窗口时先请求停止，待线程结束与队列处理完毕再关闭。")
    sub("资源边界")
    p("原始队列最多 2048 个包，缓存最多 20000 个包，解析对象预算为 128 MiB。预算包括原始字节、协议字段、"
      "字符串及容器，并对跨包共享对象保守重复计费。预算不等于整个进程的 RSS。达到限额后停止抓包并保留已有列表；"
      "队列丢弃和内核丢包分别计数，不混为一个指标。")
    page()

    heading("3 抓包与协议解析")
    sub("原生内存与 C ABI")
    p("ctypes 显式声明函数参数、返回类型及结构体。macOS timeval 的秒字段为 C long，微秒字段为 32 位整数，"
      "其后存在自然对齐填充。回归测试将填充设为非零，确认微秒字段不会读取填充内容。"
      "pcap_next_ex 返回借用指针，数据在下一次读取前复制到 bytes，避免跨线程使用失效内存。")
    table([["协议或层次", "解析内容", "边界与限制"],
           ["链路层", "Ethernet、VLAN、NULL、LOOP、原始 IP", "依据 DLT 定位 IP，不统一假设 14 字节头"],
           ["IPv4", "IHL、总长、标志/分片、TTL、地址、协议号", "按 IHL 定位上层；真正分片不继续解释传输层"],
           ["IPv6", "载荷长度、下一头部、跳数、地址与常见扩展头", "扩展头最多 8 层；ESP 不解密，AH 与巨帧未实现"],
           ["TCP", "端口、序列/确认号、Data Offset、标志、窗口", "按实际头长跳过选项；不重组流"],
           ["UDP", "端口、长度和校验和值", "检查最小长度与 IP 声明边界"],
           ["ICMP / ICMPv6", "类型、代码及 Echo 标识符/序号", "错误消息中引用的报文不冒充外层协议"],
           ["HTTP/1.x", "请求行、状态行、完整可见头字段", "依据载荷格式识别；最多 16 KiB、128 个字段"]], [85, 205, 200])
    sub("解析层次与可见性")
    p("IP 声明的长度限定上层范围，防止将 Ethernet 填充解释为 TCP 数据。可见字节不足时标记 truncated；"
      "长度相互矛盾时标记 malformed。未知协议保留原始字节与 unsupported 提示。"
      "HTTP 识别不依赖端口，80 端口上的 TLS 字节不会仅因端口被标成 HTTP。"
      "起始行或头字段跨段时说明未完整解析，不将单包分析描述为完整会话分析。")
    page()

    heading("4 GUI 与协议显示过滤")
    screenshot(ROOT / "artifacts/stage4/gui-files-native.png", "图 1 离线浏览时只显示 2 个 HTTP 包，源缓存仍有 5 个包；右侧显示请求行对应的字节。")
    p("顶部 BPF 在开始实时捕获前设置，决定哪些包进入程序；列表旁显示过滤只改变可见行。"
      "显示条件包括 HTTP、TCP、UDP、IPv4、IPv6、ICMP、ICMPv6。匹配沿全部已解析层进行，"
      "所以 HTTP 包也可匹配 TCP 和相应 IP 版本。")
    p("QSortFilterProxyModel 只提供过滤后的视图。用户选择可见行后，必须 mapToSource 回原始模型，"
      "以原始序号定位协议详情。测试验证 UDP 可见第 1 行对应源模型第 3 包，避免过滤后显示错误包。"
      "过滤掉当前包后重新选择可见包，或清空详情。")
    p("协议字段包含字节偏移与长度。选择层或字段时，对应 HEX 和 ASCII 区域同时高亮。"
      "原始字节先预览前 4096 字节，用户可展开全部；选择预览范围外的字段也会自动展开。")
    page()

    heading("5 PCAP 读写与异常处理")
    p("本版读取和导出微秒精度经典 PCAP 2.4，支持单一链路类型、大小端文件头与最高 262144 字节 snaplen。"
      "PCAPNG、纳秒时间戳、其他版本和额外全局链路标志明确拒绝，不做隐式有损转换。")
    sub("完整导入后再替换")
    p("文件线程逐包核对记录长度、时间戳和剩余文件范围，再通过 libpcap 读取并复制数据，调用同一解析器。"
      "超过包数或解析预算、文件截断、读取中变更或取消操作都会拒绝整个导入，保留原列表。"
      "加载时旧缓存与暂存结果可能同时存在，各受 128 MiB 预算约束。")
    p("DLT_NULL 的四字节地址族伪头根据文件字节序规范为本机格式，确保跨平台文件可以再次正确导出；"
      "其后的线上 IP 内容不变。同平台正常导出再读取的时间戳、长度及数据逐包一致。")
    sub("全量导出与原子替换")
    p("保存先从源模型取得不可变原始包快照，不遍历可见行。后台写入同目录临时文件，完整刷新、关闭后才原子替换目标。"
      "取消或写入失败清理临时文件并保留原文件。抓包需先停止再保存。")
    table([["场景", "程序行为"], ["BPF 无效或接口打开失败", "提示原因；不清空旧列表"],
           ["显示过滤后零条可见", "源缓存仍保留，仍可全量导出"],
           ["文件结构损坏或超预算", "整体拒绝导入，保留当前文档"],
           ["保存失败或取消", "原文件不被替换，未保存状态保留"],
           ["关闭窗口时读写仍在进行", "读取请求取消；保存等待完成；界面继续响应"],
           ["有尚未保存的数据", "替换、清空、关闭前要求确认放弃，可取消后保存"]], [175, 315])
    page()

    heading("6 验证方法与结果")
    table([["验证层次", "结果", "覆盖内容"],
           ["全套 pytest", f"{metadata.get('test_count',156)} 项通过", "抓包、解析、文件、GUI 状态及错误路径"],
           ["实时 Cocoa GUI", "14 项通过", "真实 HTTP/UDP/ICMP、字段高亮、十次启停、抓包中关闭"],
           ["离线 Cocoa GUI", "22 项通过", "协议过滤、源行映射、全量导出、零条显示、错误保留"],
           ["独立工具", "tcpdump 核对通过", "地址、端口、TCP 序列号、TTL/跳数、ICMP 字段和文件读回"],
           ["异常输入", "测试通过", "五类样本所有截断前缀、1500 组确定性随机字节"]], [115, 100, 275])
    p("测试样本按协议字段独立构造，预期值不由生产解析器生成。实际抓包使用随机标记和本地服务核对流量来源，"
      "并分别验证 en0 的 Ethernet 与 lo0 的 NULL 链路头。自动 GUI 文件验收使用真实 Cocoa 窗口与文件 API，"
      "仅将系统文件选择器替换成预定路径；系统选择面板的操作由手动检查补充。")
    sub("显示与保存分离的关键验证")
    table([["显示条件", "可见包", "源缓存", "实际导出"], ["HTTP", "2", "5", "5"],
           ["TCP", "2（最高层为 HTTP）", "5", "5"], ["UDP", "1", "5", "5"],
           ["UDP 对仅有 HTTP 的文件", "0", "1", "1"]], [175, 105, 105, 105])
    p("相同文件往返比较时间戳、捕获长度、线上长度、链路类型及原始字节。失败测试还确认旧文件与临时文件的状态，"
      "而不只检查界面是否出现错误提示。")
    page()

    heading("7 五分钟连续抓包")
    samples = stable["samples"]
    mib = 1024 * 1024
    min_rss = min(s["rss_bytes"] for s in samples) / mib
    max_rss = max(s["rss_bytes"] for s in samples) / mib
    last = samples[-1]
    table([["指标", "实测"], ["持续时间", f"{stable['seconds_elapsed']:.3f} 秒"],
           ["流量", "约 20 包/秒，本机 IPv4/IPv6 UDP 交替"],
           ["产生 / 捕获", f"{stable['generated_packets']:,} / {stable['captured_packets']:,} 个包"],
           ["队列 / 内核丢包", f"{stable['capture_status']['queue_dropped']} / {stable['capture_status']['kernel']['dropped']}"],
           ["末次解析缓存预算占用", f"{last['cache_budget_bytes'] / mib:.2f} MiB"],
           ["采样进程 RSS 范围", f"{min_rss:.2f} 至 {max_rss:.2f} MiB"],
           ["Qt 20ms 心跳最大间隔", f"{stable['max_heartbeat_gap_seconds'] * 1000:.2f} ms"],
           ["进程累计 CPU 时间", f"{stable['cpu_seconds']:.3f} 秒（含结束处理）"],
           ["文件往返 / 退出资源", "逐包一致；未遗留 pcap 工作线程"]], [210, 280])
    p("测试每 10 秒采样进程 RSS 与模型缓存占用，持续更新列表并周期选择数据包。"
      "RSS 包括解释器、Qt 和原生库，不等于缓存预算；采样最大值也不是所有瞬时峰值的保证。"
      "内存随所保留数据增长符合缓存设计，测试未触及 20000 包或 128 MiB 预算上限。")
    p("此次结果证明在约 20 包/秒的受控本机负载下持续运行、UI 事件处理、停止和保存往返均正常。"
      "它不证明高吞吐网络下零丢包，也不能单凭五分钟观察断言不存在长期内存泄漏。")
    p("复现命令：.venv/bin/python scripts/gui_stability.py", "code")
    page()

    heading("8 运行复现与实验总结")
    sub("环境与操作")
    p("安装 Python 3.13 与 uv 后，在源码目录执行 uv sync --frozen。无需安装完整 Xcode 或编译 Qt。"
      "实时抓包需当前用户可读写 /dev/bpf*；离线文件浏览无需打开 BPF 设备。程序不自动提权或修改系统权限。")
    p("uv sync --frozen<br/>.venv/bin/python -m lab1a_sniffer gui<br/>"
      ".venv/bin/python -m pytest --run-live --physical-interface en0", "code")
    p("选择 lo0 并开始抓包，再在另一个终端运行 selfcheck --analyze 可产生本地协议流量；"
      "选择 en0 则观察普通网络访问。停止后可以选择包、展开字段、保存全部，再打开文件复查。"
      "samples/protocols.pcap 提供五个合成独立报文供离线验收，不是完整 TCP 会话。")
    sub("局限与改进方向")
    p("当前不实现 IP 分片和 TCP 流重组、HTTP 消息体还原、HTTPS 解密、进程关联、校验和验证及内核高速抓包优化。"
      "HTTP 按单个 TCP 载荷起始格式识别，可能漏掉跨段内容；TCP/IP 选项主要展示原始字节。"
      "后续可围绕流重组、更多应用协议与高负载基准扩展，但不将这些功能描述为已完成。")
    sub("实现过程中需要掌握的机制")
    p("本实验的关键是明确抓包位置与解析层次、原生指针与 Python 数据的生命周期、协议声明长度与实际捕获长度的区别，"
      "以及可见视图与原始缓存之间的关系。保留字段字节范围、错误原因和可复现测试，有助于解释程序行为并定位问题。")
    p("开发采用 AI 辅助实现和测试，实验执行者按阶段运行验收并核对输出。各阶段说明记录模块职责、数据流和限制；"
      "报告中的功能与结果依据实际代码和验收记录，不以 AI 生成的说明代替运行验证。")
    page()

    heading("参考资料")
    references = [
        "刘鹏 软件与系统安全 实验 1A 与 1B 讲解 2026年11月10日 第2至3页 第5页 第9页 第14至15页",
        "IPv4 RFC 791 https://www.rfc-editor.org/rfc/rfc791.html",
        "IPv6 RFC 8200 https://www.rfc-editor.org/rfc/rfc8200.html",
        "TCP RFC 9293 https://www.rfc-editor.org/rfc/rfc9293.html",
        "UDP RFC 768 https://www.rfc-editor.org/rfc/rfc768.html",
        "ICMP RFC 792 https://www.rfc-editor.org/rfc/rfc792.html",
        "ICMPv6 RFC 4443 https://www.rfc-editor.org/rfc/rfc4443.html",
        "HTTP/1.1 RFC 9112 https://www.rfc-editor.org/rfc/rfc9112.html",
        "libpcap https://github.com/the-tcpdump-group/libpcap",
        "Qt for Python https://doc.qt.io/qtforpython-6/",
        "Python ctypes https://docs.python.org/3.13/library/ctypes.html",
    ]
    for i, ref in enumerate(references, 1):
        p(f"[{i}] {escape(ref)}", "small")
    sub("随附复现材料")
    p("源码、uv.lock、测试代码、合成 PCAP 样本、各阶段原理说明，以及原生 GUI 与稳定性验收脚本。"
      "演示视频展示实际程序操作，录制脚本可复现。真实抓包测试数据保存在 artifacts 目录并被 Git 忽略。")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    def footer(canvas, doc):
        canvas.setFont("Chinese", 8)
        canvas.setFillColor(GRAY)
        canvas.drawString(52, 27, f"实验 1A  {name}  {student_id}")
        canvas.drawRightString(A4[0] - 52, 27, str(doc.page))
    document = SimpleDocTemplate(str(args.output), pagesize=A4,
        rightMargin=52, leftMargin=52, topMargin=44, bottomMargin=46,
        title="实验1A网络嗅探器设计与实现", author=name)
    document.build(story, onFirstPage=footer, onLaterPages=footer)
    print(args.output)


if __name__ == "__main__":
    main()
