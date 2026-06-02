import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
import bisect
import select
from pathlib import Path

try:
    from PySide6 import QtCore, QtGui, QtWidgets
except Exception:
    from PyQt6 import QtCore, QtGui, QtWidgets  # type: ignore


class Adb:
    # 功能：初始化调试组件状态与运行所需资源。
    def __init__(self) -> None:
        self.serial = ""

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def base(self):
        return ["adb", "-s", self.serial] if self.serial else ["adb"]

    # 功能：封装ADB交互能力，为调试器提供设备与进程操作接口。
    def run(self, args, timeout=60):
        return subprocess.run(self.base() + args, check=False, text=True, capture_output=True, timeout=timeout)

    # 功能：封装ADB交互能力，为调试器提供设备与进程操作接口。
    def shell(self, cmd, timeout=60):
        return self.run(["shell", cmd], timeout=timeout)

    # 功能：处理调试器与服务端通信连接、部署与会话维护。
    def ensure_server(self):
        return self.run(["start-server"], timeout=20)

    # 功能：封装ADB交互能力，为调试器提供设备与进程操作接口。
    def devices(self):
        cp = self.run(["devices", "-l"], timeout=20)
        serials = []
        for ln in cp.stdout.splitlines():
            ln = ln.strip()
            if (not ln) or ln.startswith("List of devices"):
                continue
            parts = ln.split()
            if len(parts) >= 2 and parts[1] == "device":
                serials.append(parts[0])
        return serials, cp

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def check_root(self):
        r = self.shell("su -c id", timeout=10)
        return ("uid=0" in r.stdout), r

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def remount(self):
        cp1 = self.run(["root"], timeout=20)
        cp2 = self.run(["remount"], timeout=20)
        return cp1, cp2

    # 功能：封装ADB交互能力，为调试器提供设备与进程操作接口。
    def push(self, local: Path, remote: str):
        return self.run(["push", str(local), remote], timeout=120)

    # 功能：封装ADB交互能力，为调试器提供设备与进程操作接口。
    def chmod(self, remote: str, mode="777"):
        return self.shell(f"chmod {mode} {remote}", timeout=10)

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def ps_list(self):
        cp = self.shell("ps -A", timeout=20)
        out = cp.stdout.splitlines()
        procs = []
        for i, ln in enumerate(out):
            if i == 0:
                continue
            parts = ln.split()
            if len(parts) < 2:
                continue
            name = parts[-1]
            pid = ""
            for p in parts:
                if p.isdigit():
                    pid = p
                    break
            if not pid:
                continue
            try:
                procs.append((int(pid), name))
            except Exception:
                pass
        return procs

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def get_abi(self):
        cp = self.shell("getprop ro.product.cpu.abi", timeout=10)
        return (cp.stdout.strip() or ""), cp

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def run_check(self, remote, timeout=10):
        cp = self.shell(f"ls -l {remote} 2>/dev/null", timeout=timeout)
        ok = (cp.returncode == 0) and ("No such" not in cp.stdout)
        return ok, cp


class Session:
    # 功能：初始化调试组件状态与运行所需资源。
    def __init__(self) -> None:
        self.sock = None
        self._rbuf = b""

    # 功能：处理调试器与服务端通信连接、部署与会话维护。
    def connect_only(self, adb: Adb):
        self.stop()
        adb.run(["forward", "--remove", "tcp:31337"], timeout=10)
        cp_fwd = adb.run(["forward", "tcp:31337", "tcp:31337"], timeout=10)
        if cp_fwd.returncode != 0:
            return False
        for _ in range(80):
            try:
                self.sock = socket.create_connection(("127.0.0.1", 31337), timeout=0.2)
                self.sock.settimeout(0.2)
                self._rbuf = b""
                return True
            except Exception:
                time.sleep(0.05)
        return False

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def stop(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        self._rbuf = b""

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def send(self, s: str):
        if self.sock is None:
            return
        try:
            self.sock.sendall((s.rstrip("\n") + "\n").encode("utf-8", errors="ignore"))
        except Exception:
            pass

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def read_line(self):
        if self.sock is None:
            return ""
        while b"\n" not in self._rbuf:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return ""
                self._rbuf += chunk
            except socket.timeout:
                continue
            except Exception:
                return ""
        line, self._rbuf = self._rbuf.split(b"\n", 1)
        return line.decode("utf-8", errors="ignore") + "\n"

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def read_available_lines_nonblocking(self, max_lines=200):
        lines = []
        if self.sock is None:
            return lines
        try:
            while True:
                if b"\n" in self._rbuf:
                    raw, self._rbuf = self._rbuf.split(b"\n", 1)
                    lines.append(raw.decode("utf-8", errors="ignore") + "\n")
                    if len(lines) >= max_lines:
                        break
                    continue
                r, _, _ = select.select([self.sock], [], [], 0)
                if not r:
                    break
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                self._rbuf += chunk
        except Exception:
            pass
        return lines


class Reader(threading.Thread):
    # 功能：初始化调试组件状态与运行所需资源。
    def __init__(self, sess: Session, rx: queue.Queue, stop_evt: threading.Event):
        super().__init__(daemon=True)
        self.sess = sess
        self.rx = rx
        self.stop_evt = stop_evt

    # 功能：封装ADB交互能力，为调试器提供设备与进程操作接口。
    def run(self):
        while not self.stop_evt.is_set():
            ln = self.sess.read_line()
            if not ln:
                break
            self.rx.put(ln)


class MemoryTableWidget(QtWidgets.QTableWidget):
    """Memory table: first column(address) is not selectable, selection is cell-based."""

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def selectionCommand(self, index, event=None):  # type: ignore[override]
        if index.column() == 0:
            return QtCore.QItemSelectionModel.SelectionFlag.NoUpdate
        return super().selectionCommand(index, event)

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def mouseReleaseEvent(self, event):  # type: ignore[override]
        super().mouseReleaseEvent(event)
        self._clear_first_column_selection()

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def mouseMoveEvent(self, event):  # type: ignore[override]
        self.setUpdatesEnabled(False)
        super().mouseMoveEvent(event)
        self.setUpdatesEnabled(True)
        self._clear_first_column_selection()

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _clear_first_column_selection(self):
        sm = self.selectionModel()
        if not sm:
            return
        for idx in sm.selectedIndexes():
            if idx.column() == 0:
                sm.select(idx, QtCore.QItemSelectionModel.SelectionFlag.Deselect)


class MainWindow(QtWidgets.QMainWindow):
    # 功能：初始化调试组件状态与运行所需资源。
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Just_client - 公众号：零基础学逆向")
        self.resize(1440, 900)
        self.adb = Adb()
        self.session = Session()
        self.reader_stop = threading.Event()
        self.rx = queue.Queue()
        self.reader_thread = None

        self.connected = False
        self.current_target_pid = 0
        self.current_thread_tid = 0
        self.server_pid = 0
        self.device_serial = ""
        self.attach_state = "idle"
        self._attach_requested_pid = 0
        self.target_running = False
        self.last_goto_context = "disasm"
        self.current_pc_addr = 0
        self.memory_center_expr = "sp"
        self.memory_display_mode = "八字节"
        self.pending_clear_channels = set()
        self.breakpoints = {}
        self.module_rows = []
        self._module_rows_pid = 0
        self.thread_rows = []
        self.trace_collecting = False
        self.trace_rows_raw = []

        self._ansi_re = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
        self._hex_re = re.compile(r"0x[0-9a-fA-F]+")
        self._dis_row_by_addr = {}
        self._dis_sorted_addrs = []
        self._dis_comment_addr_shadow = {}
        self._dis_raw_insn_by_addr = {}
        self._dis_stream_desc = None
        self._dis_last_addr = None
        self._dis_last_addr = None
        self._mem_row_by_addr = {}
        self._reg_row_by_name = {}
        self._call_row_by_idx = {}
        self._stack_row_by_off = {}
        self._mem_selected_col = 1
        self._mem_selected_addr = None
        self._mem_active_cell = None
        self._pending_disasm_scroll_addr = None
        self._pending_disasm_scroll_hint = "center"
        self._deferred_disasm_scroll_addr = None
        self._deferred_disasm_scroll_hint = "center"
        self._pending_disasm_request_expr = None
        self._pending_disasm_request_addr = None
        self._pending_disasm_request_hint = "center"
        self._pending_disasm_no_select_once = False
        self._pending_disasm_focus_shift_up_rows = 0
        self._attach_disasm_batch_active = False
        self._attach_disasm_batch_rows = {}
        self._attach_disasm_batch_last_rx_at = 0.0
        self._pending_mem_scroll_addr = None
        self._pending_mem_scroll_hint = "center"
        self._pending_mem_focus_shift_up_rows = 0
        self._stack_menu_addr = None
        self._regs_menu_addr = None
        self._attach_post_init_done = False
        self._target_dead_notified = False
        self._suppress_thread_refresh_until = 0.0
        self._max_lines_per_tick = 120
        self._disasm_style_dirty = False
        self._dis_reorder_needed = False
        self._mem_addr_col_width_base = 0
        self._last_step_pc_addr = None
        self._pending_asm_patch_addr = None
        self._pending_asm_patch_text = ""
        # 内存断点(bm*)：等服务端回执后再入表，避免“界面已显示但未设置成功”
        self._pending_mem_bp_ack = None  # type: tuple[int, str] | None  (addr, cmd_base)
        self._disasm_rx_count = 0
        self._disasm_rx_first_addr = None
        self._disasm_rx_last_addr = None
        self._disasm_rx_cmd = ""
        self._disasm_rx_expect = 0
        self._disasm_rx_summary_once = False
        self._disasm_rx_started_at = 0.0
        self._disasm_seq_sid = 0
        self._disasm_seq_total = 0
        self._disasm_seq_parts = {}
        self._disasm_seq_bad = 0
        self._disasm_seq_last_at = 0.0
        self._disasm_seq_retry = 0
        # 关闭纯文本兜底反汇编解析，避免把单步Dashboard等文本误入反汇编表格
        self._plain_disasm_fallback_enabled = False

        self._build_ui()
        self._apply_style()
        self._bind_hotkeys()
        self._init_device()
        app = QtWidgets.QApplication.instance()
        if app is not None:
            app.focusChanged.connect(self._on_app_focus_changed)

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(30)
        self.alive_timer = QtCore.QTimer(self)
        self.alive_timer.timeout.connect(self._check_target_alive_tick)
        self.alive_timer.start(2000)

    # 功能：负责调试界面的样式重绘与状态可视化。
    def _apply_style(self):
        self.setStyleSheet(
            """
            QWidget { background:#0a0d12; color:#e6edf3; }
            QLineEdit, QPlainTextEdit, QComboBox, QTableWidget, QListWidget { background:#0f141b; color:#e6edf3; border:1px solid #2f6fed; }
            QPushButton { background:#2f6fed; color:#fff; border:1px solid #2f6fed; padding:4px 8px; }
            QPushButton:pressed, QPushButton:checked { background:#3fb950; border-color:#3fb950; }
            QHeaderView::section { background:#2f6fed; color:#fff; border:1px solid #2f6fed; }
            QMenu { background:#2f6fed; color:#fff; border:1px solid #2f6fed; }
            QMenu::item:selected { background:#3fb950; }
            QTabBar::tab { background:#2f6fed; color:#fff; border:1px solid #2f6fed; padding:6px 10px; }
            QTabBar::tab:selected { background:#3fb950; }
            QTableWidget::item:selected:!active { background:#0f141b; color:#e6edf3; }
            """
        )

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _mk_table(self, headers, select_rows=True):
        t = QtWidgets.QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.verticalHeader().setVisible(False)
        t.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignVCenter)
        if select_rows:
            t.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        else:
            t.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectItems)
        t.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        t.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        t.horizontalHeader().setStretchLastSection(True)
        return t

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _group(self, title, widget):
        g = QtWidgets.QGroupBox(title)
        v = QtWidgets.QVBoxLayout(g)
        v.setContentsMargins(4, 6, 4, 4)
        v.addWidget(widget)
        return g

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _build_ui(self):
        c = QtWidgets.QWidget(self)
        self.setCentralWidget(c)
        root = QtWidgets.QVBoxLayout(c)
        root.setContentsMargins(8, 6, 8, 8)

        top = QtWidgets.QHBoxLayout()
        top.addWidget(QtWidgets.QLabel("设备型号 "))
        self.model_edit = QtWidgets.QLineEdit()
        self.model_edit.setFixedWidth(220)
        top.addWidget(self.model_edit)
        self.conn_lbl = QtWidgets.QLabel("❌设备")
        self.root_lbl = QtWidgets.QLabel("❌Root")
        top.addWidget(self.conn_lbl)
        top.addWidget(self.root_lbl)
        self.info_lbl = QtWidgets.QLabel("序列号=- | 架构=- | SDK=- | 可调试=- | SELinux=-")
        top.addWidget(self.info_lbl, 1)
        self.status_lbl = QtWidgets.QLabel("状态: 就绪")
        top.addWidget(self.status_lbl)
        root.addLayout(top)

        tool = QtWidgets.QHBoxLayout()
        for txt, tip, cb in [
            ("■", "结束目标进程", self._stop_and_clear),
            ("▶", "继续运行", self._resume_debuggee),
            ("⏸", "暂停目标进程", self._pause_target),
            ("↓", "单步步入", lambda: self._send_menu_cmd("c")),
            ("↷", "单步步过", lambda: self._send_menu_cmd("n")),
            ("T", "Trace追踪", self._trace_prompt),
            ("D", "Dump当前模块", self._dump_current_module),
        ]:
            b = QtWidgets.QPushButton(txt)
            b.setFixedWidth(32)
            b.setToolTip(tip)
            b.clicked.connect(cb)
            tool.addWidget(b)
        tool.addStretch(1)
        root.addLayout(tool)

        vs = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
        hs = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)
        ls = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
        rs = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)

        self.dis = self._mk_table(["断点", "地址", "机器码", "指令", "注释"])
        self.dis.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.dis.customContextMenuRequested.connect(self._popup_disasm_menu)
        self.dis.cellDoubleClicked.connect(self._on_disasm_double_click)
        self.dis.itemSelectionChanged.connect(self._repaint_disasm_styles)
        self.dis.setColumnWidth(0, 28)

        mem_wrap = QtWidgets.QWidget()
        mem_layout = QtWidgets.QVBoxLayout(mem_wrap)
        mem_layout.setContentsMargins(0, 0, 0, 0)
        mem_top = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel("内存")
        f = title.font()
        f.setBold(True)
        title.setFont(f)
        title.setStyleSheet("color:#58a6ff;")
        mem_top.addWidget(title)
        mem_top.addWidget(QtWidgets.QLabel("显示 "))
        self.mem_mode = QtWidgets.QComboBox()
        self.mem_mode.addItems(["字节", "双字节", "四字节", "八字节"])
        self.mem_mode.setCurrentText("字节")
        self.mem_mode.currentTextChanged.connect(self._on_memory_display_changed)
        mem_top.addWidget(self.mem_mode)
        mem_top.addWidget(QtWidgets.QLabel("编码 "))
        self.mem_encoding = QtWidgets.QComboBox()
        self.mem_encoding.addItems(["ASCII", "UTF8"])
        self.mem_encoding.setCurrentText("ASCII")
        self.mem_encoding.currentTextChanged.connect(self._on_memory_display_changed)
        mem_top.addWidget(self.mem_encoding)
        mem_top.addStretch(1)
        mem_layout.addLayout(mem_top)
        self.mem = MemoryTableWidget(0, 17)
        self.mem.setHorizontalHeaderLabels(["地址"] + [f"Q{i}" for i in range(1, 3)])
        self.mem.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.mem.verticalHeader().setVisible(False)
        self.mem.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectItems)
        self.mem.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.mem.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.mem.horizontalHeader().setStretchLastSection(True)
        self.mem.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.mem.customContextMenuRequested.connect(self._popup_memory_menu)
        self.mem.cellClicked.connect(self._on_mem_click)
        self.mem.itemSelectionChanged.connect(self._refresh_memory_active_cell_style)
        mem_layout.addWidget(self.mem)

        self.regs = self._mk_table(["寄存器", "值", "注释"])
        self.call = self._mk_table(["序号", "地址", "注释"])
        self.stack = self._mk_table(["偏移", "地址", "值", "注释"])
        self.call.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.call.customContextMenuRequested.connect(self._popup_call_menu)

        ls.addWidget(self._group("反汇编", self.dis))
        ls.addWidget(mem_wrap)
        rs.addWidget(self._group("寄存器", self.regs))
        rs.addWidget(self._group("调用栈", self.call))
        rs.addWidget(self._group("栈", self.stack))
        hs.addWidget(ls)
        hs.addWidget(rs)
        hs.setSizes([950, 490])
        ls.setSizes([580, 320])
        rs.setSizes([420, 240, 240])

        self.tabs = QtWidgets.QTabWidget()
        self.tabs.currentChanged.connect(self._on_tab_changed)
        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.log.customContextMenuRequested.connect(self._popup_log_menu)
        self.bp = self._mk_table(["分类", "类型", "地址", "状态"])
        self.bp.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.bp.customContextMenuRequested.connect(self._popup_bp_menu)
        self.trace = QtWidgets.QPlainTextEdit()
        self.trace.setReadOnly(True)
        self.mod = self._mk_table(["起始", "结束", "权限", "模块"])
        self.mod.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.mod.customContextMenuRequested.connect(self._popup_module_menu)
        self.thr = self._mk_table(["TID", "线程名", "状态", "切换"])
        self.thr.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.thr.customContextMenuRequested.connect(self._popup_thread_menu)
        self.regs.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.regs.customContextMenuRequested.connect(self._popup_regs_menu)
        self.stack.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.stack.customContextMenuRequested.connect(self._popup_stack_menu)

        mod_tab = QtWidgets.QWidget()
        mod_layout = QtWidgets.QVBoxLayout(mod_tab)
        mod_layout.setContentsMargins(0, 0, 0, 0)
        mod_search_bar = QtWidgets.QHBoxLayout()
        mod_search_bar.addWidget(QtWidgets.QLabel("搜索:"))
        self.mod_search_edit = QtWidgets.QLineEdit()
        self.mod_search_edit.textChanged.connect(self._filter_module_tree)
        mod_search_bar.addWidget(self.mod_search_edit, 1)
        mod_layout.addLayout(mod_search_bar)
        mod_layout.addWidget(self.mod)

        self.tabs.addTab(self.log, "日志")
        self.tabs.addTab(self.bp, "断点")
        self.tabs.addTab(self.trace, "Trace")
        self.tabs.addTab(mod_tab, "模块")
        self.tabs.addTab(self.thr, "线程")
        vs.addWidget(hs)
        vs.addWidget(self.tabs)
        vs.setSizes([730, 170])
        root.addWidget(vs, 1)

        bot = QtWidgets.QHBoxLayout()
        self.cmd = QtWidgets.QLineEdit()
        self.cmd.returnPressed.connect(self._send_cmd)
        btn = QtWidgets.QPushButton("发送")
        btn.clicked.connect(self._send_cmd)
        bot.addWidget(self.cmd, 1)
        bot.addWidget(btn)
        root.addLayout(bot)

        self._setup_table_widths()
        self._rebuild_memory_columns()
        self._build_menu()

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _setup_table_widths(self):
        # 功能：在调试器中执行该模块的核心辅助逻辑。
        def scale_col(t, c, mul):
            if c >= t.columnCount():
                return
            base = max(16, t.columnWidth(c))
            t.setColumnWidth(c, int(base * mul))

        # 所有地址列放大到当前的 1.5 倍
        for tbl, col in [
            (self.dis, 1),
            (self.mem, 0),
            (self.call, 1),
            (self.stack, 1),
            (self.bp, 2),
            (self.mod, 0),
            (self.mod, 1),
        ]:
            scale_col(tbl, col, 1.5)
        self._mem_addr_col_width_base = max(64, self.mem.columnWidth(0))
        # 指定列比例调整
        scale_col(self.regs, 1, 1.5)   # 寄存器值列
        scale_col(self.stack, 2, 1.5)  # 栈值列
        scale_col(self.regs, 0, 2 / 3)
        scale_col(self.call, 0, 0.5)
        scale_col(self.stack, 0, 0.5)
        self.dis.setColumnWidth(0, int(max(20, self.dis.columnWidth(0)) * 2.0))
        # 反汇编“指令”列宽显式设置（列索引3）
        self.dis.setColumnWidth(3, int(max(140, self.dis.columnWidth(3)) * 1.4))

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _build_menu(self):
        mb = self.menuBar()
        m1 = mb.addMenu("设备")
        a = QtGui.QAction("连接设备", self)
        a.triggered.connect(self._init_device)
        m1.addAction(a)
        m2 = mb.addMenu("部署")
        a = QtGui.QAction("一键部署并运行", self)
        a.triggered.connect(self._deploy_and_run_server)
        m2.addAction(a)
        a = QtGui.QAction("停止", self)
        a.triggered.connect(self._stop_server)
        m2.addAction(a)
        m3 = mb.addMenu("进程")
        a = QtGui.QAction("附加进程...", self)
        a.triggered.connect(self._attach_process)
        m3.addAction(a)

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _bind_hotkeys(self):
        s = QtGui.QShortcut(QtGui.QKeySequence("Ctrl+G"), self)
        s.activated.connect(self._hotkey_goto)

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _on_tab_changed(self, idx: int):
        txt = self.tabs.tabText(idx)
        if txt == "模块":
            self._refresh_modules_from_adb()
        elif txt == "线程":
            self._refresh_threads_from_adb()

    # 功能：输出调试日志，记录会话关键行为与异常信息。
    def _log(self, s):
        self.log.appendPlainText(s)

    # 功能：输出调试日志，记录会话关键行为与异常信息。
    def _log_ok(self, s):
        self._log(f"[OK] {s}")

    # 功能：输出调试日志，记录会话关键行为与异常信息。
    def _log_err(self, s):
        self._log(f"[ERR] {s}")

    # 功能：处理单步/继续执行控制，驱动断下后的界面刷新链路。
    def _log_step(self, s):
        self._log(f"[STEP] {s}")

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _set_row(self, t, row, vals, bg=None):
        if row >= t.rowCount():
            t.setRowCount(row + 1)
        for c, v in enumerate(vals):
            item = t.item(row, c)
            if item is None:
                item = QtWidgets.QTableWidgetItem(str(v))
                t.setItem(row, c, item)
            elif item.text() != str(v):
                item.setText(str(v))
            if bg:
                item.setBackground(QtGui.QColor(bg))

    # 功能：负责调试界面的样式重绘与状态可视化。
    def _set_cell_style(self, t, row: int, col: int, bg: str = "", fg: str = "", bold: bool = False):
        item = t.item(row, col)
        if item is None:
            item = QtWidgets.QTableWidgetItem("")
            t.setItem(row, col, item)
        if bg:
            item.setBackground(QtGui.QColor(bg))
        else:
            item.setBackground(QtGui.QColor("#0f141b"))
        if fg:
            item.setForeground(QtGui.QColor(fg))
        else:
            item.setForeground(QtGui.QColor("#e6edf3"))
        f = item.font()
        if f.bold() != bold:
            f.setBold(bold)
            item.setFont(f)

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _hx(self, v: int):
        return f"0x{int(v):X}"

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _upper_hex_text(self, text: str):
        return re.sub(r"0x([0-9a-fA-F]+)", lambda m: "0x" + m.group(1).upper(), text or "")

    # 功能：解析服务端输出并路由到对应调试视图。
    def _parse_addr_text(self, text: str):
        m = re.search(r"0x[0-9a-fA-F]+", text or "")
        if not m:
            return None
        try:
            return int(m.group(0), 16)
        except Exception:
            return None

    # 功能：解析服务端输出并路由到对应调试视图。
    def _parse_plain_hex_expr(self, text: str):
        s = (text or "").strip()
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", s):
            try:
                return int(s, 16)
            except Exception:
                return None
        if not re.fullmatch(r"[0-9a-fA-F]+", s):
            return None
        try:
            return int(s, 16)
        except Exception:
            return None

    # 功能：处理调试器与服务端通信连接、部署与会话维护。
    def _ensure_session_ready(self, need_attach=True):
        if self.session.sock is None:
            QtWidgets.QMessageBox.warning(self, "连接已断开", "当前客户端与服务端连接已终止，请先重新连接/部署并附加进程。")
            return False
        if need_attach and (self.attach_state != "ok" or self.current_target_pid <= 0):
            QtWidgets.QMessageBox.warning(self, "附加已终止", "当前未附加调试进程，请先附加进程后再发送命令。")
            return False
        return True

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _send_cmd(self):
        s = self.cmd.text().strip()
        if not s:
            return
        need_attach = not (s.startswith("attach ") or s in ("help", "cls"))
        if not self._ensure_session_ready(need_attach=need_attach):
            return
        self._log(f"[命令详细] 发送请求: {s}")
        # 只要用户发送了命令（如单步、继续），就取消对[THREAD]反汇编更新的抑制
        if s in ("c", "n", "r") or s.startswith("brk") or s.startswith("u ") or s.startswith("upkt "):
            self._suppress_thread_refresh_until = 0.0
        self.session.send(s)

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _send_menu_cmd(self, cmd):
        self.cmd.setText(cmd)
        self._send_cmd()

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _send_prompt_cmd(self, base: str, hint: str, initial: str = ""):
        v, ok = QtWidgets.QInputDialog.getText(self, "输入参数", f"{base} {hint}", text=initial)
        if not ok:
            return
        s = v.strip()
        if s:
            self._send_menu_cmd(f"{base} {s}")
        else:
            self._send_menu_cmd(base)

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _memory_cells_from_bytes(self, b):
        unit, _prefix, count = self._memory_mode_layout()
        cells = []
        for i in range(0, 16, unit):
            chunk = b[i:i + unit]
            cells.append("" if len(chunk) < unit else "".join(reversed(chunk)))
        while len(cells) < count:
            cells.append("")
        cells.append(self._memory_encoded_text(b))
        return cells

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _memory_encoded_text(self, b):
        vals = []
        for hx in (b or [])[:16]:
            hs = str(hx or "").strip()
            if re.fullmatch(r"[0-9a-fA-F]{2}", hs):
                vals.append(int(hs, 16))
            else:
                vals.append(None)
        while len(vals) < 16:
            vals.append(None)
        mode = self.mem_encoding.currentText() if hasattr(self, "mem_encoding") else "ASCII"
        if mode == "UTF8":
            raw = bytes(v if v is not None else 0x2E for v in vals)
            txt = raw.decode("utf-8", errors="replace")
            out = []
            for ch in txt:
                code = ord(ch)
                if code < 32 or code == 127:
                    out.append(".")
                else:
                    out.append(ch)
            return "".join(out)
        out = []
        for v in vals:
            if v is None:
                out.append(".")
            elif 32 <= v <= 126:
                out.append(chr(v))
            else:
                out.append(".")
        return "".join(out)

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _memory_mode_layout(self):
        mode = self.mem_mode.currentText()
        if mode == "字节":
            return 1, "B", 16
        if mode == "双字节":
            return 2, "W", 8
        if mode == "四字节":
            return 4, "D", 4
        return 8, "Q", 2

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _rebuild_memory_columns(self):
        _unit, prefix, count = self._memory_mode_layout()
        enc_name = self.mem_encoding.currentText() if hasattr(self, "mem_encoding") else "ASCII"
        headers = ["地址"] + [f"{prefix}{i}" for i in range(1, count + 1)] + [f"编码({enc_name})"]
        self.mem.setColumnCount(len(headers))
        self.mem.setHorizontalHeaderLabels(headers)
        if self._mem_addr_col_width_base <= 0:
            self._mem_addr_col_width_base = max(64, self.mem.columnWidth(0))
        if not hasattr(self, "_mem_data_col_width_base") or self._mem_data_col_width_base <= 0:
            self._mem_data_col_width_base = max(24, self.mem.columnWidth(1) if self.mem.columnCount() > 1 else 24)
        self.mem.setColumnWidth(0, self._mem_addr_col_width_base)
        # 先按显示方式分支，当前统一同一个基准宽度，后续可按模式分别调整。
        mode = self.mem_mode.currentText()
        self._log(f"[内存窗口] 切换模式: {mode}")
        if mode == "字节":
            data_w = 25 #self._mem_data_col_width_base
        elif mode == "双字节":
            data_w = 50
        elif mode == "四字节":
            data_w = 100
        else:
            data_w = 200
        for c in range(1, count + 1):
            self.mem.setColumnWidth(c, data_w)
        self.mem.setColumnWidth(count + 1, max(140, self.mem.columnWidth(count + 1)))
        self._mem_selected_col = min(max(1, self._mem_selected_col), count)

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _slide_disasm_window_forward(self):
        self._log("[入口] 单步滑窗")
        if self.dis.rowCount() <= 1:
            return False
        first_it = self.dis.item(0, 1)
        last_it = self.dis.item(self.dis.rowCount() - 1, 1)
        first_addr = self._parse_addr_text(first_it.text() if first_it else "")
        last_addr = self._parse_addr_text(last_it.text() if last_it else "")
        if first_addr is None or last_addr is None:
            return False
        
        # 删除第一行
        self.dis.removeRow(0)
        
        # 快速更新映射，避免全量重新解析
        new_row_by_addr = {}
        for k, v in self._dis_row_by_addr.items():
            if v > 0:
                new_row_by_addr[k] = v - 1
        self._dis_row_by_addr = new_row_by_addr
        if self._dis_sorted_addrs:
            self._dis_sorted_addrs.pop(0)
            
        cmd = f"upkt {self._hx(last_addr + 4)} 1"
        self._disasm_rx_count = 0
        self._disasm_rx_first_addr = None
        self._disasm_rx_last_addr = None
        self._disasm_rx_cmd = cmd
        self._disasm_rx_expect = 1
        self._disasm_rx_summary_once = False
        self._disasm_rx_started_at = time.monotonic()
        self._disasm_seq_retry = 0
        self._reset_disasm_seq_state()
        self._rx_discard_pending_disasm()
        self._log(f"[单步收发] 发送反汇编命令: {cmd}")
        self._send_menu_cmd(cmd)
        return True

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _on_memory_display_changed(self, _=None):
        self._rebuild_memory_columns()
        for r, (addr, b) in enumerate(self._mem_row_by_addr.items()):
            self._set_row(self.mem, r, [addr] + self._memory_cells_from_bytes(b))
            addr_item = self.mem.item(r, 0)
            if addr_item:
                addr_item.setFlags(addr_item.flags() & ~QtCore.Qt.ItemFlag.ItemIsSelectable)
        self._refresh_memory_active_cell_style()

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _apply_memory_columns(self):
        self._on_memory_display_changed()

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _repaint_disasm_styles(self):
        self._log("[DEBUG] 开始重绘反汇编样式")
        sel_rows = {idx.row() for idx in self.dis.selectionModel().selectedIndexes()} if self.dis.selectionModel() else set()
        self._log(f"[DEBUG] 选择行: {sel_rows}, 当前PC: {hex(self.current_pc_addr) if self.current_pc_addr else 'None'}")
        
        for r in range(self.dis.rowCount()):
            it = self.dis.item(r, 1)
            if not it:
                continue
            addr = self._parse_addr_text(it.text())
            bp = self.breakpoints.get(addr, {}) if addr is not None else {}
            kind = bp.get("kind", "")
            mark = self._bp_mark(kind)
            mark_item = self.dis.item(r, 0)
            if mark_item and mark_item.text() != mark:
                mark_item.setText(mark)
            insn_item = self.dis.item(r, 3)
            if kind == "software" and insn_item is not None:
                orig = str(bp.get("orig_insn", "") or "")
                if orig and insn_item.text() != orig:
                    insn_item.setText(orig)
            if addr is not None:
                addr_text = f"0x{addr:X}"
                if addr == self.current_pc_addr:
                    addr_text = f"{addr_text}  <-"
                if it.text() != addr_text:
                    it.setText(addr_text)
            bg = "#0f141b"
            fg = "#e6edf3"
            bold = False
            is_pc_row = addr is not None and addr == self.current_pc_addr
            if is_pc_row:
                self._log(f"[DEBUG] 设置PC行样式 r={r}, addr={hex(addr)}")
                bg, fg, bold = "#3FB950", "#ffffff", True
            elif self.dis.hasFocus() and r in sel_rows:
                bg, fg = "#D0D7DE", "#111111"
            elif kind == "software":
                bg, fg = "#c62828", "#ffffff"
            elif kind == "hardware":
                bg, fg = "#7b1fa2", "#ffffff"
            elif kind == "memory":
                bg, fg = "#1565c0", "#ffffff"
            
            for c in range(self.dis.columnCount()):
                self._set_cell_style(self.dis, r, c, bg=bg, fg=fg, bold=bold)
                it_c = self.dis.item(r, c)
                if it_c:
                    # 如果是PC行，取消可选状态，防止Qt的选择样式覆盖自定义颜色
                    if is_pc_row:
                        it_c.setFlags(it_c.flags() & ~QtCore.Qt.ItemFlag.ItemIsSelectable)
                        # 如果该行当前被选中，取消选中
                        it_c.setSelected(False)
                    else:
                        it_c.setFlags(it_c.flags() | QtCore.Qt.ItemFlag.ItemIsSelectable)
                        
            if is_pc_row:
                self._log(f"[DEBUG] 强制PC行背景色 r={r}")
                for c in range(self.dis.columnCount()):
                    it_pc = self.dis.item(r, c)
                    if it_pc:
                        it_pc.setBackground(QtGui.QColor("#3FB950"))

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _scroll_disasm_to_addr(self, addr: int, hint_name: str = "center"):
        if self.dis.rowCount() <= 0:
            return False
        self._log("[入口] 滚动定位 addr={}".format(hex(addr) if addr else "None"))
        if addr is None:
            return False
        for r in range(self.dis.rowCount()):
            it = self.dis.item(r, 1)
            a = self._parse_addr_text(it.text() if it else "")
            if a != addr:
                continue
            hint = QtWidgets.QAbstractItemView.ScrollHint.PositionAtCenter
            if hint_name == "top":
                hint = QtWidgets.QAbstractItemView.ScrollHint.PositionAtTop
            if it is not None:
                skip_select = bool(self._pending_disasm_no_select_once)
                self._pending_disasm_no_select_once = False
                if not skip_select:
                    self.dis.itemSelectionChanged.disconnect()
                    self.dis.setCurrentCell(r, 1)
                    self.dis.itemSelectionChanged.connect(self._repaint_disasm_styles)
                    self._repaint_disasm_styles()
                if hint_name == "goto_down4":
                    anchor_row = max(0, r - 4)
                    anchor_item = self.dis.item(anchor_row, 1)
                    if anchor_item is not None:
                        self.dis.scrollToItem(anchor_item, QtWidgets.QAbstractItemView.ScrollHint.PositionAtTop)
                    else:
                        self.dis.scrollToItem(it, QtWidgets.QAbstractItemView.ScrollHint.PositionAtTop)
                else:
                    self.dis.scrollToItem(it, hint)
                shift_up = max(0, int(self._pending_disasm_focus_shift_up_rows or 0))
                self._pending_disasm_focus_shift_up_rows = 0
                if shift_up > 0:
                    focus_row = max(0, r - shift_up)
                    self.dis.itemSelectionChanged.disconnect()
                    self.dis.setCurrentCell(focus_row, 1)
                    self.dis.itemSelectionChanged.connect(self._repaint_disasm_styles)
                    self._repaint_disasm_styles()
            return True
        return False

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _refresh_memory_active_cell_style(self):
        if self._mem_active_cell:
            old_r, old_c = self._mem_active_cell
            if 0 <= old_r < self.mem.rowCount() and 0 <= old_c < self.mem.columnCount():
                self._set_cell_style(self.mem, old_r, old_c, bg="#0f141b", fg="#e6edf3", bold=False)
        idx = self.mem.currentIndex()
        if not idx.isValid():
            self._mem_active_cell = None
            return
        r, c = idx.row(), idx.column()
        if c == 0:
            self._mem_active_cell = None
            return
        self._mem_active_cell = (r, c)
        if self._pending_mem_scroll_addr is not None:
            base_it = self.mem.item(r, 0)
            base = self._parse_addr_text(base_it.text() if base_it else "")
            if base is not None and base <= self._pending_mem_scroll_addr <= base + 15:
                hint = QtWidgets.QAbstractItemView.ScrollHint.PositionAtCenter
                if self._pending_mem_scroll_hint == "top":
                    hint = QtWidgets.QAbstractItemView.ScrollHint.PositionAtTop
                self.mem.scrollToItem(base_it, hint)
                self._pending_mem_scroll_addr = None
                self._pending_mem_scroll_hint = "center"

    # 功能：处理寄存器数据解析与展示，用于更新当前执行上下文。
    def _reg_priority_index(self, reg: str):
        order = {"pc": 0, "sp": 1, "x30": 2}
        if reg in order:
            return order[reg]
        m = re.fullmatch(r"x(\d+)", reg or "")
        if m:
            idx = int(m.group(1))
            if 0 <= idx <= 29:
                return 3 + idx
            return 1000
        if reg == "pstate":
            return 100
        return 1000

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _parse_disasm_row(self, payload: str):
        m = re.match(r"^\s*(=>)?\s*(0x[0-9a-fA-F]+)(?:\s+\(([^)]*)\))?\s*:\s*(.*)$", payload)
        if not m:
            return False
        is_pc = bool(m.group(1))
        addr_int = int(m.group(2), 16)
        addr_txt = self._hx(addr_int)
        rest = m.group(4).strip()
        m2 = re.match(r"^(([0-9a-fA-F]{2}\s+){3}[0-9a-fA-F]{2}|[0-9a-fA-F]{8})\s+(.+)$", rest)
        if not m2:
            return False
        code = " ".join(m2.group(1).split()).upper()
        insn_raw = m2.group(3).strip()
        insn = insn_raw
        if (not insn) or re.fullmatch(r"[0-9a-fA-F ]+", insn):
            return False
        need_refresh_modules = (
            self.current_target_pid > 0
            and self.attach_state == "ok"
            and ((not self.module_rows) or self._module_rows_pid != self.current_target_pid)
        )
        if need_refresh_modules:
            self._refresh_modules_from_adb()
        self._dis_raw_insn_by_addr[addr_int] = insn_raw
        insn_addrs = []
        for h in self._hex_re.findall(insn_raw):
            if len(h[2:]) < 6:
                continue
            hh = self._upper_hex_text(h)
            if hh not in insn_addrs:
                insn_addrs.append(hh)
        for mm in re.finditer(r"\b(?:0x|0X)?([0-9a-fA-F]{8,16})\b", insn_raw):
            raw = mm.group(0)
            h2 = raw if raw.lower().startswith("0x") else ("0x" + mm.group(1))
            h2 = self._upper_hex_text(h2)
            if h2 not in insn_addrs:
                insn_addrs.append(h2)
        insn = self._rewrite_insn_with_module_offsets(insn)
        self._dis_comment_addr_shadow[addr_int] = insn_addrs
        comment = ", ".join(insn_addrs)
        self._disasm_rx_count += 1
        if self._disasm_rx_first_addr is None:
            self._disasm_rx_first_addr = addr_int
        self._disasm_rx_last_addr = addr_int
        if self._attach_disasm_batch_active:
            self._attach_disasm_batch_rows[addr_int] = (addr_txt, code, insn, comment)
            self._attach_disasm_batch_last_rx_at = time.monotonic()
            if is_pc:
                self.current_pc_addr = addr_int
            return True
        if self._dis_last_addr is not None and addr_int < self._dis_last_addr:
            self._dis_reorder_needed = True
        self._dis_last_addr = addr_int
        if addr_txt in self._dis_row_by_addr:
            row = self._dis_row_by_addr[addr_txt]
        else:
            row = bisect.bisect_left(self._dis_sorted_addrs, addr_int)
            if row < self.dis.rowCount():
                self.dis.insertRow(row)
                for k, rv in list(self._dis_row_by_addr.items()):
                    if rv >= row:
                        self._dis_row_by_addr[k] = rv + 1
            self._dis_row_by_addr[addr_txt] = row
            self._dis_sorted_addrs.insert(row, addr_int)
        self._set_row(self.dis, row, ["", addr_txt, code, insn, comment])
        if is_pc:
            self.current_pc_addr = addr_int
        self._disasm_style_dirty = True
        return True

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _rebuild_disasm_sorted(self):
        rows = []
        for r in range(self.dis.rowCount()):
            it_addr = self.dis.item(r, 1)
            addr = self._parse_addr_text(it_addr.text() if it_addr else "")
            if addr is None:
                continue
            vals = []
            for c in range(self.dis.columnCount()):
                it = self.dis.item(r, c)
                vals.append(it.text() if it else "")
            rows.append((addr, vals))
        rows.sort(key=lambda x: x[0])
        self.dis.setUpdatesEnabled(False)
        self.dis.setRowCount(0)
        self._dis_row_by_addr = {}
        self._dis_sorted_addrs = []
        for i, (_addr, vals) in enumerate(rows):
            self._set_row(self.dis, i, vals)
            self._dis_row_by_addr[str(vals[1]).strip().split()[0].upper()] = i
            self._dis_sorted_addrs.append(_addr)
        self.dis.setUpdatesEnabled(True)
        self._dis_reorder_needed = False

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _parse_memory_row(self, payload: str):
        m = re.match(r"^(0x[0-9a-fA-F]+):\s*(.*)$", payload)
        if not m:
            return False
        addr = self._upper_hex_text(m.group(1))
        data = re.findall(r"[0-9a-fA-F?]+", m.group(2))
        b = []
        for t in data:
            if len(t) % 2 != 0:
                continue
            pairs = [t[i:i + 2].upper() for i in range(0, len(t), 2)]
            # 输入是多字节单元（W/D/Q）时，统一转为“地址从左到右”的真实字节顺序。
            if len(pairs) > 1:
                pairs.reverse()
            b.extend(pairs)
        b = (b + ["??"] * 16)[:16]
        if addr not in self._mem_row_by_addr:
            self._mem_row_by_addr[addr] = b
            row = self.mem.rowCount()
        else:
            self._mem_row_by_addr[addr] = b
            row = list(self._mem_row_by_addr.keys()).index(addr)
        self._set_row(self.mem, row, [addr] + self._memory_cells_from_bytes(b))
        addr_item = self.mem.item(row, 0)
        if addr_item:
            addr_item.setFlags(addr_item.flags() & ~QtCore.Qt.ItemFlag.ItemIsSelectable)
        if self._pending_mem_scroll_addr is not None:
            base = self._parse_addr_text(addr)
            if base is not None and base <= self._pending_mem_scroll_addr <= base + 15:
                self.mem.setCurrentCell(row, self._memory_col_by_addr(self._pending_mem_scroll_addr, base))
                hint = QtWidgets.QAbstractItemView.ScrollHint.PositionAtCenter
                if self._pending_mem_scroll_hint == "top":
                    hint = QtWidgets.QAbstractItemView.ScrollHint.PositionAtTop
                self.mem.scrollToItem(addr_item, hint)
                self._pending_mem_scroll_addr = None
                self._pending_mem_scroll_hint = "center"
                shift_up = max(0, int(self._pending_mem_focus_shift_up_rows or 0))
                self._pending_mem_focus_shift_up_rows = 0
                if shift_up > 0:
                    focus_row = max(0, row - shift_up)
                    focus_col = self.mem.currentColumn()
                    if focus_col <= 0:
                        focus_col = 1
                    self.mem.setCurrentCell(focus_row, focus_col)
        self._refresh_memory_active_cell_style()
        return True

    # 功能：处理寄存器数据解析与展示，用于更新当前执行上下文。
    def _parse_regs_row(self, payload: str):
        # 兼容单行一个寄存器、以及“x0=... | x16=...”这类单行多寄存器场景
        matches = list(
            re.finditer(
                r"\b((?:x(?:[12]?\d|30))|sp|pc|pstate)\b\s*[:=]\s*(?:0x)?([0-9a-fA-F]+)(?:\s+\(([^)]*)\))?",
                payload.strip(),
                re.IGNORECASE,
            )
        )
        entries = []
        for m in matches:
            reg = m.group(1).strip().lower()
            # 过滤调用栈片段中的“#0 pc=...”，避免误覆盖当前线程PC。
            if reg == "pc":
                left = payload[max(0, m.start() - 16):m.start()]
                if re.search(r"#\d+\s*$", left):
                    continue
            val = "0x" + m.group(2).upper()
            sym = self._upper_hex_text((m.group(3) or "").strip())
            entries.append((reg, val, sym))
        return self._upsert_regs_sorted(entries, call_attach_init=True)

    # 功能：处理寄存器数据解析与展示，用于更新当前执行上下文。
    def _parse_regs_from_dashboard(self, payload: str):
        entries = []
        # 兼容 dashboard 里的 "x0=... | x16=..." 与 "sp=... | pc=..." 等组合行
        for m in re.finditer(r"\b((?:x(?:[12]?\d|30))|sp|pc|pstate)\b\s*=\s*([0-9A-Fa-f]{8,16})(?:\s+\(([^)]*)\))?", payload, re.IGNORECASE):
            reg = m.group(1).strip().lower()
            # 过滤调用栈片段中的“#0 pc=...”，避免误覆盖当前线程PC。
            if reg == "pc":
                left = payload[max(0, m.start() - 16):m.start()]
                if re.search(r"#\d+\s*$", left):
                    continue
            val = "0x" + m.group(2).upper()
            sym = self._upper_hex_text((m.group(3) or "").strip())
            entries.append((reg, val, sym))
        return self._upsert_regs_sorted(entries, call_attach_init=False)

    # 功能：处理寄存器数据解析与展示，用于更新当前执行上下文。
    def _upsert_regs_sorted(self, entries, call_attach_init: bool):
        if not entries:
            return False
        uniq = {}
        # 合并已有寄存器数据，保证每次更新后都按固定顺序重排入表。
        for reg, row in list(self._reg_row_by_name.items()):
            if row < 0 or row >= self.regs.rowCount():
                continue
            it_val = self.regs.item(row, 1)
            it_sym = self.regs.item(row, 2)
            if it_val is None:
                continue
            uniq[reg] = (it_val.text().strip(), (it_sym.text().strip() if it_sym else ""))
        for reg, val, sym in entries:
            uniq[reg] = (val, sym)
        ordered = sorted(uniq.items(), key=lambda kv: self._reg_priority_index(kv[0]))
        self.regs.setRowCount(0)
        self._reg_row_by_name = {}
        for row, (reg, (val, sym)) in enumerate(ordered):
            self._reg_row_by_name[reg] = row
            self._set_row(self.regs, row, [reg, val, sym])
        pc_entry = uniq.get("pc")
        if pc_entry:
            try:
                self.current_pc_addr = int(pc_entry[0], 16)
                self._disasm_style_dirty = True
                if call_attach_init:
                    self._maybe_do_attach_post_init()
            except Exception:
                pass
        return True

    # 功能：处理调用栈/栈数据采集与展示，辅助定位执行路径。
    def _parse_callstack_row(self, payload: str):
        # 兼容单行一个栈帧，及异常情况下的单行多栈帧文本
        matches = list(re.finditer(r"#(\d+)\s+pc\s*=\s*(?:0x)?([0-9a-fA-F]+)(?:\s+\(([^)]*)\))?", payload.strip(), re.IGNORECASE))
        if not matches:
            return False
        for m in matches:
            idx = m.group(1)
            row = self._call_row_by_idx.get(idx, self.call.rowCount())
            self._call_row_by_idx[idx] = row
            self._set_row(self.call, row, [idx, "0x" + m.group(2).upper(), self._upper_hex_text((m.group(3) or "").strip())])
        return True

    # 功能：处理调用栈/栈数据采集与展示，辅助定位执行路径。
    def _parse_callstack_from_dashboard(self, payload: str):
        parsed = False
        for m in re.finditer(r"#(\d+)\s+pc\s*=\s*(?:0x)?([0-9A-Fa-f]+)(?:\s+\(([^)]*)\))?", payload, re.IGNORECASE):
            idx = m.group(1)
            row = self._call_row_by_idx.get(idx, self.call.rowCount())
            self._call_row_by_idx[idx] = row
            self._set_row(self.call, row, [idx, "0x" + m.group(2).upper(), self._upper_hex_text((m.group(3) or "").strip())])
            parsed = True
        return parsed

    # 功能：处理调用栈/栈数据采集与展示，辅助定位执行路径。
    def _parse_stack_row(self, payload: str):
        m = re.match(r"^sp([+-](?:0x)?[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+=>\s+(0x[0-9a-fA-F]+)(?:\s+\(([^)]*)\))?$", payload, re.IGNORECASE)
        if not m:
            return False
        off = m.group(1)
        row = self._stack_row_by_off.get(off, self.stack.rowCount())
        self._stack_row_by_off[off] = row
        self._set_row(self.stack, row, [off, self._upper_hex_text(m.group(2)), self._upper_hex_text(m.group(3)), self._upper_hex_text((m.group(4) or "").strip())])
        try:
            s = off.strip()
            sign = -1 if s.startswith("-") else 1
            num = s[1:] if s[:1] in "+-" else s
            off_val = sign * int(num, 16)
        except Exception:
            off_val = None
        if off_val == 0:
            anchor = self.stack.item(row, 0) or self.stack.item(row, 1)
            if anchor is not None:
                self.stack.setCurrentCell(row, 1)
                self.stack.scrollToItem(anchor, QtWidgets.QAbstractItemView.ScrollHint.PositionAtCenter)
        return True

    # 功能：校验分片反汇编数据，检测传输中内容损坏。
    def _fnv1a32(self, s: str) -> int:
        h = 2166136261
        for ch in s.encode("utf-8", errors="ignore"):
            h ^= ch
            h = (h * 16777619) & 0xFFFFFFFF
        return h

    # 功能：解析服务端分片反汇编元信息，提取包序号、总包数和校验值。
    def _parse_seq_meta(self, meta: str):
        vals = {}
        for seg in meta.split(";"):
            if "=" not in seg:
                continue
            k, v = seg.split("=", 1)
            vals[k.strip().lower()] = v.strip()
        try:
            sid = int(vals.get("sid", "0"))
            seq = int(vals.get("seq", "0"))
            total = int(vals.get("total", "0"))
            crc = int(vals.get("crc", "0"), 16)
            return sid, seq, total, crc
        except Exception:
            return 0, 0, 0, 0

    # 功能：重置分片反汇编接收状态，开始新的完整包收集。
    def _reset_disasm_seq_state(self):
        self._disasm_seq_sid = 0
        self._disasm_seq_total = 0
        self._disasm_seq_parts = {}
        self._disasm_seq_bad = 0
        self._disasm_seq_last_at = 0.0

    # 功能：解析服务端输出并路由到对应调试视图。
    def _parse_packet(self, line: str):
        parts = line.split("|", 3)
        if len(parts) < 4:
            return
        ch = parts[1].strip().upper()
        meta = parts[2]
        payload = parts[3]
        if payload == "__CLEAR__":
            self.pending_clear_channels.add(ch)
            return
        if ch == "LOG":
            if payload.startswith("[") and payload.endswith("]"):
                self._log(payload)
            if self.trace_collecting and (not payload.startswith("trace完成")):
                self.trace_rows_raw.append(payload)
            if payload.startswith("trace完成"):
                self.trace_collecting = False
                self._show_trace_table()
            return
        if ch == "DISASM":
            if self.attach_state != "ok":
                return
            if "DISASM" in self.pending_clear_channels:
                self.dis.setRowCount(0)
                self._dis_row_by_addr = {}
                self._dis_sorted_addrs = []
                self._dis_stream_desc = None
                self._dis_last_addr = None
                self._dis_reorder_needed = False
                self.pending_clear_channels.discard("DISASM")
            self._parse_disasm_row(payload)
            return
        if ch == "DISASMSEQ":
            if self.attach_state != "ok":
                return
            sid, seq, total, crc = self._parse_seq_meta(meta)
            if sid <= 0 or seq <= 0 or total <= 0:
                return
            try:
                payload_txt = bytes.fromhex(payload.strip()).decode("utf-8", errors="ignore")
            except Exception:
                self._disasm_seq_bad += 1
                return
            if self._fnv1a32(payload_txt) != crc:
                self._disasm_seq_bad += 1
                return
            if self._disasm_seq_sid != sid:
                self._disasm_seq_sid = sid
                self._disasm_seq_total = total
                self._disasm_seq_parts = {}
                self._disasm_seq_bad = 0
            self._disasm_seq_last_at = time.monotonic()
            self._disasm_seq_parts[seq] = payload_txt
            self._disasm_rx_count = len(self._disasm_seq_parts)
            self._disasm_rx_first_addr = None
            self._disasm_rx_last_addr = None
            return
        if ch == "DISASMSEQ_END":
            vals = {}
            for seg in meta.split(";"):
                if "=" in seg:
                    k, v = seg.split("=", 1)
                    vals[k.strip().lower()] = v.strip()
            try:
                sid = int(vals.get("sid", "0"))
                total = int(vals.get("total", "0"))
            except Exception:
                return
            if sid <= 0 or total <= 0 or sid != self._disasm_seq_sid:
                return
            if not self._disasm_seq_parts:
                return
            # 排序重组：按包序号顺序灌入反汇编批量缓冲
            missing = [i for i in range(1, total + 1) if i not in self._disasm_seq_parts]
            if (not missing) and self._disasm_seq_bad == 0:
                for i in range(1, total + 1):
                    self._parse_disasm_row(self._disasm_seq_parts[i])
                self._flush_disasm_batch("SEQ_END")
                self._reset_disasm_seq_state()
                return
            # 超时/校验失败兜底重发：重发整条反汇编命令
            if self._disasm_seq_retry < 2 and self._disasm_rx_cmd:
                self._disasm_seq_retry += 1
                miss_preview = ",".join(str(x) for x in missing[:12]) if missing else "无"
                self._log(
                    "[重传] 分片缺失/校验失败，重发命令({}/2): {} 缺片={} 坏包={} 缺失序号={}".format(
                        self._disasm_seq_retry, self._disasm_rx_cmd, len(missing), self._disasm_seq_bad, miss_preview
                    )
                )
                self._rx_discard_pending_disasm()
                self._reset_disasm_seq_state()
                self._send_menu_cmd(self._disasm_rx_cmd)
            else:
                # 降级策略：仅缺少极少分片且无坏包时，先用已收齐分片入表，避免窗口空白。
                if self._disasm_seq_bad == 0 and len(missing) <= 2 and self._disasm_seq_parts:
                    miss_preview = ",".join(str(x) for x in missing)
                    self._log(
                        "[降级] 分片重试达上限但仅缺少少量分片，先部分入表: 已收={} 总数={} 缺失序号={}".format(
                            len(self._disasm_seq_parts), total, miss_preview
                        )
                    )
                    for i in sorted(self._disasm_seq_parts.keys()):
                        self._parse_disasm_row(self._disasm_seq_parts[i])
                    self._flush_disasm_batch("SEQ_PARTIAL")
                    self._reset_disasm_seq_state()
                else:
                    self._log_err(
                        "[重传失败] 分片缺失/校验失败且重试达上限: 缺片={} 坏包={}".format(
                            len(missing), self._disasm_seq_bad
                        )
                    )
                    self._reset_disasm_seq_state()
            return
        if ch == "REGS":
            if "REGS" in self.pending_clear_channels:
                self.regs.setRowCount(0)
                self._reg_row_by_name = {}
                self.pending_clear_channels.discard("REGS")
            self._parse_regs_row(payload)
            return
        if ch == "MEMORY":
            if "MEMORY" in self.pending_clear_channels:
                self.mem.setRowCount(0)
                self._mem_row_by_addr = {}
                self.pending_clear_channels.discard("MEMORY")
            self._parse_memory_row(payload)
            return
        if ch == "CALLSTACK":
            if "CALLSTACK" in self.pending_clear_channels:
                self.call.setRowCount(0)
                self._call_row_by_idx = {}
                self.pending_clear_channels.discard("CALLSTACK")
            self._parse_callstack_row(payload)
            return
        if ch == "STACK":
            if "STACK" in self.pending_clear_channels:
                self.stack.setRowCount(0)
                self._stack_row_by_off = {}
                self.pending_clear_channels.discard("STACK")
            self._parse_stack_row(payload)
            return

    # 功能：解析服务端输出并路由到对应调试视图。
    def _parse_line(self, s: str):
        line = self._ansi_re.sub("", s.rstrip("\r\n"))
        if not line:
            return
        if line.startswith("asm失败"):
            self._log_err(line)
            self._pending_asm_patch_addr = None
            self._pending_asm_patch_text = ""
            return
        if line.startswith("asm写入成功"):
            self._log_ok(line)
            addr = self._pending_asm_patch_addr
            insn = self._pending_asm_patch_text
            if addr is not None:
                bp = self.breakpoints.get(addr)
                if bp and bp.get("kind") == "software":
                    bp["orig_insn"] = insn
                    self.breakpoints[addr] = bp
                    self._refresh_bp_tab()
                self._send_menu_cmd(f"upkt {self._hx(addr)} 1")
            self._pending_asm_patch_addr = None
            self._pending_asm_patch_text = ""
            return
        if line.startswith("wm失败") or line.startswith("wm成功"):
            if "失败" in line:
                self._log_err(line)
            else:
                self._log_ok(line)
            return
        if "内存断点已设置" in line:
            if self._pending_mem_bp_ack is not None:
                p_addr, p_cmd = self._pending_mem_bp_ack
                m_ack = re.search(r"addr\s*=\s*0x([0-9a-fA-F]+)", line, re.IGNORECASE)
                if m_ack:
                    try:
                        ack_addr = int(m_ack.group(1), 16)
                        if ack_addr != p_addr:
                            self._log(
                                "[排查] 内存断点应答地址与请求不一致: req={} ack={}，仍按请求地址更新界面".format(
                                    self._hx(p_addr), self._hx(ack_addr)
                                )
                            )
                    except Exception:
                        pass
                # 服务端已确认设置成功：始终以本次请求的地址更新断点表（避免因解析/大小写/格式差异导致界面无反馈）。
                self._append_bp_item(p_cmd, p_addr)
                self._pending_mem_bp_ack = None
            self._log_ok(line)
            return
        if "设置内存断点失败" in line:
            self._pending_mem_bp_ack = None
            self._log_err(line)
            return
        if line.startswith("[PKT]|"):
            self._parse_packet(line)
            return
        if line == "[PKT_END]":
            if self._attach_disasm_batch_active and self._attach_disasm_batch_rows:
                self._flush_disasm_batch("PKT_END")
            return
        # 服务端命令提示符到达，表示上一轮命令输出结束，可视为“完整包边界”
        if line.startswith("命令 ["):
            if self._attach_disasm_batch_active and self._attach_disasm_batch_rows:
                self._flush_disasm_batch("PROMPT")
            return
        if line.startswith("ATTACH_OK"):
            self.connected = True
            self.attach_state = "ok"
            self._pending_mem_bp_ack = None
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                self.current_target_pid = int(parts[1])
            if len(parts) >= 3 and parts[2].isdigit():
                self.server_pid = int(parts[2])
            self._update_title()
            self.status_lbl.setText(f"状态: 已连接 pid={self.current_target_pid}")
            self._log_ok("附加成功")
            self._attach_post_init_done = False
            self._target_dead_notified = False
            self._rx_discard_pending_disasm()
            return
        if line == "ATTACH_FAIL":
            if self.attach_state == "ok":
                self._log_step("收到延迟 ATTACH_FAIL，已忽略")
                return
            self.attach_state = "fail"
            self._log_err("附加失败")
            return
        if line.startswith("[THREAD]"):
            self.status_lbl.setText("状态: " + line)
            # 收到 THREAD 代表目标已断下，避免后续断点操作误判为“运行中”而自动继续执行。
            self.target_running = False
            if time.time() >= self._suppress_thread_refresh_until:
                mpc = re.search(r"pc\s*=\s*(0x[0-9a-fA-F]+)", line)
                if not mpc:
                    self._log(f"[排查] [THREAD] 行未携带pc，跳过刷新: {line}")
                    return
                try:
                    new_pc = int(mpc.group(1), 16)
                except Exception:
                    return
                if new_pc is None:
                    return
                self.current_pc_addr = new_pc
                self._disasm_style_dirty = True
                self._log(f"[排查] 解析到THREAD.pc={self._hx(new_pc)}，开始刷新反汇编/内存")
                if not self._attach_post_init_done:
                    self._last_step_pc_addr = new_pc
                    self._maybe_do_attach_post_init()
                    return
                if self._pending_disasm_request_expr is not None:
                    expr = self._pending_disasm_request_expr
                    addr = self._pending_disasm_request_addr
                    hint = self._pending_disasm_request_hint
                    self._pending_disasm_request_expr = None
                    self._pending_disasm_request_addr = None
                    self._pending_disasm_request_hint = "center"
                    self._request_disasm_around(expr, addr, scroll_hint=hint)
                    if new_pc is not None:
                        self._last_step_pc_addr = new_pc
                    return
                
                if new_pc is not None and self._last_step_pc_addr is not None and new_pc == self._last_step_pc_addr + 4:
                    if not self._slide_disasm_window_forward():
                        self._request_disasm_around(self._hx(new_pc), new_pc, scroll_hint="center")
                    else:
                        # +4路径下优先直接命中新PC行样式；若行不存在则回退整窗请求，避免样式丢失。
                        if self._scroll_disasm_to_addr(new_pc, "center"):
                            self._pending_disasm_scroll_addr = new_pc
                            self._pending_disasm_scroll_hint = "center"
                            self._disasm_style_dirty = True
                            self._repaint_disasm_styles()
                        else:
                            self._request_disasm_around(self._hx(new_pc), new_pc, scroll_hint="center")
                else:
                    self._request_disasm_around(self._hx(new_pc), new_pc, scroll_hint="center")
                
                if new_pc is not None:
                    self._last_step_pc_addr = new_pc
            return
            
        # 拦截服务端单步断下时自动输出的 Dashboard 分栏内容（如 => 0x... : ... | x0 : 0x...）
        if " | " in line:
            parts = line.split(" | ", 1)
            left = parts[0].strip()
            right = parts[1].strip()
            # 不解析分栏中的反汇编左列，仅解析其余状态；右列可能还包含二级“ | ”分栏，需逐段解析。
            right_segs = [seg.strip() for seg in right.split(" | ") if seg.strip()]
            left_segs = [left] if left else []
            parsed_any = False
            # 先尝试整行提取，兼容服务端对齐填充导致的分段偏差
            if self._parse_callstack_row(line):
                parsed_any = True
            if self._parse_regs_row(line):
                parsed_any = True
            if self._parse_callstack_from_dashboard(line):
                parsed_any = True
            if self._parse_regs_from_dashboard(line):
                parsed_any = True
            # 左列在下半区会出现内存行，需解析到内存表格
            if left and self._parse_memory_row(left):
                parsed_any = True
            for seg in left_segs + right_segs:
                # 优先解析调用栈/栈，避免把“#0 pc=...”误判成寄存器pc
                if self._parse_callstack_row(seg):
                    parsed_any = True
                    continue
                if self._parse_callstack_from_dashboard(seg):
                    parsed_any = True
                    continue
                if self._parse_stack_row(seg):
                    parsed_any = True
                    continue
                if self._parse_regs_row(seg):
                    parsed_any = True
                    continue
                if self._parse_regs_from_dashboard(seg):
                    parsed_any = True
                    continue
            if not parsed_any and ("[REGS]" in right or "pc=" in right or "sp=" in right):
                self._log(f"[排查] 分栏行未命中解析器: {line}")
            return
            
        if self.attach_state != "ok":
            return
        if self._plain_disasm_fallback_enabled and self._parse_disasm_row(line):
            return
        if self._parse_regs_row(line):
            return
        if self._parse_callstack_row(line):
            return
        if self._parse_stack_row(line):
            return
        if self._parse_memory_row(line):
            return

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _flush_disasm_batch(self, reason: str):
        rows = sorted(self._attach_disasm_batch_rows.items(), key=lambda x: x[0])
        if rows:
            pre_first_addr = self._hx(rows[0][0])
            pre_last_addr = self._hx(rows[-1][0])
        else:
            pre_first_addr = "N/A"
            pre_last_addr = "N/A"
        self._log(
            "[单步收包统计] 准备加入反汇编表格: 行数={} 地址范围=[{}, {}] 来源命令={} 结束条件={}".format(
                len(rows), pre_first_addr, pre_last_addr, self._disasm_rx_cmd or "未知", reason
            )
        )
        # +4 单步滑窗是“增量补一行”场景：保留现有窗口，仅插入/更新新行，避免整表重建丢失当前PC行样式。
        is_slide_incremental = (
            self._disasm_rx_expect == 1
            and self.dis.rowCount() > 0
            and len(rows) == 1
        )
        if is_slide_incremental:
            addr_int, row_vals = rows[0]
            addr_txt, code, insn, comment = row_vals
            if addr_txt in self._dis_row_by_addr:
                row = self._dis_row_by_addr[addr_txt]
            else:
                row = bisect.bisect_left(self._dis_sorted_addrs, addr_int)
                if row < self.dis.rowCount():
                    self.dis.insertRow(row)
                    for k, rv in list(self._dis_row_by_addr.items()):
                        if rv >= row:
                            self._dis_row_by_addr[k] = rv + 1
                self._dis_row_by_addr[addr_txt] = row
                self._dis_sorted_addrs.insert(row, addr_int)
            self._set_row(self.dis, row, ["", addr_txt, code, insn, comment])
            self._attach_disasm_batch_active = False
            self._attach_disasm_batch_rows = {}
            self._attach_disasm_batch_last_rx_at = 0.0
            self._dis_reorder_needed = False
            self._repaint_disasm_styles()
            if (
                self.current_pc_addr > 0
                and self._pending_disasm_scroll_addr is None
                and self._deferred_disasm_scroll_addr is None
            ):
                self._scroll_disasm_to_addr(self.current_pc_addr, "center")
            self._log(
                "[单步收包统计] 增量入表完成: 行数={} 地址范围=[{}, {}] 来源命令={} 结束条件={}".format(
                    len(rows), self._hx(addr_int), self._hx(addr_int), self._disasm_rx_cmd or "未知", reason
                )
            )
            return
        self.dis.setUpdatesEnabled(False)
        self.dis.setRowCount(0)
        self._dis_row_by_addr = {}
        self._dis_sorted_addrs = []
        for i, (addr_int, row_vals) in enumerate(rows):
            addr_txt, code, insn, comment = row_vals
            self._set_row(self.dis, i, ["", addr_txt, code, insn, comment])
            self._dis_row_by_addr[addr_txt] = i
            self._dis_sorted_addrs.append(addr_int)
        self.dis.setUpdatesEnabled(True)
        if rows:
            first_addr = self._hx(rows[0][0])
            last_addr = self._hx(rows[-1][0])
        else:
            first_addr = "N/A"
            last_addr = "N/A"
        self._log(
            "[单步收包统计] 入表完成: 行数={} 地址范围=[{}, {}] 来源命令={} 结束条件={}".format(
                len(rows), first_addr, last_addr, self._disasm_rx_cmd or "未知", reason
            )
        )
        self._attach_disasm_batch_active = False
        self._attach_disasm_batch_rows = {}
        self._attach_disasm_batch_last_rx_at = 0.0
        self._dis_reorder_needed = False
        self._repaint_disasm_styles()
        if (
            self.current_pc_addr > 0
            and self._pending_disasm_scroll_addr is None
            and self._deferred_disasm_scroll_addr is None
        ):
            self._scroll_disasm_to_addr(self.current_pc_addr, "center")

    # 功能：定时驱动调试事件循环，处理收包、刷新与状态检查。
    def _tick(self):
        # 线程已禁用：在主线程定时轮询socket，将新数据泵入rx队列
        for ln in self.session.read_available_lines_nonblocking(max_lines=200):
            self.rx.put(ln)
        processed = 0
        exhausted = False
        try:
            for _ in range(self._max_lines_per_tick):
                self._parse_line(self.rx.get_nowait())
                processed += 1
        except queue.Empty:
            exhausted = True

        # 分片超时重发：若长时间未收到新分片，则重发本轮反汇编命令
        if self._disasm_seq_sid > 0 and self._disasm_seq_last_at > 0:
            if (time.monotonic() - self._disasm_seq_last_at) >= 1.5:
                if self._disasm_seq_retry < 2 and self._disasm_rx_cmd:
                    self._disasm_seq_retry += 1
                    self._log(f"[重传] 分片接收超时，重发命令({self._disasm_seq_retry}/2): {self._disasm_rx_cmd}")
                    self._rx_discard_pending_disasm()
                    self._reset_disasm_seq_state()
                    self._send_menu_cmd(self._disasm_rx_cmd)
                else:
                    self._log_err("[重传失败] 分片接收超时且重试已达上限")
                    self._reset_disasm_seq_state()
        
        # 增加判断：如果当前收集的数据量太小（比如<100），说明可能只是服务端断下时的自动输出，而不是 u 1000 的结果。
        # 此时我们适当延长超时时间，等待真正的 llvm-objdump 结果返回。
        timeout_threshold = 0.15
        if self._attach_disasm_batch_active and len(self._attach_disasm_batch_rows) < 100:
            timeout_threshold = 1.5  # 等待外部 objdump 执行返回
        
        # 优先按预期行数判定“收完”；其次等待服务端提示符；超时只做兜底
        rows_count = len(self._attach_disasm_batch_rows) if self._attach_disasm_batch_active else 0
        reached_expected = self._attach_disasm_batch_active and self._disasm_rx_expect > 0 and rows_count >= self._disasm_rx_expect
        idle_timed_out = (
            exhausted
            and self._attach_disasm_batch_active
            and rows_count > 0
            and (time.monotonic() - self._attach_disasm_batch_last_rx_at) >= timeout_threshold
        )
        hard_wait_exceeded = (
            self._attach_disasm_batch_active
            and self._disasm_rx_started_at > 0
            and (time.monotonic() - self._disasm_rx_started_at) >= 5.0
        )

        if reached_expected:
            self._flush_disasm_batch("EXPECT")
        elif idle_timed_out and (self._disasm_rx_expect <= 0 or hard_wait_exceeded):
            self._flush_disasm_batch("TIMEOUT")
        if self._dis_reorder_needed and (exhausted or processed == 0):
            self._rebuild_disasm_sorted()
            self._disasm_style_dirty = True
        if self._disasm_style_dirty and (exhausted or processed == 0):
            self._repaint_disasm_styles()
            self._disasm_style_dirty = False
        if exhausted:
            target = None
            hint = "center"
            if self._pending_disasm_scroll_addr is not None:
                target = self._pending_disasm_scroll_addr
                hint = self._pending_disasm_scroll_hint
            elif self._deferred_disasm_scroll_addr is not None:
                target = self._deferred_disasm_scroll_addr
                hint = self._deferred_disasm_scroll_hint
            if target is not None:
                # 无反汇编数据时先不滚动，避免日志刷屏；待入表后再滚动定位
                if self.dis.rowCount() > 0 and self._scroll_disasm_to_addr(target, hint):
                    self._pending_disasm_scroll_addr = None
                    self._pending_disasm_scroll_hint = "center"
                    self._deferred_disasm_scroll_addr = None
                    self._deferred_disasm_scroll_hint = "center"
            

    # 功能：定时驱动调试事件循环，处理收包、刷新与状态检查。
    def _check_target_alive_tick(self):
        if self.current_target_pid <= 0 or self.attach_state != "ok" or (not self.device_serial):
            return
        self.adb.serial = self.device_serial
        cp = self.adb.shell(f"su -c 'if [ -d /proc/{self.current_target_pid} ]; then echo OK; else echo NO; fi'", timeout=8)
        alive = "OK" in (cp.stdout or "")
        if alive:
            self._target_dead_notified = False
            return
        if self._target_dead_notified:
            return
        self._target_dead_notified = True
        pid = self.current_target_pid
        self._clear_debug_views()
        self.status_lbl.setText("状态: 目标进程已终止")
        self._styled_alert("目标进程已终止", f"目标进程 pid={pid} 已不存在，调试窗口已清空。")

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _rx_discard_pending_disasm(self):
        self._log("[入口] 清空队列中残留DISASM")
        keep = []
        try:
            while True:
                ln = self.rx.get_nowait()
                stripped = self._ansi_re.sub("", ln.rstrip("\r\n"))
                # 仅保留确实携带寄存器/调用栈信息的复合行，避免再次丢失 x0-x29 与多层调用栈。
                if " | " in stripped:
                    has_regs = re.search(r"\b(?:x(?:[12]?\d|30)|sp|pc|pstate)\b\s*=", stripped, re.IGNORECASE) is not None
                    has_call = re.search(r"#\d+\s+pc\s*=", stripped, re.IGNORECASE) is not None
                    if has_regs or has_call:
                        keep.append(ln)
                        continue
                if stripped.startswith("[PKT]|DISASM|") or stripped.startswith("[PKT]|DISASMSEQ|") or stripped.startswith("[PKT]|DISASMSEQ_END|") or stripped.startswith("0x") or re.match(r"^\s*(=>)?\s*0x", stripped):
                    continue
                keep.append(ln)
        except queue.Empty:
            pass
        for ln in keep:
            self.rx.put(ln)
        self._attach_disasm_batch_active = True
        self._attach_disasm_batch_rows = {}
        self._attach_disasm_batch_last_rx_at = time.monotonic()

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _drain_rx_queue(self):
        try:
            while True:
                self._parse_line(self.rx.get_nowait())
        except queue.Empty:
            pass

    # 功能：处理附加目标进程流程，建立调试会话并同步初始状态。
    def _wait_attach_result(self, timeout_s: float = 8.0):
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            self._drain_rx_queue()
            QtWidgets.QApplication.processEvents()
            if self.attach_state in ("ok", "fail"):
                return self.attach_state
            time.sleep(0.03)
        self._drain_rx_queue()
        return self.attach_state

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _refresh_device_flags(self, dev_ok=False, root_ok=False):
        self.conn_lbl.setText("✅设备" if dev_ok else "❌设备")
        self.root_lbl.setText("✅Root" if root_ok else "❌Root")

    # 功能：初始化调试组件状态与运行所需资源。
    def _init_device(self):
        cp = self.adb.ensure_server()
        self._log_step("初始化设备连接")
        self._log(f"adb start-server: rc={cp.returncode}")
        devs, cp2 = self.adb.devices()
        self._log(f"adb devices: rc={cp2.returncode} devices={len(devs)}")
        self.device_serial = devs[0] if devs else ""
        self.adb.serial = self.device_serial
        abi, _ = self.adb.get_abi()
        model = self.adb.shell("getprop ro.product.model", timeout=10).stdout.strip()
        self.model_edit.setText(model or "-")
        sdk = self.adb.shell("getprop ro.build.version.sdk", timeout=10).stdout.strip()
        dbg = self.adb.shell("getprop ro.debuggable", timeout=10).stdout.strip()
        selinux = self.adb.shell("getenforce", timeout=10).stdout.strip()
        self.info_lbl.setText(f"序列号={self.device_serial or '-'} | 架构={abi or '-'} | SDK={sdk or '-'} | 可调试={dbg or '-'} | SELinux={selinux or '-'}")
        root_ok, _ = self.adb.check_root() if self.device_serial else (False, None)
        self._refresh_device_flags(bool(self.device_serial), bool(root_ok))
        if self.device_serial and root_ok:
            self._ensure_server_ready_on_startup()

    # 功能：处理调试器与服务端通信连接、部署与会话维护。
    def _deploy_server(self):
        cp1, cp2 = self.adb.remount()
        self._log(f"adb root: rc={cp1.returncode}")
        self._log(f"adb remount: rc={cp2.returncode}")
        p = Path(__file__).resolve().parent / "Just_server_arm64"
        if not p.exists():
            self._log_err("找不到 Just_server_arm64（请先运行 build.bat）")
            return False
        cp = self.adb.push(p, "/data/local/tmp/Just_server_arm64")
        self._log(f"adb push: rc={cp.returncode}")
        if cp.returncode != 0:
            return False
        cp_chmod = self.adb.chmod("/data/local/tmp/Just_server_arm64", "777")
        self._log(f"chmod server: rc={cp_chmod.returncode}")
        return cp_chmod.returncode == 0

    # 功能：处理调试器与服务端通信连接、部署与会话维护。
    def _kill_server_process(self):
        self.adb.shell("su -c 'for p in $(pidof Just_server_arm64 2>/dev/null); do kill -9 $p; done'", timeout=10)

    # 功能：处理调试器与服务端通信连接、部署与会话维护。
    def _start_server_process(self, force_restart: bool = False):
        if force_restart:
            self._kill_server_process()
        cp_alive = self.adb.shell("pidof Just_server_arm64 2>/dev/null", timeout=10)
        if cp_alive.stdout.strip():
            self._log_step("检测到服务端已在运行，复用现有进程")
            return True
        self.adb.shell("su -c 'nohup /data/local/tmp/Just_server_arm64 >/data/local/tmp/Just_server_arm64.log 2>&1 &'", timeout=10)
        for _ in range(10):
            time.sleep(0.5)
            cp = self.adb.shell("pidof Just_server_arm64 2>/dev/null", timeout=10)
            if cp.stdout.strip():
                return True
        return False

    # 功能：处理调试器与服务端通信连接、部署与会话维护。
    def _ensure_server_ready_on_startup(self):
        if not self.device_serial:
            self._styled_alert("环境检查失败", "未检测到设备，无法启动服务端。")
            return False
        self.adb.serial = self.device_serial
        root_ok, cp_root = self.adb.check_root()
        self._log(f"su -c id: rc={cp_root.returncode}")
        if not root_ok:
            self._styled_alert("环境检查失败", "Root 检查失败，无法部署服务端。")
            return False
        if not self._deploy_server():
            self._styled_alert("环境检查失败", "推送服务端到 /data/local/tmp 或授权失败。")
            return False
        if not self._start_server_process():
            self._styled_alert("环境检查失败", "启动服务端失败。")
            return False
        if not self.session.connect_only(self.adb):
            self._styled_alert("环境检查失败", "连接服务端失败。")
            return False
        self.reader_stop.clear()
        self._log_step("已禁用Reader线程，改为主线程定时轮询收包")
        self._log_ok("环境检查通过，服务端已连接")
        return True

    # 功能：处理调试器与服务端通信连接、部署与会话维护。
    def _deploy_and_run_server(self):
        if not self._deploy_server():
            return
        if not self._start_server_process(force_restart=True):
            self._log_err("启动Server失败")
            return
        if not self.session.connect_only(self.adb):
            self._log_err("连接 server 端口失败")
            return
        self._restart_reader_thread()
        self._log_ok("Server端口连接成功")

    # 功能：处理线程状态与切换逻辑，确保断下线程与界面状态一致。
    def _restart_reader_thread(self):
        self.reader_stop.set()
        time.sleep(0.05)
        self.reader_stop.clear()
        self._log_step("已禁用Reader线程重启，当前使用主线程轮询收包")

    # 功能：处理附加目标进程流程，建立调试会话并同步初始状态。
    def _ensure_server_connection_for_attach(self):
        self._log_step("附加前检查服务端连接")
        self.reader_stop.set()
        self.session.stop()
        self.reader_stop.clear()
        if self.session.connect_only(self.adb):
            self._log_ok("服务端直连成功")
            self._restart_reader_thread()
            return True
        self._log_err("服务端直连失败，尝试重启服务端")
        ok_deploy = self._deploy_server()
        self._log_step(f"重新部署服务端结果: {ok_deploy}")
        ok_start = self._start_server_process(force_restart=True) if ok_deploy else False
        self._log_step(f"重启服务端结果: {ok_start}")
        if (not ok_deploy) or (not ok_start):
            return False
        if not self.session.connect_only(self.adb):
            self._log_err("重启后连接服务端仍失败")
            return False
        self._log_ok("重启后连接服务端成功")
        self._restart_reader_thread()
        return True

    # 功能：处理附加目标进程流程，建立调试会话并同步初始状态。
    def _attach_process(self):
        self.adb.serial = self.device_serial
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("选择进程")
        dlg.resize(520, 620)
        v = QtWidgets.QVBoxLayout(dlg)
        e = QtWidgets.QLineEdit()
        v.addWidget(e)
        l = QtWidgets.QListWidget()
        v.addWidget(l, 1)
        b_refresh = QtWidgets.QPushButton("刷新进程")
        v.addWidget(b_refresh)
        b = QtWidgets.QPushButton("附加")
        v.addWidget(b)
        procs = []

        # 功能：在调试器中执行该模块的核心辅助逻辑。
        def filter_local():
            k = e.text().strip().lower()
            l.clear()
            for pid, name in procs:
                if k and (k not in str(pid)) and (k not in name.lower()):
                    continue
                l.addItem(f"{pid:>8}  {name}")

        # 功能：在调试器中执行该模块的核心辅助逻辑。
        def refresh():
            nonlocal procs
            procs = sorted(self.adb.ps_list(), key=lambda x: x[0])
            filter_local()
            if not procs:
                self._log_err("未读取到进程列表，请确认设备连接、Root状态和adb可用性。")

        # 功能：在调试器中执行该模块的核心辅助逻辑。
        def ok():
            it = l.currentItem()
            if not it:
                return
            try:
                pid = int(it.text().split()[0])
            except Exception:
                return
            dlg.accept()
            self._run_session(pid)

        # 功能：在调试器中执行该模块的核心辅助逻辑。
        def ok_first():
            if l.currentRow() < 0 and l.count() > 0:
                l.setCurrentRow(0)
            ok()

        e.textChanged.connect(filter_local)
        e.returnPressed.connect(ok_first)
        b_refresh.clicked.connect(refresh)
        b.clicked.connect(ok)
        l.itemDoubleClicked.connect(lambda _it: ok())
        refresh()
        dlg.exec()

    # 功能：处理调试器与服务端通信连接、部署与会话维护。
    def _run_session(self, pid: int):
        self.adb.serial = self.device_serial
        if not self.device_serial:
            self._styled_alert("附加失败", "当前未检测到设备，请先连接设备。")
            return
        self._log_step(f"开始附加 pid={pid}")
        if self.session.sock is None:
            self._log_step("优先尝试直连现有Server")
            ok = self.session.connect_only(self.adb)
            if not ok:
                if not self._deploy_server():
                    self._log_err("部署失败，取消附加")
                    return
                if not self._start_server_process(force_restart=False):
                    self.status_lbl.setText("状态: Server启动失败")
                    self._log_err("启动Server失败")
                    return
                ok = self.session.connect_only(self.adb)
                if not ok:
                    self._log_err("连接 server 端口失败")
                    self.status_lbl.setText("状态: Server已启动，但端口连接失败")
                    return
        else:
            self._log_step("复用现有Server连接")
        self.reader_stop.clear()
        if self.reader_thread is None or (not self.reader_thread.is_alive()):
            self._restart_reader_thread()
        self.connected = False
        self.attach_state = "pending"
        self._attach_requested_pid = pid
        self.status_lbl.setText(f"状态: 正在附加 pid={pid}")
        self.session.send(f"attach {pid}")
        self._log_step(f"发送附加命令 attach {pid}")
        self._wait_attach_result(timeout_s=3.5)
        if self.attach_state == "ok":
            return
        self._log_err("首次附加未收到 ATTACH_OK，自动切换到全新Server重试")
        self.reader_stop.set()
        self.session.stop()
        self.reader_stop.clear()
        if not self._start_server_process(force_restart=True):
            self.status_lbl.setText(f"状态: 附加失败 pid={pid}")
            self._log_err("重启Server失败")
            return
        if not self.session.connect_only(self.adb):
            self.status_lbl.setText(f"状态: 附加失败 pid={pid}")
            self._log_err("重连Server失败")
            return
        self._restart_reader_thread()
        self.attach_state = "pending"
        self.session.send(f"attach {pid}")
        self._log_step(f"重试附加 attach {pid}")
        self._wait_attach_result(timeout_s=3.5)
        if self.attach_state != "ok":
            self.status_lbl.setText(f"状态: 附加失败 pid={pid}")
            self._log_err("重试附加仍失败")

    # 功能：处理调试器与服务端通信连接、部署与会话维护。
    def _stop_server(self):
        self.reader_stop.set()
        self.session.stop()
        self.adb.shell("su -c 'for p in $(pidof Just_server_arm64 2>/dev/null); do kill -9 $p; done'", timeout=10)
        self._log("[STEP] Server 已停止")

    # 功能：处理调试器与服务端通信连接、部署与会话维护。
    def _end_debug_session(self):
        if self.session.sock is not None:
            self.session.send("q")
        self._stop_server()

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _stop_and_clear(self):
        if self.current_target_pid > 0:
            self.adb.serial = self.device_serial
            self.adb.shell(f"su -c 'kill -9 {self.current_target_pid}'", timeout=10)
        self._end_debug_session()
        self._clear_debug_views()

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _clear_debug_views(self):
        self.dis.setRowCount(0)
        self.mem.setRowCount(0)
        self.regs.setRowCount(0)
        self.call.setRowCount(0)
        self.stack.setRowCount(0)
        self.bp.setRowCount(0)
        self.mod.setRowCount(0)
        self.thr.setRowCount(0)
        self.trace.clear()
        self.log.clear()
        self._dis_row_by_addr = {}
        self._dis_stream_desc = None
        self._dis_last_addr = None
        self._dis_reorder_needed = False
        self._mem_row_by_addr = {}
        self._reg_row_by_name = {}
        self._call_row_by_idx = {}
        self._stack_row_by_off = {}
        self.breakpoints = {}
        self.module_rows = []
        self._module_rows_pid = 0
        self.thread_rows = []
        self.trace_rows_raw = []
        self._attach_requested_pid = 0
        self.current_pc_addr = 0
        self.current_target_pid = 0
        self.attach_state = "idle"
        self.status_lbl.setText("状态: 就绪")
        self._update_title()

    # 功能：处理调试器与服务端通信连接、部署与会话维护。
    def _restart_debug_session(self):
        pid = self.current_target_pid
        self._end_debug_session()
        if pid > 0:
            self._run_session(pid)

    # 功能：处理单步/继续执行控制，驱动断下后的界面刷新链路。
    def _resume_debuggee(self):
        self.target_running = True
        self._send_menu_cmd("r")

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _pause_target(self):
        if self.current_target_pid > 0:
            # traced 目标用 SIGTRAP 可被服务端主循环识别并进入断下交互。
            self.adb.shell(f"su -c 'kill -TRAP {self.current_target_pid}'", timeout=10)
            self.target_running = False

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _trace_prompt(self):
        v, ok = QtWidgets.QInputDialog.getText(self, "Trace", "trace <行数>", text="100")
        if ok and v.strip():
            self.trace_collecting = True
            self.trace_rows_raw = []
            self._send_menu_cmd(f"trace {v.strip()}")

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _show_trace_table(self):
        rows = self.trace_rows_raw[:1000]
        if not rows:
            return
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("Trace")
        dlg.resize(1200, 680)
        v = QtWidgets.QVBoxLayout(dlg)
        t = self._mk_table(["序号", "指令"])
        for i, ln in enumerate(rows, 1):
            self._set_row(t, i - 1, [str(i), ln])
        v.addWidget(t)
        dlg.exec()

    # 功能：执行视图定位与滚动，将焦点移动到目标地址。
    def _hotkey_goto(self):
        fw = self.focusWidget()
        if fw is self.mem or fw is self.mem.viewport():
            self._goto_memory_prompt()
        else:
            self._goto_disasm_prompt()

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _goto_disasm_by_addr(self, addr: int):
        if addr is None:
            return
        target = addr + 0x10
        self._pending_disasm_focus_shift_up_rows = 4
        self._request_disasm_around(self._hx(target), target, scroll_hint="center")

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _goto_disasm_prompt(self):
        v, ok = QtWidgets.QInputDialog.getText(self, "转到地址", "输入反汇编地址表达式(如 pc / 0x1234):")
        if ok and v.strip():
            expr = v.strip()
            target = self._parse_plain_hex_expr(expr)
            if target is None:
                m_hex = re.fullmatch(r"0[xX]([0-9a-fA-F]+)", expr)
                if m_hex:
                    target = int(m_hex.group(1), 16)
            if target is None and expr.lower() == "pc" and self.current_pc_addr > 0:
                target = self.current_pc_addr
            self._goto_disasm_by_addr(target)

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _goto_memory_prompt(self):
        v, ok = QtWidgets.QInputDialog.getText(self, "转到地址", "输入内存地址表达式(如 sp / 0x1234):")
        if ok and v.strip():
            expr = v.strip()
            self.memory_center_expr = expr
            self.mem.setRowCount(0)
            self._mem_row_by_addr = {}
            target = self._parse_plain_hex_expr(expr)
            self._goto_memory(expr, target)

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _request_disasm_around(self, expr: str, target_addr, scroll_hint: str = "center"):
        if self.target_running:
            self._pending_disasm_request_expr = expr
            self._pending_disasm_request_addr = target_addr
            self._pending_disasm_request_hint = scroll_hint
            self._pause_target()
            return
        self._log("[入口] 请求反汇编 地址={} 目标={}".format(expr, hex(target_addr) if target_addr else "None"))
        self._pending_disasm_scroll_addr = target_addr if target_addr is not None else None
        self._pending_disasm_scroll_hint = scroll_hint
        self._deferred_disasm_scroll_addr = target_addr if target_addr is not None else None
        self._deferred_disasm_scroll_hint = scroll_hint
        self._dis_row_by_addr = {}
        self._dis_sorted_addrs = []
        self._dis_raw_insn_by_addr = {}
        self.dis.setRowCount(0)
        self._dis_stream_desc = None
        self._dis_last_addr = None
        self._dis_reorder_needed = False
        
        # 启用跟附加成功一致的批量接收逻辑
        self._rx_discard_pending_disasm()
        
        half_range = 0x100
        line_count = (half_range * 2) // 4
        start_expr = expr
        if target_addr is not None:
            # 请求窗口调整为上下0x100字节，降低延迟并保持定位精度
            start_expr = self._hx(max(0, target_addr - half_range))
        else:
            start_expr = f"{expr}-0x{half_range:X}"
        cmd = f"upkt {start_expr} {line_count}"
        self._disasm_rx_count = 0
        self._disasm_rx_first_addr = None
        self._disasm_rx_last_addr = None
        self._disasm_rx_cmd = cmd
        self._disasm_rx_expect = line_count
        self._disasm_rx_summary_once = False
        self._disasm_rx_started_at = time.monotonic()
        self._disasm_seq_retry = 0
        self._reset_disasm_seq_state()
        self._log(f"[单步收发] 发送反汇编命令: {cmd}")
        self._send_menu_cmd(cmd)

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _memory_cmd_and_count(self):
        cmd = "db"
        # 服务端各内存命令的 count 语义按“行数”处理，16字节/行。
        # 自动刷新场景收敛到0x800字节窗口（128行），降低单步后UI与传输延迟。
        count = 0x800 // 16
        return cmd, count

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _goto_memory(self, expr: str, target_addr=None, scroll_hint: str = "center"):
        self._log("[入口] 跳转内存 addr={}".format(expr))
        cmd, count = self._memory_cmd_and_count()
        self._pending_mem_scroll_addr = (target_addr + 0x40) if target_addr is not None else None
        self._pending_mem_scroll_hint = scroll_hint
        self._pending_mem_focus_shift_up_rows = 4
        self.mem.setRowCount(0)
        self._mem_row_by_addr = {}
        self.pending_clear_channels.add("MEMORY")
        start_expr = expr
        goto_window = 0x500
        goto_count = (goto_window * 2) // 16
        if target_addr is not None:
            start_expr = self._hx(max(0, target_addr - goto_window))
            count = max(count, goto_count)
        else:
            start_expr = f"{expr}-0x{goto_window:X}"
            count = max(count, goto_count)
        self._log("[入口] 跳转内存 start_expr={}".format(start_expr))
        self._send_menu_cmd(f"{cmd} {start_expr} {count}")

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _memory_col_by_addr(self, addr: int, base: int):
        unit, _prefix, count = self._memory_mode_layout()
        off = max(0, min(15, addr - base))
        col = 1 + (off // unit)
        return max(1, min(count, col))

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _current_selected_disasm_addr(self):
        r = self.dis.currentRow()
        if r < 0:
            return None
        it = self.dis.item(r, 1)
        return self._parse_addr_text(it.text() if it else "")

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _get_disasm_insn_by_addr(self, addr: int):
        if addr is None:
            return ""
        key = self._hx(addr)
        row = self._dis_row_by_addr.get(key)
        if row is None:
            return ""
        it = self.dis.item(row, 3)
        return it.text() if it else ""

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _memory_selected_addr(self):
        r = self.mem.currentRow()
        c = self.mem.currentColumn()
        if r < 0:
            return None
        base_it = self.mem.item(r, 0)
        if not base_it:
            return None
        base = self._parse_addr_text(base_it.text())
        if base is None:
            return None
        unit, _prefix, count = self._memory_mode_layout()
        col = max(1, c) if c >= 1 else self._mem_selected_col
        col = min(col, count)
        return base + (col - 1) * unit

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _copy_to_clipboard(self, text: str):
        if not text:
            return
        QtWidgets.QApplication.clipboard().setText(text)
        self._log_ok(f"已复制: {text}")

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _copy_selected_disasm_addr(self):
        a = self._current_selected_disasm_addr()
        if a is not None:
            self._copy_to_clipboard(self._hx(a))

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _copy_selected_memory_addr(self):
        a = self._memory_selected_addr()
        if a is not None:
            self._copy_to_clipboard(self._hx(a))

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _copy_selected_memory_cells(self):
        idxs = self.mem.selectedIndexes()
        if not idxs:
            r = self.mem.currentRow()
            c = self.mem.currentColumn()
            if r >= 0 and c >= 0:
                it = self.mem.item(r, c)
                if it:
                    self._copy_to_clipboard(it.text().strip())
            return
        idxs = sorted(idxs, key=lambda x: (x.row(), x.column()))
        rows = {}
        for idx in idxs:
            rows.setdefault(idx.row(), []).append(idx.column())
        lines = []
        for r in sorted(rows.keys()):
            cols = sorted(set(rows[r]))
            vals = []
            for c in cols:
                it = self.mem.item(r, c)
                vals.append((it.text().strip() if it else ""))
            lines.append("\t".join(vals))
        self._copy_to_clipboard("\n".join(lines))

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _copy_selected_disasm_code(self):
        r = self.dis.currentRow()
        if r < 0:
            return
        it = self.dis.item(r, 2)
        if it:
            self._copy_to_clipboard(it.text().strip())

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _copy_selected_disasm_insn(self):
        r = self.dis.currentRow()
        if r < 0:
            return
        it = self.dis.item(r, 3)
        if it:
            self._copy_to_clipboard(it.text().strip())

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _copy_selected_disasm_comment(self):
        r = self.dis.currentRow()
        if r < 0:
            return
        it = self.dis.item(r, 4)
        if it:
            self._copy_to_clipboard(it.text().strip())

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _copy_selected_disasm_row(self):
        r = self.dis.currentRow()
        if r < 0:
            return
        addr = self.dis.item(r, 1).text().strip() if self.dis.item(r, 1) else ""
        code = self.dis.item(r, 2).text().strip() if self.dis.item(r, 2) else ""
        insn = self.dis.item(r, 3).text().strip() if self.dis.item(r, 3) else ""
        comment = self.dis.item(r, 4).text().strip() if self.dis.item(r, 4) else ""
        self._copy_to_clipboard(" | ".join([addr, code, insn, comment]))

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _copy_selected_table_col_text(self, table, col: int):
        r = table.currentRow()
        if r < 0:
            return
        it = table.item(r, col)
        if not it:
            return
        self._copy_to_clipboard(it.text().strip())

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _selected_table_addr(self, table, col: int = 1):
        r = table.currentRow()
        if r < 0:
            return None
        it = table.item(r, col)
        return self._parse_addr_text(it.text() if it else "")

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _on_mem_click(self, row: int, col: int):
        if col == 0:
            col = 1
            self.mem.setCurrentCell(row, col)
        _dummy_unit, _dummy_prefix, count = self._memory_mode_layout()
        if col > count:
            col = count
            self.mem.setCurrentCell(row, col)
        self._mem_selected_col = max(1, col)
        base_it = self.mem.item(row, 0)
        if base_it:
            b = self._parse_addr_text(base_it.text())
            if b is not None:
                unit, _prefix, _count = self._memory_mode_layout()
                self._mem_selected_addr = b + (self._mem_selected_col - 1) * unit
        self._refresh_memory_active_cell_style()

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _on_disasm_double_click(self, row: int, col: int):
        self.dis.setCurrentCell(row, col)
        if col in (0, 1):
            self._toggle_breakpoint_from_disasm(None, scroll_after=False)
            return
        if col == 2:
            self._edit_disasm_machine_code()
            return
        if col == 3:
            self._patch_disasm_instruction()
            return

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _popup_disasm_menu(self, pos):
        idx = self.dis.indexAt(pos)
        if idx.isValid():
            self.dis.setCurrentCell(idx.row(), idx.column())
        menu = QtWidgets.QMenu(self)
        menu.addAction("转到地址(Ctrl+G)", self._goto_disasm_prompt)
        menu.addAction("复制地址", self._copy_selected_disasm_addr)
        menu.addAction("复制机器码", self._copy_selected_disasm_code)
        menu.addAction("复制指令", self._copy_selected_disasm_insn)
        menu.addAction("复制注释", self._copy_selected_disasm_comment)
        menu.addAction("复制行", self._copy_selected_disasm_row)
        menu.addSeparator()
        menu.addAction("软件执行断点", lambda: self._toggle_breakpoint_from_disasm(None, scroll_after=False))
        menu.addAction("硬件执行断点", lambda: self._set_bp_from_disasm("bhx"))
        menu.addAction("内存执行断点", lambda: self._set_bp_from_disasm("bmx"))
        menu.addSeparator()
        menu.addAction("修改汇编指令", self._patch_disasm_instruction)
        menu.exec(self.dis.viewport().mapToGlobal(pos))

    # 功能：处理调用栈/栈数据采集与展示，辅助定位执行路径。
    def _popup_call_menu(self, pos):
        idx = self.call.indexAt(pos)
        if idx.isValid():
            self.call.setCurrentCell(idx.row(), idx.column())
        menu = QtWidgets.QMenu(self)
        menu.addAction("在反汇编窗口转到地址", self._goto_disasm_from_callstack)
        menu.addAction("在内存窗口转到地址", self._goto_memory_from_callstack)
        menu.addAction("复制地址", self._copy_selected_call_addr)
        menu.addAction("复制注释", self._copy_selected_call_comment)
        menu.exec(self.call.viewport().mapToGlobal(pos))

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _popup_memory_menu(self, pos):
        idx = self.mem.indexAt(pos)
        if idx.isValid():
            self.mem.setCurrentCell(idx.row(), idx.column())
        menu = QtWidgets.QMenu(self)
        menu.addAction("转到地址(Ctrl+G)", self._goto_memory_prompt)
        menu.addAction("复制地址", self._copy_selected_memory_addr)
        menu.addAction("复制选中单元格", self._copy_selected_memory_cells)
        menu.addSeparator()
        menu.addAction("硬件读断点", lambda: self._set_bp_from_memory("bhr"))
        menu.addAction("硬件写断点", lambda: self._set_bp_from_memory("bhw"))
        menu.addAction("硬件读写断点", lambda: self._set_bp_from_memory("bha"))
        menu.addSeparator()
        menu.addAction("内存读断点", lambda: self._set_bp_from_memory("bmr"))
        menu.addAction("内存写断点", lambda: self._set_bp_from_memory("bmw"))
        menu.addAction("内存读写断点", lambda: self._set_bp_from_memory("bma"))
        menu.addSeparator()
        menu.addAction("修改当前内存", self._edit_memory_cell)
        menu.exec(self.mem.viewport().mapToGlobal(pos))

    # 功能：处理调用栈/栈数据采集与展示，辅助定位执行路径。
    def _goto_disasm_from_callstack(self):
        addr = self._selected_table_addr(self.call, 1)
        if addr is None:
            return
        self._goto_disasm_by_addr(addr)

    # 功能：处理调用栈/栈数据采集与展示，辅助定位执行路径。
    def _goto_memory_from_callstack(self):
        addr = self._selected_table_addr(self.call, 1)
        if addr is None:
            return
        expr = self._hx(addr)
        self.memory_center_expr = expr
        target = self._parse_plain_hex_expr(expr)
        self._goto_memory(expr, target, scroll_hint="center")

    # 功能：处理调用栈/栈数据采集与展示，辅助定位执行路径。
    def _copy_selected_call_addr(self):
        addr = self._selected_table_addr(self.call, 1)
        if addr is not None:
            self._copy_to_clipboard(self._hx(addr))

    # 功能：处理调用栈/栈数据采集与展示，辅助定位执行路径。
    def _copy_selected_call_comment(self):
        self._copy_selected_table_col_text(self.call, 2)

    # 功能：处理断点增删改查与命中后的状态同步。
    def _can_set_bp(self, addr: int, cmd_base: str):
        old = self.breakpoints.get(addr)
        if old and old.get("cmd") != cmd_base:
            return False
        if cmd_base == "bhx":
            cnt = sum(1 for a, b in self.breakpoints.items() if a != addr and b.get("cmd") == "bhx")
            if cnt >= 6:
                self._log_err("硬件执行断点最多6个")
                return False
        if cmd_base in ("bhr", "bhw", "bha"):
            cnt = sum(1 for a, b in self.breakpoints.items() if a != addr and b.get("cmd") in ("bhr", "bhw", "bha"))
            if cnt >= 4:
                self._log_err("硬件读写断点最多4个")
                return False
        return True

    # 功能：处理断点增删改查与命中后的状态同步。
    def _apply_breakpoint_cmd(self, cmd: str, scroll_after: bool = True):
        self._log("[入口] 设置断点 cmd={}".format(cmd))
        was_running = self.target_running and (self.current_target_pid > 0)
        self._suppress_thread_refresh_until = time.time() + 1.0
        if was_running:
            self._pause_target()
            time.sleep(0.1)
        self._send_menu_cmd(cmd)
        m = re.match(r"^(brk|brkc|bmx|bmr|bmw|bma)\s+(0x[0-9a-fA-F]+)", cmd.strip(), re.IGNORECASE)
        if m and scroll_after:
            try:
                a = int(m.group(2), 16)
                # 不重载反汇编表格：仅定位并重绘样式，实现断点行即时效果。
                self._pending_disasm_scroll_addr = a
                self._pending_disasm_scroll_hint = "center"
                self._disasm_style_dirty = True
            except Exception:
                pass
        if was_running:
            self._send_menu_cmd("r")

    # 功能：处理断点增删改查与命中后的状态同步。
    def _bp_access_type_text(self, cmd_base: str) -> str:
        c = (cmd_base or "").lower()
        if c in ("brk", "bhx", "bmx"):
            return "执行"
        if c in ("bhr", "bmr"):
            return "读"
        if c in ("bhw", "bmw"):
            return "写"
        if c in ("bha", "bma"):
            return "读写"
        return "未知"

    # 功能：处理断点增删改查与命中后的状态同步。
    def _append_bp_item(self, cmd_base: str, addr: int):
        kind = "software" if cmd_base.startswith("brk") else ("hardware" if cmd_base.startswith("bh") else "memory")
        label = "软件断点" if kind == "software" else ("硬件断点" if kind == "hardware" else "内存断点")
        bp = {"kind": kind, "cmd": cmd_base, "label": label}
        if kind == "software":
            bp["orig_insn"] = self._get_disasm_insn_by_addr(addr)
        self.breakpoints[addr] = bp
        self._refresh_bp_tab()

    # 功能：处理断点增删改查与命中后的状态同步。
    def _refresh_bp_tab(self):
        self.bp.setRowCount(0)
        for i, addr in enumerate(sorted(self.breakpoints.keys())):
            b = self.breakpoints[addr]
            self._set_row(
                self.bp,
                i,
                [
                    b.get("label", "未知断点"),
                    self._bp_access_type_text(b.get("cmd", "")),
                    f"0x{addr:016X}",
                    "已启用",
                ],
            )
        self._refresh_disasm_breakpoint_styles_only()

    # 功能：处理断点增删改查与命中后的状态同步。
    def _refresh_disasm_breakpoint_styles_only(self):
        for r in range(self.dis.rowCount()):
            it_addr = self.dis.item(r, 1)
            if not it_addr:
                continue
            addr = self._parse_addr_text(it_addr.text())
            if addr is None:
                continue
            bp = self.breakpoints.get(addr, {})
            kind = bp.get("kind", "")
            mark_item = self.dis.item(r, 0)
            if mark_item:
                mark = self._bp_mark(kind)
                if mark_item.text() != mark:
                    mark_item.setText(mark)
            insn_item = self.dis.item(r, 3)
            if kind == "software" and insn_item is not None:
                orig = str(bp.get("orig_insn", "") or "")
                if orig and insn_item.text() != orig:
                    insn_item.setText(orig)
            if addr == self.current_pc_addr:
                continue
            if kind == "software":
                bg, fg = "#c62828", "#ffffff"
            elif kind == "hardware":
                bg, fg = "#7b1fa2", "#ffffff"
            elif kind == "memory":
                bg, fg = "#1565c0", "#ffffff"
            else:
                bg, fg = "#0f141b", "#e6edf3"
            for c in range(self.dis.columnCount()):
                self._set_cell_style(self.dis, r, c, bg=bg, fg=fg, bold=False)

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _set_bp_from_disasm(self, cmd_base: str):
        addr = self._current_selected_disasm_addr()
        if addr is None:
            return
        if not self._can_set_bp(addr, cmd_base):
            return
        if cmd_base in ("bmx", "bmr", "bmw", "bma"):
            self._pending_mem_bp_ack = (addr, cmd_base)
        self._apply_breakpoint_cmd(f"{cmd_base} {self._hx(addr)}")
        if cmd_base not in ("bmx", "bmr", "bmw", "bma"):
            self._append_bp_item(cmd_base, addr)

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _set_bp_from_memory(self, cmd_base: str):
        addr = self._memory_selected_addr()
        if addr is None:
            return
        if not self._can_set_bp(addr, cmd_base):
            return
        if cmd_base in ("bmx", "bmr", "bmw", "bma"):
            self._pending_mem_bp_ack = (addr, cmd_base)
        self._apply_breakpoint_cmd(f"{cmd_base} {self._hx(addr)}")
        if cmd_base not in ("bmx", "bmr", "bmw", "bma"):
            self._append_bp_item(cmd_base, addr)

    def _toggle_breakpoint_from_disasm(self, _index, scroll_after: bool = True):
        addr = self._current_selected_disasm_addr()
        if addr is None:
            return
        old = self.breakpoints.get(addr)
        if old and old.get("kind") == "software":
            self._apply_breakpoint_cmd(f"brkc {self._hx(addr)}", scroll_after=scroll_after)
            self.breakpoints.pop(addr, None)
        elif old:
            self._log_err(f"地址 {self._hx(addr)} 已存在其它类型断点")
            return
        else:
            self._apply_breakpoint_cmd(f"brk {self._hx(addr)}", scroll_after=scroll_after)
            self.breakpoints[addr] = {
                "kind": "software",
                "cmd": "brk",
                "label": "软件断点",
                "orig_insn": self._get_disasm_insn_by_addr(addr),
            }
        self._refresh_bp_tab()

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _patch_disasm_instruction(self):
        addr = self._current_selected_disasm_addr()
        if addr is None:
            return
        if self.target_running and self.current_target_pid > 0:
            self._pause_target()
        old = self._dis_raw_insn_by_addr.get(addr, "")
        r = self.dis.currentRow()
        if (not old) and r >= 0 and self.dis.item(r, 3):
            old = self.dis.item(r, 3).text()
        ins, ok = QtWidgets.QInputDialog.getText(self, "汇编Patch", "输入ARM64指令:", text=old)
        if not (ok and ins.strip()):
            return
        new_insn = ins.strip()
        self._pending_asm_patch_addr = addr
        self._pending_asm_patch_text = new_insn
        self._send_menu_cmd(f"asm {self._hx(addr)} {new_insn}")

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _edit_memory_cell(self):
        addr = self._memory_selected_addr()
        if addr is None:
            return
        mode = self.mem_mode.currentText()
        size = "1" if mode == "字节" else ("2" if mode == "双字节" else ("4" if mode == "四字节" else "8"))
        prompt = f"地址: {self._hx(addr)}\n写入方式: {mode}({size}字节)\n输入新值(16进制，如0x12):"
        v, ok = QtWidgets.QInputDialog.getText(self, "修改内存", prompt)
        if not (ok and v.strip()):
            return
        try:
            vv = v.strip().lower()
            num = int(vv, 16) if vv.startswith("0x") else int(vv, 16)
            max_mask = (1 << (8 * int(size))) - 1
            num &= max_mask
            self._send_menu_cmd(f"wm {self._hx(addr)} {self._hx(num)} {size}")
            self._send_menu_cmd(f"db {self._hx(addr)} 1")
            bs = []
            sz = int(size)
            for i in range(sz):
                bs.append((num >> (8 * i)) & 0xFF)
            self._refresh_memory_cells_after_patch(addr, bs)
        except Exception:
            self._styled_alert("格式错误", "请输入十六进制数值（支持0x或不带0x）。")

    # 功能：封装ADB交互能力，为调试器提供设备与进程操作接口。
    def _refresh_modules_from_adb(self):
        if not self.device_serial:
            return
        self.adb.serial = self.device_serial
        cp = self.adb.shell(f"su -c 'cat /proc/{self.current_target_pid}/maps 2>/dev/null'", timeout=20) if self.current_target_pid > 0 else self.adb.shell("su -c 'cat /proc/self/maps'", timeout=20)
        self.module_rows = []
        self._module_rows_pid = self.current_target_pid if self.current_target_pid > 0 else 0
        self.mod.setRowCount(0)
        for ln in cp.stdout.splitlines():
            m = re.match(r"^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+([rwxps\-]{4})\s+[0-9a-fA-F]+\s+\S+\s+\d+\s*(.*)$", ln.strip())
            if not m:
                continue
            start = "0x" + m.group(1).upper()
            end = "0x" + m.group(2).upper()
            perm = m.group(3)
            path = m.group(4).strip() or "[anon]"
            self.module_rows.append((start, end, perm, path))
            self._set_row(self.mod, self.mod.rowCount(), [start, end, perm, path])
        self._filter_module_tree()

    # 功能：处理线程状态与切换逻辑，确保断下线程与界面状态一致。
    def _refresh_threads_from_adb(self):
        if self.current_target_pid <= 0:
            return
        self.adb.serial = self.device_serial
        cp = self.adb.shell(f"su -c 'ls /proc/{self.current_target_pid}/task 2>/dev/null'", timeout=20)
        tids = [x.strip() for x in cp.stdout.split() if x.strip().isdigit()]
        self.thr.setRowCount(0)
        self.thread_rows = []
        for tid in tids:
            cpn = self.adb.shell(f"su -c 'cat /proc/{self.current_target_pid}/task/{tid}/comm 2>/dev/null'", timeout=10)
            name = cpn.stdout.strip() or "-"
            row = (tid, name, "-", "可切换")
            self.thread_rows.append(row)
            self._set_row(self.thr, self.thr.rowCount(), row)

    # Compatibility layer: keep same method names as just_client.py
    # 功能：负责调试界面的样式重绘与状态可视化。
    def _build_style(self):
        self._apply_style()

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _build_layout(self):
        return None

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _mk_tree(self, *args, **kwargs):
        return None

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _bind_tip(self, *args, **kwargs):
        return None

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _show_tip(self, *args, **kwargs):
        return None

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _hide_tip(self, *args, **kwargs):
        return None

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _center_toplevel(self, *args, **kwargs):
        return None

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _popup_menu(self):
        return QtWidgets.QMenu(self)

    # 功能：输出调试日志，记录会话关键行为与异常信息。
    def _popup_log_menu(self, pos):
        m = self._popup_menu()
        m.addAction("清除日志", self.log.clear)
        m.exec(self.log.viewport().mapToGlobal(pos))

    # 功能：负责调试界面的样式重绘与状态可视化。
    def _styled_prompt(self, title: str, prompt: str, initial: str = ""):
        v, ok = QtWidgets.QInputDialog.getText(self, title, prompt, text=initial)
        return v if ok else None

    # 功能：负责调试界面的样式重绘与状态可视化。
    def _styled_alert(self, title: str, msg: str):
        QtWidgets.QMessageBox.warning(self, title, msg)

    # 功能：处理断点增删改查与命中后的状态同步。
    def _bp_meta(self, cmd_base: str):
        if cmd_base.startswith("brk"):
            return ("software", "软件断点/" + cmd_base[3:])
        if cmd_base.startswith("bh"):
            return ("hardware", "硬件断点/" + cmd_base[2:])
        if cmd_base.startswith("bm"):
            return ("memory", "内存断点/" + cmd_base[2:])
        return ("unknown", "未知断点")

    # 功能：处理断点增删改查与命中后的状态同步。
    def _bp_mark(self, kind: str):
        if kind == "software":
            return "●"
        if kind == "memory":
            return "■"
        if kind == "hardware":
            return "★"
        return ""

    # 功能：处理断点增删改查与命中后的状态同步。
    def _bp_tag(self, kind: str):
        if kind == "software":
            return "sw_bp"
        if kind == "memory":
            return "mem_bp"
        if kind == "hardware":
            return "hw_bp"
        return ""

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _clear_tree(self, tree):
        if hasattr(tree, "setRowCount"):
            tree.setRowCount(0)

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _reader(self):
        while not self.reader_stop.is_set():
            ln = self.session.read_line()
            if not ln:
                break
            self.rx.put(ln)

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _check_root(self):
        self.adb.serial = self.device_serial
        ok, cp = self.adb.check_root()
        self._refresh_device_flags(bool(self.device_serial), bool(ok))
        self._log(f"su -c id: rc={cp.returncode}")

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _remount(self):
        cp1, cp2 = self.adb.remount()
        self._log(f"adb root: rc={cp1.returncode}")
        self._log(f"adb remount: rc={cp2.returncode}")

    # 功能：处理调试器与服务端通信连接、部署与会话维护。
    def _pick_local_server(self, abi: str):
        p = Path(__file__).resolve().parent / "Just_server_arm64"
        return p if p.exists() else None

    # 功能：处理调试器与服务端通信连接、部署与会话维护。
    def _pick_remote_server(self, abi: str):
        return "/data/local/tmp/Just_server_arm64"

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _update_title(self):
        pid_txt = str(self.current_target_pid) if self.current_target_pid > 0 else "-"
        tid_txt = str(self.current_thread_tid) if self.current_thread_tid > 0 else "-"
        self.setWindowTitle(f"Just_client - 目标进程:{pid_txt} 线程:{tid_txt} - 公众号：零基础学逆向")

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _module_offset_text(self, addr: int):
        for row in self.module_rows:
            try:
                start = int(str(row[0]), 16)
                end = int(str(row[1]), 16)
            except Exception:
                continue
            if start <= addr < end:
                mod = str(row[3]).split("/")[-1]
                return f"{mod}+0x{addr - start:X}"
        return ""

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _rewrite_insn_with_module_offsets(self, insn: str):
        # 功能：在调试器中执行该模块的核心辅助逻辑。
        def repl(m):
            raw = m.group(0)
            try:
                a = int(raw, 16)
            except Exception:
                return self._upper_hex_text(raw)
            t = self._module_offset_text(a)
            return t if t else self._upper_hex_text(raw)

        return re.sub(r"0x[0-9a-fA-F]+", repl, insn or "")

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _insn_module_comment(self, insn: str):
        labels = []
        # 指令已被替换为“模块+偏移”时，直接抽取该格式作为注释，避免回退原始地址。
        for m in re.finditer(r"\b([A-Za-z0-9_.\-\[\]]+\+0x[0-9a-fA-F]+)\b", insn or ""):
            t = m.group(1)
            if t not in labels:
                labels.append(t)
        if labels:
            return ", ".join(labels)
        found_hex = set(self._hex_re.findall(insn or ""))
        for m in re.finditer(r"\b(?:0x|0X)?([0-9a-fA-F]{8,16})\b", insn or ""):
            raw = m.group(0)
            found_hex.add(raw if raw.lower().startswith("0x") else ("0x" + m.group(1)))
        for h in found_hex:
            try:
                a = int(h, 16)
            except Exception:
                continue
            t = self._module_offset_text(a)
            if t and t not in labels:
                labels.append(t)
        return ", ".join(labels)

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _refresh_disasm_around(self, expr: str):
        self.dis.setRowCount(0)
        self._dis_row_by_addr = {}
        self._send_menu_cmd(f"u {expr} 1000")

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _capture_disasm_original_row(self, addr: int):
        return None

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _repaint_disasm_bp_tags(self):
        for r in range(self.dis.rowCount()):
            it = self.dis.item(r, 1)
            if not it:
                continue
            a = self._parse_addr_text(it.text())
            if a is None:
                continue
            mark = self._bp_mark(self.breakpoints.get(a, {}).get("kind", ""))
            self._set_row(self.dis, r, [mark, self.dis.item(r, 1).text(), self.dis.item(r, 2).text() if self.dis.item(r, 2) else "", self.dis.item(r, 3).text() if self.dis.item(r, 3) else "", self.dis.item(r, 4).text() if self.dis.item(r, 4) else ""])

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _set_mem_active_cell(self, row_idx: int, col_idx: int):
        self.mem.setCurrentCell(row_idx, col_idx)
        self._mem_selected_col = max(1, col_idx)

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _clear_mem_active_cell(self):
        self.mem.clearSelection()

    # 功能：负责调试界面的样式重绘与状态可视化。
    def _force_pc_row_style(self, pc_addr):
        """强制设置PC行的样式，确保不会被其他操作覆盖"""
        self._log(f"[DEBUG] 强制设置PC行样式 pc_addr={hex(pc_addr)}")
        found = False
        for r in range(self.dis.rowCount()):
            it = self.dis.item(r, 1)
            if not it:
                continue
            addr = self._parse_addr_text(it.text())
            if addr == pc_addr:
                found = True
                self._log(f"[DEBUG] 找到PC行 r={r}, addr={hex(addr)}")
                # 强制设置PC行的背景色为绿色
                for c in range(self.dis.columnCount()):
                    it_pc = self.dis.item(r, c)
                    if it_pc:
                        it_pc.setBackground(QtGui.QColor("#3FB950"))
                        it_pc.setForeground(QtGui.QColor("#ffffff"))
                        f = it_pc.font()
                        f.setBold(True)
                        it_pc.setFont(f)
                        it_pc.setFlags(it_pc.flags() & ~QtCore.Qt.ItemFlag.ItemIsSelectable)
                        it_pc.setSelected(False)
                        self._log(f"[DEBUG] 设置单元格 r={r}, c={c} 样式")
                break
        if not found:
            self._log(f"[DEBUG] 未找到PC行 pc_addr={hex(pc_addr)}")

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _clear_tree_selection_on_blur(self, *_args):
        current_pc = self.current_pc_addr
        
        for t in [self.dis, self.mem, self.regs, self.call, self.stack]:
            t.clearSelection()
        
        # 重新设置PC行样式，确保不会被选择清除操作覆盖
        if current_pc:
            self._force_pc_row_style(current_pc)
        self._repaint_disasm_breakpoints_after_blur(current_pc)
        
        self._repaint_disasm_styles()
        self._refresh_memory_active_cell_style()

    # 功能：负责调试界面的样式重绘与状态可视化。
    def _repaint_disasm_breakpoints_after_blur(self, current_pc: int):
        # 丢失焦点后，对断点地址做专项恢复：除当前PC外，断点行统一恢复断点背景。
        for r in range(self.dis.rowCount()):
            it = self.dis.item(r, 1)
            if not it:
                continue
            addr = self._parse_addr_text(it.text())
            if addr is None or addr == current_pc:
                continue
            kind = self.breakpoints.get(addr, {}).get("kind", "")
            if not kind:
                continue
            if kind == "software":
                bg, fg = "#c62828", "#ffffff"
            elif kind == "hardware":
                bg, fg = "#7b1fa2", "#ffffff"
            elif kind == "memory":
                bg, fg = "#1565c0", "#ffffff"
            else:
                continue
            for c in range(self.dis.columnCount()):
                self._set_cell_style(self.dis, r, c, bg=bg, fg=fg, bold=False)
                it_bp = self.dis.item(r, c)
                if it_bp:
                    it_bp.setSelected(False)

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _on_app_focus_changed(self, _old, now):
        if now is None:
            self._clear_tree_selection_on_blur()
            return
        if now is self:
            return
        if isinstance(now, QtWidgets.QWidget) and self.isAncestorOf(now):
            in_dis = (now is self.dis) or (self.dis.isAncestorOf(now))
            if not in_dis:
                self._repaint_disasm_breakpoints_after_blur(self.current_pc_addr)
                self._repaint_disasm_styles()
            return
        self._clear_tree_selection_on_blur()

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _rerender_memory_from_cache(self):
        items = list(self._mem_row_by_addr.items())
        self.mem.setRowCount(0)
        for i, (addr, b) in enumerate(items):
            self._set_row(self.mem, i, [addr] + self._memory_cells_from_bytes(b))

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _upsert_memory_row(self, addr: str, b):
        self._mem_row_by_addr[addr] = b
        row = list(self._mem_row_by_addr.keys()).index(addr)
        self._set_row(self.mem, row, [addr] + self._memory_cells_from_bytes(b))
        addr_item = self.mem.item(row, 0)
        if addr_item:
            addr_item.setFlags(addr_item.flags() & ~QtCore.Qt.ItemFlag.ItemIsSelectable)

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _restore_active_memory_cell(self):
        if self._mem_selected_addr is None:
            return
        for r in range(self.mem.rowCount()):
            it = self.mem.item(r, 0)
            if not it:
                continue
            base = self._parse_addr_text(it.text())
            if base is None:
                continue
            if base <= self._mem_selected_addr <= base + 15:
                self.mem.setCurrentCell(r, self._mem_selected_addr - base + 1)
                break

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _refresh_memory_cells_after_patch(self, addr: int, bs):
        touched = False
        for k, b in list(self._mem_row_by_addr.items()):
            base = self._parse_addr_text(k)
            if base is None:
                continue
            if base <= addr <= base + 15:
                b2 = list(b)
                for i, bv in enumerate(bs):
                    off = addr + i - base
                    if 0 <= off < 16:
                        b2[off] = f"{bv:02X}"
                self._mem_row_by_addr[k] = b2
                self._upsert_memory_row(k, b2)
                touched = True
        if touched:
            self._refresh_memory_active_cell_style()

    # 功能：在调试上下文中查找目标地址/模块/条目并返回匹配结果。
    def _find_module_base_for_addr(self, addr: int):
        if addr <= 0:
            return None
        # 仅从已缓存模块中查找，避免在UI线程里adb shell导致界面卡住
        for row in self.module_rows:
            try:
                s = int(str(row[0]), 16)
                e = int(str(row[1]), 16)
            except Exception:
                continue
            if s <= addr < e:
                return s
        return None

    # 功能：处理附加目标进程流程，建立调试会话并同步初始状态。
    def _maybe_do_attach_post_init(self):
        self._log("[入口] 附加后初始化，当前pc={}".format(hex(self.current_pc_addr) if self.current_pc_addr else "0"))
        if self._attach_post_init_done:
            return
        if self.current_pc_addr <= 0:
            return
        self._attach_post_init_done = True
        self._last_step_pc_addr = self.current_pc_addr
        self._suppress_thread_refresh_until = time.time() + 5.0
        self._request_disasm_around(self._hx(self.current_pc_addr), self.current_pc_addr, scroll_hint="center")
        expr = (self.memory_center_expr or "sp").strip()
        target = self._parse_plain_hex_expr(expr)
        if target is None and expr.lower() == "pc" and self.current_pc_addr > 0:
            target = self.current_pc_addr
        self._goto_memory(expr, target, scroll_hint="center")

    # 功能：在调试上下文中查找目标地址/模块/条目并返回匹配结果。
    def _find_mem_perm(self, addr: int):
        for row in self.module_rows:
            try:
                start = int(str(row[0]), 16)
                end = int(str(row[1]), 16)
            except Exception:
                continue
            if start <= addr < end:
                return str(row[2]) if len(row) > 2 else ""
        return ""

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _write_code_bytes(self, addr: int, bs):
        try:
            for i, b in enumerate(bs):
                self._send_menu_cmd(f"wm {self._hx(addr + i)} 0x{b:02X} 1")
            return True
        except Exception:
            return False

    # 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
    def _edit_disasm_machine_code(self, *_args):
        addr = self._current_selected_disasm_addr()
        if addr is None:
            return
        old = "00 00 00 00"
        r = self.dis.currentRow()
        if r >= 0 and self.dis.item(r, 2):
            old = self.dis.item(r, 2).text().strip().upper()
        v = self._styled_prompt("修改机器码", "输入机器码(格式: XX XX XX XX)", old)
        if not v:
            return
        code = " ".join(v.strip().upper().split())
        if not re.fullmatch(r"[0-9A-F]{2}( [0-9A-F]{2}){3}", code):
            self._styled_alert("格式错误", "机器码格式必须是: XX XX XX XX")
            return
        bs = [int(x, 16) for x in code.split()]
        if self._write_code_bytes(addr, bs):
            self._send_menu_cmd(f"u {self._hx(max(0, addr - 0x20))} 64")
            self._refresh_memory_cells_after_patch(addr, bs)

    # 功能：处理寄存器数据解析与展示，用于更新当前执行上下文。
    def _edit_selected_register(self):
        r = self.regs.currentRow()
        if r < 0:
            return
        reg = self.regs.item(r, 0).text().strip().lower() if self.regs.item(r, 0) else ""
        old = self.regs.item(r, 1).text().strip() if self.regs.item(r, 1) else "0x0"
        v = self._styled_prompt("修改寄存器", f"{reg} =", old)
        if v:
            self._send_menu_cmd(f"r {reg} {v.strip()}")

    # 功能：处理内存读写与显示刷新，保持内存窗口与当前上下文一致。
    def _edit_stack_memory_cell(self):
        r = self.stack.currentRow()
        if r < 0:
            return
        it = self.stack.item(r, 1)
        if not it:
            return
        addr = self._parse_addr_text(it.text())
        if addr is None:
            return
        v = self._styled_prompt("修改栈内存", "输入新QWORD值(16进制):")
        if v:
            self._send_menu_cmd(f"wm {self._hx(addr)} {v.strip()} 8")

    # 功能：处理寄存器数据解析与展示，用于更新当前执行上下文。
    def _popup_regs_menu(self, pos):
        idx = self.regs.indexAt(pos)
        if idx.isValid():
            self.regs.setCurrentCell(idx.row(), idx.column())
        m = self._popup_menu()
        m.addAction("在反汇编窗口转到值", self._goto_disasm_from_regs)
        m.addAction("在内存窗口转到值", self._goto_memory_from_regs)
        m.addAction("复制值", self._copy_selected_regs_value)
        m.addAction("复制注释", self._copy_selected_regs_comment)
        m.addSeparator()
        self._regs_menu_addr = None
        addr = self._selected_table_addr(self.regs, 1)
        if addr is not None:
            self._regs_menu_addr = addr
        m.addAction("修改寄存器", self._edit_selected_register)
        m.exec(self.regs.viewport().mapToGlobal(pos))

    # 功能：处理调用栈/栈数据采集与展示，辅助定位执行路径。
    def _popup_stack_menu(self, pos):
        idx = self.stack.indexAt(pos)
        if idx.isValid():
            self.stack.setCurrentCell(idx.row(), idx.column())
        self._stack_menu_addr = None
        r = self.stack.currentRow()
        if r >= 0:
            it = self.stack.item(r, 1)
            a = self._parse_addr_text(it.text() if it else "")
            if a is not None:
                self._stack_menu_addr = a
        m = self._popup_menu()
        m.addAction("在反汇编窗口转到地址", self._goto_disasm_from_stack)
        m.addAction("在内存窗口转到地址", self._goto_memory_from_stack)
        m.addAction("复制地址", self._copy_selected_stack_addr)
        m.addAction("复制值", self._copy_selected_stack_value)
        m.addAction("复制注释", self._copy_selected_stack_comment)
        m.addSeparator()
        m.addAction("修改栈内存值", self._edit_stack_memory_cell)
        m.exec(self.stack.viewport().mapToGlobal(pos))

    # 功能：处理调用栈/栈数据采集与展示，辅助定位执行路径。
    def _goto_memory_from_stack(self):
        addr = self._stack_menu_addr
        if addr is None:
            r = self.stack.currentRow()
            if r < 0:
                return
            it = self.stack.item(r, 1)
            addr = self._parse_addr_text(it.text() if it else "")
        if addr is None:
            return
        self._stack_menu_addr = None
        expr = self._hx(addr)
        self.memory_center_expr = expr
        target = self._parse_plain_hex_expr(expr)
        self._goto_memory(expr, target, scroll_hint="center")

    # 功能：处理调用栈/栈数据采集与展示，辅助定位执行路径。
    def _goto_disasm_from_stack(self):
        addr = self._stack_menu_addr
        if addr is None:
            addr = self._selected_table_addr(self.stack, 1)
        if addr is None:
            return
        self._goto_disasm_by_addr(addr)

    # 功能：处理调用栈/栈数据采集与展示，辅助定位执行路径。
    def _copy_selected_stack_addr(self):
        addr = self._selected_table_addr(self.stack, 1)
        if addr is not None:
            self._copy_to_clipboard(self._hx(addr))

    # 功能：处理调用栈/栈数据采集与展示，辅助定位执行路径。
    def _copy_selected_stack_value(self):
        self._copy_selected_table_col_text(self.stack, 2)

    # 功能：处理调用栈/栈数据采集与展示，辅助定位执行路径。
    def _copy_selected_stack_comment(self):
        self._copy_selected_table_col_text(self.stack, 3)

    # 功能：处理寄存器数据解析与展示，用于更新当前执行上下文。
    def _goto_disasm_from_regs(self):
        addr = self._regs_menu_addr
        if addr is None:
            r = self.regs.currentRow()
            if r < 0:
                return
            it = self.regs.item(r, 1)
            addr = self._parse_addr_text(it.text() if it else "")
        if addr is None:
            return
        self._regs_menu_addr = None
        self._goto_disasm_by_addr(addr)

    # 功能：处理寄存器数据解析与展示，用于更新当前执行上下文。
    def _goto_memory_from_regs(self):
        addr = self._regs_menu_addr
        if addr is None:
            addr = self._selected_table_addr(self.regs, 1)
        if addr is None:
            return
        expr = self._hx(addr)
        self.memory_center_expr = expr
        target = self._parse_plain_hex_expr(expr)
        self._goto_memory(expr, target, scroll_hint="center")

    # 功能：处理寄存器数据解析与展示，用于更新当前执行上下文。
    def _copy_selected_regs_value(self):
        self._copy_selected_table_col_text(self.regs, 1)

    # 功能：处理寄存器数据解析与展示，用于更新当前执行上下文。
    def _copy_selected_regs_comment(self):
        self._copy_selected_table_col_text(self.regs, 2)

    # 功能：处理断点增删改查与命中后的状态同步。
    def _popup_bp_menu(self, pos):
        m = self._popup_menu()
        m.addAction("删除断点", self._delete_selected_breakpoint)
        m.exec(self.bp.viewport().mapToGlobal(pos))

    # 功能：处理断点增删改查与命中后的状态同步。
    def _delete_selected_breakpoint(self):
        r = self.bp.currentRow()
        if r < 0:
            return
        it = self.bp.item(r, 2)
        if not it:
            return
        addr = self._parse_addr_text(it.text())
        if addr is None:
            return
        b = self.breakpoints.get(addr)
        if not b:
            return
        kind = b.get("kind")
        if kind == "software":
            self._apply_breakpoint_cmd(f"brkc {self._hx(addr)}")
        elif kind == "hardware":
            self._apply_breakpoint_cmd(f"bhc {self._hx(addr)}")
        elif kind == "memory":
            self._apply_breakpoint_cmd(f"bmc {self._hx(addr)}")
        self.breakpoints.pop(addr, None)
        self._refresh_bp_tab()

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _selected_module_path(self):
        r = self.mod.currentRow()
        if r < 0:
            return ""
        it = self.mod.item(r, 3)
        return it.text().strip() if it else ""

    # 功能：处理线程状态与切换逻辑，确保断下线程与界面状态一致。
    def _selected_thread_tid(self):
        r = self.thr.currentRow()
        if r < 0:
            return ""
        it = self.thr.item(r, 0)
        return it.text().strip() if it else ""

    # 功能：解析服务端输出并路由到对应调试视图。
    def _parse_symbol_lines(self, text: str):
        rows = []
        for ln in text.splitlines():
            m = re.match(r"^\s*(\d+):\s*([0-9A-Fa-f]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$", ln.strip())
            if not m:
                continue
            rows.append((m.group(1), "0x" + m.group(2).upper(), "0x" + m.group(2).upper(), m.group(3), m.group(4), m.group(5), m.group(6), m.group(7), m.group(8).strip()))
        return rows

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _show_symbol_table(self, title: str, rows):
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle(title)
        dlg.resize(1220, 680)
        v = QtWidgets.QVBoxLayout(dlg)
        t = self._mk_table(["序号", "函数地址", "值", "大小", "类型", "绑定", "可见性", "节索引", "符号"])
        for i, r in enumerate(rows):
            self._set_row(t, i, r[:9])
        v.addWidget(t)
        dlg.exec()

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _view_module_exports(self):
        p = self._selected_module_path()
        if not p:
            self._log_err("请选择有效模块")
            return
        self.adb.serial = self.device_serial
        cp = self.adb.shell(f"su -c 'readelf -Ws {p} 2>/dev/null | head -n 1200'", timeout=20)
        rows = [r for r in self._parse_symbol_lines(cp.stdout or "") if r[7] != "UND" and r[5] in ("GLOBAL", "WEAK")]
        if not rows:
            self._log("未读取到导出符号")
            return
        self._show_symbol_table(f"导出函数 - {Path(p).name}", rows[:600])

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _view_module_imports(self):
        p = self._selected_module_path()
        if not p:
            self._log_err("请选择有效模块")
            return
        self.adb.serial = self.device_serial
        cp = self.adb.shell(f"su -c 'readelf -Ws {p} 2>/dev/null | head -n 1200'", timeout=20)
        rows = [r for r in self._parse_symbol_lines(cp.stdout or "") if r[7] == "UND"]
        if not rows:
            self._log("未读取到导入符号")
            return
        self._show_symbol_table(f"导入函数 - {Path(p).name}", rows[:600])

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _popup_module_menu(self, pos):
        m = self._popup_menu()
        m.addAction("查看导出函数", self._view_module_exports)
        m.addAction("查看导入函数", self._view_module_imports)
        m.exec(self.mod.viewport().mapToGlobal(pos))

    # 功能：处理线程状态与切换逻辑，确保断下线程与界面状态一致。
    def _signal_thread(self, sig: str):
        tid = self._selected_thread_tid()
        if not tid.isdigit() or self.current_target_pid <= 0:
            return
        self.adb.serial = self.device_serial
        cp = self.adb.shell(f"su -c 'kill -{sig} {tid}'", timeout=10)
        self._log(f"线程信号 {sig} tid={tid} rc={cp.returncode}")

    # 功能：处理线程状态与切换逻辑，确保断下线程与界面状态一致。
    def _popup_thread_menu(self, pos):
        m = self._popup_menu()
        m.addAction("暂停线程", lambda: self._signal_thread("STOP"))
        m.addAction("恢复线程", lambda: self._signal_thread("CONT"))
        m.addAction("结束线程", lambda: self._signal_thread("TERM"))
        m.exec(self.thr.viewport().mapToGlobal(pos))

    # 功能：在调试器中执行该模块的核心辅助逻辑。
    def _filter_module_tree(self):
        key = self.mod_search_edit.text().strip().lower() if hasattr(self, "mod_search_edit") else ""
        self.mod.setRowCount(0)
        for row in self.module_rows:
            s = " | ".join([str(x) for x in row]).lower()
            if key and (key not in s):
                continue
            self._set_row(self.mod, self.mod.rowCount(), row)

    # 功能：执行内存/模块转储，用于离线分析目标数据。
    def _dump_current_module(self):
        p = self._selected_module_path()
        if (not p) or (self.current_target_pid <= 0):
            self._log_err("请先附加进程并在模块窗口选择模块")
            return
        selected = None
        for r in self.module_rows:
            if len(r) >= 4 and str(r[3]) == p:
                selected = r
                break
        if not selected:
            self._log_err("未找到模块映射范围")
            return
        try:
            s = int(str(selected[0]), 16)
            e = int(str(selected[1]), 16)
        except Exception:
            self._log_err("模块地址解析失败")
            return
        if e <= s:
            self._log_err("模块范围无效")
            return
        size = e - s
        mod = Path(p).name.replace("/", "_")
        remote = f"/data/local/tmp/{mod}_{s:X}_{e:X}.bin"
        local = os.path.join(os.getcwd(), os.path.basename(remote))
        self.adb.serial = self.device_serial
        cp1 = self.adb.shell(f"su -c 'dd if=/proc/{self.current_target_pid}/mem of={remote} bs=1 skip={s} count={size} 2>/dev/null'", timeout=120)
        cp2 = self.adb.run(["pull", remote, local], timeout=120)
        self._log(f"dump模块: {p} [{self._hx(s)}-{self._hx(e)}] rc1={cp1.returncode} rc2={cp2.returncode} -> {local}")


# 功能：调试器程序入口，负责初始化并启动主循环。
def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
