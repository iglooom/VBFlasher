#!/usr/bin/env python3
"""VBFlasher GUI — PySide6 front end for the VBFlasher CLI.

    python3 vbflasher_gui.py

Design
  * Short bus operations (ident, DID read/write, DTC, reset, config read/write)
    run in-process on ONE worker thread through gui_backend (vbf.Ecu + the CLI's
    own session/unlock code). Everything they print lands in the log pane.
  * Long / risky operations (flash, memread, memwrite, routine, silence,
    brute-force, self-test) run the proven CLI itself as a subprocess with
    --yes after the GUI has asked for confirmation; its output is streamed.
  * DID/config decoding comes from defs/vbflasher_defs.sqlite (tools/build_defs.py).

Only one bus job runs at a time; the UI refuses a second one while busy.
"""
import os
import queue
import re
import signal
import sys
import threading
import time
import traceback
from contextlib import redirect_stdout
from pathlib import Path

from PySide6.QtCore import (QObject, QProcess, QSettings, QSocketNotifier, Qt,
                            QThread, QTimer, Signal)
from PySide6.QtGui import QAction, QBrush, QColor, QFont, QTextCursor
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog,
    QDialogButtonBox, QDockWidget, QDoubleSpinBox, QFileDialog, QFormLayout,
    QGridLayout, QGroupBox, QHBoxLayout, QHeaderView, QInputDialog, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar,
    QPushButton, QSpinBox, QSplitter, QStyledItemDelegate, QTableWidget,
    QTableWidgetItem, QTabWidget, QToolBar, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget)

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)

import defs as D                      # noqa: E402
import ecu_db                         # noqa: E402
import gui_backend as B               # noqa: E402
import vbflasher as vf                # noqa: E402
from vbf import Vbf, dtc_code, dtc_is_actual, dtc_status_str  # noqa: E402

APP = "VBFlasher"
MONO = QFont("monospace")
MONO.setStyleHint(QFont.StyleHint.Monospace)
CHANGED = QBrush(QColor("#c05000"))
BAD = QBrush(QColor("#b00020"))
OKC = QBrush(QColor("#1b7f2a"))
DIM = QBrush(QColor("#808080"))


def hx(b):
    return b.hex().upper() if b is not None else ""


def parse_hex(s):
    s = s.replace("0x", "").replace("0X", "").replace(" ", "").replace(":", "")
    if len(s) % 2 or any(c not in "0123456789abcdefABCDEF" for c in s):
        raise ValueError(f"not hex bytes: {s!r}")
    return bytes.fromhex(s)


def parse_int(s, default=None):
    s = (s or "").strip()
    if not s:
        return default
    return int(s, 0) if s.lower().startswith("0x") else int(s, 16) if any(
        c in "abcdefABCDEF" for c in s) else int(s)


def _unique(path):
    """path, or path with _2, _3 … before the extension if it already exists."""
    stem, ext = os.path.splitext(path)
    n, out = 1, path
    while os.path.exists(out):
        n += 1
        out = f"{stem}_{n}{ext}"
    return out


# ==========================================================================
# background execution
# ==========================================================================
class _Stream:
    """File-like object that forwards prints from the worker to the log."""

    def __init__(self, emit):
        self.emit = emit
        self.buf = ""

    def write(self, s):
        self.buf += s
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n", 1)
            self.emit(line.split("\r")[-1])
        return len(s)

    def flush(self):
        if self.buf:
            self.emit(self.buf.split("\r")[-1])
            self.buf = ""

    def isatty(self):
        return False


class Worker(QThread):
    """Runs bus jobs one at a time. job(ctx) -> result; ctx has log(),
    post(obj) for streaming partial results, and cancel (threading.Event)."""
    log = Signal(str)
    posted = Signal(object, object)          # (callback, obj)
    finished_job = Signal(object, object, object)   # (callback, result, error)
    busy_changed = Signal(bool)

    def __init__(self):
        super().__init__()
        self.q = queue.Queue()
        self.cancel = threading.Event()
        self.pending = 0            # submitted and not yet finished (GUI thread view)
        self.busy = False

    @property
    def active(self):
        return self.pending > 0

    def submit(self, name, fn, done=None, on_post=None):
        self.pending += 1
        self.q.put((name, fn, done, on_post))

    def shutdown(self, timeout_ms=15000):
        """Stop the worker; True when the thread has finished."""
        self.cancel.set()
        self.q.put(None)
        return self.wait(timeout_ms)

    def run(self):
        while True:
            item = self.q.get()
            if item is None:
                return
            name, fn, done, on_post = item
            self.busy = True
            self.busy_changed.emit(True)
            self.cancel.clear()
            ctx = _Ctx(self, on_post)
            res = err = None
            stream = _Stream(self.log.emit)
            try:
                with redirect_stdout(stream):
                    print(f"── {name} ── {time.strftime('%H:%M:%S')}")
                    res = fn(ctx)
            except (B.OpError, SystemExit, ValueError, OSError) as e:
                err = str(e) or e.__class__.__name__
            except Exception as e:      # noqa: BLE001
                err = f"{e.__class__.__name__}: {e}"
                self.log.emit(traceback.format_exc())
            stream.flush()
            if err:
                self.log.emit(f"!! {name}: {err}")
            self.busy = False
            self.busy_changed.emit(False)
            self.finished_job.emit(done, res, err)


class _Ctx:
    def __init__(self, w, on_post):
        self.w, self.on_post = w, on_post
        self.cancel = w.cancel

    def post(self, obj):
        if self.on_post:
            self.w.posted.emit(self.on_post, obj)


class Proc(QObject):
    """Runs the CLI as a subprocess, streams output, parses progress."""
    log = Signal(str)
    progress = Signal(float)
    busy_changed = Signal(bool)

    def __init__(self):
        super().__init__()
        self.p = None
        self.done = None
        self.buf = ""

    @property
    def busy(self):
        return self.p is not None

    def run(self, argv, done=None, title=""):
        if self.p is not None:
            raise RuntimeError("a CLI job is already running")
        self.done = done
        self.p = QProcess()
        self.p.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        env = self.p.processEnvironment()
        env = env.systemEnvironment()
        env.insert("PYTHONUNBUFFERED", "1")
        env.insert("TERM", "dumb")
        self.p.setProcessEnvironment(env)
        self.p.readyReadStandardOutput.connect(self._read)
        self.p.finished.connect(self._fin)
        # Own session: a Ctrl+C in the launching terminal must not reach a
        # running flash/memwrite; the GUI decides (Main.on_unix_signal) and
        # interrupt() still signals the child explicitly.
        if hasattr(QProcess, "setUnixProcessParameters"):
            self.p.setUnixProcessParameters(QProcess.UnixProcessFlag.CreateNewSession)
        self.log.emit(f"── {title or 'vbflasher'} ── {time.strftime('%H:%M:%S')}")
        self.log.emit("$ " + " ".join(argv[2:] if argv[1] == "-u" else argv))
        self.busy_changed.emit(True)
        self.p.start(argv[0], argv[1:])

    def _read(self):
        data = bytes(self.p.readAllStandardOutput()).decode("utf-8", "replace")
        self.buf += data
        parts = self.buf.replace("\r\n", "\n").split("\n")
        self.buf = parts.pop()
        for line in parts:
            self._line(line)
        # progress lines are \r-terminated without \n
        if "\r" in self.buf:
            seg = self.buf.split("\r")
            self.buf = seg[-1]
            for s in seg[:-1]:
                self._progress(s)

    def _progress(self, s):
        import re
        m = re.search(r"(\d+(?:\.\d+)?)%", s)
        if m:
            self.progress.emit(float(m.group(1)))

    def _line(self, line):
        segs = line.split("\r")
        for s in segs[:-1]:
            self._progress(s)
        last = segs[-1]
        self._progress(last)
        if last.strip():
            self.log.emit(last)

    def _fin(self, code, status):
        if self.buf.strip():
            self._line(self.buf)
        self.buf = ""
        self.log.emit(f"── exit code {code} ──")
        done, self.done = self.done, None
        self.p.deleteLater()
        self.p = None
        self.busy_changed.emit(False)
        if done:
            done(code)

    def interrupt(self):
        if self.p is not None:
            pid = self.p.processId()
            if pid:
                os.kill(pid, signal.SIGINT)

    def kill(self):
        if self.p is not None:
            self.p.kill()


# ==========================================================================
# main window
# ==========================================================================
class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VBFlasher")
        self.resize(1400, 900)
        self.settings = QSettings(APP, "gui")
        self.defs = D.Defs()
        self.ident = {}                       # txid -> {did: bytes}
        self.worker = Worker()
        self.worker.log.connect(self.log)
        self.worker.posted.connect(lambda cb, o: cb(o))
        self.worker.finished_job.connect(self._job_done)
        self.worker.busy_changed.connect(self._busy)
        self.worker.start()
        self.proc = Proc()
        self.proc.log.connect(self.log)
        self.proc.busy_changed.connect(self._busy)

        self._build_toolbar()
        self._build_log()
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.modules_tab = ModulesTab(self)
        self.flash_tab = FlashTab(self)
        self.direct_tab = DirectConfigTab(self)
        self.central_tab = CentralConfigTab(self)
        self.did_tab = DidTab(self)
        self.dtc_tab = DtcTab(self)
        self.service_tab = ServiceTab(self)
        for t, n in ((self.modules_tab, "Modules"), (self.flash_tab, "Flash"),
                     (self.direct_tab, "Module data && config"),
                     (self.central_tab, "Central config (CCC)"),
                     (self.did_tab, "DIDs"), (self.dtc_tab, "DTCs"),
                     (self.service_tab, "Service")):
            self.tabs.addTab(t, n)
        self.tabs.setCurrentIndex(int(self.settings.value("tab", 0)))
        meta = self.defs.meta()
        self.statusBar().showMessage(
            f"definitions: {meta.get('built', 'MISSING — run tools/build_defs.py')}"
            if self.defs.ok else "defs/vbflasher_defs.sqlite missing — run tools/build_defs.py")

    # -- toolbar: module + interface ---------------------------------------
    def _build_toolbar(self):
        tb = QToolBar("target")
        tb.setMovable(False)
        self.addToolBar(tb)
        tb.addWidget(QLabel(" Module: "))
        self.mod_combo = QComboBox()
        self.mod_combo.setMinimumWidth(320)
        for txid in sorted(ecu_db.ECUS):
            p = ecu_db.ECUS[txid]
            self.mod_combo.addItem(f"{p.name}  [0x{txid:03X}, {p.bus}]", txid)
        self.mod_combo.addItem("Custom CAN id…", -1)
        tb.addWidget(self.mod_combo)
        self.custom_tx = QLineEdit()
        self.custom_tx.setPlaceholderText("tx id e.g. 7D0")
        self.custom_tx.setMaximumWidth(110)
        self.custom_tx.setVisible(False)
        self.custom_tx_act = tb.addWidget(self.custom_tx)
        self.custom_tx_act.setVisible(False)
        tb.addSeparator()
        tb.addWidget(QLabel(" Interface: "))
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(170)
        tb.addWidget(self.iface_combo)
        rb = QPushButton("↻")
        rb.setToolTip("rescan CAN interfaces")
        rb.clicked.connect(self.refresh_ifaces)
        tb.addWidget(rb)
        tb.addSeparator()
        tb.addWidget(QLabel(" HS-CAN→"))
        self.hs_combo = QComboBox()
        tb.addWidget(self.hs_combo)
        tb.addWidget(QLabel(" MS-CAN→"))
        self.ms_combo = QComboBox()
        tb.addWidget(self.ms_combo)
        tb.addWidget(QLabel(" I-CAN→"))
        self.ic_combo = QComboBox()
        tb.addWidget(self.ic_combo)
        tb.addSeparator()
        self.busy_lbl = QLabel("  idle  ")
        tb.addWidget(self.busy_lbl)
        stop = QPushButton("Stop")
        stop.setToolTip("cancel a polling job / send Ctrl-C to the running CLI job")
        stop.clicked.connect(self.stop_jobs)
        tb.addWidget(stop)
        self.refresh_ifaces()
        idx = self.mod_combo.findData(int(self.settings.value("module", 0x726)))
        if idx >= 0:
            self.mod_combo.setCurrentIndex(idx)
        self.mod_combo.currentIndexChanged.connect(self._mod_changed)
        self._mod_changed()

    def refresh_ifaces(self):
        ifs = B.can_ifaces() or ["can0", "can1"]
        cur = self.iface_combo.currentData() or self.settings.value("iface", "")
        self.iface_combo.blockSignals(True)
        self.iface_combo.clear()
        self.iface_combo.addItem("auto (by bus)", "")
        for i in ifs:
            self.iface_combo.addItem(f"{i}  ({B.iface_state(i)})", i)
        k = self.iface_combo.findData(cur)
        self.iface_combo.setCurrentIndex(max(0, k))
        self.iface_combo.blockSignals(False)
        for combo, key, dflt in ((self.hs_combo, "hs", "can0"), (self.ms_combo, "ms", "can1"),
                                  (self.ic_combo, "ic", "can2")):
            val = combo.currentText() or self.settings.value(key, dflt)
            combo.clear()
            combo.addItems(sorted(set(ifs) | {dflt}))
            combo.setCurrentText(val)

    def _mod_changed(self):
        custom = self.mod_combo.currentData() == -1
        self.custom_tx_act.setVisible(custom)
        self.custom_tx.setVisible(custom)
        for t in ("direct_tab", "did_tab", "dtc_tab"):
            tab = getattr(self, t, None)
            if tab and hasattr(tab, "module_changed"):
                tab.module_changed()

    def bus_iface(self, profile):
        if profile is None:
            return "can0"
        return {"HS-CAN": self.hs_combo.currentText(),
                "MS-CAN": self.ms_combo.currentText(),
                "I-CAN": self.ic_combo.currentText()}.get(profile.bus) or profile.default_iface()

    def iface_override(self):
        return self.iface_combo.currentData() or ""

    def target(self, txid=None) -> B.Target:
        """Current (or given) module + resolved interface."""
        if txid is None:
            txid = self.mod_combo.currentData()
        if txid == -1:
            t = parse_int(self.custom_tx.text())
            if t is None:
                raise B.OpError("enter a custom tx CAN id")
            prof = ecu_db.get_profile(t)
            return B.Target(t, self.iface_override() or self.bus_iface(prof) if prof else
                            self.iface_override() or "can0", prof)
        prof = ecu_db.ECUS[txid]
        return B.Target(txid, self.iface_override() or self.bus_iface(prof), prof)

    def cli_iface_args(self, target):
        """Always pass the resolved interface so bus remapping applies to the CLI."""
        return ["--iface", target.iface]

    # -- log ----------------------------------------------------------------
    def _build_log(self):
        dock = QDockWidget("Log", self)
        dock.setObjectName("log")
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(2, 2, 2, 2)
        self.logbox = QPlainTextEdit()
        self.logbox.setReadOnly(True)
        self.logbox.setFont(MONO)
        self.logbox.setMaximumBlockCount(20000)
        lay.addWidget(self.logbox)
        row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setFormat("%p%")
        row.addWidget(self.progress, 1)
        clr = QPushButton("Clear log")
        clr.clicked.connect(self.logbox.clear)
        row.addWidget(clr)
        opn = QPushButton("Open logs folder")
        opn.clicked.connect(lambda: os.system(f"xdg-open '{B.LOG_DIR}' >/dev/null 2>&1 &"))
        row.addWidget(opn)
        lay.addLayout(row)
        dock.setWidget(w)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, dock)
        self.proc.progress.connect(lambda v: self.progress.setValue(int(v * 10)))

    def log(self, s):
        self.logbox.appendPlainText(s)
        self.logbox.moveCursor(QTextCursor.MoveOperation.End)

    # -- job plumbing -------------------------------------------------------
    def busy(self):
        return self.worker.active or self.proc.busy

    def _busy(self, _=None):
        b = self.busy()
        self.busy_lbl.setText("  BUSY  " if b else "  idle  ")
        self.busy_lbl.setStyleSheet("color:#b00020;font-weight:bold" if b else "")

    def guard(self):
        if self.busy():
            QMessageBox.information(self, APP, "A bus job is still running. Wait or press Stop.")
            return False
        return True

    def run_job(self, name, fn, done=None, on_post=None):
        if not self.guard():
            return False
        self.worker.submit(name, fn, done, on_post)
        QTimer.singleShot(0, self._busy)
        return True

    def _job_done(self, cb, res, err):
        self.worker.pending = max(0, self.worker.pending - 1)
        self._busy()
        if cb:
            try:
                cb(res, err)
            except Exception:       # noqa: BLE001
                self.log(traceback.format_exc())

    def run_cli(self, argv, done=None, title=""):
        if not self.guard():
            return False
        self.progress.setValue(0)
        self.proc.run(B.cli_cmd(*argv) if argv and argv[0] != "@raw" else argv[1:],
                      done, title)
        return True

    def stop_jobs(self):
        self.worker.cancel.set()
        if self.proc.busy:
            if QMessageBox.question(
                    self, APP, "Send Ctrl-C to the running CLI job?\n\n"
                    "Interrupting a flash/memwrite mid-write can leave the module "
                    "in its bootloader (recoverable with --recovery).") == \
                    QMessageBox.StandardButton.Yes:
                self.proc.interrupt()

    def confirm(self, title, text, detail=""):
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle(title)
        box.setText(text)
        if detail:
            box.setDetailedText(detail)
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        return box.exec() == QMessageBox.StandardButton.Yes

    # -- Ctrl+C / SIGTERM from the launching terminal ------------------------
    # Qt's event loop runs in C++, so Python's default SIGINT handler only
    # fires the next time some Python slot runs - then KeyboardInterrupt is
    # raised inside that slot and the window is left half-dead (greyed out).
    # Instead the signal is written to a socket (signal.set_wakeup_fd) that a
    # QSocketNotifier watches, and handled here on the GUI thread.
    def install_signal_handlers(self):
        import socket
        self._sig_r, self._sig_w = socket.socketpair()
        for s in (self._sig_r, self._sig_w):
            s.setblocking(False)
        signal.set_wakeup_fd(self._sig_w.fileno(), warn_on_full_buffer=False)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, lambda *_: None)      # real work: on_unix_signal
        self._sig_note = QSocketNotifier(self._sig_r.fileno(), QSocketNotifier.Type.Read, self)
        self._sig_note.activated.connect(self._sig_ready)
        self._sig_count = 0
        self._force_quit = False

    def _sig_ready(self):
        try:
            data = self._sig_r.recv(64)
        except BlockingIOError:
            return
        for signum in data:
            self.on_unix_signal(signum)

    def on_unix_signal(self, signum):
        name = signal.Signals(signum).name
        self._sig_count += 1
        if self._sig_count >= 3:
            print(f"\n{APP}: {name} x3 - exiting immediately", file=sys.__stderr__)
            os._exit(130)
        if self.proc.busy and self._sig_count == 1 and signum == signal.SIGINT:
            self.log(f"!! {name}: a CLI job is running (flash / memwrite?). It was NOT "
                     "interrupted. Press Ctrl+C again to abort it and quit.")
            print(f"\n{APP}: CLI job running - Ctrl+C again aborts it and quits",
                  file=sys.__stderr__)
            return
        print(f"\n{APP}: {name} - closing", file=sys.__stderr__)
        self._force_quit = True
        self.close()

    def closeEvent(self, ev):
        force = getattr(self, "_force_quit", False)
        if self.proc.busy and not force and not self.confirm(
                APP, "A CLI job is running. Quit anyway?"):
            ev.ignore()
            return
        self.settings.setValue("module", self.mod_combo.currentData())
        self.settings.setValue("iface", self.iface_combo.currentData())
        self.settings.setValue("hs", self.hs_combo.currentText())
        self.settings.setValue("ms", self.ms_combo.currentText())
        self.settings.setValue("ic", self.ic_combo.currentText())
        self.settings.setValue("tab", self.tabs.currentIndex())
        for t in (self.direct_tab, self.central_tab):
            t.save_settings()
        self.settings.sync()
        self.proc.kill()
        if not self.worker.shutdown(3000 if force else 15000):
            # a bus job is stuck in I/O: do not let QThread's destructor abort
            print(f"{APP}: worker still busy - exiting without waiting", file=sys.__stderr__)
            os._exit(130 if force else 1)
        ev.accept()


# ==========================================================================
# Modules tab: scan / ident
# ==========================================================================
class ModulesTab(QWidget):
    COLS = ["Module", "TX/RX", "Bus", "Iface", "Status", "F111 hardware", "F188 software",
            "F110 spec", "F113 assembly", "F124 cal", "VIN", "Definition"]

    def __init__(self, m: Main):
        super().__init__()
        self.m = m
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        for text, fn in (("Scan all modules", self.scan_all),
                         ("Scan selected", self.scan_sel),
                         ("Use selected as current module", self.use_sel)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch()
        lay.addLayout(row)
        self.tbl = QTableWidget(len(ecu_db.ECUS), len(self.COLS))
        self.tbl.setHorizontalHeaderLabels(self.COLS)
        self.tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl.verticalHeader().setVisible(False)
        self.txids = sorted(ecu_db.ECUS)
        for r, txid in enumerate(self.txids):
            p = ecu_db.ECUS[txid]
            for c, v in enumerate([p.name, f"{txid:03X}/{p.resp_id():03X}", p.bus, "", "", "",
                                   "", "", "", "", "", ""]):
                self.tbl.setItem(r, c, QTableWidgetItem(v))
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.tbl.doubleClicked.connect(self.use_sel)
        lay.addWidget(self.tbl)
        lay.addWidget(QLabel(
            "Scan reads identity DIDs from every registered module on its bus "
            "(HS-CAN/MS-CAN/I-CAN mapping in the toolbar; the Interface override applies to "
            "all when set). Double-click a row to make it the current module."))

    def _row(self, txid):
        return self.txids.index(txid)

    def scan_all(self):
        self._scan(self.txids)

    def scan_sel(self):
        rows = sorted({i.row() for i in self.tbl.selectedIndexes()})
        self._scan([self.txids[r] for r in rows])

    def use_sel(self, *_):
        rows = sorted({i.row() for i in self.tbl.selectedIndexes()})
        if rows:
            k = self.m.mod_combo.findData(self.txids[rows[0]])
            self.m.mod_combo.setCurrentIndex(k)

    def _scan(self, txids):
        targets = [self.m.target(t) for t in txids]
        for t in targets:
            self.tbl.item(self._row(t.txid), 3).setText(t.iface)
            self.tbl.item(self._row(t.txid), 4).setText("…")

        def job(ctx):
            for t in targets:
                if ctx.cancel.is_set():
                    break
                try:
                    with B.Link(t, "ident") as ln:
                        alive = ln.wake(tries=2, timeout=0.3) is not None
                        if not alive:
                            p, _ = ln.read(0xF111, timeout=0.4)
                            alive = p is not None
                        res = ln.ident() if alive else None
                    print(f"   {t.name:34s} {t.iface}: "
                          + ("present" if res is not None else "no response"))
                    ctx.post((t, res, None))
                except B.OpError as e:
                    ctx.post((t, None, str(e)))

        self.m.run_job(f"scan {len(targets)} module(s)", job, on_post=self._got)

    def _got(self, o):
        t, res, err = o
        r = self._row(t.txid)
        if err or res is None:
            it = self.tbl.item(r, 4)
            it.setText(err or "silent")
            it.setForeground(DIM)
            return
        self.m.ident[t.txid] = res
        it = self.tbl.item(r, 4)
        it.setText("present")
        it.setForeground(OKC)
        vals = [B.text(res.get(d)) for d in ("F111", "F188", "F110", "F113", "F124", "F190")]
        for c, v in zip(range(5, 11), vals):
            self.tbl.item(r, c).setText(v)
        cands = self.m.defs.candidates(t.txid, B.text(res.get("F110")))
        best = cands[0] if cands else None
        self.tbl.item(r, 11).setText(best.label() if best else "-")


# ==========================================================================
# Flash tab
# ==========================================================================
class FlashTab(QWidget):
    def __init__(self, m: Main):
        super().__init__()
        self.m = m
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        for text, fn in (("Add VBF…", self.add), ("Remove", self.remove),
                         ("Clear", self.clear), ("Info (full)", self.info),
                         ("Verify CRCs", self.verify)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch()
        lay.addLayout(row)
        self.tbl = QTableWidget(0, 7)
        self.tbl.setHorizontalHeaderLabels(["File", "ECU", "Module", "Part", "Type",
                                            "Blocks / bytes", "Integrity"])
        self.tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        lay.addWidget(self.tbl, 2)
        self.files = []

        opt = QGroupBox("Options")
        g = QGridLayout(opt)
        self.cb = {}
        flags = [("test_sbl", "--test-sbl  (load+run SBL only; no erase/write)"),
                 ("recovery", "--recovery  (catch the PBL after power-up)"),
                 ("skip_security", "--skip-security"),
                 ("quiet_bus", "--quiet-bus  (silence other modules)"),
                 ("decompress", "--decompress  (send LZSS blocks decompressed)"),
                 ("force", "--force  (override integrity / generation / part gates)")]
        for i, (k, t) in enumerate(flags):
            c = QCheckBox(t)
            self.cb[k] = c
            g.addWidget(c, i // 2, i % 2)
        r = len(flags) // 2 + 1
        self.hw = QLineEdit()
        self.hw.setPlaceholderText("F111 for --recovery / --hw, e.g. DV6T-14B476-xx")
        self.sbl = QLineEdit()
        self.sbl.setPlaceholderText("--sbl override (path)")
        sb = QPushButton("…")
        sb.clicked.connect(self._pick_sbl)
        self.secret = QLineEdit()
        self.secret.setPlaceholderText("--secret 0x…  (blank = ecu_db)")
        self.level = QSpinBox()
        self.level.setRange(1, 0x41)
        self.level.setValue(1)
        self.skip_blank = QLineEdit()
        self.skip_blank.setPlaceholderText("--skip-blank [min], blank = off")
        self.extra = QLineEdit()
        self.extra.setPlaceholderText("extra CLI args (advanced)")
        g.addWidget(QLabel("--hw"), r, 0)
        g.addWidget(self.hw, r, 1)
        h = QHBoxLayout()
        h.addWidget(self.sbl)
        h.addWidget(sb)
        g.addWidget(QLabel("--sbl"), r + 1, 0)
        g.addLayout(h, r + 1, 1)
        g.addWidget(QLabel("--secret"), r + 2, 0)
        g.addWidget(self.secret, r + 2, 1)
        g.addWidget(QLabel("--sec-level"), r + 3, 0)
        g.addWidget(self.level, r + 3, 1)
        g.addWidget(QLabel("--skip-blank"), r + 4, 0)
        g.addWidget(self.skip_blank, r + 4, 1)
        g.addWidget(QLabel("extra"), r + 5, 0)
        g.addWidget(self.extra, r + 5, 1)
        self.use_iface = QCheckBox("pass --iface of the target module (toolbar mapping); "
                                   "unchecked = CLI picks by bus")
        self.use_iface.setChecked(True)
        g.addWidget(self.use_iface, r + 6, 0, 1, 2)
        lay.addWidget(opt)
        row = QHBoxLayout()
        dry = QPushButton("Dry run (plan only)")
        dry.clicked.connect(lambda: self.flash(dry=True))
        go = QPushButton("FLASH")
        go.setStyleSheet("font-weight:bold;color:#b00020")
        go.clicked.connect(lambda: self.flash(dry=False))
        row.addWidget(dry)
        row.addWidget(go)
        row.addStretch()
        lay.addLayout(row)

    def _pick_sbl(self):
        f, _ = QFileDialog.getOpenFileName(self, "SBL VBF", os.path.join(HERE, "sbl"),
                                           "VBF (*.vbf *.VBF);;All (*)")
        if f:
            self.sbl.setText(f)

    def add(self):
        d = self.m.settings.value("vbfdir", HERE)
        fs, _ = QFileDialog.getOpenFileNames(self, "VBF files", d, "VBF (*.vbf *.VBF);;All (*)")
        for f in fs:
            self.m.settings.setValue("vbfdir", os.path.dirname(f))
            if f in self.files:
                continue
            try:
                v = Vbf(f)
                probs = v.check()
                prof = ecu_db.get_profile(v.ecu) if v.ecu is not None else None
                nblk = len(v.blocks or [])
                size = sum(b.get("length", 0) for b in (v.blocks or []))
                row = [os.path.basename(f), f"0x{v.ecu:03X}" if v.ecu is not None else "?",
                       prof.name if prof else "UNREGISTERED", v.part, v.ptype,
                       f"{nblk} / {size}", "OK" if not probs else "; ".join(probs)[:200]]
            except Exception as e:      # noqa: BLE001
                row = [os.path.basename(f), "?", "?", "?", "?", "?", f"parse error: {e}"]
                probs = [1]
            self.files.append(f)
            r = self.tbl.rowCount()
            self.tbl.insertRow(r)
            for c, v in enumerate(row):
                it = QTableWidgetItem(str(v))
                if c == 6:
                    it.setForeground(OKC if not probs else BAD)
                it.setToolTip(f)
                self.tbl.setItem(r, c, it)
        self.tbl.resizeColumnsToContents()

    def remove(self):
        for r in sorted({i.row() for i in self.tbl.selectedIndexes()}, reverse=True):
            self.tbl.removeRow(r)
            del self.files[r]

    def clear(self):
        self.tbl.setRowCount(0)
        self.files = []

    def info(self):
        if self.files:
            self.m.run_cli(["info", *self.files], title="info")

    def verify(self):
        if self.files:
            self.m.run_cli(["verify", *self.files], title="verify")

    def argv(self, dry):
        a = ["flash"]
        tgt = None
        if self.files:
            a += self.files
            ecus = {Vbf(f).ecu for f in self.files}
            if len(ecus) == 1 and None not in ecus:
                tgt = self.m.target(next(iter(ecus))) if next(iter(ecus)) in ecu_db.ECUS \
                    else None
        elif self.cb["test_sbl"].isChecked():
            tgt = self.m.target()
            a.append(tgt.short)
        else:
            raise B.OpError("add VBF file(s), or tick --test-sbl to test the current module's SBL")
        for k, c in self.cb.items():
            if c.isChecked():
                a.append("--" + k.replace("_", "-"))
        if self.hw.text().strip():
            a += ["--hw", self.hw.text().strip()]
        if self.sbl.text().strip():
            a += ["--sbl", self.sbl.text().strip()]
        if self.secret.text().strip():
            a += ["--secret", self.secret.text().strip()]
        if self.level.value() != 1:
            a += ["--sec-level", hex(self.level.value())]
        sbk = self.skip_blank.text().strip()
        if sbk:
            a += ["--skip-blank"] + ([] if sbk.lower() in ("y", "yes", "on", "default")
                                     else [sbk])
        if self.use_iface.isChecked() and tgt is not None:
            a += self.m.cli_iface_args(tgt)
        if self.extra.text().strip():
            a += self.extra.text().split()
        a.append("--dry-run" if dry else "--yes")
        return a

    def flash(self, dry):
        try:
            a = self.argv(dry)
        except (B.OpError, OSError, ValueError) as e:
            QMessageBox.warning(self, APP, str(e))
            return
        if dry:
            self.m.run_cli(a, title="flash dry-run")
            return
        plan = self.argv(True)

        def after_plan(code):
            if code != 0:
                QMessageBox.warning(self, APP, "The dry-run plan failed — see the log. "
                                    "Nothing was written.")
                return
            if not self.m.confirm(
                    "Flash", "The plan is in the log.\n\nWrite these file(s) to the module now?\n"
                    "Do not power off or disconnect during the flash.",
                    " ".join(a)):
                self.m.log("flash cancelled by user")
                return
            self.m.run_cli(a, title="FLASH")

        self.m.run_cli(plan, done=after_plan, title="flash plan")


# ==========================================================================
# field editing delegate (shared by Direct config and Central config)
# ==========================================================================
ROLE_FIELD = Qt.ItemDataRole.UserRole + 1     # (key, Field)


def _parse_raw(text):
    """'6', '0x06', '06h' or a combo label ending in '(0x6)' -> int."""
    t = text.strip()
    if t.endswith(")") and "(0x" in t:
        t = t[t.rindex("(0x") + 1:-1]
    if t.lower().endswith("h"):
        t = "0x" + t[:-1]
    return int(t, 0) if t.lower().startswith("0x") else int(t)


class FieldDelegate(QStyledItemDelegate):
    """Column-2 editor: fixed combo for enums (the definition's values only),
    line edit for numbers, text for ASCII. Column 3 ("Raw") edits the raw
    integer, including values the definition does not list."""

    def __init__(self, tab):
        super().__init__(tab)
        self.tab = tab

    @staticmethod
    def _raw_col(index, f):
        return index.column() == 3 and f.type not in ("ascii", "bytes", "dtc") and f.width <= 64

    def createEditor(self, parent, option, index):
        data = index.siblingAtColumn(2).data(ROLE_FIELD)
        if not data or index.column() not in (2, 3):
            return None
        key, f = data
        if index.column() == 3:
            if not self._raw_col(index, f):
                return None
            le = QLineEdit(parent)
            le.setPlaceholderText(f"raw 0..0x{(1 << f.width) - 1:X}  (dec, or 0x hex)")
            return le
        if f.enum:
            cb = QComboBox(parent)
            for v, lab in f.enum:
                cb.addItem(f"{lab}  (0x{v:X})", v)
            cb.setMaxVisibleItems(30)
            return cb
        if f.type == "ascii":
            return QLineEdit(parent)
        if f.is_editable_scalar():
            le = QLineEdit(parent)
            le.setPlaceholderText(f"raw 0..{(1 << f.width) - 1}  (dec, or 0x hex)")
            return le
        le = QLineEdit(parent)
        le.setPlaceholderText(f"{(f.width + 7) // 8} hex bytes")
        return le

    def setEditorData(self, ed, index):
        key, f = index.siblingAtColumn(2).data(ROLE_FIELD)
        payload = self.tab.payload_of(key)
        if payload is None:
            return
        if index.column() == 3:
            ed.setText(f"0x{f.get_raw(payload):X}")
            return
        if isinstance(ed, QComboBox):
            raw = f.get_raw(payload)
            k = ed.findData(raw)
            if k < 0:
                ed.addItem(f"(undefined 0x{raw:X})", raw)
                k = ed.count() - 1
            ed.setCurrentIndex(k)
        elif f.type == "ascii":
            ed.setText(f.display(payload))
        elif f.is_editable_scalar():
            ed.setText(str(f.get_raw(payload)))
        else:
            ed.setText(f.get_bytes(payload).hex(" ").upper())

    def setModelData(self, ed, model, index):
        key, f = index.siblingAtColumn(2).data(ROLE_FIELD)
        payload = self.tab.payload_of(key)
        if payload is None:
            return
        try:
            if index.column() == 3:
                new = f.set_raw(payload, _parse_raw(ed.text()))
            elif isinstance(ed, QComboBox):
                new = f.set_raw(payload, ed.currentData())
            elif f.type == "ascii":
                new = f.set_bytes(payload, ed.text().encode("latin-1", "replace"))
            elif f.is_editable_scalar():
                t = ed.text().strip()
                new = f.set_raw(payload, int(t, 0) if t.lower().startswith("0x") else int(t))
            else:
                new = f.set_bytes(payload, parse_hex(ed.text()))
        except (ValueError, TypeError) as e:
            QMessageBox.warning(self.tab, APP, str(e))
            return
        self.tab.set_payload(key, new)


# ==========================================================================
# Direct configuration tab
# ==========================================================================
class DirectConfigTab(QWidget):
    def __init__(self, m: Main):
        super().__init__()
        self.m = m
        self.mdef = None
        self.dids = {}            # did -> DidDef
        self.orig = {}            # did -> bytes as read from the module
        self.cur = {}             # did -> bytes (edited)
        self.errors = {}
        self.items = {}           # did -> QTreeWidgetItem
        self.ident = {}
        lay = QVBoxLayout(self)

        top = QGroupBox("Module definition")
        g = QGridLayout(top)
        b = QPushButton("Identify module")
        b.clicked.connect(self.identify)
        g.addWidget(b, 0, 0)
        self.id_lbl = QLabel("—")
        self.id_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        g.addWidget(self.id_lbl, 0, 1, 1, 5)
        g.addWidget(QLabel("Vehicle"), 1, 0)
        self.model = QComboBox()
        self.model.setEditable(True)
        self.model.addItems([""] + self.m.defs.models())
        self.model.setCurrentText(self.m.settings.value("model", "C520_EU"))
        self.year = QComboBox()
        self.year.setEditable(True)
        self.model.currentTextChanged.connect(self._years)
        self._years()
        self.year.setCurrentText(self.m.settings.value("year", ""))
        g.addWidget(self.model, 1, 1)
        g.addWidget(self.year, 1, 2)
        sug = QPushButton("Suggest definitions")
        sug.clicked.connect(self.suggest)
        g.addWidget(sug, 1, 3)
        self.search = QLineEdit()
        self.search.setPlaceholderText("search spec / model / acronym (e.g. 14G371, C520, IPMA)")
        self.search.returnPressed.connect(self.do_search)
        g.addWidget(self.search, 1, 4)
        sb = QPushButton("Search")
        sb.clicked.connect(self.do_search)
        g.addWidget(sb, 1, 5)
        g.addWidget(QLabel("Definition"), 2, 0)
        self.defcombo = QComboBox()
        self.defcombo.currentIndexChanged.connect(self.load_def)
        g.addWidget(self.defcombo, 2, 1, 1, 5)
        g.setColumnStretch(4, 1)
        lay.addWidget(top)

        acc = QHBoxLayout()
        acc.addWidget(QLabel("Show"))
        self.view = QComboBox()
        self.view.addItems(["Config (writable)", "Diagnostic data (read-only)", "All DIDs"])
        self.view.currentIndexChanged.connect(self.populate)
        acc.addWidget(self.view)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("filter: DID / name / field (e.g. batt, TPM, 40)")
        self.filter.setMinimumWidth(240)
        self.filter.textChanged.connect(self.populate)
        acc.addWidget(self.filter)
        acc.addWidget(QLabel("  read: session"))
        self.rd_sess = QComboBox()
        self.rd_sess.addItems(["auto", "01", "03", "60", "40"])
        acc.addWidget(self.rd_sess)
        acc.addWidget(QLabel("unlock"))
        self.rd_lvl = QComboBox()
        self.rd_lvl.addItems(["none", "27 01", "27 03", "27 05", "27 11"])
        acc.addWidget(self.rd_lvl)
        acc.addWidget(QLabel("   write: session"))
        self.wr_sess = QComboBox()
        self.wr_sess.addItems(["auto", "03", "60", "40", "01"])
        acc.addWidget(self.wr_sess)
        acc.addWidget(QLabel("unlock"))
        self.wr_lvl = QComboBox()
        self.wr_lvl.addItems(["auto", "none", "27 01", "27 03", "27 05", "27 11"])
        acc.addWidget(self.wr_lvl)
        acc.addStretch()
        lay.addLayout(acc)

        row = QHBoxLayout()
        for text, fn in (("Read shown DIDs", self.read_module),
                         ("Read selected", self.read_selected),
                         ("Write changed DIDs", self.write_module),
                         ("Revert edits", self.revert),
                         ("Load UCDS Direct XML…", self.load_xml),
                         ("Save UCDS Direct XML…", self.save_xml),
                         ("Edit raw hex of selected DID", self.edit_raw)):
            bb = QPushButton(text)
            bb.clicked.connect(fn)
            row.addWidget(bb)
        row.addStretch()
        row.addWidget(QLabel("live every"))
        self.poll_s = QDoubleSpinBox()
        self.poll_s.setRange(0.0, 60.0)
        self.poll_s.setValue(1.0)
        self.poll_s.setSuffix(" s")
        row.addWidget(self.poll_s)
        self.poll_btn = QPushButton("Live poll (selected / shown)")
        self.poll_btn.setCheckable(True)
        self.poll_btn.toggled.connect(self.toggle_poll)
        row.addWidget(self.poll_btn)
        lay.addLayout(row)

        self.tree = QTreeWidget()
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.setColumnCount(5)
        self.tree.setHeaderLabels(["DID / field", "Position", "Value", "Raw", "Access / info"])
        self.tree.setItemDelegate(FieldDelegate(self))
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.DoubleClicked
                                  | QAbstractItemView.EditTrigger.EditKeyPressed)
        self.tree.setAlternatingRowColors(True)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.tree.setColumnWidth(0, 420)
        self.tree.setColumnWidth(1, 110)
        self.tree.setColumnWidth(2, 380)
        self.tree.setColumnWidth(3, 260)
        lay.addWidget(self.tree, 1)
        self.status = QLabel("")
        lay.addWidget(self.status)

    def save_settings(self):
        self.m.settings.setValue("model", self.model.currentText())
        self.m.settings.setValue("year", self.year.currentText())

    def _years(self):
        cur = self.year.currentText()
        self.year.clear()
        self.year.addItems([""] + self.m.defs.years(self.model.currentText()))
        self.year.setCurrentText(cur)

    def module_changed(self):
        try:
            t = self.m.target()
        except B.OpError:
            return
        self.ident = self.m.ident.get(t.txid, {})
        self._show_ident()
        self.suggest()

    def _show_ident(self):
        if not self.ident:
            self.id_lbl.setText("not identified — press Identify (reads F110/F111/F113/F188)")
            return
        self.id_lbl.setText("   ".join(f"{d}: <b>{B.text(self.ident.get(d)) or '—'}</b>"
                                       for d in ("F110", "F111", "F113", "F188", "F190")))

    def identify(self):
        try:
            t = self.m.target()
        except B.OpError as e:
            QMessageBox.warning(self, APP, str(e))
            return

        def job(ctx):
            with B.Link(t, "ident") as ln:
                ln.wake()
                res = ln.ident()
            for k, v in res.items():
                print(f"   {k}: {B.text(v) if v else '—'}")
            return t, res

        def done(r, err):
            if err:
                return
            t, res = r
            self.m.ident[t.txid] = res
            self.ident = res
            self._show_ident()
            self.suggest()

        self.m.run_job(f"identify {t.name} on {t.iface}", job, done)

    def suggest(self):
        try:
            t = self.m.target()
        except B.OpError:
            return
        cands = self.m.defs.candidates(t.txid, B.text(self.ident.get("F110")),
                                       self.model.currentText() or None,
                                       self.year.currentText() or None)
        self._fill(cands)

    def do_search(self):
        txt = self.search.text().strip()
        if not txt:
            return self.suggest()
        try:
            addr = self.m.target().txid
        except B.OpError:
            addr = None
        res = self.m.defs.search(txt, addr) or self.m.defs.search(txt)
        self._fill(res)

    def _fill(self, cands):
        self.defcombo.blockSignals(True)
        self.defcombo.clear()
        self.defcombo.addItem("— none (raw DIDs only) —", None)
        for c in cands:
            self.defcombo.addItem(c.label(), c)
        self.defcombo.blockSignals(False)
        self.defcombo.setCurrentIndex(1 if cands else 0)
        self.load_def()

    def load_def(self):
        self.mdef = self.defcombo.currentData()
        self.dids = self.m.defs.dids(self.mdef.id) if self.mdef else {}
        self.populate()

    # -- tree ----------------------------------------------------------------
    def shown_dids(self):
        view = self.view.currentIndex()        # 0 config, 1 diagnostic, 2 all
        ds = set(self.cur) | set(self.orig) | set(self.dids)
        out = []
        q = self.filter.text().strip().lower()
        for d in sorted(ds):
            dd = self.dids.get(d)
            w = dd.writable if dd else d in self.cur and d not in self.orig
            if view == 0 and dd is not None and not w:
                continue
            if view == 1 and (dd is None or w):
                continue
            if q:
                hay = f"{d:04x} " + (dd.name.lower() if dd else "") + " " + " ".join(
                    (f.name + " " + (f.key or "")).lower() for f in (dd.fields if dd else []))
                if q not in hay:
                    continue
            out.append(d)
        return out

    def selected_dids(self):
        out = []
        for it in self.tree.selectedItems():
            while it.parent():
                it = it.parent()
            d = it.data(0, Qt.ItemDataRole.UserRole)
            if d is not None and d not in out:
                out.append(d)
        return out

    def populate(self):
        self.tree.clear()
        self.items = {}
        for did in self.shown_dids():
            dd = self.dids.get(did)
            it = QTreeWidgetItem([f"{did:04X}  {dd.name if dd else '(not in definition)'}",
                                  f"{dd.size} B" if dd and dd.size else "", "", "",
                                  self._access(dd)])
            it.setFont(0, QFont(MONO.family(), weight=QFont.Weight.Bold))
            it.setData(0, Qt.ItemDataRole.UserRole, did)
            self.tree.addTopLevelItem(it)
            self.items[did] = it
            if dd:
                for f in sorted(dd.fields, key=lambda f: -f.msb):   # byte 0 / MSB first
                    info = " · ".join(x for x in (f.key, f.desc) if x)
                    ch = QTreeWidgetItem(["   " + f.name, f.position(dd.size or 0), "", "",
                                          info])
                    ch.setData(2, ROLE_FIELD, (did, f))
                    ch.setToolTip(0, f.name)
                    if dd.writable:
                        ch.setFlags(ch.flags() | Qt.ItemFlag.ItemIsEditable)
                        ch.setToolTip(2, "double-click to edit")
                    else:
                        ch.setToolTip(2, "read-only DID")
                    it.addChild(ch)
            self.refresh_did(did)
        self.status.setText(f"{len(self.items)} DID(s) shown; definition "
                            f"{self.mdef.label() if self.mdef else 'none'}")

    def _access(self, dd):
        if not dd:
            return ""
        s = f"read {dd.rd}" if dd.rd else "read (default session)"
        if dd.writable:
            s += f" · write {dd.wr or '?'}"
            lvl = B.ford_level_to_seed(dd.wr_sec)
            if lvl:
                s += f" · 27 {lvl:02X}"
        return s

    def payload_of(self, did):
        return self.cur.get(did)

    def set_payload(self, did, new):
        self.cur[did] = new
        self.refresh_did(did)

    def refresh_did(self, did):
        it = self.items.get(did)
        if it is None:
            return
        p = self.cur.get(did)
        dd = self.dids.get(did)
        changed = p is not None and self.orig.get(did) is not None and p != self.orig[did]
        it.setText(3, hx(p) if p is not None else self.errors.get(did, ""))
        it.setForeground(3, CHANGED if changed else (BAD if did in self.errors else
                                                     QBrush()))
        it.setText(2, "MODIFIED" if changed else "")
        it.setForeground(2, CHANGED)
        if dd and p is not None and dd.size and len(p) != dd.size:
            it.setText(2, f"length {len(p)} ≠ definition {dd.size}")
            it.setForeground(2, BAD)
        for i in range(it.childCount()):
            ch = it.child(i)
            _, f = ch.data(2, ROLE_FIELD)
            if p is None:
                ch.setText(2, "")
                ch.setText(3, "")
                continue
            ch.setText(2, f.display(p))
            raw = "" if not f.fits(len(p)) else (
                f"0x{f.get_raw(p):X}" if f.width <= 64 else "")
            ch.setText(3, raw)
            o = self.orig.get(did)
            fch = (o is not None and f.fits(len(o)) and f.fits(len(p))
                   and f.get_raw(o) != f.get_raw(p))
            ch.setForeground(2, CHANGED if fch else QBrush())
            ch.setToolTip(3, f"was 0x{f.get_raw(o):X}" if fch else "")

    # -- module I/O ------------------------------------------------------------
    @staticmethod
    def _lvl(text):
        return None if text in ("none", "auto") else int(text.split()[1], 16)

    def read_selected(self):
        d = self.selected_dids()
        if not d:
            QMessageBox.information(self, APP, "Select DID rows first.")
            return
        self.read_module(d)

    def _read_groups(self, dids):
        sess_over = self.rd_sess.currentText()
        groups = {}
        for d in dids:
            dd = self.dids.get(d)
            s = (None if sess_over == "01" else int(sess_over, 16)) if sess_over != "auto" \
                else B.first_session(dd.rd if dd else "")
            groups.setdefault(s, []).append(d)
        return groups

    def _got(self, d, p, e):
        """A fresh read. Keeps the user's pending edit of a writable DID."""
        if p is not None:
            edited = d in self.cur and d in self.orig and self.cur[d] != self.orig[d]
            self.orig[d] = p
            if not edited:
                self.cur[d] = p
            self.errors.pop(d, None)
        else:
            self.errors[d] = e
        if d in self.items:
            self.refresh_did(d)

    def toggle_poll(self, on):
        if not on:
            self.m.worker.cancel.set()
            return
        try:
            t = self.m.target()
        except B.OpError as e:
            QMessageBox.warning(self, APP, str(e))
            self.poll_btn.setChecked(False)
            return
        dids = self.selected_dids() or self.shown_dids()
        if not dids:
            self.poll_btn.setChecked(False)
            return
        if len(dids) > 40 and not self.m.confirm(
                "Live poll", f"Poll {len(dids)} DIDs? Select fewer rows for a faster refresh."):
            self.poll_btn.setChecked(False)
            return
        groups = self._read_groups(dids)
        sessions = [s for s in groups if s is not None]
        lvl = self._lvl(self.rd_lvl.currentText())
        interval = self.poll_s.value()

        def job(ctx):
            with B.Link(t, "livepoll") as ln:
                ln.wake()
                if sessions:
                    ln.session(max(sessions))
                    ln.start_keepalive()
                if lvl:
                    ln.unlock(lvl)
                n = 0
                while not ctx.cancel.is_set():
                    for d in dids:
                        if ctx.cancel.is_set():
                            break
                        p, err = ln.read(d, timeout=1.0)
                        ctx.post((d, p, err))
                    n += 1
                    ctx.cancel.wait(interval)
                ln.stop_keepalive()
                if sessions:
                    ln.session(0x01)
            print(f"   live poll stopped after {n} round(s)")

        if not self.m.run_job(f"live poll {len(dids)} DID(s) on {t.name}", job,
                              lambda r, e: self.poll_btn.setChecked(False),
                              on_post=lambda o: self._got(*o)):
            self.poll_btn.setChecked(False)

    def read_module(self, dids=None):
        try:
            t = self.m.target()
        except B.OpError as e:
            QMessageBox.warning(self, APP, str(e))
            return
        if not dids:
            dids = self.shown_dids() if self.dids else sorted(self.cur)
        if not dids:
            QMessageBox.information(self, APP, "Choose a definition first (or load a file).")
            return
        sess_over = self.rd_sess.currentText()
        lvl = self._lvl(self.rd_lvl.currentText())
        groups = {}
        for d in dids:
            dd = self.dids.get(d)
            s = (None if sess_over == "01" else int(sess_over, 16)) if sess_over != "auto" \
                else B.first_session(dd.rd if dd else "")
            groups.setdefault(s, []).append(d)

        def job(ctx):
            out = {}
            with B.Link(t, "cfgread") as ln:
                ln.wake()
                ln.ident(("F111",))
                for s in sorted(groups, key=lambda x: (x is not None, x or 0)):
                    if s is not None:
                        ln.session(s)
                        ln.start_keepalive()
                    if lvl:
                        ln.unlock(lvl)
                    for d in groups[s]:
                        if ctx.cancel.is_set():
                            return out
                        p, err = ln.read(d)
                        out[d] = (p, err)
                        print(f"   {d:04X}: {hx(p) if p is not None else err}")
                # Config DIDs refused without SecurityAccess (e.g. IPMA needs
                # 10 03 + 27 03 even to READ): retry them once, unlocked with
                # the level the definition publishes for writing.
                retry = [d for d, (p, _) in out.items() if p is None and not lvl
                         and self.dids.get(d) is not None and self.dids[d].wr_sec]
                if retry and not ctx.cancel.is_set():
                    dd0 = self.dids[retry[0]]
                    s = B.first_session(dd0.wr) or 0x03
                    seed = B.ford_level_to_seed(dd0.wr_sec) or 0x03
                    print(f"   {len(retry)} DID(s) refused -> session {s:02X} + 27 {seed:02X} "
                          "and retry")
                    try:
                        ln.session(s)
                        ln.start_keepalive()
                        ln.unlock(seed)
                        for d in retry:
                            p, err = ln.read(d)
                            out[d] = (p, err)
                            print(f"   {d:04X}: {hx(p) if p is not None else err}")
                    except B.OpError as e:
                        print(f"   unlock failed: {e}")
                    groups.setdefault(s, [])
                ln.stop_keepalive()
                if any(s is not None for s in groups):
                    ln.session(0x01)
            return out

        def done(res, err):
            if not res:
                return
            for d, (p, e) in res.items():
                self._got(d, p, e)
            self.populate()
            ok = sum(1 for p, _ in res.values() if p is not None)
            self.status.setText(f"read {ok}/{len(res)} DID(s) from {t.name}")
            if any(self.dids.get(d) is None or self.dids[d].writable for d in res):
                self._auto_backup(t)

        self.m.run_job(f"read {len(dids)} DID(s) from {t.name}", job, done)

    def _auto_backup(self, t):
        if not self.orig:
            return
        os.makedirs(B.BACKUP_DIR, exist_ok=True)
        fn = os.path.join(B.BACKUP_DIR, f"Direct_{t.short}_{time.strftime('%Y%m%d-%H%M%S')}"
                          "_read.xml")
        D.save_direct_xml(fn, t.short, self.orig, B.text(self.ident.get("F190")) or "NONE",
                          self.model.currentText(), self.year.currentText())
        self.m.log(f"   backup of the values read: {fn}")

    def changed(self):
        return {d: p for d, p in self.cur.items()
                if p is not None and (self.orig.get(d) is None or self.orig[d] != p)}

    def write_module(self):
        ch = self.changed()
        if not ch:
            QMessageBox.information(self, APP, "Nothing changed.")
            return
        try:
            t = self.m.target()
        except B.OpError as e:
            QMessageBox.warning(self, APP, str(e))
            return
        missing = [d for d in ch if d not in self.orig]
        detail = "\n".join(f"{d:04X}: {hx(self.orig.get(d)) or '(not read)'}\n   -> {hx(p)}"
                           for d, p in sorted(ch.items()))
        warn = ""
        if missing:
            warn = (f"\n\n{len(missing)} DID(s) were not read from this module first "
                    "(values come from a file). ")
        for d, p in ch.items():
            dd = self.dids.get(d)
            if dd and dd.size and len(p) != dd.size:
                warn += f"\nDID {d:04X}: length {len(p)} ≠ definition {dd.size}!"
        if not self.m.confirm("Write configuration",
                              f"Write {len(ch)} DID(s) to {t.name} on {t.iface}?{warn}",
                              detail):
            return
        sess_over = self.wr_sess.currentText()
        lvl_over = self.wr_lvl.currentText()
        plan = {}
        for d, p in sorted(ch.items()):
            dd = self.dids.get(d)
            s = int(sess_over, 16) if sess_over != "auto" else (
                B.first_session(dd.wr) if dd and dd.wr else 0x03) or 0x03
            if sess_over == "01":
                s = None
            lv = (self._lvl(lvl_over) if lvl_over != "auto" else
                  B.ford_level_to_seed(dd.wr_sec) if dd else None)
            plan.setdefault((s, lv), []).append((d, p))
        # always keep a backup of what the module had
        self._auto_backup(t)

        def job(ctx):
            out = {}
            with B.Link(t, "cfgwrite") as ln:
                ln.wake()
                ln.ident(("F111",))
                for (s, lv), items in plan.items():
                    ln.session(s)
                    ln.start_keepalive()
                    if lv:
                        ln.unlock(lv)
                    for d, p in items:
                        ok, resp = ln.write(d, p)
                        rb, err = ln.read(d)
                        out[d] = (ok, resp, rb)
                        print(f"   {'OK  ' if ok else 'FAIL'} 2E {d:04X} {hx(p)}  -> {resp}; "
                              f"read-back {hx(rb) if rb is not None else err}"
                              + ("  ✓" if rb == p else "  ✗ MISMATCH" if ok else ""))
                    ln.stop_keepalive()
                ln.session(0x01)
            return out

        def done(res, err):
            if not res:
                return
            bad = []
            for d, (ok, resp, rb) in res.items():
                if rb is not None:
                    self.orig[d] = rb
                    self.cur[d] = rb if not ok else self.cur[d]
                if not ok or rb != ch[d]:
                    bad.append(f"{d:04X}: {resp}")
            self.populate()
            if bad:
                QMessageBox.warning(self, APP, "Some writes failed or did not verify:\n"
                                    + "\n".join(bad))
            else:
                QMessageBox.information(self, APP, f"{len(res)} DID(s) written and verified. "
                                        "Most modules apply configuration after a reset "
                                        "(Service tab → Reset).")

        self.m.run_job(f"write {len(ch)} DID(s) to {t.name}", job, done)

    def revert(self):
        self.cur = dict(self.orig)
        self.populate()

    def load_xml(self):
        f, _ = QFileDialog.getOpenFileName(self, "UCDS Direct Configuration XML",
                                           self.m.settings.value("xmldir", HERE),
                                           "XML (*.xml);;All (*)")
        if not f:
            return
        self.m.settings.setValue("xmldir", os.path.dirname(f))
        try:
            attrs, dids = D.load_direct_xml(f)
        except Exception as e:      # noqa: BLE001
            QMessageBox.warning(self, APP, f"{f}: {e}")
            return
        if self.orig:
            mode = QMessageBox.question(
                self, APP, f"Apply the {len(dids)} DID value(s) from the file as EDITS "
                "on top of what was read from the module?\n\n(No = replace everything, "
                "treating the file as the baseline.)")
            if mode == QMessageBox.StandardButton.No:
                self.orig = {}
                self.cur = {}
        for d, p in dids.items():
            self.cur[d] = p
        mod = attrs.get("MODULE", "")
        self.m.log(f"loaded {len(dids)} DID(s) from {f}  MODULE={mod} VIN={attrs.get('VIN')} "
                   f"VEHICLE={attrs.get('VEHICLE_ID')} {attrs.get('VEHICLE_YEAR')}")
        if attrs.get("VEHICLE_ID") and not self.orig:
            self.model.setCurrentText(attrs["VEHICLE_ID"])
            self.year.setCurrentText(attrs.get("VEHICLE_YEAR", ""))
        self.populate()

    def save_xml(self):
        if not self.cur:
            return
        try:
            t = self.m.target()
            mod = t.short
        except B.OpError:
            mod = "MODULE"
        mod_tag = "mod" if any(self.orig.get(d) != p for d, p in self.cur.items()) else ""
        f, _ = QFileDialog.getSaveFileName(
            self, "Save UCDS Direct Configuration XML",
            _unique(os.path.join(self.m.settings.value("xmldir", HERE),
                                 f"Direct_{mod}_{time.strftime('%d%m%y')}_{mod_tag}.xml")),
            "XML (*.xml)")
        if f:
            D.save_direct_xml(f, mod, {d: p for d, p in self.cur.items() if p is not None},
                              B.text(self.ident.get("F190")) or "NONE",
                              self.model.currentText(), self.year.currentText())
            self.m.settings.setValue("xmldir", os.path.dirname(f))
            self.m.log(f"saved {f}")

    def edit_raw(self):
        it = self.tree.currentItem()
        if it is None:
            return
        while it.parent():
            it = it.parent()
        did = it.data(0, Qt.ItemDataRole.UserRole)
        cur = self.cur.get(did)
        txt, ok = QInputDialog.getText(self, "Raw DID value", f"DID {did:04X} hex:",
                                       text=hx(cur))
        if ok:
            try:
                self.set_payload(did, parse_hex(txt))
            except ValueError as e:
                QMessageBox.warning(self, APP, str(e))


# ==========================================================================
# Central configuration (CCC) tab
# ==========================================================================
class CentralConfigTab(QWidget):
    def __init__(self, m: Main):
        super().__init__()
        self.m = m
        self.img = None
        self.orig = None
        self.vin = ""
        self.blocks = []
        lay = QVBoxLayout(self)
        g = QGridLayout()
        g.addWidget(QLabel("Module"), 0, 0)
        self.src = QComboBox()
        for txid in (0x726, 0x720):
            if txid in ecu_db.ECUS:
                self.src.addItem(f"{ecu_db.ECUS[txid].name} [0x{txid:03X}]", txid)
        g.addWidget(self.src, 0, 1)
        g.addWidget(QLabel("Address"), 0, 2)
        self.addr = QLineEdit("auto (D12B)")
        self.addr.setToolTip("CCC buffer address; 'auto' reads DID D12B (BCM: 0x00008000)")
        g.addWidget(self.addr, 0, 3)
        g.addWidget(QLabel("CCF definition"), 1, 0)
        self.ccf = QComboBox()
        for cid, name, model, year, cc, length, mods in self.m.defs.ccc_defs():
            self.ccf.addItem(f"{name}   ({model} {year or ''}, {cc})", cid)
        self.ccf.currentIndexChanged.connect(self.populate)
        g.addWidget(self.ccf, 1, 1, 1, 3)
        self.no_verify = QCheckBox("memwrite --no-verify (skip 31 01 0304)")
        g.addWidget(self.no_verify, 0, 4)
        g.setColumnStretch(1, 1)
        lay.addLayout(g)
        row = QHBoxLayout()
        for text, fn in (("Read CCC from module", self.read_module),
                         ("Write CCC to module", self.write_module),
                         ("Load As-Built XML / .bin…", self.load),
                         ("Save As-Built XML…", self.save_xml),
                         ("Save .bin…", self.save_bin),
                         ("Edit raw bytes…", self.edit_raw),
                         ("Revert edits", self.revert)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            row.addWidget(b)
            if fn == self.write_module:
                self.write_btn = b
        self.write_btn.setEnabled(False)
        self.write_btn.setToolTip("Read the CCC from the module or load a file first")
        self._addr = self._hw = None
        self._source = None           # backup file the current image came from
        row.addStretch()
        lay.addLayout(row)
        self.info = QLabel("No CCC loaded. Read it from the BCM/IPC (SBL + RequestUpload "
                           "of the 512-byte buffer) or load a UCDS As-Built XML.")
        lay.addWidget(self.info)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Block / parameter", "Position", "Value", "Raw", "Key"])
        self.tree.setItemDelegate(FieldDelegate(self))
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.DoubleClicked
                                  | QAbstractItemView.EditTrigger.EditKeyPressed)
        self.tree.setAlternatingRowColors(True)
        self.tree.setColumnWidth(0, 380)
        self.tree.setColumnWidth(1, 90)
        self.tree.setColumnWidth(2, 420)
        self.tree.setColumnWidth(3, 120)
        lay.addWidget(self.tree, 1)
        k = self.ccf.findText(self.m.settings.value("ccf", ""), Qt.MatchFlag.MatchStartsWith)
        if k >= 0:
            self.ccf.setCurrentIndex(k)

    def save_settings(self):
        self.m.settings.setValue("ccf", self.ccf.currentText().split()[0]
                                 if self.ccf.count() else "")

    # -- model ---------------------------------------------------------------
    def payload_of(self, bno):
        b = self._block(bno)
        return self.img[b.offset:b.offset + b.length] if b and self.img else None

    def set_payload(self, bno, new):
        b = self._block(bno)
        img = bytearray(self.img)
        img[b.offset:b.offset + b.length] = new
        self.img = D.ccc_fix_checksum(bytes(img)) if len(img) == D.CCC_LEN else bytes(img)
        self.refresh()

    def _block(self, bno):
        for b in self.blocks:
            if b.no == bno:
                return b
        return None

    def set_image(self, img, vin="", source=None, from_txid=None):
        self.img = bytes(img)
        self.orig = bytes(img)
        self.vin = vin
        self._source = source
        self._from_txid = from_txid           # module it was read from (None: file)
        self.write_btn.setEnabled(True)
        self.write_btn.setToolTip(f"Write to the module; pre-write backup: {source}")
        dt = self.m.direct_tab
        cid, why = self.m.defs.guess_ccc(self.img, dt.model.currentText().strip() or None,
                                         dt.year.currentText().strip() or None)
        cur = self.ccf.currentData()
        if cur is not None and self.m.defs.ccc_vehicle_type_ok(cur, self.img):
            if cid is not None and cid != cur:
                self.m.log(f"CCF definition kept: {self.ccf.currentText().split()[0]} "
                           f"(best guess would be {why})")
        elif cid is not None:
            k = self.ccf.findData(cid)
            self.ccf.blockSignals(True)
            self.ccf.setCurrentIndex(k)
            self.ccf.blockSignals(False)
            self.m.log(f"CCF definition chosen: {why}")
        else:
            self.m.log(f"CCF definition: {why} - pick one by hand")
        self.populate()

    def populate(self):
        self.tree.clear()
        cid = self.ccf.currentData()
        self.blocks = self.m.defs.ccc_blocks(cid) if cid else []
        for b in self.blocks:
            it = QTreeWidgetItem([f"Block {b.no}", f"+{b.offset} ({b.length} B)", "", "", ""])
            it.setFont(0, QFont(MONO.family(), weight=QFont.Weight.Bold))
            it.setData(0, Qt.ItemDataRole.UserRole, b.no)
            self.tree.addTopLevelItem(it)
            for f in b.fields:
                if "Carriage return" in f.name:
                    continue
                ch = QTreeWidgetItem(["   " + f.name, self._pos(b, f), "", "", f.key or ""])
                ch.setData(2, ROLE_FIELD, (b.no, f))
                ch.setFlags(ch.flags() | Qt.ItemFlag.ItemIsEditable)
                ch.setToolTip(2, "double-click: pick a defined value")
                ch.setToolTip(3, "double-click: type any raw value (6 / 0x06)")
                it.addChild(ch)
            it.setExpanded(b.no >= 4)
        self.refresh()

    @staticmethod
    def _pos(b, f):
        """Block position plus, inside the F106 range, the DID byte index."""
        pos = f.position(b.length)
        span = f.byte_span(b.length) if f.fits(b.length) else None
        first = b.offset + (span[0] if span else (b.length * 8 - 1 - f.msb) // 8)
        if first >= D.F106_BASE:
            pos += f"  F106[{first - D.F106_BASE}]"
        return pos

    def edit_raw(self):
        """Edit image bytes directly: offset as image offset (0x111 / 273) or
        F106 index (F106:17); value as hex bytes. Checksum is re-fixed."""
        if self.img is None:
            QMessageBox.information(self, APP, "Load or read a CCC first.")
            return
        txt, ok = QInputDialog.getText(
            self, "Raw CCC bytes",
            "Offset: image offset (0x111) or F106 index (F106:17), then '=' and hex bytes\n"
            "e.g.  F106:17 = 06      or      0x111 = 06\n"
            "Without '=' the current bytes are shown.",
            text="F106:")
        if not ok or not txt.strip():
            return
        try:
            where, _, val = txt.partition("=")
            where = where.strip()
            if where.upper().startswith("F106:"):
                idx = parse_int(where[5:].strip())
                off = None if idx is None else D.F106_BASE + idx
            else:
                off = parse_int(where)
            if off is None or not 0 <= off < len(self.img):
                raise ValueError(f"offset {where!r} outside the {len(self.img)}-byte image")
            if not val.strip():
                cur = self.img[off:off + 8]
                QMessageBox.information(
                    self, APP, f"image 0x{off:03X}"
                    + (f" (F106[{off - D.F106_BASE}])" if off >= D.F106_BASE else "")
                    + f": {cur.hex(' ').upper()} …")
                return
            data = parse_hex(val)
            if off + len(data) > len(self.img):
                raise ValueError("value runs past the end of the image")
            if off <= D.CCC_CHECKSUM_OFF < off + len(data):
                raise ValueError("byte 257 (F106[1]) is the checksum; it is recomputed "
                                 "automatically")
        except ValueError as e:
            QMessageBox.warning(self, APP, str(e))
            return
        img = bytearray(self.img)
        img[off:off + len(data)] = data
        self.img = D.ccc_fix_checksum(bytes(img)) if len(img) == D.CCC_LEN else bytes(img)
        self.m.log(f"CCC raw edit: 0x{off:03X} = {data.hex(' ').upper()}")
        self.refresh()

    def refresh(self):
        if self.img is None:
            return
        probs = D.ccc_check(self.img)
        nchg = sum(1 for a, c in zip(self.orig or b"", self.img) if a != c)
        vin = self.img[11:28].decode("latin-1", "replace") if len(self.img) >= 28 else ""
        self.info.setText(f"CCC {len(self.img)} bytes · VIN {vin!r} · "
                          + ("checksum OK" if not probs else "; ".join(probs))
                          + (f" · {nchg} byte(s) modified" if nchg else ""))
        self.info.setStyleSheet("" if not probs else "color:#b00020")
        for i in range(self.tree.topLevelItemCount()):
            it = self.tree.topLevelItem(i)
            bno = it.data(0, Qt.ItemDataRole.UserRole)
            b = self._block(bno)
            p = self.img[b.offset:b.offset + b.length]
            o = self.orig[b.offset:b.offset + b.length] if self.orig else p
            it.setText(3, "MODIFIED" if p != o else "")
            it.setForeground(3, CHANGED)
            for j in range(it.childCount()):
                ch = it.child(j)
                _, f = ch.data(2, ROLE_FIELD)
                if not f.fits(len(p)):
                    continue
                ch.setText(2, f.display(p))
                ch.setText(3, f"0x{f.get_raw(p):X}" if f.width <= 32 else "")
                fch = f.get_raw(o) != f.get_raw(p)
                ch.setForeground(2, CHANGED if fch else QBrush())
                ch.setToolTip(2, f"was: {f.display(o)}" if fch else "")

    def revert(self):
        if self.orig:
            self.img = self.orig
            self.refresh()

    # -- files ---------------------------------------------------------------
    def load(self):
        f, _ = QFileDialog.getOpenFileName(self, "As-Built XML or 512-byte binary",
                                           self.m.settings.value("xmldir", HERE),
                                           "As-Built (*.xml *.bin);;All (*)")
        if not f:
            return
        self.m.settings.setValue("xmldir", os.path.dirname(f))
        try:
            if f.lower().endswith(".xml"):
                vin, ind, img = D.load_asbuilt_xml(f)
            else:
                img, vin = Path(f).read_bytes(), ""
        except Exception as e:      # noqa: BLE001
            QMessageBox.warning(self, APP, f"{f}: {e}")
            return
        self.m.log(f"loaded CCC {len(img)} bytes from {f}")
        self.set_image(img, vin, source=f)

    def _default_name(self, ext):
        """UCDS-style name, e.g. Asbuilt121126_WF0AXXWPMAEL32600_mod.xml;
        '_mod' when the image differs from what was read/loaded, '_2', '_3'…
        so an existing file is never offered for overwrite."""
        vin = re.sub(r"[^0-9A-Z]", "", self.img[11:28].decode("latin-1", "replace").upper())
        mod = "_mod" if self.orig is not None and self.img != self.orig else ""
        base = f"Asbuilt{time.strftime('%d%m%y')}" + (f"_{vin}" if vin else "") + mod
        d = self.m.settings.value("xmldir", HERE)
        return _unique(os.path.join(d, base + ext))

    def _saved(self, f):
        self.m.settings.setValue("xmldir", os.path.dirname(f))
        self.m.log(f"saved {f}")

    def save_xml(self):
        if self.img is None:
            return
        f, _ = QFileDialog.getSaveFileName(self, "Save UCDS As-Built XML",
                                           self._default_name(".xml"), "XML (*.xml)")
        if f:
            vin = self.img[11:28].decode("latin-1", "replace")
            D.save_asbuilt_xml(f, self.img, vin)
            self._saved(f)

    def save_bin(self):
        if self.img is None:
            return
        f, _ = QFileDialog.getSaveFileName(self, "Save CCC binary",
                                           self._default_name(".bin"), "Binary (*.bin)")
        if f:
            Path(f).write_bytes(self.img)
            self._saved(f)

    # -- module I/O ------------------------------------------------------------
    def _target(self):
        return self.m.target(self.src.currentData())

    def _resolve_addr(self, t, then):
        """then(addr, hw): address from the field or DID D12B, plus F111 (the
        erase length depends on it). Default-session DID reads only."""
        txt = self.addr.text().strip()
        fixed = None if txt.lower().startswith("auto") else parse_int(txt)

        def job(ctx):
            with B.Link(t, "d12b") as ln:
                ln.wake()
                hw = B.text(ln.read(0xF111)[0])
                if fixed is not None:
                    print(f"   CCC address 0x{fixed:08X} (manual); F111 {hw}")
                    return fixed, hw
                p, err = ln.read(0xD12B)
            if p is None or len(p) < 2:
                print(f"   D12B not readable ({err}); using 0x00008000")
                return 0x8000, hw
            a = int.from_bytes(p[:4], "big")
            print(f"   D12B -> CCC address 0x{a:08X}; F111 {hw}")
            return a, hw

        self.m.run_job(f"read CCC address (D12B) from {t.name}", job,
                       lambda r, e: then(*r) if r else None)

    def read_module(self, *_):
        """Read the CCC (SBL + 35 upload, one module reset). The file it is
        saved to is THE pre-write backup: Write does not read again."""
        t = self._target()
        os.makedirs(B.BACKUP_DIR, exist_ok=True)
        out = os.path.join(B.BACKUP_DIR,
                           f"CCC_{t.short}_{time.strftime('%Y%m%d-%H%M%S')}.bin")

        def go(addr, hw):
            if addr is None:
                return
            argv = ["memread", t.short, "--addr", hex(addr), "--length", "0x200",
                    "-o", out, "--yes", *self.m.cli_iface_args(t)]

            def fin(code):
                if code != 0 or not os.path.exists(out):
                    QMessageBox.warning(self, APP, "memread failed — see the log.")
                    return
                self.m.log(f"   CCC saved to {out} (backup for a later write)")
                self.set_image(Path(out).read_bytes(), source=out, from_txid=t.txid)
                self._addr, self._hw = addr, hw
            self.m.run_cli(argv, fin, title=f"read CCC from {t.name}")

        self._resolve_addr(t, go)

    def write_module(self, *_):
        """One confirmation, one memwrite (one SBL session, one reset). No
        backup read before and no read-back after: the backup is the file the
        image was read into / loaded from."""
        if self.img is None or self._source is None:
            QMessageBox.information(self, APP, "Read the CCC from the module or load a "
                                    "file first.")
            return
        probs = D.ccc_check(self.img)
        if probs:
            QMessageBox.warning(self, APP, "Refusing to write an inconsistent CCC:\n"
                                + "\n".join(probs))
            return
        t = self._target()
        if self._from_txid is not None and self._from_txid != t.txid:
            QMessageBox.warning(self, APP, f"This CCC was read from module 0x{self._from_txid:03X}"
                                f", but {t.name} is selected. Select the module it came from.")
            return
        new = self.img
        diff = [i for i in range(len(new)) if (self.orig or b"")[i:i + 1] != new[i:i + 1]]
        if not diff:
            QMessageBox.information(self, APP, "Nothing changed — nothing to write.")
            return

        def go(addr, hw):
            if addr is None:
                return
            self._addr, self._hw = addr, hw
            if not hw:
                QMessageBox.warning(self, APP, f"F111 of {t.name} is unknown, so the erase "
                                    "length cannot be chosen. Nothing written.")
                return
            elen = B.ccc_erase_len(t.profile, hw)
            detail = "\n".join(f"0x{i:03X}" + (f" F106[{i - D.F106_BASE}]" if i >= D.F106_BASE
                                               else "") + f": {self.orig[i]:02X} -> {new[i]:02X}"
                               for i in diff)
            src = ("read from the module" if self._from_txid is not None
                   else "loaded file (not a fresh module read)")
            if not self.m.confirm(
                    "Write Central Configuration",
                    f"Ready to write the CCC to {t.name}?\n\n"
                    f"{len(diff)} byte(s) changed (details below).\n"
                    f"Address 0x{addr:08X}, erase 0x{elen:X}. One SBL session, then one "
                    f"module reset. No read-back.\n\n"
                    f"Backup = {src}:\n{self._source}",
                    detail):
                self.m.log("CCC write cancelled")
                return
            fn = os.path.join(B.BACKUP_DIR,
                              f"CCC_{t.short}_{time.strftime('%Y%m%d-%H%M%S')}_new.bin")
            os.makedirs(B.BACKUP_DIR, exist_ok=True)
            Path(fn).write_bytes(new)
            argv = ["memwrite", t.short, "--addr", hex(addr), "-i", fn,
                    "--erase-len", hex(elen), "--hw", hw, "--yes", *self.m.cli_iface_args(t)]
            if self.no_verify.isChecked():
                argv.append("--no-verify")

            def written(code):
                if code != 0:
                    QMessageBox.warning(self, APP, "memwrite FAILED — see the log.\n"
                                        f"Backup: {self._source}")
                    return
                self.orig = new               # module now holds the written image
                self._source = fn
                self.refresh()
                self.m.log(f"CCC written to {t.name}; image saved as {fn}")
                QMessageBox.information(self, APP, "CCC written.")

            self.m.run_cli(argv, written, title=f"write CCC to {t.name}")

        if self._addr is not None and self._from_txid == t.txid:
            go(self._addr, self._hw)          # known from the read: no bus access yet
        else:
            self._resolve_addr(t, go)         # loaded file: D12B/F111 read, no reset


# ==========================================================================
# DIDs tab (raw read / write / poll)
# ==========================================================================
class DidTab(QWidget):
    def __init__(self, m: Main):
        super().__init__()
        self.m = m
        lay = QVBoxLayout(self)
        f = QGridLayout()
        self.dids = QLineEdit(self.m.settings.value("dids", "F188 F111 F113 F190"))
        f.addWidget(QLabel("DIDs"), 0, 0)
        f.addWidget(self.dids, 0, 1, 1, 5)
        f.addWidget(QLabel("session"), 1, 0)
        self.sess = QComboBox()
        self.sess.addItems(["none", "01", "03", "02", "60", "40"])
        f.addWidget(self.sess, 1, 1)
        f.addWidget(QLabel("unlock"), 1, 2)
        self.lvl = QComboBox()
        self.lvl.addItems(["none", "27 01", "27 03", "27 05", "27 11"])
        f.addWidget(self.lvl, 1, 3)
        self.secret = QLineEdit()
        self.secret.setPlaceholderText("secret 0x… (blank = ecu_db by F111)")
        f.addWidget(self.secret, 1, 4, 1, 2)
        f.addWidget(QLabel("write data"), 2, 0)
        self.wdata = QLineEdit()
        self.wdata.setPlaceholderText("hex for the FIRST DID listed")
        f.addWidget(self.wdata, 2, 1, 1, 3)
        f.addWidget(QLabel("poll every s"), 3, 0)
        self.poll = QDoubleSpinBox()
        self.poll.setRange(0.0, 3600)
        self.poll.setValue(1.0)
        f.addWidget(self.poll, 3, 1)
        self.changes = QCheckBox("changes only")
        self.changes.setChecked(True)
        f.addWidget(self.changes, 3, 2)
        self.until = QLineEdit()
        self.until.setPlaceholderText("stop when first DID starts with hex…")
        f.addWidget(self.until, 3, 3, 1, 2)
        lay.addLayout(f)
        row = QHBoxLayout()
        for text, fn in (("Read", self.read), ("Write", self.write), ("Poll", self.start_poll),
                         ("Stop poll", lambda: self.m.worker.cancel.set()),
                         ("Clear", lambda: self.tbl.setRowCount(0))):
            b = QPushButton(text)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch()
        lay.addLayout(row)
        self.tbl = QTableWidget(0, 6)
        self.tbl.setHorizontalHeaderLabels(["time", "DID", "name (current definition)", "len",
                                            "hex", "ascii / decoded"])
        self.tbl.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl.setFont(MONO)
        lay.addWidget(self.tbl, 1)

    def module_changed(self):
        pass

    def _dids(self):
        out = []
        for tok in self.dids.text().replace(",", " ").split():
            d = vf._norm_did(tok)
            if d is None:
                raise ValueError(f"{tok}: not a 2-byte DID")
            out.append(int(d, 16))
        self.m.settings.setValue("dids", self.dids.text())
        return out

    def _prep(self, ln):
        s = self.sess.currentText()
        if s != "none":
            ln.session(int(s, 16))
        if self.lvl.currentText() != "none":
            sec = self.secret.text().strip()
            ln.unlock(int(self.lvl.currentText().split()[1], 16),
                      int(sec, 16).to_bytes(5, "big") if sec else None,
                      settle=s != "none")

    def _name(self, did):
        dd = self.m.direct_tab.dids.get(did)
        return dd.name if dd else ""

    def _add(self, o):
        did, p, err = o
        r = self.tbl.rowCount()
        self.tbl.insertRow(r)
        dd = self.m.direct_tab.dids.get(did)
        dec = ""
        if p is not None:
            dec = "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in p)
            if dd and len(dd.fields) == 1 and dd.fields[0].fits(len(p)):
                dec = dd.fields[0].display(p)
        vals = [time.strftime("%H:%M:%S"), f"{did:04X}", self._name(did),
                str(len(p)) if p is not None else "", hx(p) if p is not None else err, dec]
        for c, v in enumerate(vals):
            it = QTableWidgetItem(v)
            if p is None and c == 4:
                it.setForeground(BAD)
            self.tbl.setItem(r, c, it)
        self.tbl.scrollToBottom()

    def read(self):
        try:
            dids, t = self._dids(), self.m.target()
        except (ValueError, B.OpError) as e:
            QMessageBox.warning(self, APP, str(e))
            return

        def job(ctx):
            with B.Link(t, "readdid") as ln:
                ln.wake()
                self._prep(ln)
                for d in dids:
                    p, err = ln.read(d)
                    ctx.post((d, p, err))

        self.m.run_job(f"read DIDs on {t.name}", job, on_post=self._add)

    def write(self):
        try:
            dids, t = self._dids(), self.m.target()
            data = parse_hex(self.wdata.text())
        except (ValueError, B.OpError) as e:
            QMessageBox.warning(self, APP, str(e))
            return
        if not dids or not data:
            return
        d = dids[0]
        if not self.m.confirm("Write DID", f"Write {len(data)} byte(s) to DID {d:04X} on "
                              f"{t.name}?\n\n{hx(data)}"):
            return

        def job(ctx):
            with B.Link(t, "writedid") as ln:
                ln.wake()
                p, err = ln.read(d)
                print(f"   before: {hx(p) if p is not None else err}")
                self._prep(ln)
                ok, resp = ln.write(d, data)
                print(f"   2E {d:04X}: {'OK' if ok else 'FAIL'} {resp}")
                p, err = ln.read(d)
                ctx.post((d, p, err))
                print("   verified: read-back matches" if p == data else
                      "   !! read-back does NOT match")

        self.m.run_job(f"write DID {d:04X} on {t.name}", job, on_post=self._add)

    def start_poll(self):
        try:
            dids, t = self._dids(), self.m.target()
            until = parse_hex(self.until.text()) if self.until.text().strip() else None
        except (ValueError, B.OpError) as e:
            QMessageBox.warning(self, APP, str(e))
            return
        interval = self.poll.value()
        changes = self.changes.isChecked()
        keep = self.sess.currentText() != "none" or self.lvl.currentText() != "none"

        def job(ctx):
            last = {}
            with B.Link(t, "poll") as ln:
                ln.wake()
                self._prep(ln)
                if keep:
                    ln.start_keepalive()
                while not ctx.cancel.is_set():
                    first = None
                    for i, d in enumerate(dids):
                        p, err = ln.read(d)
                        if err and keep and any(x in err for x in ("33", "7E", "7F")) \
                                and p is None:
                            print(f"   {d:04X} {err} -> re-entering session/security")
                            ln.stop_keepalive()
                            self._prep(ln)
                            ln.start_keepalive()
                            p, err = ln.read(d)
                        if i == 0:
                            first = p
                        val = hx(p) if p is not None else err
                        if not changes or last.get(d) != val:
                            ctx.post((d, p, err))
                        last[d] = val
                    if until is not None and first is not None and first.startswith(until):
                        print(f"   {dids[0]:04X} reached {hx(until)} — stopping")
                        break
                    ctx.cancel.wait(interval)
            print("   poll stopped")

        self.m.run_job(f"poll DIDs on {t.name}", job, on_post=self._add)


# ==========================================================================
# DTC tab
# ==========================================================================
class DtcTab(QWidget):
    def __init__(self, m: Main):
        super().__init__()
        self.m = m
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        self.all = QCheckBox("include 'not completed'")
        self.mask = QLineEdit("0xFF")
        self.mask.setMaximumWidth(70)
        for text, fn in (("Read DTCs (current module)", self.read),
                         ("Scan all modules (counts)", self.scan),
                         ("Clear DTCs (current module)", self.clear),
                         ("Clear ALL (7DF broadcast)", self.clear_all)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addWidget(self.all)
        row.addWidget(QLabel("status mask"))
        row.addWidget(self.mask)
        row.addStretch()
        lay.addLayout(row)
        self.tbl = QTableWidget(0, 6)
        self.tbl.setHorizontalHeaderLabels(["Module", "DTC", "raw", "status", "flags",
                                            "description"])
        self.tbl.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        lay.addWidget(self.tbl, 1)

    def module_changed(self):
        pass

    def _rows(self, rows):
        self.tbl.setRowCount(0)
        for r in rows:
            k = self.tbl.rowCount()
            self.tbl.insertRow(k)
            for c, v in enumerate(r):
                self.tbl.setItem(k, c, QTableWidgetItem(str(v)))
        self.tbl.resizeColumnsToContents()

    def read(self):
        try:
            t = self.m.target()
            mask = parse_int(self.mask.text(), 0xFF)
        except (B.OpError, ValueError) as e:
            QMessageBox.warning(self, APP, str(e))
            return
        show_all = self.all.isChecked()

        def job(ctx):
            with B.Link(t, "dtc") as ln:
                ln.wake()
                dtcs, avail = ln.read_dtcs(mask)
            if dtcs is None:
                raise B.OpError("no valid 19 02 response (module silent or refused)")
            print(f"   {len(dtcs)} DTC(s), availability mask 0x{avail:02X}")
            return dtcs

        def done(dtcs, err):
            if dtcs is None:
                return
            rows = []
            for dtc, st in dtcs:
                if not show_all and not dtc_is_actual(st):
                    continue
                rows.append([t.short, dtc_code(dtc), f"{dtc:06X}", f"0x{st:02X}",
                             dtc_status_str(st), self.m.defs.dtc_text(t.txid, dtc) or ""])
            self._rows(rows)
            hidden = len(dtcs) - len(rows)
            self.m.log(f"   {len(rows)} shown" + (f", {hidden} not-completed hidden"
                                                  if hidden else ""))

        self.m.run_job(f"read DTCs on {t.name}", job, done)

    def scan(self):
        targets = [self.m.target(tx) for tx in sorted(ecu_db.ECUS)]
        mask = parse_int(self.mask.text(), 0xFF)

        def job(ctx):
            out = []
            for t in targets:
                if ctx.cancel.is_set():
                    break
                try:
                    with B.Link(t, "dtcscan") as ln:
                        if ln.wake(tries=2, timeout=0.3) is None:
                            out.append((t, None))
                            continue
                        dtcs, _ = ln.read_dtcs(mask)
                    out.append((t, dtcs))
                    n = sum(1 for _, s in dtcs or [] if dtc_is_actual(s))
                    print(f"   {t.name:34s} {'-' if dtcs is None else n} actual "
                          f"/ {'-' if dtcs is None else len(dtcs)} total")
                except B.OpError as e:
                    print(f"   {t.name}: {e}")
            return out

        def done(out, err):
            if not out:
                return
            rows = []
            for t, dtcs in out:
                for dtc, st in dtcs or []:
                    if self.all.isChecked() or dtc_is_actual(st):
                        rows.append([t.short, dtc_code(dtc), f"{dtc:06X}", f"0x{st:02X}",
                                     dtc_status_str(st),
                                     self.m.defs.dtc_text(t.txid, dtc) or ""])
            self._rows(rows)

        self.m.run_job("scan DTCs on all modules", job, done)

    def clear(self):
        try:
            t = self.m.target()
        except B.OpError as e:
            QMessageBox.warning(self, APP, str(e))
            return
        if not self.m.confirm("Clear DTCs", f"Clear all DTCs on {t.name}?"):
            return

        def job(ctx):
            with B.Link(t, "cleardtc") as ln:
                ln.wake()
                ok = ln.clear_dtcs()
            print("   14 clearDiagnosticInformation:", "OK (54)" if ok else "FAILED")

        self.m.run_job(f"clear DTCs on {t.name}", job, lambda r, e: self.read())

    def clear_all(self):
        ifs, skipped = B.usable_ifaces(sorted({self.m.target(tx).iface for tx in ecu_db.ECUS}))
        if not ifs:
            QMessageBox.warning(self, APP, f"No usable interface ({', '.join(skipped)} "
                                           "absent or DOWN).")
            return
        note = f"\n(skipping {', '.join(skipped)}: absent or DOWN)" if skipped else ""
        if not self.m.confirm("Clear ALL DTCs", "Broadcast 14 FFFFFF on 0x7DF to every "
                              f"module on {', '.join(ifs)}? (unconfirmed, fire-and-forget)"
                              + note):
            return

        def job(ctx):
            for i in ifs:
                vf.functional_broadcast(i, [[0x14, 0xFF, 0xFF, 0xFF]], can_id=0x7DF, repeat=5)
                print(f"   {i}: sent 7DF 04 14 FF FF FF x5 [unconfirmed]")

        self.m.run_job("clear DTCs on ALL", job)


# ==========================================================================
# Service tab: reset, routine, silence, memory, brute-force, self-test
# ==========================================================================
class ServiceTab(QWidget):
    def __init__(self, m: Main):
        super().__init__()
        self.m = m
        lay = QVBoxLayout(self)

        g = QGroupBox("ECU reset")
        h = QHBoxLayout(g)
        self.rmode = QComboBox()
        self.rmode.addItems(["01 hardReset", "03 softReset", "02 keyOffOnReset"])
        h.addWidget(self.rmode)
        for text, fn in (("Reset current module", self.reset),
                         ("Reset ALL (7DF broadcast)", self.reset_all)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            h.addWidget(b)
        h.addStretch()
        lay.addWidget(g)

        g = QGroupBox("RoutineControl (31) — runs `vbflasher routine` on the current module")
        f = QGridLayout(g)
        self.rids = QLineEdit()
        self.rids.setPlaceholderText("routine ids in order, e.g. 0E08 0E06")
        self.rsub = QLineEdit("0x01")
        self.rdata = QLineEdit()
        self.rdata.setPlaceholderText("option data hex")
        self.rwait = QDoubleSpinBox()
        self.rwait.setRange(0, 600)
        self.rwait.setValue(15)
        self.rsess = QComboBox()
        self.rsess.addItems(["none", "0x03", "0x02", "0x60"])
        self.rlvl = QComboBox()
        self.rlvl.addItems(["none", "1", "3", "5", "0x11"])
        for i, (lab, w) in enumerate((("RIDs", self.rids), ("sub", self.rsub),
                                      ("data", self.rdata), ("wait s", self.rwait),
                                      ("session", self.rsess), ("sec level", self.rlvl))):
            f.addWidget(QLabel(lab), i // 3, (i % 3) * 2)
            f.addWidget(w, i // 3, (i % 3) * 2 + 1)
        b = QPushButton("Run routine(s)")
        b.clicked.connect(self.routine)
        f.addWidget(b, 2, 0, 1, 2)
        lay.addWidget(g)

        g = QGroupBox("Silence (hold in programmingSession; Stop = Ctrl-C restores)")
        h = QHBoxLayout(g)
        self.sdur = QDoubleSpinBox()
        self.sdur.setRange(0, 86400)
        self.sdur.setSpecialValueText("until Stop")
        h.addWidget(QLabel("duration s"))
        h.addWidget(self.sdur)
        for text, fn in (("Silence current module", lambda: self.silence(False)),
                         ("Silence ALL", lambda: self.silence(True))):
            b = QPushButton(text)
            b.clicked.connect(fn)
            h.addWidget(b)
        h.addStretch()
        lay.addWidget(g)

        g = QGroupBox("Memory (SBL + 35 RequestUpload / 34 download) — current module")
        f = QGridLayout(g)
        self.maddr = QLineEdit("0x00008000")
        self.mlen = QLineEdit("0x200")
        self.mfile = QLineEdit()
        mb = QPushButton("…")
        mb.clicked.connect(self._mfile)
        self.merase = QLineEdit()
        self.merase.setPlaceholderText("erase len (sector), blank = data length")
        self.mnoverify = QCheckBox("--no-verify")
        self.mnoerase = QCheckBox("--no-erase")
        self.mnoreset = QCheckBox("--no-reset (read)")
        self.mquiet = QCheckBox("--quiet-bus")
        for i, (lab, w) in enumerate((("addr", self.maddr), ("length", self.mlen),
                                      ("erase len", self.merase))):
            f.addWidget(QLabel(lab), 0, i * 2)
            f.addWidget(w, 0, i * 2 + 1)
        f.addWidget(QLabel("file"), 1, 0)
        f.addWidget(self.mfile, 1, 1, 1, 4)
        f.addWidget(mb, 1, 5)
        hh = QHBoxLayout()
        for w in (self.mnoverify, self.mnoerase, self.mnoreset, self.mquiet):
            hh.addWidget(w)
        f.addLayout(hh, 2, 0, 1, 6)
        b1 = QPushButton("memread → file")
        b1.clicked.connect(self.memread)
        b2 = QPushButton("memwrite ← file")
        b2.clicked.connect(self.memwrite)
        b3 = QPushButton("Test SBL only (flash --test-sbl)")
        b3.clicked.connect(self.test_sbl)
        f.addWidget(b1, 3, 0, 1, 2)
        f.addWidget(b2, 3, 2, 1, 2)
        f.addWidget(b3, 3, 4, 1, 2)
        lay.addWidget(g)

        g = QGroupBox("Find an unknown SecurityAccess secret (ford_brutekey.py)")
        h = QHBoxLayout(g)
        self.blevel = QComboBox()
        self.blevel.addItems(["1", "3", "5", "0x11"])
        self.bonly = QLineEdit()
        self.bonly.setPlaceholderText("--only SECRET (test one)")
        self.bnoext = QCheckBox("--no-ext")
        h.addWidget(QLabel("level"))
        h.addWidget(self.blevel)
        h.addWidget(self.bonly)
        h.addWidget(self.bnoext)
        for text, dry in (("Plan (dry run)", True), ("Run on current module", False)):
            b = QPushButton(text)
            b.clicked.connect(lambda _=False, d=dry: self.brute(d))
            h.addWidget(b)
        h.addStretch()
        lay.addWidget(g)

        h = QHBoxLayout()
        for text, fn in (("Run CLI self-test", lambda: self.m.run_cli(["--selftest"],
                                                                      title="selftest")),
                         ("List registered ECUs", lambda: self.m.run_cli(["list"],
                                                                         title="list"))):
            b = QPushButton(text)
            b.clicked.connect(fn)
            h.addWidget(b)
        h.addStretch()
        lay.addLayout(h)
        lay.addStretch()

    def _t(self):
        try:
            return self.m.target()
        except B.OpError as e:
            QMessageBox.warning(self, APP, str(e))
            return None

    def reset(self):
        t = self._t()
        if not t:
            return
        mode = int(self.rmode.currentText().split()[0], 16)
        if not self.m.confirm("Reset", f"11 {mode:02X} ECUReset {t.name}?"):
            return

        def job(ctx):
            with B.Link(t, "reset") as ln:
                ln.wake()
                ok = ln.reset(mode)
            print(f"   11 {mode:02X} ECUReset:", "OK (51)" if ok else "FAILED / no reply")

        self.m.run_job(f"reset {t.name}", job)

    def reset_all(self):
        mode = int(self.rmode.currentText().split()[0], 16)
        ifs, skipped = B.usable_ifaces(sorted({self.m.target(tx).iface for tx in ecu_db.ECUS}))
        if not ifs:
            QMessageBox.warning(self, APP, f"No usable interface ({', '.join(skipped)} "
                                           "absent or DOWN).")
            return
        note = f"\n(skipping {', '.join(skipped)}: absent or DOWN)" if skipped else ""
        if not self.m.confirm("Reset ALL", f"Broadcast 11 {mode | 0x80:02X} to EVERY module on "
                              f"{', '.join(ifs)}? Vehicle stationary, engine off." + note):
            return

        def job(ctx):
            for i in ifs:
                vf.functional_broadcast(i, [[0x11, mode | 0x80]], can_id=0x7DF, repeat=5)
                print(f"   {i}: sent 7DF 02 11 {mode | 0x80:02X} x5 [unconfirmed]")

        self.m.run_job("reset ALL", job)

    def routine(self):
        t = self._t()
        if not t or not self.rids.text().strip():
            return
        a = ["routine", t.short, *self.rids.text().split(), "--sub", self.rsub.text(),
             "--wait", str(self.rwait.value()), "--yes", *self.m.cli_iface_args(t)]
        if self.rdata.text().strip():
            a += ["--data", self.rdata.text().strip()]
        if self.rsess.currentText() != "none":
            a += ["--session", self.rsess.currentText()]
        if self.rlvl.currentText() != "none":
            a += ["--sec-level", self.rlvl.currentText()]
        if self.m.confirm("Routine", f"Run {self.rids.text()} on {t.name}?", " ".join(a)):
            self.m.run_cli(a, title="routine")

    def silence(self, all_):
        t = self._t()
        if not t:
            return
        a = ["silence", "ALL" if all_ else t.short]
        if not all_ or self.m.iface_override():
            a += self.m.cli_iface_args(t) if not all_ else ["--iface", self.m.iface_override()]
        if self.sdur.value() > 0:
            a += ["--duration", str(self.sdur.value())]
        self.m.run_cli(a, title="silence (press Stop to end)")

    def _mfile(self):
        f, _ = QFileDialog.getSaveFileName(self, "binary file", self.mfile.text() or HERE,
                                           options=QFileDialog.Option.DontConfirmOverwrite)
        if f:
            self.mfile.setText(f)

    def _mem_common(self, t):
        a = ["--addr", self.maddr.text().strip(), "--yes", *self.m.cli_iface_args(t)]
        if self.mquiet.isChecked():
            a.append("--quiet-bus")
        return a

    def memread(self):
        t = self._t()
        if not t or not self.mfile.text().strip():
            QMessageBox.information(self, APP, "choose an output file")
            return
        a = ["memread", t.short, "--length", self.mlen.text().strip(), "-o",
             self.mfile.text().strip(), *self._mem_common(t)]
        if self.mnoreset.isChecked():
            a.append("--no-reset")
        if self.m.confirm("memread", f"Load the SBL into {t.name} and read "
                          f"{self.mlen.text()} bytes at {self.maddr.text()}?", " ".join(a)):
            self.m.run_cli(a, title="memread")

    def memwrite(self):
        t = self._t()
        fn = self.mfile.text().strip()
        if not t or not os.path.exists(fn):
            QMessageBox.information(self, APP, "choose an existing input file")
            return
        a = ["memwrite", t.short, "-i", fn, *self._mem_common(t)]
        if self.merase.text().strip():
            a += ["--erase-len", self.merase.text().strip()]
        if self.mnoverify.isChecked():
            a.append("--no-verify")
        if self.mnoerase.isChecked():
            a.append("--no-erase")
        if self.m.confirm("memwrite", f"WRITE {os.path.getsize(fn)} bytes from {fn} to "
                          f"{t.name} at {self.maddr.text()}?\nThis is irreversible — "
                          "have a memread backup.", " ".join(a)):
            self.m.run_cli(a, title="memwrite")

    def test_sbl(self):
        t = self._t()
        if t and self.m.confirm("Test SBL", f"Enter programming session on {t.name}, "
                                "load and start its SBL (no erase/write), then reset?"):
            self.m.run_cli(["flash", t.short, "--test-sbl", "--yes",
                            *self.m.cli_iface_args(t)], title="test SBL")

    def brute(self, dry):
        t = self._t()
        if not t:
            return
        a = ["@raw", sys.executable, "-u", os.path.join(HERE, "ford_brutekey.py"), t.short,
             "--iface", t.iface, "--level", self.blevel.currentText()]
        if self.bonly.text().strip():
            a += ["--only", self.bonly.text().strip()]
        if self.bnoext.isChecked():
            a.append("--no-ext")
        a.append("--dry-run" if dry else "--yes")
        if dry or self.m.confirm("Brute-force secret", f"Try candidate secrets on {t.name}? "
                                 "Each wrong key costs a lockout delay."):
            self.m.run_cli(a, title="brutekey")


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP)
    w = Main()
    w.install_signal_handlers()
    w.show()
    rc = app.exec()
    signal.set_wakeup_fd(-1)
    sys.exit(rc)


if __name__ == "__main__":
    main()
