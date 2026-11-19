from collections import deque
from importlib.resources import files
import json
from pathlib import Path
import platform
import shutil
from threading import Event

import psutil
import pyqtgraph as pg
from pydantic import TypeAdapter, ValidationError
from PySide6.QtCore import QLockFile, QObject, QRunnable, QThreadPool, QTimer, Qt, Signal
from PySide6.QtGui import QIcon, QTextDocument
from PySide6.QtPrintSupport import QPrintDialog, QPrinter
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import __version__, backup, engines, intelligence, platforms, reporting
from .ai_panel import AiPanel
from .database import Database, InspectorError, json_text
from .models import (
    Asset,
    Authorization,
    Code,
    COMMON_MODULES,
    MobileCheck,
    Module,
    Note,
    PLATFORM_MODULES,
    Platform,
    Product,
)
from .posture import evaluate
from .workflow import Selection, api_health, run

MODULE_NAMES = {
    Module.WINDOWS: "Konfigurasi Windows",
    Module.SOFTWARE: "Inventaris dan patch Windows",
    Module.ANDROID: "Checklist Android",
    Module.IOS: "Checklist iOS",
    Module.FILES: "Signatur, arsip, dan hash file",
    Module.APK: "Analisis statis APK",
    Module.MALWARE: "Engine malware/YARA",
    Module.VULNERABILITY: "Korelasi kerentanan",
    Module.INTELLIGENCE: "Pencarian intelijen lokal",
}
STATUS = {
    "pass": "Memenuhi",
    "fail": "Tidak memenuhi",
    "unknown": "Belum tersedia",
    "not_applicable": "Tidak berlaku",
}
PAGES = [
    "Dashboard",
    "Aset institusi",
    "Monitor USB",
    "Ruang kerja",
    "Katalog intelijen",
    "Aturan YARA",
    "Sistem",
    "AI Assistant",
]
METRICS = {
    "assets": "Aset terdaftar",
    "running": "Pemeriksaan aktif",
    "complete": "Pemeriksaan selesai",
    "findings": "Temuan terbuka",
    "critical": "CVE kritis",
    "malware": "Indikator malware",
}
DARK = dict(
    base="#0B1220",
    nav="#0F172A",
    card="#162235",
    ink="#F8FAFC",
    muted="#A9B8CE",
    line="#2C4260",
    gold="#D4AF37",
)
LIGHT = dict(
    base="#F0F4FA",
    nav="#DEE7F5",
    card="#FFFFFF",
    ink="#14243C",
    muted="#485A75",
    line="#C3D2E6",
    gold="#805E0A",
)


def table(headers):
    widget = QTableWidget(0, len(headers))
    widget.setHorizontalHeaderLabels(headers)
    widget.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    widget.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    widget.verticalHeader().hide()
    widget.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    widget.horizontalHeader().setStretchLastSection(True)
    widget.setAlternatingRowColors(True)
    return widget


def fill(widget, values):
    widget.setRowCount(0)
    widget.setRowCount(len(values))
    for row, entries in enumerate(values):
        for column, value in enumerate(entries):
            item = QTableWidgetItem("" if value is None else str(value))
            widget.setItem(row, column, item)
    widget.resizeColumnsToContents()
    for column in range(widget.columnCount()):
        widget.setColumnWidth(column, min(300, max(88, widget.columnWidth(column))))


def plain():
    block = QPlainTextEdit()
    block.setReadOnly(True)
    block.setMinimumHeight(95)
    return block


def combo(items):
    widget = QComboBox()
    for key, value in items.items():
        widget.addItem(value, key)
    return widget


class WorkerSignals(QObject):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(str, int, int, str)
    ended = Signal()


class Worker(QRunnable):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback
        self.signals = WorkerSignals()

    def run(self):
        try:
            result = self.callback(self.signals.progress.emit)
        except InspectorError as error:
            self.signals.failed.emit(str(error))
        except Exception:
            self.signals.failed.emit(
                "Pekerjaan tidak selesai. Periksa konfigurasi, data, dan ruang penyimpanan."
            )
        else:
            self.signals.finished.emit(result)
        finally:
            self.signals.ended.emit()


class FileList(QListWidget):
    accepted = Signal(list)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setMaximumHeight(90)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    dragMoveEvent = dragEnterEvent

    def dropEvent(self, event):
        self.accepted.emit([url.toLocalFile() for url in event.mimeData().urls() if url.isLocalFile()])
        event.acceptProposedAction()


class InspectorWindow(QMainWindow):
    def __init__(self, db: Database):
        super().__init__()
        self.db = db
        self.setWindowTitle("PUSKESAU SENTINEL · Device Inspector")
        icon = files("sentinel_inspector").joinpath("sentinel.ico")
        if icon.is_file():
            self.setWindowIcon(QIcon(str(icon)))
        self.resize(1280, 820)
        self.setMinimumSize(780, 560)
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(3)
        self.workers = set()
        self.scan_cancel = Event()
        self.usb_cancel = Event()
        self.active_scan = False
        self.usb_worker = False
        self.monitor = platforms.UsbMonitor(db)
        self.selected_files: tuple[Path, ...] = ()
        self.theme = DARK
        self.last_health = "Belum diuji"
        self.session_id = None
        self.session_data = None

        root = QWidget()
        self.setCentralWidget(root)
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        rail = QWidget(objectName="Rail")
        rail.setFixedWidth(198)
        sidebar = QVBoxLayout(rail)
        ident = QLabel("PUSKESAU\nSENTINEL", objectName="Brand")
        sidebar.addWidget(ident)
        sidebar.addWidget(QLabel("DEVICE INSPECTOR", objectName="Division"))
        menu = QListWidget()
        menu.addItems(PAGES)
        sidebar.addWidget(menu, 1)
        sidebar.addWidget(QLabel(f"Advanced Endpoint Security\nVersi {__version__}", objectName="Muted"))
        layout.addWidget(rail)
        self.pages = QStackedWidget()
        layout.addWidget(self.pages, 1)
        for builder in (
            self.dashboard,
            self.assets_page,
            self.usb_page,
            self.workspace,
            self.intel_page,
            self.yara_page,
            self.system_page,
        ):
            widget = QWidget()
            pane = QVBoxLayout(widget)
            pane.setContentsMargins(20, 18, 20, 18)
            pane.setSpacing(10)
            builder(pane)
            self.pages.addWidget(widget)
        self.ai_panel = AiPanel(self)
        self.pages.addWidget(self.ai_panel)
        menu.currentRowChanged.connect(self.pages.setCurrentIndex)
        menu.setCurrentRow(0)
        self.statusBar().showMessage("Siap")
        self.usb_timer = QTimer(self)
        self.usb_timer.setInterval(8000)
        self.usb_timer.timeout.connect(self.poll_usb)
        self.system_timer = QTimer(self)
        self.system_timer.setInterval(2000)
        self.system_timer.timeout.connect(self.tick_system)
        self.system_timer.start()
        self.apply_theme()
        self.refresh()

    def setup_page(self, layout, title, subtitle=None):
        layout.addWidget(QLabel(title, objectName="Title"))
        if subtitle:
            label = QLabel(subtitle, objectName="Muted")
            label.setWordWrap(True)
            layout.addWidget(label)

    def button(self, label, action):
        widget = QPushButton(label)
        widget.clicked.connect(lambda _checked=False: self.safe(action))
        return widget

    def safe(self, callback):
        try:
            callback()
        except (InspectorError, OSError, ValidationError) as error:
            self.failure(
                str(error)
                if isinstance(error, InspectorError)
                else "Input tidak valid atau lokasi file tidak dapat diakses."
            )

    def failure(self, message):
        self.statusBar().showMessage(message, 10000)
        QMessageBox.warning(self, "Pemeriksaan Sentinel", message)

    def background(self, action, success=lambda _result: None, end=lambda: None, failed=None, progress=None):
        worker = Worker(action)
        self.workers.add(worker)
        worker.signals.finished.connect(success, Qt.ConnectionType.QueuedConnection)
        worker.signals.failed.connect(failed or self.failure, Qt.ConnectionType.QueuedConnection)
        if progress:
            worker.signals.progress.connect(progress, Qt.ConnectionType.QueuedConnection)

        def completed():
            self.workers.discard(worker)
            end()

        worker.signals.ended.connect(completed, Qt.ConnectionType.QueuedConnection)
        self.pool.start(worker)

    def apply_theme(self):
        t = self.theme
        self.setStyleSheet(f"""
            QMainWindow,QWidget {{ background:{t["base"]};color:{t["ink"]};font-size:13px; }}
            QWidget#Rail {{ background:{t["nav"]};border-right:1px solid {t["line"]}; }}
            QLabel#Brand {{ color:{t["gold"]};font-size:24px;font-weight:800;padding:6px 4px; }}
            QLabel#Division,QLabel#Muted {{color:{t["muted"]};font-size:12px;padding:2px 4px;}}
            QLabel#Title {{ font-size:24px;font-weight:700; }}
            QLabel#Value {{font-size:24px;font-weight:700;color:{t["gold"]};}}
            QGroupBox {{ background:{t["card"]};border:1px solid {t["line"]};border-radius:8px;margin-top:12px;padding:10px; }}
            QGroupBox::title {{ subcontrol-origin:margin;left:10px;padding:0 5px; }}
            QListWidget,QLineEdit,QComboBox,QPlainTextEdit,QTableWidget {{ background:{t["card"]};color:{t["ink"]};
                border:1px solid {t["line"]};border-radius:5px;selection-background-color:#2459B5;selection-color:white; }}
            QListWidget::item {{ padding:8px; }}
            QHeaderView::section {{ background:{t["nav"]};color:{t["muted"]};border:1px solid {t["line"]};padding:5px; }}
            QTabBar::tab {{ background:{t["card"]};padding:8px;border:1px solid {t["line"]}; }}
            QTabBar::tab:selected {{ border-bottom:2px solid {t["gold"]}; }}
            QPushButton {{ background:#234D84;color:white;border:1px solid #4776AE;border-radius:6px;padding:6px 11px; }}
            QPushButton:hover {{ background:#2A62A8; }}
            QPushButton:disabled {{ background:{t["card"]};color:{t["muted"]};border-color:{t["line"]}; }}
            QProgressBar {{border:1px solid {t["line"]};border-radius:6px;text-align:center;}}
            QProgressBar::chunk {{background:#2563EB;border-radius:5px;}}
            QTableWidget {{alternate-background-color:{t["nav"]};}}
        """)
        self.chart.setBackground(t["card"])

    def dashboard(self, layout):
        self.setup_page(layout, "Ringkasan keamanan", "Aset dan bukti yang tersimpan pada workstation ini.")
        grid = QGridLayout()
        self.cards = {}
        for i, (key, label) in enumerate(METRICS.items()):
            panel = QGroupBox(label)
            contents = QVBoxLayout(panel)
            self.cards[key] = QLabel("0", objectName="Value")
            contents.addWidget(self.cards[key])
            grid.addWidget(panel, i // 3, i % 3)
        layout.addLayout(grid)
        self.health = QLabel(wordWrap=True)
        layout.addWidget(self.health)
        self.chart = pg.PlotWidget()
        self.chart.addLegend()
        self.chart.setYRange(0, 100, padding=0)
        self.chart.setLabel("left", "Pemakaian", units="%")
        self.chart.setLabel("bottom", "Sampel")
        self.chart.showGrid(x=False, y=True, alpha=0.18)
        self.cpu = deque(maxlen=60)
        self.ram = deque(maxlen=60)
        self.cpu_plot = self.chart.plot(pen=pg.mkPen("#5694FF", width=2), name="CPU")
        self.ram_plot = self.chart.plot(pen=pg.mkPen("#D4AF37", width=2), name="RAM")
        layout.addWidget(self.chart, 1)

    def assets_page(self, layout):
        self.setup_page(
            layout,
            "Inventaris aset",
            "Daftarkan perangkat institusi dengan kode inventaris. Gunakan kode petugas pada pemeriksaan.",
        )
        form = QFormLayout()
        self.asset_code = QLineEdit()
        self.asset_name = QLineEdit()
        self.asset_unit = QLineEdit()
        self.asset_type = combo(
            {
                "windows": "Windows",
                "android": "Android",
                "ios": "iOS/iPadOS",
                "usb": "USB penyimpanan",
                "other": "Lainnya",
            }
        )
        for label, widget in (
            ("Kode inventaris", self.asset_code),
            ("Nama aset", self.asset_name),
            ("Unit institusi", self.asset_unit),
            ("Kategori", self.asset_type),
        ):
            form.addRow(label, widget)
        layout.addLayout(form)
        layout.addWidget(self.button("Daftarkan aset", self.add_asset), alignment=Qt.AlignmentFlag.AlignLeft)
        self.assets = table(["Kode", "Nama", "Kategori", "Unit"])
        layout.addWidget(self.assets, 1)

    def add_asset(self):
        self.db.add_asset(
            Asset(
                code=self.asset_code.text(),
                name=self.asset_name.text(),
                unit=self.asset_unit.text(),
                platform=self.asset_type.currentData(),
            )
        )
        for field in (self.asset_code, self.asset_name, self.asset_unit):
            field.clear()
        self.refresh()
        self.statusBar().showMessage("Aset didaftarkan.", 5000)

    def usb_page(self, layout):
        self.setup_page(
            layout,
            "Monitor koneksi USB",
            "Mulai pemantauan perangkat yang terlihat oleh Windows. Pencatatan terbatas pada kategori, model, dan status driver.",
        )
        bar = QHBoxLayout()
        for text, fn in (
            ("Mulai monitor", self.start_usb),
            ("Hentikan", self.stop_usb),
            ("Segarkan sekali", self.poll_usb),
        ):
            bar.addWidget(self.button(text, fn))
        bar.addStretch()
        layout.addLayout(bar)
        self.usb_state = QLabel("Monitor tidak aktif.")
        layout.addWidget(self.usb_state)
        self.usb_current = table(["Kategori", "Produsen", "Model", "Driver", "Status"])
        self.usb_history = table(["Waktu UTC", "Peristiwa", "Kategori", "Produsen", "Model", "Driver"])
        layout.addWidget(self.usb_current, 1)
        layout.addWidget(QLabel("Riwayat koneksi"))
        layout.addWidget(self.usb_history, 1)

    def start_usb(self):
        if self.usb_timer.isActive():
            return
        if platform.system() != "Windows":
            self.usb_state.setText("Monitor USB memerlukan Windows 10/11.")
            return
        self.usb_timer.start()
        self.poll_usb()

    def stop_usb(self):
        self.usb_timer.stop()
        self.usb_cancel.set()
        if not self.usb_worker:
            self.monitor.stop()
        self.usb_state.setText("Monitor dihentikan.")
        fill(self.usb_current, [])

    def poll_usb(self):
        if self.usb_worker:
            return
        self.usb_cancel = Event()
        self.usb_worker = True
        is_cancelled = self.usb_cancel

        def done(devices):
            if is_cancelled.is_set():
                self.monitor.stop()
                return
            fill(
                self.usb_current,
                [
                    (row.category, row.manufacturer, row.model, row.driver_status, "Otorisasi diperlukan")
                    for row in devices
                ],
            )
            self.usb_state.setText(f"{len(devices)} antarmuka USB terdeteksi · metadata koneksi")
            self.refresh_usb()

        def failed(error):
            if not is_cancelled.is_set():
                self.usb_state.setText(error)

        def end():
            self.usb_worker = False

        self.background(lambda _: self.monitor.poll(is_cancelled), done, end, failed=failed)

    def refresh_usb(self):
        rows = self.db.rows("SELECT * FROM usb_events ORDER BY id DESC LIMIT 200")
        fill(
            self.usb_history,
            [
                (
                    row["observed_at"],
                    row["event"],
                    row["category"],
                    row["manufacturer"],
                    row["model"],
                    row["driver_status"],
                )
                for row in rows
            ],
        )

    def workspace(self, layout):
        self.setup_page(
            layout,
            "Ruang kerja pemeriksaan",
            "Tetapkan otorisasi, pilih modul, lalu jalankan pemeriksaan lokal.",
        )
        tabs = QTabWidget()
        layout.addWidget(tabs, 1)
        setup_panel = QWidget()
        pane = QVBoxLayout(setup_panel)
        tabs.addTab(setup_panel, "Pemeriksaan baru")
        form = QFormLayout()
        self.asset_picker = QComboBox()
        self.operator = QLineEdit()
        self.reference = QLineEdit()
        self.scope = QLineEdit()
        self.scope.setMaxLength(1000)
        self.mode = combo(
            {
                "quick": "Quick Security Check",
                "comprehensive": "Comprehensive Technical Assessment",
                "custom": "Custom Security Check",
            }
        )
        self.mode.setCurrentIndex(2)
        for label, widget in (
            ("Aset institusi", self.asset_picker),
            ("Kode petugas", self.operator),
            ("Rujukan izin", self.reference),
            ("Ruang lingkup", self.scope),
            ("Mode", self.mode),
        ):
            form.addRow(label, widget)
        pane.addLayout(form)
        self.authorization = QCheckBox("Saya memverifikasi otorisasi dan ruang lingkup aset di atas.")
        self.local_target = QCheckBox("Pemeriksaan Windows menargetkan komputer ini.")
        pane.addWidget(self.authorization)
        pane.addWidget(self.local_target)
        grid = QGridLayout()
        self.modules = {}
        for i, (key, label) in enumerate(MODULE_NAMES.items()):
            box = QCheckBox(label)
            self.modules[key] = box
            grid.addWidget(box, i // 3, i % 3)
        pane.addLayout(grid)
        operations = QHBoxLayout()
        self.start_button = self.button("Mulai pemeriksaan", self.start_scan)
        operations.addWidget(self.start_button)
        operations.addWidget(self.button("Batalkan", lambda: self.scan_cancel.set()))
        operations.addWidget(self.button("Pilih file…", self.select_files))
        operations.addWidget(self.button("Kosongkan file", lambda: self.receive_files([])))
        operations.addStretch()
        pane.addLayout(operations)
        self.file_list = FileList()
        self.file_list.accepted.connect(lambda paths: self.safe(lambda: self.receive_files(paths)))
        pane.addWidget(self.file_list)
        self.engines = {
            key: QCheckBox(label)
            for key, label in {"yara": "YARA", "defender": "Defender", "clamav": "ClamAV"}.items()
        }
        more = QHBoxLayout()
        for box in self.engines.values():
            more.addWidget(box)
        more.addStretch()
        pane.addLayout(more)
        self.indicators = QLineEdit()
        self.indicators.setPlaceholderText("Indikator manual (pisahkan dengan spasi)")
        self.product = QLineEdit()
        self.product.setPlaceholderText("Produk terverifikasi: vendor | produk | versi")
        pane.addWidget(self.indicators)
        pane.addWidget(self.product)
        self.progress = QProgressBar()
        self.progress.setFormat("%v/%m modul diproses")
        self.progress.setRange(0, 1)
        pane.addWidget(self.progress)
        self.live = plain()
        pane.addWidget(self.live)
        self.build_mobile_tab(tabs)
        self.build_results_tab(tabs)
        self.asset_picker.currentIndexChanged.connect(self.target_changed)
        self.mode.currentIndexChanged.connect(self.mode_changed)

    def build_mobile_tab(self, tabs):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        phone_form = QWidget()
        form = QVBoxLayout(phone_form)
        scroll.setWidget(phone_form)
        tabs.addTab(scroll, "Checklist seluler")
        self.mobile_inputs = {}
        for kind, checks in (("android", platforms.ANDROID), ("ios", platforms.IOS)):
            panel = QGroupBox(kind.upper())
            grid = QGridLayout(panel)
            prompt = QLabel(platforms.PROMPTS[kind], wordWrap=True)
            grid.addWidget(prompt, 0, 0, 1, 3)
            controls = {}
            for index, (key, label) in enumerate(checks.items(), start=1):
                chooser = combo(
                    {
                        "unknown": STATUS["unknown"],
                        "pass": STATUS["pass"],
                        "fail": STATUS["fail"],
                        "not_applicable": STATUS["not_applicable"],
                    }
                )
                note = QLineEdit()
                note.setMaxLength(1000)
                note.setPlaceholderText("Versi, status atau catatan teknis")
                grid.addWidget(QLabel(label), index, 0)
                grid.addWidget(chooser, index, 1)
                grid.addWidget(note, index, 2)
                controls[key] = (chooser, note)
            form.addWidget(panel)
            self.mobile_inputs[kind] = controls
        form.addStretch()

    def build_results_tab(self, tabs):
        panel = QWidget()
        pane = QVBoxLayout(panel)
        tabs.addTab(panel, "Riwayat dan bukti")
        self.sessions = table(["ID sesi", "Kode aset", "Mode", "Status", "Waktu UTC"])
        self.sessions.cellClicked.connect(self.open_session)
        pane.addWidget(self.sessions, 1)
        self.posture = QLabel("Pilih sesi untuk meninjau bukti.")
        pane.addWidget(self.posture)
        audit_tabs = QTabWidget()
        self.evidence = table(["Modul", "Sumber", "Integritas", "Waktu UTC"])
        self.evidence.cellClicked.connect(self.show_evidence)
        self.details = plain()
        evidence_panel = QWidget()
        content = QVBoxLayout(evidence_panel)
        content.addWidget(self.evidence, 1)
        content.addWidget(self.details, 1)
        audit_tabs.addTab(evidence_panel, "Bukti teknis")
        self.findings = table(["Keparahan", "Temuan", "Status", "Rekomendasi"])
        self.findings.cellClicked.connect(self.edit_finding)
        audit_tabs.addTab(self.findings, "Temuan dan mitigasi")
        self.timeline = table(["Waktu UTC", "Peristiwa", "Detail"])
        audit_tabs.addTab(self.timeline, "Linimasa")
        pane.addWidget(audit_tabs, 2)
        row = QHBoxLayout()
        self.report_kind = combo({key: value[0] for key, value in reporting.KINDS.items()})
        row.addWidget(self.report_kind)
        for label, action in (
            ("Pratinjau / cetak", self.preview),
            ("Ekspor", self.export_report),
            ("Tutup sesi", self.close_session),
        ):
            row.addWidget(self.button(label, action))
        pane.addLayout(row)

    def clear_session_inputs(self):
        self.authorization.setChecked(False)
        self.local_target.setChecked(False)
        self.reference.clear()
        self.scope.clear()
        self.indicators.clear()
        self.product.clear()
        self.receive_files([])
        for controls in self.mobile_inputs.values():
            for choice, note in controls.values():
                choice.setCurrentIndex(0)
                note.clear()
        for engine in self.engines.values():
            engine.setChecked(False)

    def target_changed(self):
        self.clear_session_inputs()
        self.mode_changed()

    def mode_changed(self):
        platform_id = self.asset_picker.currentData(Qt.ItemDataRole.UserRole + 1)
        if not platform_id:
            allowed = set()
        else:
            allowed = COMMON_MODULES | PLATFORM_MODULES[Platform(platform_id)]
        mode = self.mode.currentData()
        base = {Module.WINDOWS, Module.ANDROID, Module.IOS}
        if mode == "comprehensive":
            base |= {Module.SOFTWARE, Module.FILES, Module.VULNERABILITY}
        for key, box in self.modules.items():
            box.setEnabled(key in allowed and not self.active_scan)
            if key not in allowed:
                box.setChecked(False)
            elif mode != "custom":
                box.setChecked(key in base)

    def select_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Pilih file teknis yang diotorisasi")
        if paths:
            self.receive_files(paths)

    def receive_files(self, paths):
        if self.active_scan:
            raise InspectorError("File tidak dapat diubah ketika pemeriksaan aktif.")
        if len(paths) > 12:
            raise InspectorError("Maksimum 12 file per sesi.")
        self.selected_files = tuple(dict.fromkeys(Path(path).absolute() for path in paths))
        self.file_list.clear()
        self.file_list.addItems([path.name for path in self.selected_files])

    def start_scan(self):
        if self.active_scan:
            return
        modules = [module for module, box in self.modules.items() if box.isChecked()]
        request = Authorization(
            asset_id=self.asset_picker.currentData() or "",
            operator_code=self.operator.text(),
            reference=self.reference.text(),
            scope=self.scope.text(),
            authorized=self.authorization.isChecked(),
            modules=modules,
            mode=self.mode.currentData(),
            local_host_confirmed=self.local_target.isChecked(),
        )
        if self.selected_files and not set(request.modules) & {Module.FILES, Module.APK, Module.MALWARE}:
            raise InspectorError("Pilih modul file atau kosongkan pilihan file.")
        checks = []
        for kind in ("android", "ios"):
            if Module(kind) in modules:
                checks += [
                    MobileCheck(control=key, state=selector.currentData(), note=notes.text())
                    for key, (selector, notes) in self.mobile_inputs[kind].items()
                ]
        products = []
        if self.product.text().strip():
            values = [item.strip() for item in self.product.text().split("|")]
            if len(values) != 3:
                raise InspectorError("Masukkan produk dengan format vendor | produk | versi.")
            products = [Product(vendor=values[0], name=values[1], version=values[2])]
        selected_engines = {key for key, box in self.engines.items() if box.isChecked()}
        if Module.MALWARE in modules and not selected_engines:
            raise InspectorError("Pilih engine malware untuk modul ini.")
        indicators = tuple(self.indicators.text().split())
        if len(indicators) > 20:
            raise InspectorError("Maksimum 20 indikator per sesi.")
        selection = Selection(
            set(modules), self.selected_files, tuple(checks), indicators, tuple(products), selected_engines
        )
        session = self.db.create(request)
        self.scan_cancel = Event()
        self.active_scan = True
        self.asset_picker.setEnabled(False)
        self.start_button.setEnabled(False)
        self.authorization.setChecked(False)
        self.local_target.setChecked(False)
        self.progress.setRange(0, len(modules))
        self.progress.setValue(0)
        self.live.clear()

        def update(name, count, total, notice):
            self.progress.setRange(0, total)
            self.progress.setValue(count)
            self.live.appendPlainText(name + " · " + notice)

        def done():
            self.active_scan = False
            self.asset_picker.setEnabled(True)
            self.start_button.setEnabled(True)
            self.clear_session_inputs()
            self.refresh()
            self.load_session(session)

        self.background(
            lambda progress: run(self.db, session, selection, self.scan_cancel, progress),
            end=done,
            progress=update,
        )

    def open_session(self, row, _column):
        item = self.sessions.item(row, 0)
        if item:
            self.safe(lambda: self.load_session(item.text()))

    def load_session(self, session):
        record = self.db.session(session)
        self.session_id = session
        self.session_data = record
        rule = self.db.score_rule(record["scoring_rule"])
        result = evaluate(record, rule)
        self.posture.setText(
            f"{record['asset_code']} · {record['status']} · Cakupan {result['coverage']}% · {result['category']} · Skor {result['score'] if result['score'] is not None else '—'}"
        )
        fill(
            self.evidence,
            [
                (
                    row["module"],
                    row["source"],
                    "Terverifikasi" if row["verified_integrity"] else "Tidak cocok",
                    row["observed_at"],
                )
                for row in record["evidence"]
            ],
        )
        self.details.clear()
        fill(
            self.findings,
            [
                (row["severity"], row["title"], row["status"], row["recommendation"])
                for row in record["findings"]
            ],
        )
        fill(self.timeline, [(row["occurred_at"], row["event"], row["detail"]) for row in record["timeline"]])

    def show_evidence(self, row, _column):
        if self.session_data and 0 <= row < len(self.session_data["evidence"]):
            self.details.setPlainText(
                json.dumps(self.session_data["evidence"][row], ensure_ascii=False, indent=2)
            )

    def edit_finding(self, row, _column):
        if not self.session_data or not (0 <= row < len(self.session_data["findings"])):
            return
        item = self.session_data["findings"][row]
        labels = {
            "open": "Terbuka",
            "pending": "Menunggu verifikasi",
            "verified": "Terverifikasi",
            "false_positive": "Positif palsu",
            "mitigating": "Dalam mitigasi",
            "resolved": "Selesai",
        }
        selected, ok = QInputDialog.getItem(
            self,
            "Tindak lanjut",
            item["title"],
            list(labels.values()),
            list(labels).index(item["status"]),
            False,
        )
        if not ok:
            return
        code, ok = QInputDialog.getText(self, "Verifikasi", "Kode petugas peninjau:")
        if not ok:
            return
        note, ok = QInputDialog.getMultiLineText(self, "Verifikasi", "Catatan teknis:")
        if not ok:
            return

        def persist():
            status = next(key for key, value in labels.items() if value == selected)
            self.db.review_finding(
                item["id"],
                status,
                TypeAdapter(Code).validate_python(code),
                TypeAdapter(Note).validate_python(note),
            )
            self.load_session(self.session_id)
            self.refresh()

        self.safe(persist)

    def require_session(self):
        if not self.session_id:
            raise InspectorError("Pilih sesi dari riwayat pemeriksaan.")
        return self.session_id

    def preview(self):
        result = reporting.document(self.db, self.require_session(), self.report_kind.currentData())
        dialog = QDialog(self)
        dialog.setWindowTitle(result["title"])
        dialog.resize(780, 600)
        area = QVBoxLayout(dialog)
        preview = plain()
        preview.setPlainText(reporting.preview(result))
        area.addWidget(preview, 1)

        def print_document():
            printer = QPrinter()
            if QPrintDialog(printer, dialog).exec() == QDialog.DialogCode.Accepted:
                text = QTextDocument()
                text.setPlainText(preview.toPlainText())
                text.print_(printer)

        area.addWidget(self.button("Cetak", print_document), alignment=Qt.AlignmentFlag.AlignRight)
        dialog.exec()

    def export_report(self):
        session = self.require_session()
        path, _ = QFileDialog.getSaveFileName(
            self, "Simpan laporan", "sentinel-report.pdf", "PDF (*.pdf);;JSON (*.json);;CSV (*.csv)"
        )
        if path:
            result = reporting.export(self.db, session, self.report_kind.currentData(), Path(path).absolute())
            self.statusBar().showMessage("Laporan tersimpan · SHA-256 " + result, 10000)
            self.load_session(session)

    def close_session(self):
        session = self.require_session()
        code, ok = QInputDialog.getText(self, "Tutup sesi", "Kode petugas peninjau:")
        if ok:
            self.db.close(session, TypeAdapter(Code).validate_python(code))
            self.load_session(session)
            self.refresh()

    def intel_page(self, layout):
        self.setup_page(
            layout,
            "Katalog intelijen offline",
            "Impor paket dari Fase 2. Pencarian menggunakan database lokal.",
        )
        self.freshness = QLabel(wordWrap=True)
        layout.addWidget(self.freshness)
        row = QHBoxLayout()
        self.indicator = QLineEdit()
        self.indicator.setPlaceholderText("URL, domain, IP, hash, CVE, keluarga malware, atau advisori")
        row.addWidget(self.indicator, 1)
        for title, fn in (
            ("Cocokkan", lambda: self.intel_lookup(False)),
            ("Cari keluarga / advisori", lambda: self.intel_lookup(True)),
            ("Impor paket…", self.import_package),
        ):
            row.addWidget(self.button(title, fn))
        layout.addLayout(row)
        self.intel_output = plain()
        layout.addWidget(self.intel_output, 1)

    def intel_lookup(self, broad):
        data = (
            intelligence.family_or_advisory(self.db, self.indicator.text())
            if broad
            else intelligence.lookup(self.db, self.indicator.text()).payload
        )
        self.intel_output.setPlainText(json.dumps(data, ensure_ascii=False, indent=2))

    def import_package(self):
        path, _ = QFileDialog.getOpenFileName(self, "Impor paket intelijen terotorisasi", "", "JSON (*.json)")
        if not path:
            return

        def done(result):
            self.intel_output.setPlainText(json.dumps(result, ensure_ascii=False, indent=2))
            self.refresh()

        self.background(lambda _: intelligence.load_package(self.db, Path(path).absolute()), done)

    def yara_page(self, layout):
        self.setup_page(
            layout,
            "Aturan deteksi YARA",
            "Aturan yang diimpor mulai dalam keadaan nonaktif. Aktifkan hanya kumpulan aturan defensif yang telah ditinjau.",
        )
        row = QHBoxLayout()
        for label, action in (
            ("Impor aturan…", self.add_rule),
            ("Aktifkan", lambda: self.rule_state(True)),
            ("Nonaktifkan", lambda: self.rule_state(False)),
        ):
            row.addWidget(self.button(label, action))
        row.addStretch()
        layout.addLayout(row)
        self.yara = table(["ID", "Kumpulan aturan", "Versi", "Status", "SHA-256"])
        layout.addWidget(self.yara, 1)

    def add_rule(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Impor aturan terotorisasi", "", "YARA (*.yar *.yara);;Semua file (*)"
        )
        if not path:
            return
        name, ok = QInputDialog.getText(self, "Aturan", "Nama kumpulan aturan:")
        if not ok:
            return
        version, ok = QInputDialog.getText(self, "Aturan", "Versi aturan:")
        if ok:
            self.background(
                lambda _: engines.register_rule(self.db, Path(path).absolute(), name, version),
                lambda _: self.refresh(),
            )

    def rule_state(self, active):
        item = self.yara.item(self.yara.currentRow(), 0)
        if not item:
            raise InspectorError("Pilih aturan YARA.")
        engines.toggle_rule(self.db, item.text(), active)
        self.refresh()

    def system_page(self, layout):
        self.setup_page(
            layout, "Sistem dan audit", "Database lokal, cadangan terenkripsi, status koneksi, dan tampilan."
        )
        toolbar = QHBoxLayout()
        buttons = (
            ("Verifikasi audit", self.verify),
            ("Backup…", self.backup),
            ("Pulihkan ke file baru…", self.restore),
            ("Aturan posture", self.configure_scoring),
            ("Ubah tema", self.toggle_theme),
        )
        for text, action in buttons:
            toolbar.addWidget(self.button(text, action))
        toolbar.addStretch()
        layout.addLayout(toolbar)
        row = QHBoxLayout()
        self.api_url = QLineEdit()
        self.api_url.setPlaceholderText("Origin HTTPS resmi Sentinel institusi")
        row.addWidget(self.api_url, 1)
        row.addWidget(self.button("Uji status API", self.health_check))
        layout.addLayout(row)
        self.system_log = plain()
        layout.addWidget(self.system_log, 1)

    def verify(self):
        valid = self.db.verify_audit()
        self.system_log.appendPlainText("Rantai audit " + ("cocok." if valid else "tidak cocok."))
        rows = self.db.rows(
            "SELECT sequence,event,occurred_at FROM audit_events ORDER BY sequence DESC LIMIT 100"
        )
        self.system_log.appendPlainText(
            "\n".join(f"{x['sequence']} · {x['occurred_at']} · {x['event']}" for x in rows)
        )

    def backup(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Buat cadangan", "sentinel-backup.psi", "Sentinel (*.psi)"
        )
        if not path:
            return
        secret, ok = QInputDialog.getText(
            self, "Cadangan", "Frasa sandi (minimum 14 karakter):", QLineEdit.EchoMode.Password
        )
        if ok:
            self.background(
                lambda _: backup.create(self.db, Path(path).absolute(), secret),
                lambda result: self.system_log.appendPlainText("Cadangan tersimpan · SHA-256 " + result),
            )

    def restore(self):
        source, _ = QFileDialog.getOpenFileName(self, "Pilih cadangan", "", "Sentinel (*.psi)")
        if not source:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Pulihkan sebagai database baru", "sentinel-restored.sqlite3", "SQLite (*.sqlite3)"
        )
        if not path:
            return
        secret, ok = QInputDialog.getText(
            self, "Pulihkan", "Frasa sandi cadangan:", QLineEdit.EchoMode.Password
        )
        if ok:
            self.background(
                lambda _: backup.restore(Path(source).absolute(), Path(path).absolute(), secret),
                lambda result: self.system_log.appendPlainText(
                    "Pemulihan tervalidasi. Buka file baru dengan --db. SHA-256 " + result
                ),
            )

    def configure_scoring(self):
        rule = self.db.score_rule()
        current = json.dumps(
            {"weights": json.loads(rule["weights"]), "minimum": rule["minimum_coverage"]}, indent=2
        )
        raw, ok = QInputDialog.getMultiLineText(
            self, "Aturan posture", "Bobot per kontrol dan persentase cakupan minimum", current
        )
        if ok:
            try:
                data = json.loads(raw)
                version = self.db.configure_scoring(data["weights"], data["minimum"])
            except (ValueError, TypeError, KeyError) as error:
                raise InspectorError("Konfigurasi JSON aturan tidak valid.") from error
            self.system_log.appendPlainText("Aturan untuk sesi baru: " + version)

    def toggle_theme(self):
        self.theme = LIGHT if self.theme is DARK else DARK
        self.apply_theme()

    def health_check(self):
        origin = self.api_url.text()

        def done(result):
            self.last_health = result["status"]
            self.system_log.appendPlainText("API · " + json_text(result))
            self.tick_system()

        self.background(lambda _: api_health(origin), done)

    def tick_system(self):
        self.cpu.append(psutil.cpu_percent())
        self.ram.append(psutil.virtual_memory().percent)
        self.cpu_plot.setData(list(self.cpu))
        self.ram_plot.setData(list(self.ram))
        catalog = intelligence.updated(self.db)
        self.health.setText(
            f"USB: {len(self.monitor.previous)} · API: {self.last_health} · Intelijen: "
            f"{(catalog.get('source_updated_at') or catalog['imported_at']) if catalog else 'belum ada paket'} · Ruang disk: {shutil.disk_usage(self.db.path.parent).free // (1024**3)} GiB"
        )

    def refresh(self):
        for key, value in self.db.counts().items():
            self.cards[key].setText(str(value))
        self.tick_system()
        assets = self.db.rows("SELECT * FROM assets ORDER BY code")
        active = self.asset_picker.currentData()
        self.asset_picker.blockSignals(True)
        self.asset_picker.clear()
        for row in assets:
            self.asset_picker.addItem(f"{row['code']} · {row['name']}", row["id"])
            self.asset_picker.setItemData(
                self.asset_picker.count() - 1, row["category"], Qt.ItemDataRole.UserRole + 1
            )
        if active:
            self.asset_picker.setCurrentIndex(max(0, self.asset_picker.findData(active)))
        self.asset_picker.blockSignals(False)
        self.mode_changed()
        fill(self.assets, [(a["code"], a["name"], a["category"], a["owner_unit"]) for a in assets])
        fill(
            self.sessions,
            [(r["id"], r["asset"], r["mode"], r["status"], r["created_at"]) for r in self.db.list_sessions()],
        )
        self.refresh_usb()
        fill(
            self.yara,
            [
                (r["id"], r["label"], r["version"], "aktif" if r["enabled"] else "nonaktif", r["sha256"])
                for r in self.db.rows(
                    "SELECT id,label,version,sha256,enabled FROM yara_rules ORDER BY created_at DESC LIMIT 200"
                )
            ],
        )
        catalog = intelligence.updated(self.db)
        self.freshness.setText(
            f"Impor terakhir: {catalog['imported_at']} · Pembaruan sumber: {catalog['source_updated_at'] or 'tidak tercantum'}"
            if catalog
            else "Belum ada paket yang diimpor."
        )

    def closeEvent(self, event):
        self.stop_usb()
        if self.workers:
            self.scan_cancel.set()
            self.statusBar().showMessage(
                "Menunggu pekerjaan aktif berhenti. Tutup kembali setelah selesai.", 10000
            )
            event.ignore()
            return
        super().closeEvent(event)


def launch(path: Path):
    app = QApplication.instance() or QApplication([])
    app.setApplicationName("PUSKESAU SENTINEL")
    db = Database(path)
    lock = QLockFile(str(db.path) + ".ui.lock")
    lock.setStaleLockTime(0)
    if not lock.tryLock(0):
        raise InspectorError("Jendela Inspector sudah menggunakan database ini.")
    window = InspectorWindow(db)
    window.show()
    try:
        return app.exec()
    finally:
        lock.unlock()
