import json

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .ai_client import AiClient
from .database import InspectorError


class AiPanel(QWidget):
    def __init__(self, window):
        super().__init__()
        self.window = window
        self.task_id = None
        self.busy = False
        layout = QVBoxLayout(self)
        self.mode = QComboBox()
        self.mode.addItem("Mandiri · gateway lokal", "standalone")
        self.mode.addItem("Pusat · gateway HTTPS privat", "central")
        self.origin = QLineEdit("http://127.0.0.1:8766")
        self.token = QLineEdit()
        self.token.setEchoMode(QLineEdit.EchoMode.Password)
        self.token.setPlaceholderText("Token yang diberikan administrator AI")
        config = QFormLayout()
        config.addRow("Mode", self.mode)
        config.addRow("Origin AI Gateway", self.origin)
        config.addRow("Token workstation", self.token)
        layout.addLayout(config)
        self.status = QLabel("Belum terhubung ke AI.")
        layout.addWidget(self.status)
        self.kind = QComboBox()
        for code, label in (
            ("vulnerability", "Jelaskan CVE"),
            ("threat", "Jelaskan indikator"),
            ("malware", "Jelaskan hash file"),
            ("configuration", "Tinjau status kontrol"),
            ("mitigation", "Saran mitigasi"),
            ("education", "Edukasi teknis"),
        ):
            self.kind.addItem(label, code)
        config = QFormLayout()
        config.addRow("Jenis analisis", self.kind)
        self.indicator_type = QComboBox()
        for value in ("domain", "ip", "url", "hash", "cve"):
            self.indicator_type.addItem(value, value)
        self.indicator = QLineEdit()
        self.indicator.setMaxLength(320)
        config.addRow("Tipe indikator", self.indicator_type)
        config.addRow("Indikator, CVE, atau SHA-256", self.indicator)
        self.platform = QComboBox()
        for value in ("windows", "android", "ios", "linux", "network"):
            self.platform.addItem(value, value)
        config.addRow("Platform", self.platform)
        self.controls = {}
        for control in ("firewall", "antivirus", "updates", "encryption", "secure_boot", "support"):
            box = QComboBox()
            for state in ("unknown", "pass", "fail", "not_applicable"):
                box.addItem(state, state)
            self.controls[control] = box
            config.addRow(control, box)
        self.category = QComboBox()
        for value in (
            "vulnerability",
            "phishing",
            "malware",
            "configuration",
            "education",
            "incident",
            "advisory",
        ):
            self.category.addItem(value, value)
        config.addRow("Kategori mitigasi", self.category)
        self.topic = QComboBox()
        for value in ("ioc", "cvss_epss", "phishing", "patching"):
            self.topic.addItem(value, value)
        config.addRow("Topik edukasi", self.topic)
        layout.addLayout(config)
        self.confirm = QCheckBox(
            "Saya mengizinkan pengiriman metadata teknis di atas ke gateway yang dipilih."
        )
        layout.addWidget(self.confirm)
        actions = QHBoxLayout()
        for label, handler in (
            ("Uji koneksi", self.check),
            ("Ajukan", self.submit),
            ("Lihat tugas", self.current),
            ("Riwayat", self.history),
            ("Hentikan", self.cancel),
        ):
            action = QPushButton(label)
            action.clicked.connect(lambda _flag=False, f=handler: self.window.safe(f))
            actions.addWidget(action)
        layout.addLayout(actions)
        row = QFormLayout()
        self.task_input = QLineEdit()
        self.task_input.setMaxLength(32)
        row.addRow("ID tugas untuk ditinjau", self.task_input)
        layout.addLayout(row)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output, 1)
        self.kind.currentIndexChanged.connect(self.show_fields)
        self.show_fields()

    def show_fields(self):
        kind = self.kind.currentData()
        groups = (
            ({"vulnerability", "malware", "threat"}, [self.indicator]),
            ({"threat"}, [self.indicator_type]),
            ({"configuration"}, [self.platform, *self.controls.values()]),
            ({"mitigation"}, [self.category]),
            ({"education"}, [self.topic]),
        )
        # QFormLayout ties label visibility to each input field.
        form = self.layout().itemAt(2).layout()
        for allowed, widgets in groups:
            for widget in widgets:
                form.setRowVisible(widget, kind in allowed)

    def call(self, method, path, body=None, after=None):
        if self.busy:
            raise InspectorError("Tunggu permintaan AI yang sedang berjalan.")
        client = AiClient(self.origin.text(), self.token.text(), self.mode.currentData())
        self.busy = True
        self.status.setText("Menunggu AI Gateway…")

        def done(data):
            self.status.setText(
                "AI Gateway terhubung · " + str(data.get("state", data.get("status", "siap")))
            )
            self.output.setPlainText(json.dumps(data, ensure_ascii=False, indent=2))
            if after:
                after(data)

        def failed(message):
            self.status.setText(message)

        def reset():
            self.busy = False

        self.window.background(lambda _: client.request(method, path, body), done, reset, failed=failed)

    def check(self):
        self.call("GET", "/health")

    def submit(self):
        if not self.confirm.isChecked():
            raise InspectorError("Konfirmasikan pengiriman metadata teknis.")
        kind = self.kind.currentData()
        text = self.indicator.text().strip()
        data = {"kind": kind}
        if kind == "vulnerability":
            data["cve"] = text
        elif kind == "threat":
            data.update(type=self.indicator_type.currentData(), indicator=text)
        elif kind == "malware":
            data["sha256"] = text
        elif kind == "configuration":
            data.update(
                platform=self.platform.currentData(),
                controls={key: value.currentData() for key, value in self.controls.items()},
            )
        elif kind == "mitigation":
            data["category"] = self.category.currentData()
        else:
            data["topic"] = self.topic.currentData()

        def created(result):
            self.task_id = result.get("id")
            if self.task_id:
                self.task_input.setText(self.task_id)
            self.confirm.setChecked(False)

        self.call("POST", "/analyze/" + kind, data, created)

    def identifier(self):
        key = self.task_input.text().strip() or self.task_id or ""
        if len(key) != 32 or any(c not in "abcdef0123456789" for c in key):
            raise InspectorError("Masukkan ID tugas yang valid.")
        return key

    def current(self):
        self.call("GET", "/tasks/" + self.identifier())

    def history(self):
        self.call("GET", "/tasks")

    def cancel(self):
        self.call("POST", "/tasks/" + self.identifier() + "/cancel")
