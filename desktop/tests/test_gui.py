import os
from time import monotonic, sleep

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
pytest.importorskip("pyqtgraph")
from PySide6.QtWidgets import QApplication, QMessageBox

from sentinel_inspector.gui import InspectorWindow
from sentinel_inspector.models import Asset, Module


def test_qt_workflow_and_selected_file(db, tmp_path, monkeypatch):
    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", lambda _self, _title, message: warnings.append(message))
    app = QApplication.instance() or QApplication([])
    db.add_asset(Asset(code="TEST-USB", name="TEST USB asset", unit="TEST Lab", platform="usb"))
    window = InspectorWindow(db)
    window.show()
    try:
        assert window.pages.count() == 8
        assert window.asset_picker.currentData()
        window.reference.setText("TEST-001")
        window.operator.setText("TEST.OP")
        window.scope.setText("TEST selected file integrity check")
        window.authorization.setChecked(True)
        window.modules[Module.FILES].setChecked(True)
        selected = tmp_path / "test-file.txt"
        selected.write_text("TEST inert local file", encoding="utf-8")
        window.receive_files([str(selected)])
        window.start_button.click()
        until = monotonic() + 8
        while window.workers and monotonic() < until:
            app.processEvents()
            sleep(0.02)
        app.processEvents()
        assert not warnings
        assert not window.workers and not window.active_scan
        assert window.session_data["status"] == "review"
        assert window.progress.value() == 1
        assert window.evidence.rowCount() == 2
        assert window.file_list.count() == 0
        assert not window.scope.text() and not window.reference.text()
        window.show_evidence(0, 0)
        assert len(window.details.toPlainText()) > 50
        window.toggle_theme()
        assert "#F0F4FA" in window.styleSheet()
    finally:
        window.close()
        app.processEvents()
