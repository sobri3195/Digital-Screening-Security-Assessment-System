import os
import platform
from threading import Event

import pytest

from sentinel_inspector import platforms


@pytest.mark.skipif(
    platform.system() != "Windows" or os.getenv("SENTINEL_TEST_NATIVE_WINDOWS") != "1",
    reason="Requires an explicitly enabled Windows lab or CI runner",
)
def test_native_windows_read_only_observations(db):
    cancel = Event()
    security = platforms.security(cancel)
    assert security.payload["os_version"]
    assert "firewall" in security.payload
    software = platforms.software(cancel)
    assert isinstance(software.payload["products"], list)
    devices = platforms.UsbMonitor(db).poll(cancel)
    assert all(device.category and device.driver_status for device in devices)
    print("Native Windows configuration, HKLM software and USB enumeration completed.")
