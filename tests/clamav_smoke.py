"""Exercise the local clamd transport with inert inputs and deterministic responses."""
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import os
import socket
import struct
import subprocess


PHP = os.getenv("SENTINEL_TEST_PHP", "php")


def check(address, path, expected):
    code = 'require "app/Core/bootstrap.php"; echo Sentinel\\Services\\ClamAv::scan($argv[1]);'
    process = subprocess.run(
        [PHP, "-r", code, str(path)],
        env=os.environ | {"CLAMD_SOCKET": address},
        capture_output=True, text=True, timeout=7, check=True,
    )
    assert process.stdout == expected, process.stdout


with TemporaryDirectory() as workspace:
    root = Path(workspace)
    address = str(root / "clamd.sock")
    plain = root / "fixture.txt"
    plain.write_bytes(b"TEST inert document")
    check("", plain, "Belum diperiksa antivirus")
    check(address, plain, "ClamAV: tidak tersedia")
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(address)
        server.listen()
        for reply, expected in (
            (b"stream: OK\0", "ClamAV: tidak terdeteksi"),
            (b"stream: Synthetic.Rule FOUND\0", "ClamAV: terdeteksi"),
            (b"stream: parsing failed ERROR\0", "ClamAV: pemindaian gagal"),
        ):
            received = []

            def fixture():
                accepted, _ = server.accept()
                with accepted, accepted.makefile("rb") as client:
                    received.append(client.read(10))
                    payload = bytearray()
                    while size := struct.unpack(">I", client.read(4))[0]:
                        payload.extend(client.read(size))
                    received.append(bytes(payload))
                    accepted.sendall(reply)

            thread = Thread(target=fixture, daemon=True)
            thread.start()
            check(address, plain, expected)
            thread.join(2)
            assert received == [b"zINSTREAM\0", plain.read_bytes()]
print("Five local ClamAV transport checks passed.")
