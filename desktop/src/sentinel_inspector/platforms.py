from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
from pathlib import Path
import platform
from secrets import token_bytes
import subprocess
from threading import Event
from time import monotonic

from .database import Database, InspectorError, now
from .file_inspection import check_cancel
from .models import Finding, Observation

ANDROID = {
    "os_version": "Versi Android",
    "patch_level": "Level patch keamanan",
    "os_updates": "Pembaruan OS",
    "screen_lock": "Kunci layar",
    "storage_encryption": "Enkripsi penyimpanan",
    "play_protect": "Google Play Protect",
    "unknown_sources": "Pembatasan sumber tidak dikenal",
    "usb_debugging": "Pembatasan USB debugging",
    "management": "Pengelolaan institusi",
    "backup": "Kebijakan backup",
    "network": "Konfigurasi jaringan",
    "support": "Dukungan pembaruan keamanan",
}
IOS = {
    "model": "Model institusi",
    "os_version": "Versi iOS/iPadOS",
    "os_updates": "Pembaruan OS",
    "passcode": "Passcode diaktifkan",
    "automatic_update": "Pembaruan otomatis",
    "backup": "Kebijakan backup",
    "management": "Pengelolaan institusi",
    "security_config": "Konfigurasi keamanan",
    "support": "Dukungan pembaruan",
}
PROMPTS = {
    "android": "Verifikasi di Setelan > Keamanan, Tentang ponsel, atau konsol pengelolaan institusi yang diotorisasi.",
    "ios": "Verifikasi di Pengaturan > Umum, Face ID/Touch ID & Kode Sandi, atau konsol institusi yang diotorisasi.",
}

# Local Windows commands are fixed and read only. No user input is interpolated.
SECURITY_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
function Probe([scriptblock]$body) { try { & $body } catch { $null } }
$os = Probe { Get-CimInstance Win32_OperatingSystem }
$def = Probe { Get-MpComputerStatus }
$fw = @(Probe { Get-NetFirewallProfile | Select-Object Name,Enabled })
$disk = @(Probe { Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' |
    Select-Object DeviceID,@{n='bytes';e={[long]$_.Size}},@{n='free';e={[long]$_.FreeSpace}} })
$encrypted = @(Probe { Get-BitLockerVolume | Select-Object MountPoint,ProtectionStatus,VolumeStatus })
$tpm = Probe { Get-Tpm }
$smb = Probe { Get-SmbServerConfiguration }
$rdp = Probe { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections }
$uac = Probe { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA).EnableLUA }
$lock = Probe { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs).InactivityTimeoutSecs }
$autorun = Probe { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun).NoDriveTypeAutoRun }
$logging = Probe { (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging).EnableScriptBlockLogging }
$hello = Probe { (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' -Name Enabled).Enabled }
$policy = Probe { (Get-AppLockerPolicy -Effective).RuleCollections.Count }
$last = Probe { Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1 }
$health = @(Probe { Get-PhysicalDisk | Select-Object MediaType,HealthStatus,Size })
[ordered]@{
 os_caption=$os.Caption; os_version=$os.Version; build=$os.BuildNumber;
 recent_hotfix=$last.HotFixID; hotfix_date=if($last.InstalledOn){$last.InstalledOn.ToString('yyyy-MM-dd')};
 firewall=$fw; defender_antivirus=$def.AntivirusEnabled; defender_realtime=$def.RealTimeProtectionEnabled;
 defender_signature=$def.AntivirusSignatureVersion; signature_age_days=$def.AntivirusSignatureAge;
 defender_engine=$def.AMEngineVersion;
 bitlocker=$encrypted; secure_boot=(Probe { Confirm-SecureBootUEFI }); tpm_present=$tpm.TpmPresent; tpm_ready=$tpm.TpmReady;
 uac=$uac; windows_hello_policy=$hello; screen_lock_seconds=$lock; rdp_denied=$rdp;
 smb_v1=$smb.EnableSMB1Protocol; smb_signing_required=$smb.RequireSecuritySignature;
 autorun_mask=$autorun; powershell_script_logging=$logging; applocker_rule_collections=$policy;
 disk=$disk; physical_disk_health=$health
} | ConvertTo-Json -Compress -Depth 5
"""
SOFTWARE_SCRIPT = r"""
$keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$items = @(Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName } | Select-Object -First 2000 DisplayName,Publisher,DisplayVersion,InstallDate)
ConvertTo-Json -Compress -InputObject $items -Depth 3
"""
USB_SCRIPT = r"""
$ErrorActionPreference='Stop'
$items = @(Get-CimInstance Win32_PnPEntity -Filter 'Present=True' |
    Where-Object { $_.PNPDeviceID -match '^USB\\VID_[0-9A-F]+&PID_[0-9A-F]+' } |
    Select-Object -First 400 PNPDeviceID,Name,Manufacturer,PNPClass,Service,ConfigManagerErrorCode)
ConvertTo-Json -Compress -InputObject $items -Depth 3
"""


class Unavailable(InspectorError):
    pass


def windows_directory() -> Path:
    if platform.system() != "Windows":
        raise Unavailable("Memerlukan Windows 10/11.")
    import ctypes

    buffer = ctypes.create_unicode_buffer(32768)
    count = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if not count or count >= len(buffer):
        raise Unavailable("Direktori Windows tidak tersedia.")
    return Path(buffer.value)


def command(args: list[str], cancel: Event, timeout: int) -> tuple[int, bytes]:
    check_cancel(cancel)
    try:
        process = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError as error:
        raise Unavailable("Engine atau antarmuka sistem tidak dapat dijalankan.") from error
    deadline = monotonic() + timeout
    try:
        while not cancel.is_set() and monotonic() < deadline:
            try:
                output, _ = process.communicate(timeout=min(0.25, max(0.01, deadline - monotonic())))
                if len(output) > 5 * 1024 * 1024:
                    raise InspectorError("Keluaran pemeriksaan melampaui batas.")
                check_cancel(cancel)
                return process.returncode, output
            except subprocess.TimeoutExpired:
                continue
        check_cancel(cancel)
        raise InspectorError("Batas waktu pemeriksaan terlampaui.")
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


def powershell(script: str, cancel: Event):
    host = windows_directory() / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    code, output = command(
        [
            str(host),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);\n" + script,
        ],
        cancel,
        40,
    )
    if code:
        raise Unavailable("Antarmuka Windows tidak tersedia atau aksesnya ditolak.")
    try:
        return json.loads(output.decode("utf-8-sig"))
    except (ValueError, UnicodeError) as error:
        raise InspectorError("Pemeriksaan Windows tidak menghasilkan respons yang valid.") from error


def mobile(kind: str, checks) -> Observation:
    controls = ANDROID if kind == "android" else IOS
    states = {key: {"label": label, "state": "unknown", "note": ""} for key, label in controls.items()}
    supplied = set()
    observations = []
    for check in checks:
        if check.control not in controls or check.control in supplied:
            raise InspectorError("Kontrol checklist tidak tersedia atau diisi dua kali.")
        supplied.add(check.control)
        states[check.control].update(state=check.state, note=check.note)
        if check.state == "fail":
            observations.append(
                Finding(
                    "mobile_configuration",
                    f"Kontrol memerlukan verifikasi: {controls[check.control]}",
                    "medium",
                    "Verifikasi konfigurasi melalui pengaturan resmi dan terapkan kebijakan perangkat institusi.",
                )
            )
    return Observation(
        "Verifikasi manual pengaturan resmi atau administrasi perangkat",
        {
            "platform": kind,
            "checks": states,
            "instruction": PROMPTS[kind],
        },
        tuple(observations),
    )


def security(cancel: Event, collector=powershell) -> Observation:
    payload = collector(SECURITY_SCRIPT, cancel)
    if not isinstance(payload, dict) or not payload.get("os_version"):
        raise Unavailable("Metadata Windows tidak tersedia.")
    payload["password_policy"] = "Tidak diverifikasi; perlu kebijakan institusi yang berwenang."
    payload["windows_auditing"] = "Tidak diverifikasi oleh modul ini."
    payload["patch_note"] = "Hotfix yang tercatat tidak membuktikan seluruh patch telah terpasang."
    findings = []
    firewall = [item.get("Enabled") for item in payload.get("firewall", []) if isinstance(item, dict)]
    if False in firewall:
        findings.append(
            Finding(
                "weak_firewall",
                "Profil firewall nonaktif",
                "high",
                "Verifikasi kebutuhan operasional dan aktifkan sesuai kebijakan.",
            )
        )
    if payload.get("defender_antivirus") is False or payload.get("defender_realtime") is False:
        findings.append(
            Finding(
                "antivirus_review",
                "Proteksi Microsoft Defender perlu ditinjau",
                "medium",
                "Konfirmasi proteksi endpoint yang disetujui. Defender dapat berada dalam mode pasif jika produk lain mengelola proteksi.",
            )
        )
    if payload.get("smb_v1") is True:
        findings.append(
            Finding(
                "legacy_protocol",
                "SMBv1 diaktifkan",
                "high",
                "Tinjau ketergantungan layanan dan rencanakan penonaktifan terotorisasi.",
            )
        )
    return Observation("Windows CIM, PowerShell, dan HKLM", payload, tuple(findings))


def software(cancel: Event, collector=powershell) -> Observation:
    records = collector(SOFTWARE_SCRIPT, cancel)
    if not isinstance(records, list):
        raise InspectorError("Format inventaris Windows tidak valid.")
    rows = []
    seen = set()
    for item in records:
        if not isinstance(item, dict) or not isinstance(item.get("DisplayName"), str):
            continue
        name = item["DisplayName"][:160]
        vendor = (item.get("Publisher") or "")[:160]
        version = (item.get("DisplayVersion") or "")[:100]
        key = (vendor.casefold(), name.casefold(), version.casefold())
        if key not in seen:
            seen.add(key)
            rows.append(
                {
                    "name": name,
                    "vendor": vendor,
                    "version": version,
                    "install_date": (item.get("InstallDate") or "")[:16],
                }
            )
    return Observation(
        "Windows HKLM Uninstall (machine-wide)",
        {
            "products": rows,
            "coverage": "Entri instalasi tingkat mesin. Status dukungan dan EOL memerlukan data vendor.",
            "limit": 2000,
        },
    )


@dataclass(frozen=True)
class Device:
    key: str
    category: str
    manufacturer: str
    model: str
    driver_status: str


class UsbMonitor:
    def __init__(self, db: Database, collector=powershell):
        self.db = db
        self.collector = collector
        self.key = token_bytes(32)
        self.previous: dict[str, Device] = {}

    def poll(self, cancel: Event) -> list[Device]:
        found = self.collector(USB_SCRIPT, cancel)
        if not isinstance(found, list):
            raise InspectorError("Daftar perangkat USB tidak valid.")
        devices = {}
        for item in found:
            if not isinstance(item, dict) or not item.get("PNPDeviceID"):
                continue
            technical_id = item["PNPDeviceID"]
            model = (item.get("Name") or "Model tidak tersedia")[:140]
            manufacturer = (item.get("Manufacturer") or "Tidak tersedia")[:100]
            label = " ".join([model, item.get("PNPClass") or "", item.get("Service") or ""]).lower()
            if "iphone" in label or "ipad" in label or "apple mobile device" in label:
                category = "ios"
            elif "android" in label or "adb interface" in label:
                category = "android"
            elif "ssd" in label:
                category = "usb_ssd"
            elif "hdd" in label:
                category = "usb_hdd"
            elif "tablet" in label:
                category = "tablet"
            elif "mass storage" in label or "usbstor" in label or "uaspstor" in label:
                category = "usb_storage"
            else:
                category = "other_usb"
            key = hmac.new(self.key, technical_id.encode(), sha256).hexdigest()
            if item.get("ConfigManagerErrorCode") is None:
                driver = "tidak_diketahui"
            elif item["ConfigManagerErrorCode"] == 0:
                driver = "driver_terdeteksi"
            else:
                driver = "driver_bermasalah"
            devices[key] = Device(key, category, manufacturer, model, driver)
        added = [(device, "connected") for key, device in devices.items() if key not in self.previous]
        removed = [(device, "disconnected") for key, device in self.previous.items() if key not in devices]
        if added or removed:
            with self.db.write() as c:
                for device, action in added + removed:
                    c.exec_driver_sql(
                        "INSERT INTO usb_events (event,category,manufacturer,model,driver_status,observed_at) VALUES (?,?,?,?,?,?)",
                        (
                            action,
                            device.category,
                            device.manufacturer,
                            device.model,
                            device.driver_status,
                            now(),
                        ),
                    )
        self.previous = devices
        return list(devices.values())

    def stop(self):
        self.previous = {}
