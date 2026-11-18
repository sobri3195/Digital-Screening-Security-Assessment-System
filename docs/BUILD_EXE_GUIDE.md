# Build Windows x64

Gunakan Windows 10/11 x64 untuk verifikasi penerimaan, Python 3.12 x64 dan Inno Setup 6.3+. Dari root repository jalankan `./desktop/packaging/build.ps1` melalui PowerShell. Jika ISCC tidak berada pada jalur standar, teruskan `-Compiler "C:\Path\ISCC.exe"`. Skrip memasang dependency pada venv, menjalankan pytest, membuat artefak PyInstaller dan Inno Setup, serta menghasilkan release manifest dan SHA-256.

Targetnya adalah `desktop/dist/PUSKESAU_SENTINEL_Advanced_Portable.exe` dan `desktop/dist/PUSKESAU_SENTINEL_Advanced_Setup.exe`. Rilis resmi perlu penandatanganan institusi dan uji portable, install, upgrade, uninstall dan USB pada Windows target.
