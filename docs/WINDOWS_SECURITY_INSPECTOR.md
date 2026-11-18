# Windows Security Inspector

Konfirmasikan bahwa aset adalah workstation Windows yang menjalankan Inspector. Perintah lokal tetap membaca CIM, properti PowerShell Windows, dan HKLM untuk versi/build, firewall, Defender, BitLocker, Secure Boot, TPM, UAC, Windows Hello policy, penguncian, RDP, SMB, autorun, script logging, AppLocker, disk dan hotfix. Instalasi tingkat mesin diambil dari entri Uninstall 32/64-bit. Nilai tanpa akses dilaporkan tidak tersedia. Hotfix terbaru merupakan observasi, sedangkan status pemenuhan patch maupun umur dukungan perlu dibandingkan dengan sumber kebijakan vendor. Pemeriksaan password policy dan auditing belum didukung.

Jalankan sebagai pengguna biasa dan pertahankan batasan kebijakan Windows. Tidak ada perubahan registry, proteksi, policy, atau kredensial.
