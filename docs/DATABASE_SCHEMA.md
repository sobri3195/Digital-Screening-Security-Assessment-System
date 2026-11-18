# Skema database

Definisi berurutan berada di [database/migrations](../database/migrations/). Jalankan `php bin/setup.php migrate`, yang mencatat migrasi di `schema_migrations` dan menanam role, izin, dan indikator checklist awal.

| Area | Tabel |
| --- | --- |
| Akun | users, roles, permissions, user_roles, role_permissions, login_attempts, user_sessions |
| Kegiatan | activity_periods, activities, activity_history, inspection_schedules, education |
| Pemeriksaan | institutional_assets, asset_maintenance, url_inspections, file_inspections, security_checklists, checklist_items, checklist_results |
| Temuan | security_findings, security_incidents, incident_timelines, evidence_metadata |
| Laporan | reports, report_approvals, notifications |
| Sistem | audit_logs, api_clients, api_tokens, api_limits, system_settings, backup_history |

Relasi bisnis dilindungi foreign key. Riwayat dan hasil checklist memiliki tabel anak. Token tersimpan sebagai SHA-256; backup dan TOTP menggunakan enkripsi terautentikasi. Kolom logo berisi PNG/JPEG terverifikasi dalam format teks base64, dan data hasil laporan disetujui disimpan sebagai snapshot. Semua timestamp aplikasi dan koneksi database menggunakan zona waktu Jakarta.
