<?php
declare(strict_types=1);

return [
    'Super Administrator' => ['*'],
    'Administrator' => ['dashboard.read', 'notifications.read', 'admin.read', 'admin.write', 'technical.read', 'report.read', 'users.read'],
    'Petugas Pemeriksaan' => ['dashboard.read', 'notifications.read', 'admin.read', 'technical.read', 'technical.write', 'report.read', 'report.write'],
    'Supervisor' => ['dashboard.read', 'notifications.read', 'admin.read', 'technical.read', 'technical.write', 'technical.approve', 'report.read', 'report.write', 'report.approve'],
    'Pimpinan' => ['dashboard.read', 'notifications.read', 'report.approved'],
    'Auditor' => ['audit.read'],
];
