<?php
declare(strict_types=1);

return [
    'permissions' => [
        'threat.dashboard.view', 'threat.scan.execute', 'threat.indicator.view', 'threat.indicator.manage',
        'threat.vulnerability.view', 'threat.advisory.view', 'threat.finding.verify', 'threat.provider.manage',
        'threat.sync.execute', 'threat.alert.manage', 'threat.report.generate', 'threat.report.approve',
        'threat.settings.manage', 'threat.audit.view',
    ],
    'roles' => [
        'Administrator' => ['dashboard.view','indicator.view','vulnerability.view','advisory.view','provider.manage','sync.execute','alert.manage','audit.view'],
        'Petugas Pemeriksaan' => ['dashboard.view','scan.execute','indicator.view','vulnerability.view','advisory.view','report.generate'],
        'Supervisor' => ['dashboard.view','scan.execute','indicator.view','indicator.manage','vulnerability.view','advisory.view','finding.verify','alert.manage','report.generate','report.approve','audit.view'],
        'Pimpinan' => ['dashboard.view','vulnerability.view','advisory.view'],
        'Auditor' => ['audit.view'],
    ],
    'providers' => [
        'cisa' => ['CISA KEV', 1440, null],
        'nvd' => ['NIST NVD', 360, null],
        'epss' => ['FIRST EPSS', 1440, null],
        'urlhaus' => ['URLhaus', 360, 'TI_URLHAUS_KEY'],
        'threatfox' => ['ThreatFox', 360, 'TI_THREATFOX_KEY'],
        'malwarebazaar' => ['MalwareBazaar', 360, 'TI_MALWAREBAZAAR_KEY'],
        'bssn' => ['BSSN · input manual', 1440, null],
        'kemkes' => ['Kemenkes CSIRT · input manual', 1440, null],
        'manual' => ['Observasi internal', 1440, null],
        'offline' => ['Paket offline', 1440, null],
    ],
];
