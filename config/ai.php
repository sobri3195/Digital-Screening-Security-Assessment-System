<?php
declare(strict_types=1);

return [
    'permissions' => [
        'ai.dashboard.view', 'ai.analysis.execute', 'ai.threat.analyze', 'ai.vulnerability.analyze', 'ai.malware.analyze',
        'ai.configuration.analyze', 'ai.mitigation.generate', 'ai.report.generate', 'ai.report.review',
        'ai.knowledge.view', 'ai.knowledge.manage', 'ai.knowledge.approve', 'ai.model.manage', 'ai.template.manage',
        'ai.template.approve', 'ai.evaluation.execute', 'ai.audit.view', 'ai.settings.manage',
    ],
    'roles' => [
        'Administrator' => ['dashboard.view','analysis.execute','threat.analyze','vulnerability.analyze','configuration.analyze','knowledge.view','knowledge.manage'],
        'Petugas Pemeriksaan' => ['dashboard.view','analysis.execute','threat.analyze','vulnerability.analyze','malware.analyze','configuration.analyze','mitigation.generate','knowledge.view','report.generate'],
        'Supervisor' => ['dashboard.view','analysis.execute','threat.analyze','vulnerability.analyze','malware.analyze','configuration.analyze','mitigation.generate','report.generate','report.review','knowledge.view','knowledge.approve','evaluation.execute','audit.view'],
        'Pimpinan' => ['dashboard.view','analysis.execute','report.generate'],
        'Auditor' => ['audit.view'],
    ],
];
