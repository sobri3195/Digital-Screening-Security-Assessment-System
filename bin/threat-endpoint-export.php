<?php
declare(strict_types=1);

// Run by an authorized operator with local PHP database access.
require dirname(__DIR__) . '/app/Core/bootstrap.php';

if (PHP_SAPI !== 'cli') {
    exit(1);
}
$cursorCve = $argv[1] ?? '0';
$cursorAdvisory = $argv[2] ?? '0';
if (!preg_match('/^[0-9]{1,18}$/D', $cursorCve) || !preg_match('/^[0-9]{1,18}$/D', $cursorAdvisory)) {
    fwrite(STDERR, "Penggunaan: php bin/threat-endpoint-export.php [after_cve] [after_advisory]\n");
    exit(2);
}
$vulnerabilities = [];
$advisories = [];
$cveBytes = $advisoryBytes = 0;
foreach (query('SELECT id,cve,vendor,product,description,cvss,severity,kev_added_on,kev_due_on,kev_action,epss,epss_on,nvd_evidence
        FROM ti_vulnerabilities WHERE id>? ORDER BY id LIMIT 200', [$cursorCve]) as $row) {
    $meta = json_decode($row['nvd_evidence'] ?? '{}', true, 64, JSON_THROW_ON_ERROR);
    $entry = [
        'cve'=>$row['cve'], 'vendor'=>$row['vendor'], 'product'=>$row['product'], 'description'=>mb_substr($row['description'] ?? '', 0, 3000),
        'cvss'=>$row['cvss'], 'severity'=>$row['severity'], 'kev_added'=>$row['kev_added_on'], 'kev_due'=>$row['kev_due_on'],
        'required_action'=>mb_substr($row['kev_action'] ?? '', 0, 1800), 'epss'=>$row['epss'], 'epss_on'=>$row['epss_on'],
        'products'=>array_slice($meta['products'] ?? [], 0, 100), 'weaknesses'=>array_slice($meta['weaknesses'] ?? [], 0, 30),
    ];
    $cveBytes += strlen(json_encode($entry, JSON_THROW_ON_ERROR));
    if ($cveBytes > 1800000 && $vulnerabilities) {
        break;
    }
    $vulnerabilities[] = $entry;
    $cursorCve = $row['id'];
}
foreach (query("SELECT id,title,publisher,published_on AS published,summary,cve,reference_text AS reference
        FROM ti_advisories WHERE id>? AND state<>'arsip' ORDER BY id LIMIT 200", [$cursorAdvisory]) as $row) {
    $id = $row['id'];
    unset($row['id']);
    $row['summary'] = mb_substr($row['summary'], 0, 3000);
    $advisoryBytes += strlen(json_encode($row, JSON_THROW_ON_ERROR));
    if ($advisoryBytes > 800000 && $advisories) {
        break;
    }
    $advisories[] = $row;
    $cursorAdvisory = $id;
}
$updated = query('SELECT MAX(last_success_at) FROM ti_providers')->fetchColumn();
$payload = base64_encode(json_encode(['vulnerabilities'=>$vulnerabilities, 'advisories'=>$advisories,
    'source_updated_at'=>$updated ? gmdate('Y-m-d\TH:i:s\Z', strtotime($updated)) : null],
    JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
echo json_encode(['format'=>'sentinel-endpoint-v1', 'sha256'=>hash('sha256', $payload), 'payload'=>$payload,
    'next_after_cve'=>$cursorCve, 'next_after_advisory'=>$cursorAdvisory], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), PHP_EOL;
