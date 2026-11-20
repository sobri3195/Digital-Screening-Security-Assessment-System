<?php
declare(strict_types=1);

require dirname(__DIR__) . '/app/Core/bootstrap.php';

if (PHP_SAPI !== 'cli') {
    exit(1);
}
$cve = strtoupper($argv[1] ?? '');
if (!preg_match('/^CVE-[0-9]{4}-[0-9]{4,19}$/D', $cve)) {
    fwrite(STDERR, "Penggunaan: php bin/threat-ai-export.php CVE-YYYY-NNNN\n");
    exit(2);
}
$docs = Sentinel\Services\Ai\CveDrafts::forCve($cve);
if (!$docs) {
    fwrite(STDERR, "Tidak ada observasi CISA, NVD atau FIRST yang dapat diekspor.\n");
    exit(3);
}
echo json_encode($docs,JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), PHP_EOL;
