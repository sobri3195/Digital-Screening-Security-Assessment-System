<?php
declare(strict_types=1);
require dirname(__DIR__) . '/app/Core/bootstrap.php';

use Sentinel\Services\Threat\{AdvisoryImport, Analysis, Queue};

switch ($argv[1] ?? '') {
    case 'schedule':
        echo 'Provider diperiksa: ', Queue::schedule(), PHP_EOL;
        break;
    case 'work':
        echo 'Job diproses: ', Queue::work(max(1, min(30, (int) ($argv[2] ?? 10)))), PHP_EOL;
        break;
    case 'maintenance':
        Queue::maintenance();
        echo "Pemeliharaan Threat Intelligence selesai.\n";
        break;
    case 'tick':
        Queue::schedule();
        echo 'Job diproses: ', Queue::work(10), PHP_EOL;
        echo 'Kandidat aset baru: ', Analysis::matchAssetBatch(25), PHP_EOL;
        break;
    case 'nvd-backfill':
        echo 'Job NVD: ', Queue::nvdBackfill($argv[2] ?? '', $argv[3] ?? ''), PHP_EOL;
        break;
    case 'match-assets':
        echo 'Kandidat aset baru: ', Analysis::matchAssetBatch(max(1,min(250,(int) ($argv[2] ?? 25)))), PHP_EOL;
        break;
    case 'advisory-import':
        $path = $argv[4] ?? '';
        $bytes = is_file($path) ? file_get_contents($path, false, null, 0, 1024 * 1024 + 1) : false;
        if ($bytes === false) {
            fwrite(STDERR, "Salinan advisori lokal tidak dapat dibaca.\n");
            exit(2);
        }
        $count = AdvisoryImport::store($argv[2] ?? '', AdvisoryImport::parse($bytes, $argv[3] ?? ''));
        audit(null, 'import', 'threat:advisories');
        echo 'Entri diproses: ', $count, PHP_EOL;
        break;
    default:
        fwrite(STDERR, "Penggunaan: php bin/threat.php schedule | work [jumlah] | maintenance | tick | nvd-backfill MULAI AKHIR | match-assets [jumlah] | advisory-import PROVIDER FORMAT FILE\n");
        exit(2);
}
