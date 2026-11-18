<?php
declare(strict_types=1);
require dirname(__DIR__) . '/app/Core/bootstrap.php';

use Sentinel\Services\Threat\Queue;

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
        break;
    default:
        fwrite(STDERR, "Penggunaan: php bin/threat.php schedule | work [jumlah] | maintenance | tick\n");
        exit(2);
}
