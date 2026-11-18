<?php
declare(strict_types=1);
require dirname(__DIR__) . '/app/Core/bootstrap.php';

use Sentinel\Services\Threat\{Catalog, Indicator, Store};

if (!in_array(config('DB_NAME'), ['sentinel_phase_benchmark','sentinel_phase_benchmark_optimized'], true)
    || (int) query('SELECT COUNT(*) FROM ti_indicators')->fetchColumn() !== 0) {
    fwrite(STDERR, "Gunakan database disposable kosong sentinel_phase_benchmark.\n");
    exit(2);
}
$provider = (int) Store::provider('manual')['id'];
query('CREATE TEMPORARY TABLE ti_bench_digit (n INT UNSIGNED PRIMARY KEY)');
query('INSERT INTO ti_bench_digit VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9)');
$loaded = 0;
$started = hrtime(true);
foreach ([10000,100000,1000000] as $target) {
    while ($loaded < $target) {
        Store::transaction(static function () use ($loaded, $provider): void {
            $start = (int) query('SELECT COALESCE(MAX(id),0) FROM ti_indicators')->fetchColumn();
            query("INSERT INTO ti_indicators (kind,fingerprint,display_value,host)
                SELECT 'domain',SHA2(CONCAT('test-',v,'.example.test'),256),CONCAT('test-',v,'[.]example[.]test'),CONCAT('test-',v,'.example.test')
                FROM (SELECT ?+a.n+b.n*10+c.n*100+d.n*1000 AS v FROM ti_bench_digit a CROSS JOIN ti_bench_digit b
                    CROSS JOIN ti_bench_digit c CROSS JOIN ti_bench_digit d) samples", [$loaded]);
            query("INSERT INTO ti_indicator_sources (indicator_id,provider_id,category,severity,evidence,evidence_sha256,parser_version)
                SELECT id,?,'unknown','unknown','{\"fixture\":\"TEST\"}',SHA2('{\"fixture\":\"TEST\"}',256),'test-1' FROM ti_indicators WHERE id>?", [$provider,$start]);
        });
        $loaded += 10000;
    }
    $elapsed = (hrtime(true) - $started) / 1e9;
    $start = hrtime(true);
    for ($n = 0; $n < 100; $n++) {
        $ioc = Indicator::parse('test-' . intdiv($target, 2) . '.example.test');
        if (!query('SELECT id FROM ti_indicators WHERE kind=? AND fingerprint=?', [$ioc['kind'],$ioc['fingerprint']])->fetchColumn()) {
            throw new RuntimeException('Pencarian indeks gagal.');
        }
    }
    $average = (hrtime(true) - $start) / 1e8;
    $start = hrtime(true);
    $rows = Catalog::indicators(['kind'=>'domain','after'=>(string) intdiv($target,2)]);
    if (count($rows) !== 25) {
        throw new RuntimeException('Halaman katalog kosong.');
    }
    $page = (hrtime(true) - $start) / 1e6;
    printf("%d IOC | muat kumulatif %.2f s | pencarian rata-rata %.2f ms | halaman %.2f ms | peak PHP %.1f MiB\n",
        $target,$elapsed,$average,$page,memory_get_peak_usage(true)/1048576);
}
