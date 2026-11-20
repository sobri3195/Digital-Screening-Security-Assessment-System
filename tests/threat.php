<?php
declare(strict_types=1);
require dirname(__DIR__) . '/app/Core/bootstrap.php';

use Sentinel\Core\Http;
use Sentinel\Services\Threat\{AdvisoryImport, Analysis, FeedFailure, Feeds, Indicator, Queue, Store, Transfer};

$checks = 0;
function verify(bool $success, string $text): void
{
    if (!$success) {
        throw new RuntimeException($text);
    }
    $GLOBALS['checks']++;
    echo "PASS $text\n";
}

$inputs = ['https://ExAMPle.test:443/path?q=secret#anchor'=>'url','bücher.test'=>'domain','192.0.2.1'=>'ipv4',
    '2001:db8:0::1'=>'ipv6',str_repeat('a',32)=>'md5',str_repeat('b',40)=>'sha1',str_repeat('f',64)=>'sha256','cve-2099-12345'=>'cve'];
foreach ($inputs as $input => $kind) {
    verify(Indicator::parse($input)['kind'] === $kind, 'Normalisasi ' . $kind);
}
$url = Indicator::parse(array_key_first($inputs));
verify($url['value'] === 'hxxps://example[.]test/path' && $url['fingerprint'] !== Indicator::parse('https://example.test/path')['fingerprint'], 'redaksi query dan fragmen tanpa kehilangan pencocokan persis');
verify(Indicator::parse('192.0.2.1')['scope'] === 'non-global', 'Rentang dokumentasi bukan global');
foreach (['file:///etc/passwd','https://demo:secret@example.test','https://bad host.test','0127.0.0.1'] as $invalid) {
    try {
        Indicator::parse($invalid);
        throw new LogicException('Accepted invalid indicator');
    } catch (Http $e) {
        verify($e->status === 422, 'Input invalid ditolak');
    }
}
$bundle = Transfer::pack([['value'=>'example[.]test']], 33, 0);
verify(Transfer::unpack($bundle)[0]['value'] === 'example[.]test', 'Round trip paket offline');
try {
    Transfer::unpack(str_replace('sha256','tamper', $bundle));
    throw new LogicException('Accepted broken bundle');
} catch (Http $e) {
    verify($e->status === 422, 'Checksum paket ditolak');
}
$rss = '<rss version="2.0"><channel><item><title>TEST advisory</title><description>TEST summary</description><link>https://example.test/a</link></item></channel></rss>';
verify(AdvisoryImport::parse($rss, 'rss')[0]['title'] === 'TEST advisory', 'Parser RSS offline');
verify(AdvisoryImport::parse('<article><h2>TEST HTML</h2><p>TEST summary</p></article>', 'html')[0]['title'] === 'TEST HTML', 'Parser DOM offline');
try {
    AdvisoryImport::parse('<!DOCTYPE rss [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss>&x;</rss>', 'rss');
    throw new LogicException('Accepted XML DTD');
} catch (Http $e) {
    verify($e->status === 422, 'DTD dan entitas eksternal ditolak');
}
$fixture = json_decode(file_get_contents(__DIR__ . '/fixtures/threat-cisa-test.json'), true, 64, JSON_THROW_ON_ERROR);
[$rows, $rejected] = Feeds::parse('cisa', $fixture);
verify($rejected === 0 && $rows[0]['added'] !== $rows[0]['due'], 'Tanggal penambahan KEV berbeda dari tenggat');
[$nvd] = Feeds::parse('nvd', ['vulnerabilities' => [['cve'=>['id'=>'CVE-2099-12345','descriptions'=>[['lang'=>'en','value'=>'TEST NVD']],
    'metrics'=>['cvssMetricV31'=>[['type'=>'Primary','cvssData'=>['baseScore'=>8.8,'baseSeverity'=>'HIGH']]]],
    'configurations'=>[['nodes'=>[['cpeMatch'=>[['vulnerable'=>true,'criteria'=>'cpe:2.3:a:test_vendor:test_product:*:*:*:*:*:*:*:*',
        'versionEndExcluding'=>'2.1']]]]]]]]]]);
verify($nvd[0]['products'][0]['product'] === 'test_product' && $nvd[0]['cvss'] === 8.8, 'Parser NVD CVSS dan CPE');
verify(!Analysis::versions('2.1', $nvd[0]['products'][0]) && Analysis::versions('2.0',$nvd[0]['products'][0]), 'Batas versi aset');
[$epss] = Feeds::parse('epss', ['data'=>[['cve'=>'CVE-2099-12345','date'=>'2026-01-15','epss'=>'0.345','percentile'=>'0.800']]]);
verify($epss[0]['epss'] === 0.345, 'Parser FIRST EPSS');
[$hashes] = Feeds::parse('malwarebazaar',['query_status'=>'ok','data'=>[['sha256_hash'=>str_repeat('a',64),'signature'=>'TEST family']]]);
verify($hashes[0]['normalized']['kind'] === 'sha256' && $hashes[0]['family'] === 'TEST family', 'Parser metadata hash MalwareBazaar');
[$ti] = Feeds::parse('threatfox',['query_status'=>'ok','data'=>[['ioc'=>'192.0.2.22:443','confidence_level'=>80]]]);
verify($ti[0]['normalized']['kind'] === 'ipv4', 'Parser ThreatFox IP dan port');
[$haus] = Feeds::parse('urlhaus',['query_status'=>'ok','urls'=>[['url'=>'https://example.test/test','url_status'=>'offline']]]);
verify($haus[0]['category'] === 'malware' && $haus[0]['observed_state'] === 'offline', 'URLhaus kategori malware dan status observasi');
try {
    Feeds::parse('cisa', ['vulnerabilities'=>[['cveID'=>'TEST-invalid']]]);
    throw new LogicException('Accepted invalid provider response');
} catch (FeedFailure) {
    verify(true,'Respons feed invalid ditolak');
}
verify(Analysis::vulnerabilityPriority(['cvss'=>10,'epss'=>1,'kev_added_on'=>'2026-01-15'])['score'] === 100, 'Perhitungan skor transparan 100');
if (in_array('--integration', $argv, true)) {
    if (!str_starts_with(config('DB_NAME'), 'sentinel_phase_')) {
        throw new LogicException('Use a disposable sentinel_phase_ database.');
    }
    query("UPDATE ti_providers SET enabled=1,next_run=NOW() WHERE code='cisa'");
    $id = Queue::enqueue('cisa','sync',null);
    verify(Queue::enqueue('cisa','sync',null) === $id, 'Dedup antrean');
    verify(Queue::work(1, static function (): never { throw new FeedFailure('TEST rate limit',true,120); }) === 1, 'Worker menangani rate limit');
    $job = query('SELECT state,TIMESTAMPDIFF(SECOND,NOW(),next_attempt_at) AS delay FROM ti_sync_jobs WHERE id=?', [$id])->fetch();
    verify($job['state'] === 'retry' && $job['delay'] >= 115, 'Backoff dan Retry-After');
    query('UPDATE ti_sync_jobs SET next_attempt_at=NOW() WHERE id=?', [$id]);
    verify(Queue::work(1, static fn () => $fixture) === 1, 'Worker melanjutkan retry');
    verify(query("SELECT cve FROM ti_vulnerabilities WHERE cve='CVE-2099-12345'")->fetchColumn() === 'CVE-2099-12345', 'CVE tersimpan');
    $again = Queue::enqueue('cisa','sync',null);
    Queue::work(1, static fn () => $fixture);
    verify((int) query('SELECT unchanged FROM ti_sync_jobs WHERE id=?',[$again])->fetchColumn() === 1, 'Sinkronisasi berulang dideduplikasi');
    $replacement = $fixture;
    $replacement['vulnerabilities'][0]['cveID'] = 'CVE-2099-99999';
    $replacement['dateReleased'] = '2026-01-16T12:00:00Z';
    $partial = $replacement;
    $partial['count'] = 2;
    $partialId = Queue::enqueue('cisa','sync',null);
    Queue::work(1, static fn () => $partial);
    verify(query('SELECT state FROM ti_sync_jobs WHERE id=?', [$partialId])->fetchColumn() === 'failed'
        && query("SELECT kev_added_on FROM ti_vulnerabilities WHERE cve='CVE-2099-12345'")->fetchColumn() !== null, 'Snapshot tidak lengkap tidak mengubah status KEV');
    Queue::enqueue('cisa','sync',null);
    Queue::work(1, static fn () => $replacement);
    $removed = query("SELECT v.kev_added_on,h.status,h.evidence,h.evidence_sha256 FROM ti_vulnerabilities v
        JOIN ti_kev_history h ON h.vulnerability_id=v.id WHERE v.cve='CVE-2099-12345' ORDER BY h.id DESC LIMIT 1")->fetch();
    verify($removed['kev_added_on'] === null && $removed['status'] === 'removed'
        && hash('sha256',$removed['evidence']) === $removed['evidence_sha256'], 'Snapshot lengkap menghapus status KEV dan menyimpan bukti');
    $staleId = Queue::enqueue('cisa','sync',null);
    Queue::work(1, static fn () => $fixture);
    verify(query('SELECT state FROM ti_sync_jobs WHERE id=?', [$staleId])->fetchColumn() === 'failed', 'Snapshot lama ditolak');
    query("INSERT INTO institutional_assets (code,title,brand,model) VALUES ('TEST-AUTOMATCH','TEST automatic asset','TEST Vendor','TEST Product')");
    verify(Analysis::matchAssetBatch(25) > 0 && Analysis::matchAssetBatch(25) === 0, 'Pencocokan aset otomatis bertahap dan idempoten');
    query("UPDATE ti_providers SET enabled=1,checkpoint=? WHERE code='nvd'", ['{"watermark":"2026-01-01T00:00:00.000Z"}']);
    $historyId = Queue::nvdBackfill('2000-01-01','2000-07-01');
    $windows = [];
    $fetch = static function (string $url) use (&$windows): array {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $parameters);
        $windows[] = $parameters;
        return ['startIndex'=>0,'totalResults'=>0,'vulnerabilities'=>[]];
    };
    Queue::work(1, $fetch);
    query('UPDATE ti_sync_jobs SET next_attempt_at=NOW() WHERE id=?', [$historyId]);
    Queue::work(1, $fetch);
    verify(count($windows) === 2 && isset($windows[0]['pubStartDate'], $windows[1]['pubEndDate'])
        && strtotime($windows[1]['pubStartDate']) === strtotime($windows[0]['pubEndDate']) + 1
        && query('SELECT state FROM ti_sync_jobs WHERE id=?', [$historyId])->fetchColumn() === 'succeeded'
        && json_decode(Store::provider('nvd')['checkpoint'], true)['watermark'] === '2026-01-01T00:00:00.000Z',
        'Backfill NVD melanjutkan rentang berurutan tanpa menggeser watermark sinkronisasi');
    query("UPDATE ti_providers SET enabled=0 WHERE code='nvd'");
    $provider = (int) Store::provider('manual')['id'];
    $ioc = ['value'=>'test-indicator.example.test','severity'=>'critical','confidence'=>90,'category'=>'phishing','first_seen'=>gmdate('Y-m-d\TH:i:s\Z')];
    Store::transaction(static fn () => Store::indicator($provider, $ioc));
    $match = Analysis::scan('https://test-indicator.example.test/demo?q=redacted', null, null, 'url');
    verify(count($match['matches']) === 1 && $match['matches'][0]['basis'] !== 'Indikator persis', 'Korelasi hostname lokal dan bukti');
    $evidence = query("SELECT evidence,evidence_sha256 FROM ti_indicator_sources WHERE evidence_sha256=?", [$match['matches'][0]['metadata']['evidence_sha256']])->fetch();
    verify(hash('sha256',$evidence['evidence']) === $evidence['evidence_sha256'], 'Integritas bukti tersimpan');
    Analysis::scan('test-indicator.example.test',null);
    Analysis::scan('test-indicator.example.test',null);
    verify((int) query("SELECT COUNT(*) FROM ti_alerts WHERE category='pemeriksaan'")->fetchColumn() === 2, 'Alert URL dan domain terpisah serta deduplikasi pemeriksaan berulang');
    query("UPDATE ti_providers SET enabled=0 WHERE code='cisa'");
}
echo "$checks checks passed.\n";
