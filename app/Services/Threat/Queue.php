<?php
declare(strict_types=1);
namespace Sentinel\Services\Threat;

use Sentinel\Core\Http;

final class Queue
{
    public static function enqueue(string $code, string $action, ?int $user): int
    {
        if (!in_array($code, Feeds::AUTOMATED, true) || !Feeds::configured($code) || !in_array($action, ['sync','preview'], true)) {
            throw new Http(422, 'Provider otomatis atau kredensial belum dikonfigurasi.');
        }
        return Store::transaction(static function () use ($code, $action, $user): int {
            $provider = query('SELECT * FROM ti_providers WHERE code=? FOR UPDATE', [$code])->fetch();
            if (!$provider || ($action === 'sync' && !$provider['enabled'])) {
                throw new Http(422, 'Aktifkan provider sebelum sinkronisasi.');
            }
            $pending = query("SELECT id FROM ti_sync_jobs WHERE provider_id=? AND action=? AND state IN ('queued','running','retry') ORDER BY id LIMIT 1",
                [$provider['id'], $action])->fetchColumn();
            if ($pending) {
                return (int) $pending;
            }
            $checkpoint = $action === 'sync' ? $provider['checkpoint'] : null;
            query('INSERT INTO ti_sync_jobs (provider_id,requested_by,action,checkpoint) VALUES (?,?,?,?)', [$provider['id'], $user, $action, $checkpoint]);
            $id = (int) db()->lastInsertId();
            self::log($id, 'queued', $action === 'sync' ? 'Sinkronisasi dijadwalkan.' : 'Uji koneksi dan parser dijadwalkan.');
            audit($user, 'jadwalkan-' . $action, 'threat');
            return $id;
        });
    }

    public static function schedule(): int
    {
        $count = 0;
        $items = query('SELECT code FROM ti_providers WHERE enabled=1 AND (next_run IS NULL OR next_run<=NOW()) ORDER BY id')->fetchAll(\PDO::FETCH_COLUMN);
        foreach ($items as $code) {
            if (in_array($code, Feeds::AUTOMATED, true) && Feeds::configured($code)) {
                self::enqueue($code, 'sync', null);
                $count++;
            }
        }
        return $count;
    }

    public static function work(int $limit, ?callable $fetch = null): int
    {
        $lock = 'ti-worker:' . substr(hash('sha256', config('DB_NAME', 'puskesau_sentinel')), 0, 40);
        if ((int) query('SELECT GET_LOCK(?,0)', [$lock])->fetchColumn() !== 1) {
            return 0;
        }
        $processed = 0;
        try {
            while ($processed < $limit && ($job = self::claim())) {
                self::run($job, $fetch);
                $processed++;
            }
        } finally {
            query('SELECT RELEASE_LOCK(?)', [$lock]);
        }
        return $processed;
    }

    private static function claim(): ?array
    {
        return Store::transaction(static function (): ?array {
            $job = query("SELECT j.*,p.code,p.enabled,p.interval_minutes FROM ti_sync_jobs j JOIN ti_providers p ON p.id=j.provider_id
                WHERE (j.state IN ('queued','retry') AND j.next_attempt_at<=NOW()) OR (j.state='running' AND j.lease_until<=NOW()) ORDER BY j.next_attempt_at,j.id LIMIT 1 FOR UPDATE")->fetch();
            if (!$job) {
                return null;
            }
            $job['lease_token'] = bin2hex(random_bytes(16));
            $job['attempts']++;
            query("UPDATE ti_sync_jobs SET state='running',lease_until=NOW()+INTERVAL 5 MINUTE,lease_token=?,attempts=? WHERE id=?", [$job['lease_token'], $job['attempts'], $job['id']]);
            self::log((int) $job['id'], 'running', 'Worker mengambil job.');
            return $job;
        });
    }

    private static function run(array $job, ?callable $fetch): void
    {
        if ($job['action'] === 'sync' && !$job['enabled']) {
            self::finish($job, 'cancelled', 'Provider dinonaktifkan.', 0);
            return;
        }
        try {
            $result = Feeds::pull($job['code'], json_decode($job['checkpoint'] ?? '{}', true, 64, JSON_THROW_ON_ERROR), $job['action'] === 'preview', $fetch);
            Store::transaction(static function () use ($job, $result): void {
                $provider = query('SELECT enabled FROM ti_providers WHERE id=? FOR UPDATE', [$job['provider_id']])->fetch();
                $lease = query('SELECT lease_token FROM ti_sync_jobs WHERE id=? FOR UPDATE', [$job['id']])->fetchColumn();
                if ($lease !== $job['lease_token']) {
                    return;
                }
                if ($job['action'] === 'sync' && !$provider['enabled']) {
                    self::finish($job, 'cancelled', 'Provider dinonaktifkan.', 0);
                    return;
                }
                $unchanged = 0;
                if ($job['action'] === 'sync' && $job['code'] === 'cisa') {
                    $unchanged = Store::applyKevSnapshot($result['rows'], (int) $job['id']);
                } elseif ($job['action'] === 'sync') {
                    foreach ($result['rows'] as $row) {
                        $changed = in_array($job['code'], ['nvd','epss'], true)
                            ? Store::vulnerability($job['code'], $row) : Store::indicator((int) $job['provider_id'], $row);
                        $unchanged += (int) !$changed;
                    }
                }
                $preview = $job['action'] === 'preview' ? Store::json($result['rows']) : null;
                $next = $result['next'];
                $state = $next === null ? 'succeeded' : 'queued';
                query('UPDATE ti_sync_jobs SET state=?,received=received+?,rejected=rejected+?,unchanged=unchanged+?,checkpoint=?,preview=?,last_message=?,lease_until=NULL,
                    lease_token=NULL,next_attempt_at=NOW()+INTERVAL 7 SECOND,attempts=0 WHERE id=? AND lease_token=?',
                    [$state, count($result['rows']), $result['rejected'], $unchanged, $next ? Store::json($next) : null, $preview, $result['message'], $job['id'], $job['lease_token']]);
                self::log((int) $job['id'], $state, $next ? 'Halaman disimpan. Kelanjutan masuk antrean.' : $result['message']);
                if ($next === null && $job['action'] === 'sync') {
                    $hasPublicCves = $job['code'] !== 'epss' || ($job['received'] + count($result['rows'])) > 0 || $job['checkpoint'] !== null;
                    if ($hasPublicCves) {
                        query('UPDATE ti_providers SET last_success_at=NOW(),checkpoint=?,next_run=TIMESTAMPADD(MINUTE,interval_minutes,NOW()) WHERE id=?',
                            [$result['watermark'] ? Store::json($result['watermark']) : null, $job['provider_id']]);
                    } else {
                        query('UPDATE ti_providers SET next_run=TIMESTAMPADD(MINUTE,interval_minutes,NOW()) WHERE id=?', [$job['provider_id']]);
                    }
                }
            });
        } catch (FeedFailure $error) {
            $delay = max($error->delay, 60 * (2 ** min(5, max(0, $job['attempts'] - 1))));
            self::finish($job, $error->retry && $job['attempts'] < 5 ? 'retry' : 'failed', $error->getMessage(), $delay);
        } catch (\Throwable $error) {
            error_log('Sentinel Threat Intelligence: ' . get_class($error) . ' at ' . basename($error->getFile()) . ':' . $error->getLine());
            self::finish($job, 'failed', 'Validasi atau penyimpanan feed gagal.', 0);
        }
    }

    private static function finish(array $job, string $state, string $message, int $delay): void
    {
        if (query('UPDATE ti_sync_jobs SET state=?,last_message=?,next_attempt_at=TIMESTAMPADD(SECOND,?,NOW()),lease_until=NULL,lease_token=NULL WHERE id=? AND lease_token=?',
            [$state, $message, $delay, $job['id'], $job['lease_token']])->rowCount() !== 1) {
            return;
        }
        self::log((int) $job['id'], $state, $message);
        if ($state === 'failed' && $job['action'] === 'sync') {
            query('UPDATE ti_providers SET next_run=TIMESTAMPADD(MINUTE,interval_minutes,NOW()) WHERE id=?', [$job['provider_id']]);
            Store::alert('feed-failed:' . $job['id'], 'sinkronisasi', 'Sinkronisasi gagal: ' . $job['code'], 'medium', '/threat/monitor?id=' . $job['id']);
        }
    }

    private static function log(int $job, string $state, string $message): void
    {
        query('INSERT INTO ti_sync_logs (job_id,state,message) VALUES (?,?,?)', [$job, $state, $message]);
    }

    public static function maintenance(): void
    {
        $days = max(1, Store::setting('history_days'));
        query('DELETE FROM ti_scan_results WHERE searched_at < TIMESTAMPADD(DAY, -?, NOW())', [$days]);
        query("DELETE FROM ti_sync_jobs WHERE state IN ('failed','succeeded','cancelled') AND updated_at < TIMESTAMPADD(DAY,-?,NOW())", [$days]);
        $stale = query('SELECT id,code,last_success_at FROM ti_providers WHERE enabled=1 AND last_success_at IS NOT NULL AND NOW()>TIMESTAMPADD(MINUTE,interval_minutes*2,last_success_at)')->fetchAll();
        foreach ($stale as $row) {
            Store::alert('stale:' . $row['id'] . ':' . $row['last_success_at'], 'kedaluwarsa', 'Feed melewati ambang kesegaran: ' . $row['code'], 'medium', '/threat/feeds');
        }
        $assets = query("SELECT id,vulnerability_id FROM ti_asset_vulnerabilities WHERE due_on<CURDATE() AND state IN ('potensial','terkonfirmasi') ORDER BY due_on LIMIT 500")->fetchAll();
        foreach ($assets as $row) {
            Store::alert('late:' . $row['id'], 'mitigasi', 'Tenggat mitigasi internal terlewati', 'high', '/threat/vulnerabilities?id=' . $row['vulnerability_id']);
        }
    }
}
