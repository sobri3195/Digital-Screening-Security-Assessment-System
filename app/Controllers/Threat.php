<?php
declare(strict_types=1);
namespace Sentinel\Controllers;

use Sentinel\Core\Auth;
use Sentinel\Core\Http;
use Sentinel\Services\Threat\{AdvisoryImport, Analysis, Catalog, Feeds, Indicator, IntelligenceReports, Queue, Store, Transfer};

final class Threat
{
    public const PAGES = [
        'dashboard' => ['Threat Intelligence Dashboard','dashboard.view'],
        'scan' => ['Threat Scanner','scan.execute'],
        'urls' => ['URL Intelligence','scan.execute'],
        'domains' => ['Domain Intelligence','scan.execute'],
        'ips' => ['IP Intelligence','scan.execute'],
        'hashes' => ['File Hash Intelligence','scan.execute'],
        'phishing' => ['Phishing Intelligence','scan.execute'],
        'malware' => ['Malware Intelligence','indicator.view'],
        'vulnerabilities' => ['Vulnerability Intelligence','vulnerability.view'],
        'advisories' => ['Security Advisory','advisory.view'],
        'brand' => ['Institutional Brand Protection','scan.execute'],
        'indicators' => ['Indicator of Compromise','indicator.view'],
        'correlation' => ['Threat Correlation','scan.execute'],
        'feeds' => ['Threat Feed Management','provider.manage'],
        'monitor' => ['Data Collection Monitor','audit.view'],
        'alerts' => ['Threat Alerts','alert.manage'],
        'reports' => ['Threat Reports','dashboard.view'],
        'settings' => ['Intelligence Settings','settings.manage'],
    ];

    private const SCANNERS = ['scan' => '', 'urls' => 'url', 'domains' => 'domain', 'ips' => 'ip', 'hashes' => 'hash', 'phishing' => 'url', 'brand' => 'domain', 'correlation' => ''];

    public static function handle(string $route, array $user, bool $post): array
    {
        if (!$post && preg_match('~^reports/(\d+)(/pdf)?$~D', $route, $match)) {
            Auth::require($user, 'threat.dashboard.view');
            $report = IntelligenceReports::document((int) $match[1], (int) $user['id'],
                Auth::allows($user, 'threat.report.approve'), isset($match[2]));
            return ['preview', ['title' => 'Pratinjau Laporan Intelijen', 'pdf_url' => '/threat/reports/' . $match[1] . '/pdf'] + $report];
        }
        if (!isset(self::PAGES[$route])) {
            throw new Http(404, 'Halaman intelijen tidak ditemukan.');
        }
        [$title, $permission] = self::PAGES[$route];
        Auth::require($user, 'threat.' . $permission);
        $uid = (int) $user['id'];
        if ($post) {
            Http::limit('threat-action:' . $uid, 45);
            self::action($route, $user);
        }
        $id = Catalog::id($_GET, 'id', true);
        $page = ['title' => $title, 'route' => $route, 'id' => $id];
        if (array_key_exists($route, self::SCANNERS)) {
            $expected = self::SCANNERS[$route];
            $kinds = ['ip' => ['ipv4','ipv6'], 'hash' => ['sha256','sha1','md5']][$expected] ?? ($expected === '' ? Indicator::KINDS : [$expected]);
            $holders = implode(',', array_fill(0, count($kinds), '?'));
            $history = query("SELECT id,kind,display_value,priority,searched_at FROM ti_scan_results WHERE user_id=? AND kind IN ($holders) ORDER BY id DESC LIMIT 25", [$uid,...$kinds])->fetchAll();
            $scan = $id ? IntelligenceReports::scan($id, $uid) : null;
            $domains = $route === 'brand' ? query('SELECT id,domain,title,active FROM ti_reference_domains ORDER BY id LIMIT 500')->fetchAll() : [];
            return ['threat/scan', $page + compact('history','scan','expected','domains')];
        }
        if (isset($_GET['export']) && $route === 'indicators') {
            Auth::require($user, 'threat.indicator.manage');
            Transfer::export(text_input($_GET, 'export') === 'csv' ? 'csv' : 'json', $uid, Catalog::id($_GET,'after',true));
        }
        $extra = match ($route) {
            'dashboard' => Catalog::summary($_GET) + [
                'latest' => Auth::allows($user, 'threat.indicator.view') ? query('SELECT i.id,i.kind,i.display_value,p.title AS provider,s.severity,s.retrieved_at FROM ti_indicator_sources s
                    JOIN ti_indicators i ON i.id=s.indicator_id JOIN ti_providers p ON p.id=s.provider_id ORDER BY s.retrieved_at DESC LIMIT 8')->fetchAll() : [],
                'priority_cves' => query('SELECT id,cve,vendor,product,cvss,epss,kev_added_on FROM ti_vulnerabilities
                    WHERE cvss>=7 OR kev_added_on IS NOT NULL ORDER BY COALESCE(cvss,0)*5+IF(kev_added_on IS NULL,0,30)+COALESCE(epss,0)*20 DESC,id DESC LIMIT 8')->fetchAll()],
            'indicators','malware' => ['rows' => Catalog::indicators($_GET, 26, $route === 'malware' ? 'malware' : ''), 'detail' => $id ? Catalog::indicator($id) : null],
            'vulnerabilities' => ['rows' => Catalog::vulnerabilities($_GET, 26), 'detail' => $id ? self::vulnerability($id, Auth::allows($user, 'technical.read')) : null],
            'advisories' => ['rows' => Catalog::advisories($_GET, 26), 'detail' => $id ? self::advisory($id, $uid) : null],
            'feeds' => ['providers' => query('SELECT p.*,(SELECT state FROM ti_sync_jobs j WHERE j.provider_id=p.id ORDER BY j.id DESC LIMIT 1) AS last_state
                FROM ti_providers p ORDER BY p.id')->fetchAll()],
            'monitor' => ['rows' => query('SELECT j.id,p.title AS provider,j.action,j.state,j.received,j.unchanged,j.rejected,j.next_attempt_at,j.last_message,j.updated_at
                FROM ti_sync_jobs j JOIN ti_providers p ON p.id=j.provider_id WHERE j.id>? ORDER BY j.id LIMIT 26', [Catalog::id($_GET, 'after', true)])->fetchAll(),
                'detail' => $id ? self::job($id) : null],
            'alerts' => ['rows' => Catalog::alerts($_GET, 26)],
            'reports' => ['rows' => query('SELECT id,code,title,kind,created_at,approved_at FROM ti_reports WHERE id>? AND (approved_at IS NOT NULL OR user_id=? OR ?=1)
                ORDER BY id LIMIT 26', [Catalog::id($_GET, 'after', true), $uid, (int) Auth::allows($user, 'threat.report.approve')])->fetchAll()],
            'settings' => ['settings' => query('SELECT name,value FROM ti_settings ORDER BY name')->fetchAll(\PDO::FETCH_KEY_PAIR)],
        };
        return ['threat/' . (in_array($route, ['dashboard','feeds','settings'], true) ? $route : 'catalog'), $page + $extra];
    }

    private static function action(string $route, array $user): never
    {
        $action = text_input($_POST, 'action');
        $uid = (int) $user['id'];
        $return = '/threat/' . $route;
        $notice = 'Perubahan disimpan.';
        if (array_key_exists($route, self::SCANNERS) && $action === 'scan') {
            $result = Analysis::scan(text_input($_POST, 'indicator'), $uid, null, self::SCANNERS[$route], $route === 'phishing' ? 'phishing' : '');
            Http::redirect($return . '?id=' . $result['id']);
        }
        switch ($route . ':' . $action) {
            case 'brand:domain':
                Auth::require($user, 'threat.settings.manage');
                $domain = Indicator::domain(text_input($_POST, 'domain'));
                $label = Store::text($_POST['title'] ?? null, 160);
                $active = text_input($_POST, 'active');
                if ($label === null || !in_array($active, ['0','1'], true)) {
                    throw new Http(422, 'Nama domain rujukan atau status tidak valid.');
                }
                Store::transaction(static function () use ($domain,$label,$active): void {
                    if ($active === '1' && (int) query('SELECT COUNT(*) FROM ti_reference_domains WHERE active=1')->fetchColumn() >= 500
                        && !(int) query('SELECT active FROM ti_reference_domains WHERE domain=?', [$domain])->fetchColumn()) {
                        throw new Http(422, 'Maksimum 500 domain rujukan aktif.');
                    }
                    query('INSERT INTO ti_reference_domains (domain,title,active) VALUES (?,?,?) ON DUPLICATE KEY UPDATE title=VALUES(title),active=VALUES(active)',
                        [$domain,$label,(int) $active]);
                });
                break;
            case 'indicators:manual':
                Auth::require($user, 'threat.indicator.manage');
                $provider = (int) Store::provider('manual')['id'];
                Store::transaction(static fn () => Store::indicator($provider, [
                    'value' => text_input($_POST, 'indicator'), 'category' => text_input($_POST, 'category'), 'severity' => text_input($_POST, 'severity'),
                    'confidence' => text_input($_POST, 'confidence'), 'reference' => text_input($_POST, 'reference'), 'expires_at' => text_input($_POST, 'expires'),
                ]));
                break;
            case 'indicators:import':
                Auth::require($user, 'threat.indicator.manage');
                $format = text_input($_POST, 'format');
                if (!in_array($format, ['csv','json'], true)) {
                    throw new Http(422, 'Format impor tidak valid.');
                }
                $rows = Transfer::upload($_FILES['package'] ?? [], $format, $uid);
                $notice = $rows . ' observasi diproses.';
                break;
            case 'indicators:verify':
            case 'indicators:expire':
                Auth::require($user, $action === 'verify' ? 'threat.finding.verify' : 'threat.indicator.manage');
                $id = Catalog::id($_POST,'id');
                $provider = Catalog::id($_POST,'provider');
                $column = $action === 'verify' ? 'verified_at' : 'expires_at';
                query("UPDATE ti_indicator_sources SET $column=NOW() WHERE indicator_id=? AND provider_id=?", [$id,$provider]);
                $return .= '?id=' . $id;
                break;
            case 'vulnerabilities:match':
                Auth::require($user, 'threat.finding.verify');
                $id = Catalog::id($_POST,'id');
                $matched = Store::transaction(static fn () => Analysis::assetCandidates($id));
                $notice = "$matched kandidat aset baru ditandai.";
                $return .= '?id=' . $id;
                break;
            case 'vulnerabilities:asset':
                Auth::require($user, 'threat.finding.verify');
                $id = Catalog::id($_POST,'id');
                $finding = Catalog::id($_POST,'finding');
                $state = text_input($_POST, 'state');
                if (!in_array($state, Store::ASSET_STATES, true)) {
                    throw new Http(422, 'Status aset tidak valid.');
                }
                query('UPDATE ti_asset_vulnerabilities SET state=?,due_on=?,assignee_id=?,note=? WHERE id=? AND vulnerability_id=?',
                    [$state,Store::date($_POST['due'] ?? null),self::assignee(),Store::text($_POST['note'] ?? null,2000),$finding,$id]);
                $return .= '?id=' . $id;
                break;
            case 'vulnerabilities:link-incident':
            case 'vulnerabilities:unlink-incident':
                Auth::require($user, 'threat.finding.verify');
                Auth::require($user, 'technical.write');
                $id = Catalog::id($_POST,'id');
                $incident = Catalog::id($_POST,'incident');
                if (!query('SELECT 1 FROM security_incidents WHERE id=?', [$incident])->fetchColumn()
                    || !query('SELECT 1 FROM ti_vulnerabilities WHERE id=?', [$id])->fetchColumn()) {
                    throw new Http(404, 'Insiden atau kerentanan tidak ditemukan.');
                }
                if ($action === 'link-incident') {
                    query('INSERT IGNORE INTO ti_incident_links VALUES (?,?)', [$incident,$id]);
                } else {
                    query('DELETE FROM ti_incident_links WHERE incident_id=? AND vulnerability_id=?', [$incident,$id]);
                }
                $return .= '?id=' . $id;
                break;
            case 'advisories:add':
                Auth::require($user, 'threat.indicator.manage');
                $code = text_input($_POST, 'provider');
                if (!in_array($code,['bssn','kemkes','manual'],true)) {
                    throw new Http(422, 'Pilih organisasi penerbit yang didukung.');
                }
                $provider = Store::provider($code);
                $publisher = ['bssn'=>'BSSN','kemkes'=>'Kemenkes CSIRT','manual'=>'Observasi internal'][$code];
                $id = Store::transaction(static function () use ($provider,$publisher): int {
                    $id = Store::advisory((int) $provider['id'],$publisher,$_POST);
                    if (!empty($_POST['healthcare'])) {
                        Store::alert('healthcare:' . $id,'advisori','Advisori kesehatan perlu ditinjau','medium','/threat/advisories?id=' . $id);
                    }
                    return $id;
                });
                $return .= '?id=' . $id;
                break;
            case 'advisories:import':
                Auth::require($user, 'threat.indicator.manage');
                $code = text_input($_POST, 'provider');
                $entries = AdvisoryImport::upload($_FILES['advisory'] ?? [], text_input($_POST,'format'));
                $notice = AdvisoryImport::store($code, $entries) . ' entri advisori diproses.';
                break;
            case 'advisories:read':
            case 'advisories:bookmark':
                $id = Catalog::id($_POST, 'id');
                self::advisory($id, $uid);
                if ($action === 'read') {
                    query('INSERT INTO ti_advisory_bookmarks (advisory_id,user_id,read_at) VALUES (?,?,NOW()) ON DUPLICATE KEY UPDATE read_at=NOW()', [$id,$uid]);
                } else {
                    query('INSERT INTO ti_advisory_bookmarks (advisory_id,user_id,bookmarked) VALUES (?,?,1) ON DUPLICATE KEY UPDATE bookmarked=NOT bookmarked', [$id,$uid]);
                }
                $return .= '?id=' . $id;
                break;
            case 'advisories:follow':
                Auth::require($user, 'threat.finding.verify');
                $id = Catalog::id($_POST, 'id');
                $state = text_input($_POST,'state');
                if (!in_array($state,['baru','ditinjau','mitigasi','arsip'],true)) {
                    throw new Http(422, 'Status advisori tidak valid.');
                }
                query('UPDATE ti_advisories SET state=?,assignee_id=?,analyst_note=? WHERE id=?',
                    [$state,self::assignee(),Store::text($_POST['note'] ?? null,2000),$id]);
                $return .= '?id=' . $id;
                break;
            case 'feeds:save':
                $code = text_input($_POST,'provider');
                $active = text_input($_POST,'active');
                $interval = (int) text_input($_POST,'interval');
                if (!in_array($code,Feeds::AUTOMATED,true) || !in_array($active,['0','1'],true) || $interval<30 || $interval>10080) {
                    throw new Http(422, 'Provider atau jadwal tidak valid.');
                }
                if ($active === '1' && !Feeds::configured($code)) {
                    throw new Http(422, 'Konfigurasikan kredensial provider sebelum mengaktifkannya.');
                }
                query('UPDATE ti_providers SET next_run=IF(enabled=0,NOW(),TIMESTAMPADD(MINUTE,?,NOW())),enabled=?,interval_minutes=? WHERE code=?',
                    [$interval,(int) $active,$interval,$code]);
                break;
            case 'feeds:preview':
            case 'feeds:sync':
                Auth::require($user, 'threat.sync.execute');
                $job = Queue::enqueue(text_input($_POST,'provider'), $action, $uid);
                Http::redirect('/threat/monitor?id=' . $job);
            case 'alerts:status':
                $id = Catalog::id($_POST,'id');
                $status = text_input($_POST,'status');
                if (!in_array($status,['baru','dibaca','dikonfirmasi','selesai'],true)) {
                    throw new Http(422, 'Status alert tidak valid.');
                }
                query('UPDATE ti_alerts SET status=?,assignee_id=?,acknowledged_by=IF(?=1,?,acknowledged_by) WHERE id=?',
                    [$status,self::assignee(),(int) ($status === 'dikonfirmasi'),$uid,$id]);
                break;
            case 'reports:create':
                Auth::require($user, 'threat.report.generate');
                $kind = text_input($_POST,'kind');
                $scan = Catalog::id($_POST,'scan_id',true);
                if ($scan) {
                    Auth::require($user, 'threat.scan.execute');
                } else {
                    $permission = match ($kind) {
                        'vulnerability', 'asset' => 'threat.vulnerability.view',
                        'healthcare' => 'threat.advisory.view',
                        'brand' => 'threat.scan.execute',
                        default => 'threat.indicator.view',
                    };
                    Auth::require($user, $permission);
                    if ($kind === 'asset') {
                        Auth::require($user, 'technical.read');
                    }
                }
                $id = IntelligenceReports::create($kind, $scan, $uid);
                Http::redirect($return . '/' . $id);
            case 'reports:approve':
                Auth::require($user, 'threat.report.approve');
                $id = Catalog::id($_POST,'id');
                IntelligenceReports::approve($id, $uid);
                break;
            case 'settings:save':
                $days = (int) text_input($_POST,'history_days');
                $priority = (int) text_input($_POST,'alert_priority');
                if ($days<7 || $days>365 || $priority<15 || $priority>100) {
                    throw new Http(422, 'Retensi 7–365 hari dan ambang skor 15–100.');
                }
                Store::transaction(static function () use ($days,$priority): void {
                    query("UPDATE ti_settings SET value=? WHERE name='history_days'", [(string) $days]);
                    query("UPDATE ti_settings SET value=? WHERE name='alert_priority'", [(string) $priority]);
                });
                break;
            default:
                throw new Http(405,'Aksi tidak tersedia.');
        }
        audit($uid, $action, 'threat:' . $route);
        $_SESSION['notice'] = $notice;
        Http::redirect($return);
    }

    private static function assignee(): ?int
    {
        $id = Catalog::id($_POST,'assignee',true);
        if ($id && !query('SELECT 1 FROM users WHERE id=? AND active=1', [$id])->fetchColumn()) {
            throw new Http(422, 'Akun petugas tidak ditemukan atau nonaktif.');
        }
        return $id ?: null;
    }

    private static function vulnerability(int $id, bool $assetAccess): array
    {
        $row = query('SELECT * FROM ti_vulnerabilities WHERE id=?', [$id])->fetch();
        if (!$row) {
            throw new Http(404, 'Kerentanan tidak ditemukan.');
        }
        $row['kev_history'] = query('SELECT status,observed_at,sync_job_id,evidence_sha256 FROM ti_kev_history
            WHERE vulnerability_id=? ORDER BY id DESC LIMIT 25', [$id])->fetchAll();
        $row['incidents'] = $assetAccess ? query('SELECT i.id,i.title FROM ti_incident_links l JOIN security_incidents i ON i.id=l.incident_id
            WHERE vulnerability_id=? ORDER BY i.id DESC LIMIT 25', [$id])->fetchAll() : [];
        $row['assets'] = $assetAccess ? query('SELECT av.*,a.code,a.title FROM ti_asset_vulnerabilities av JOIN institutional_assets a ON a.id=av.asset_id
            WHERE av.vulnerability_id=? ORDER BY av.id DESC LIMIT 100', [$id])->fetchAll() : [];
        return $row;
    }

    private static function advisory(int $id, int $user): array
    {
        $row = query('SELECT a.*,b.bookmarked,b.read_at FROM ti_advisories a LEFT JOIN ti_advisory_bookmarks b ON b.advisory_id=a.id AND b.user_id=? WHERE a.id=?', [$user,$id])->fetch();
        if (!$row) {
            throw new Http(404, 'Advisori tidak ditemukan.');
        }
        return $row;
    }

    private static function job(int $id): array
    {
        $job = query('SELECT j.id,j.state,j.last_message,j.preview,j.received,j.unchanged,j.rejected,p.title AS provider
            FROM ti_sync_jobs j JOIN ti_providers p ON p.id=j.provider_id WHERE j.id=?', [$id])->fetch();
        if (!$job) {
            throw new Http(404, 'Job tidak ditemukan.');
        }
        $job['logs'] = query('SELECT state,message,created_at FROM ti_sync_logs WHERE job_id=? ORDER BY id DESC LIMIT 50', [$id])->fetchAll();
        return $job;
    }
}
