<?php
declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Core\Auth;
use Sentinel\Core\Http;
use Sentinel\Services\Ai\Gateway;
use Sentinel\Services\Branding;
use Sentinel\Services\Reports;

final class Ai
{
    public const PAGES = [
        'dashboard'=>['AI Dashboard','ai.dashboard.view'],
        'assistant'=>['AI Security Assistant','ai.analysis.execute'],
        'threat'=>['AI Threat Analyzer','ai.threat.analyze'],
        'malware'=>['AI Malware Analyst','ai.malware.analyze'],
        'vulnerability'=>['AI Vulnerability Analyst','ai.vulnerability.analyze'],
        'configuration'=>['AI Security Configuration Analyst','ai.configuration.analyze'],
        'correlation'=>['AI Threat Correlation','ai.threat.analyze'],
        'mitigation'=>['AI Mitigation Advisor','ai.mitigation.generate'],
        'report'=>['AI Report Generator','ai.report.generate'],
        'executive'=>['AI Executive Summary','ai.report.generate'],
        'knowledge'=>['AI Knowledge Base','ai.knowledge.view'],
        'rag'=>['RAG Management','ai.knowledge.view'],
        'models'=>['AI Model Manager','ai.model.manage'],
        'tasks'=>['AI Task Monitor','ai.dashboard.view'],
        'evaluation'=>['AI Evaluation Center','ai.evaluation.execute'],
        'settings'=>['AI Settings','ai.settings.manage'],
        'audit'=>['AI Audit Logs','ai.audit.view'],
    ];
    public const KINDS = [
        'threat'=>'Indikator ancaman','malware'=>'Deteksi malware','vulnerability'=>'Kerentanan CVE',
        'configuration'=>'Konfigurasi perangkat','correlation'=>'Korelasi lokal','mitigation'=>'Saran mitigasi',
        'report'=>'Laporan analisis','executive'=>'Ringkasan pimpinan','advisory'=>'Advisori yang disetujui','education'=>'Edukasi teknis',
    ];
    private const ANALYSIS_SCOPES = [
        'threat'=>'ai.threat.analyze','malware'=>'ai.malware.analyze','vulnerability'=>'ai.vulnerability.analyze',
        'configuration'=>'ai.configuration.analyze','correlation'=>'ai.threat.analyze','mitigation'=>'ai.mitigation.generate',
        'report'=>'ai.report.generate','executive'=>'ai.report.generate','advisory'=>'ai.threat.analyze','education'=>'ai.threat.analyze',
    ];

    public static function handle(string $route, array $user, bool $post): array
    {
        $scope = Gateway::sessionScopes($user);
        $actor = 'web:' . $user['id'];
        $call = static fn (string $method, string $path, ?array $payload = null) => Gateway::request($method, $path, $actor, $scope, $payload);
        if (!$post && preg_match('~^tasks/([a-f0-9]{32})(/pdf|/json|/state)?$~D', $route, $match)) {
            Auth::require($user, 'ai.dashboard.view');
            $data = $call('GET', '/tasks/' . $match[1]);
            if (($match[2] ?? '') === '/state') {
                Http::json(['state'=>$data['state']]);
            }
            if (($match[2] ?? '') === '/json') {
                header('Content-Disposition: attachment; filename="sentinel-ai-' . $match[1] . '.json"');
                audit((int) $user['id'], 'download', 'ai');
                Http::json($data);
            }
            if (($match[2] ?? '') === '/pdf') {
                Auth::require($user, 'ai.report.generate');
                self::pdf($data, (int) $user['id']);
            }
            return ['ai', ['title'=>'Rincian Tugas AI','section'=>'task','task'=>$data]];
        }
        if (!isset(self::PAGES[$route])) {
            throw new Http(404, 'Halaman AI tidak ditemukan.');
        }
        [$title, $permission] = self::PAGES[$route];
        Auth::require($user, $permission);
        $data = ['title'=>$title,'section'=>$route,'configured'=>Gateway::configured()];
        if ($post) {
            Http::limit('ai-operator:' . $user['id'], 40);
            self::actions($route, $user, $call);
        }
        try {
            $data += match ($route) {
                'dashboard'=> ['health'=>$call('GET','/health'),'status'=>$call('GET','/status')],
                'knowledge'=> ['docs'=>$call('GET','/knowledge/documents'),'sources'=>$call('GET','/knowledge/sources'),
                    'document'=>text_input($_GET,'id') !== '' ? $call('GET','/knowledge/documents/' . self::id($_GET['id'])) : null],
                'rag'=> ['docs'=>$call('GET','/knowledge/documents'),'results'=>text_input($_GET, 'q') !== ''
                    ? $call('GET','/knowledge/search?' . http_build_query(['q'=>text_input($_GET, 'q')])) : null],
                'models'=> ['models'=>$call('GET','/models')],
                'tasks'=> ['jobs'=>$call('GET','/tasks')['items'] ?? []],
                'audit'=> ['events'=>$call('GET','/audit')],
                'evaluation'=> ['evaluation'=>$call('GET','/evaluation')],
                'settings'=> ['template'=>Auth::allows($user,'ai.template.manage') ? $call('GET','/templates') : null],
                default=> [],
            };
        } catch (Http $error) {
            if ($error->status !== 503) {
                throw $error;
            }
            $data['offline'] = $error->getMessage();
        }
        return ['ai', $data];
    }

    private static function actions(string $route, array $user, callable $call): never
    {
        $action = text_input($_POST, 'action');
        $target = '/ai/' . $route;
        if ($action === 'enqueue' && ($route === 'assistant' || isset(self::ANALYSIS_SCOPES[$route]))) {
            $kind = $route === 'assistant' ? text_input($_POST,'kind') : $route;
            if (!isset(self::ANALYSIS_SCOPES[$kind])) {
                throw new Http(422, 'Jenis analisis tidak valid.');
            }
            Auth::require($user,'ai.analysis.execute');
            Auth::require($user,self::ANALYSIS_SCOPES[$kind]);
            [$path,$payload] = self::analysisInput($kind);
            $response = $call('POST',$path,$payload);
            $target = '/ai/tasks/' . self::id($response['id'] ?? '');
        } elseif ($route === 'tasks' && in_array($action, ['cancel','review'], true)) {
            $id = self::id($_POST['id'] ?? '');
            $payload = null;
            if ($action === 'review') {
                Auth::require($user,'ai.report.review');
                $payload = ['decision'=>text_input($_POST, 'decision')];
            }
            $call('POST', '/tasks/' . $id . '/' . $action, $payload);
            $target .= '/' . $id;
        } elseif ($route === 'knowledge' && $action === 'submit') {
            Auth::require($user,'ai.knowledge.manage');
            $document = json_decode(text_input($_POST,'document'), true, 24);
            if (!is_array($document) || array_is_list($document)) {
                throw new Http(422, 'Masukkan dokumen teknis sebagai objek JSON.');
            }
            $call('POST','/knowledge/documents',$document);
        } elseif ($route === 'knowledge' && $action === 'source') {
            Auth::require($user, 'ai.knowledge.manage');
            $source = text_input($_POST,'source');
            if (!preg_match('/^[a-z]{3,12}$/D', $source)) {
                throw new Http(422,'Sumber tidak valid.');
            }
            $call('PUT','/knowledge/sources/' . $source,['enabled'=>text_input($_POST,'enabled') === '1']);
        } elseif (in_array($route,['knowledge','rag'],true) && in_array($action,['approve','archive','index'],true)) {
            Auth::require($user,'ai.knowledge.approve');
            if ($action === 'index') {
                Auth::require($user,'ai.knowledge.manage');
            }
            $doc = self::id($_POST['id'] ?? '');
            $payload = $action === 'approve' ? ['reviewed'=>text_input($_POST,'reviewed') === '1','embed'=>text_input($_POST,'embed') === '1'] : null;
            $answer = $call('POST','/knowledge/documents/' . $doc . '/' . $action,$payload);
            if (isset($answer['id']) || !empty($answer['index_job'])) {
                $target = '/ai/tasks/' . self::id($answer['id'] ?? $answer['index_job']);
            }
        } elseif ($route === 'models' && $action === 'approve') {
            $call('POST','/models', ['name'=>text_input($_POST,'name'),'role'=>text_input($_POST,'role'),
                'license_reference'=>text_input($_POST,'license'),'reviewed'=>text_input($_POST,'reviewed') === '1']);
        } elseif ($route === 'models' && in_array($action,['activation','benchmark','options'], true)) {
            $model = self::id($_POST['id'] ?? '');
            $body = match ($action) {
                'activation'=> ['active'=>text_input($_POST,'active') === '1'],
                'options'=> ['context'=>(int)text_input($_POST,'context'),'device'=>text_input($_POST,'device'),
                    'temperature'=>(float)text_input($_POST,'temperature'),'top_p'=>(float)text_input($_POST,'top_p'),
                    'max_output'=>(int)text_input($_POST,'max_output')],
                default=> null,
            };
            $answer = $call($action === 'options' ? 'PUT' : 'POST','/models/' . $model . '/' . $action,$body);
            if ($action === 'benchmark') {
                $target = '/ai/tasks/' . self::id($answer['id'] ?? '');
            }
        } elseif ($route === 'evaluation' && $action === 'run') {
            $answer = $call('POST','/evaluation');
            $target = '/ai/tasks/' . self::id($answer['id'] ?? '');
        } elseif ($route === 'settings' && $action === 'retention') {
            if (text_input($_POST, 'confirm') !== '1') {
                throw new Http(422, 'Konfirmasikan penerapan retensi.');
            }
            $call('POST','/settings/retention',['days'=>(int)text_input($_POST,'days')]);
        } else {
            throw new Http(405,'Aksi AI tidak tersedia.');
        }
        $_SESSION['notice'] = 'Permintaan AI diterima.';
        Http::redirect($target);
    }

    private static function analysisInput(string $kind): array
    {
        $payload = ['kind'=>$kind];
        if (in_array($kind, ['report','executive'], true)) {
            $period = text_input($_POST,'period');
            return [$kind === 'report' ? '/reports/generate' : '/reports/summary', $payload + self::aggregate($period)];
        }
        $fields = match ($kind) {
            'threat','correlation'=>['type','indicator'],
            'vulnerability'=>['cve'],
            'malware'=>['sha256','verdict','engine'],
            'configuration'=>['platform'],
            'mitigation'=>['category'],
            'advisory'=>['document_id'],
            'education'=>['topic'],
        };
        foreach ($fields as $field) {
            $payload[$field] = text_input($_POST, $field);
        }
        if ($kind === 'configuration') {
            $controls = [];
            foreach (['firewall','antivirus','updates','encryption','secure_boot','support'] as $control) {
                $state = text_input($_POST, $control);
                if ($state !== '') {
                    $controls[$control] = $state;
                }
            }
            $payload['controls'] = $controls;
        }
        return ['/analyze/' . $kind, $payload];
    }

    private static function aggregate(string $period): array
    {
        if (!in_array($period,['current','monthly','annual'],true)) {
            throw new Http(422,'Periode tidak valid.');
        }
        $start = match ($period) {'monthly'=>date('Y-m-01'),'annual'=>date('Y-01-01'),default=>null};
        $data = [
            'period'=>$period,
            'assets'=>(int)query('SELECT COUNT(*) FROM institutional_assets')->fetchColumn(),
            'critical_vulnerabilities'=>(int)query("SELECT COUNT(DISTINCT av.vulnerability_id) FROM ti_asset_vulnerabilities av JOIN ti_vulnerabilities v ON v.id=av.vulnerability_id
                WHERE v.severity='critical' AND av.state IN ('potensial','terkonfirmasi')")->fetchColumn(),
            'active_incidents'=>(int)query("SELECT COUNT(*) FROM security_incidents WHERE state<>'selesai'")->fetchColumn(),
            'observed_malware'=>(int)query("SELECT COUNT(DISTINCT s.indicator_id) FROM ti_indicator_sources s
                WHERE s.category='malware' AND (? IS NULL OR s.retrieved_at>=?)",[$start,$start])->fetchColumn(),
            'pending_mitigations'=>(int)query("SELECT COUNT(*) FROM ti_asset_vulnerabilities WHERE state IN ('potensial','terkonfirmasi')")->fetchColumn(),
        ];
        return $data;
    }

    public static function id(mixed $value): string
    {
        if (!is_string($value) || !preg_match('/^[a-f0-9]{32}$/D', $value)) {
            throw new Http(422,'ID AI tidak valid.');
        }
        return $value;
    }

    private static function pdf(array $task, int $user): never
    {
        $result = $task['result'] ?? [];
        if ($task['state'] !== 'completed' || ($result['review_status'] ?? '') !== 'verified') {
            throw new Http(409, 'Laporan PDF memerlukan verifikasi petugas.');
        }
        $report = ['id'=>$task['id'],'title'=>'Laporan Tinjauan AI','code'=>'AI-' . substr($task['id'],0,12),
            'source'=>$task['kind'],'inspected_on'=>$task['updated_at'],'officer'=>'Petugas SENTINEL','state'=>'disetujui',
            'notes'=>$result['summary'],'evidence'=>implode(PHP_EOL, array_column($result['source_references'],'reference')),
            'mitigation'=>implode(PHP_EOL,array_column($result['recommendations'],'text'))];
        $results = array_map(static fn(array $row): array => ['title'=>$row['text'],'reference'=>implode(', ',$row['references']),
            'status'=>'ditinjau','inspected'=>$result['generated_at']],$result['technical_findings']);
        $institution = query("SELECT value FROM system_settings WHERE title='institution_name'")->fetchColumn() ?: 'Pusat Kesehatan TNI Angkatan Udara';
        $logo = Branding::dataUri();
        $signatures = [['title'=>'Terverifikasi pada AI Gateway','created_at'=>$task['updated_at']]];
        Reports::download(compact('report','institution','logo','signatures','results'),$user,'ai');
    }
}
