<?php
declare(strict_types=1);
namespace Sentinel\Controllers;

use Sentinel\Core\Http;
use Sentinel\Services\Threat\{Analysis, Catalog, DesktopResults, Feeds, Queue};

final class ThreatApi
{
    private const ROUTES = [
        'health' => ['GET','threat.dashboard.view'],
        'summary' => ['GET','threat.dashboard.view'],
        'scan' => ['POST','threat.scan.execute'],
        'indicators' => ['GET','threat.indicator.view'],
        'vulnerabilities' => ['GET','threat.vulnerability.view'],
        'advisories' => ['GET','threat.advisory.view'],
        'alerts' => ['GET','threat.alert.manage'],
        'reports' => ['GET','threat.report.generate'],
        'providers' => ['GET','threat.provider.manage'],
        'sync' => ['POST','threat.sync.execute'],
        'desktop-results' => ['POST','threat.desktop.upload'],
    ];

    public static function handle(string $route, string $method, array $client): never
    {
        if (!isset(self::ROUTES[$route])) {
            throw new Http(404, 'Endpoint intelijen tidak ditemukan.');
        }
        [$expected, $scope] = self::ROUTES[$route];
        if ($method !== $expected) {
            header('Allow: ' . $expected);
            throw new Http(405, 'Metode tidak didukung.');
        }
        if (!in_array($scope, explode(',', $client['scopes'] ?? ''), true)) {
            audit(null, 'api-ditolak', 'threat:' . $route, 'ditolak');
            throw new Http(403, 'Scope klien tidak mengizinkan endpoint ini.');
        }
        $clientId = (int) $client['id'];
        Http::limit('threat-client:' . $clientId, 60);
        $input = $method === 'POST' ? self::payload() : $_GET;
        if ($route === 'scan') {
            $data = Analysis::scan(text_input($input,'indicator'), null, $clientId);
        } elseif ($route === 'sync') {
            $data = ['job_id' => Queue::enqueue(text_input($input,'provider'),'sync',null),'state'=>'accepted'];
        } elseif ($route === 'desktop-results') {
            $data = DesktopResults::receive($input, $clientId);
        } elseif ($route === 'health') {
            $data = ['status'=>'ok','latest_success_at'=>query('SELECT MAX(last_success_at) FROM ti_providers')->fetchColumn() ?: null];
        } elseif ($route === 'summary') {
            $data = Catalog::summary($input);
        } else {
            $rows = self::list($route, $input);
            $data = ['items' => array_slice($rows,0,100), 'next_after' => count($rows) > 100 ? (int) $rows[99]['id'] : null];
        }
        audit(null, 'api-' . $route, 'threat');
        Http::json(['data' => $data], $route === 'sync' ? 202 : (($route === 'scan' || ($data['state'] ?? '') === 'received') ? 201 : 200));
    }

    private static function list(string $route, array $input): array
    {
        $after = Catalog::id($input,'after',true);
        return match ($route) {
            'indicators' => Catalog::indicators($input,101),
            'vulnerabilities' => Catalog::vulnerabilities($input,101),
            'advisories' => Catalog::advisories($input,101),
            'alerts' => Catalog::alerts($input,101),
            'reports' => query('SELECT id,code,title,kind,created_at,approved_at FROM ti_reports WHERE id>? AND approved_at IS NOT NULL ORDER BY id LIMIT 101',[$after])->fetchAll(),
            'providers' => array_map(static function (array $provider): array {
                $provider['configured'] = Feeds::configured($provider['code']);
                return $provider;
            }, query('SELECT id,code,title,enabled,interval_minutes,last_success_at,next_run FROM ti_providers WHERE id>? ORDER BY id LIMIT 101',[$after])->fetchAll()),
        };
    }

    private static function payload(): array
    {
        $contentType = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
        if ($contentType !== 'application/json') {
            throw new Http(415,'Gunakan application/json.');
        }
        $raw = file_get_contents('php://input',false,null,0,4097);
        $value = is_string($raw) ? json_decode($raw,true,16) : null;
        if (!is_string($raw) || strlen($raw)>4096 || !is_array($value) || array_is_list($value)) {
            throw new Http(422,'Objek JSON tidak valid atau terlalu besar.');
        }
        return $value;
    }
}
