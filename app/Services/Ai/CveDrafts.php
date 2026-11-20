<?php
declare(strict_types=1);
namespace Sentinel\Services\Ai;

final class CveDrafts
{
    public static function forCve(string $cve): array
    {
        $row = query('SELECT cve,description,cvss,severity,published_at,modified_at,nvd_evidence,kev_title,
            kev_added_on,kev_action,epss,epss_on FROM ti_vulnerabilities WHERE cve = ?', [$cve])->fetch();
        if (!$row) {
            return [];
        }
        $docs = [];
        $proposal = static function (string $title, string $source, string $date, string $url, string $content, array $facts) use ($cve): array {
            return ['title'=>mb_substr($title,0,150),'source'=>$source,'version'=>$source . '-' . str_replace('-','',$date),
                'published'=>$date,'reference'=>$url,'classification'=>'public','content'=>mb_substr(trim($content),0,64000),
                'facts'=>['topic'=>'vulnerability','cve'=>$cve] + $facts];
        };
        if ($row['kev_added_on'] !== null) {
            $docs[] = $proposal($cve . ' · ' . ($row['kev_title'] ?: 'CISA KEV'), 'cisa', $row['kev_added_on'],
                'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
                $cve . ' tercatat dalam katalog CISA KEV. ' . ($row['kev_action'] ?? ''), ['kev'=>true,'actions'=>['apply_patch','verify_version']]);
        }
        if ($row['nvd_evidence'] !== null && $row['published_at'] !== null) {
            $meta = json_decode($row['nvd_evidence'], true, 64, JSON_THROW_ON_ERROR);
            $weakness = $meta['weaknesses'][0] ?? null;
            $severity = $row['severity'] ?? 'unknown';
            if (!in_array($severity, ['informational','low','medium','high','critical','unknown'],true)) {
                $severity = 'unknown';
            }
            $doc = $proposal('NVD ' . $cve, 'nist', substr($row['published_at'],0,10), 'https://nvd.nist.gov/vuln/detail/' . $cve,
                'Entri NVD ' . $cve . '. ' . ($row['description'] ?? ''),
                ['cvss'=>$row['cvss'] !== null ? (float)$row['cvss'] : null,'severity'=>$severity,
                    'cwe'=>is_string($weakness) && preg_match('/^CWE-[0-9]{1,7}$/D',$weakness) ? $weakness : null,'actions'=>['verify_version']]);
            if ($row['modified_at']) {
                $doc['version'] = 'nist-' . date('YmdHis',strtotime($row['modified_at']));
            }
            $docs[] = $doc;
        }
        if ($row['epss'] !== null && $row['epss_on'] !== null) {
            $docs[] = $proposal('FIRST EPSS ' . $cve, 'first', $row['epss_on'], 'https://www.first.org/epss/data',
                'Observasi FIRST EPSS untuk ' . $cve . '. Nilai terikat pada tanggal observasi. Gunakan sebagai salah satu masukan untuk prioritas mitigasi.',
                ['epss'=>(float)$row['epss'],'epss_on'=>$row['epss_on'],'actions'=>['verify_version']]);
        }
        return $docs;
    }
}
