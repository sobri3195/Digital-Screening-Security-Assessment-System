<?php
declare(strict_types=1);
namespace Sentinel\Services\Threat;

use DOMDocument;
use DOMXPath;
use Sentinel\Core\Http;

final class AdvisoryImport
{
    public static function store(string $code, array $entries): int
    {
        if (!in_array($code, ['bssn','kemkes'], true)) {
            throw new Http(422, 'Pilih publikasi resmi BSSN atau Kemenkes.');
        }
        $provider = Store::provider($code);
        $publisher = $code === 'bssn' ? 'BSSN' : 'Kemenkes CSIRT';
        $domain = $code === 'bssn' ? 'bssn.go.id' : 'kemkes.go.id';
        Store::transaction(static function () use ($entries,$code,$provider,$publisher,$domain): void {
            foreach ($entries as $entry) {
                $entry['healthcare'] = $code === 'kemkes';
                if (($entry['reference'] ?? '') !== '') {
                    $host = strtolower((string) parse_url($entry['reference'], PHP_URL_HOST));
                    if ($host !== $domain && !str_ends_with($host, '.' . $domain)) {
                        throw new Http(422, 'Rujukan advisori berada di luar organisasi penerbit.');
                    }
                }
                $id = Store::advisory((int) $provider['id'], $publisher, $entry);
                if ($entry['healthcare']) {
                    Store::alert('healthcare:' . $id,'advisori','Advisori kesehatan perlu ditinjau','medium','/threat/advisories?id=' . $id);
                }
            }
        });
        return count($entries);
    }

    public static function upload(array $file, string $format): array
    {
        if (($file['error'] ?? null) !== UPLOAD_ERR_OK || !is_uploaded_file($file['tmp_name'] ?? '')) {
            throw new Http(422, 'Pilih salinan advisori yang diotorisasi.');
        }
        $bytes = file_get_contents($file['tmp_name'], false, null, 0, 1024 * 1024 + 1);
        if ($bytes === false) {
            throw new Http(422, 'Salinan advisori tidak dapat dibaca.');
        }
        return self::parse($bytes, $format);
    }

    public static function parse(string $bytes, string $format): array
    {
        if (strlen($bytes) > 1024 * 1024 || str_contains($bytes, "\0") || !mb_check_encoding($bytes, 'UTF-8')
            || preg_match('/<!\s*(DOCTYPE|ENTITY)\b/i', $bytes) || !in_array($format, ['rss','html'], true)) {
            throw new Http(422, 'Format advisori ditolak. Gunakan RSS, Atom, atau HTML tanpa DTD, maksimum 1 MiB.');
        }
        $document = new DOMDocument();
        $previous = libxml_use_internal_errors(true);
        try {
            $valid = $format === 'html' ? $document->loadHTML('<?xml encoding="UTF-8">' . $bytes, LIBXML_NONET)
                : $document->loadXML($bytes, LIBXML_NONET);
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
        if (!$valid) {
            throw new Http(422, 'Dokumen advisori tidak valid.');
        }
        $xpath = new DOMXPath($document);
        $nodes = $xpath->query($format === 'html' ? '//article[.//h1 or .//h2 or .//h3]'
            : '//*[local-name()="channel"]/*[local-name()="item"] | /*[local-name()="feed"]/*[local-name()="entry"]');
        $records = [];
        foreach ($nodes as $node) {
            if (count($records) >= 100) {
                break;
            }
            $get = static fn (string $expression): string => trim($xpath->evaluate('string((' . $expression . ')[1])', $node));
            $title = $get($format === 'html' ? './/h1 | .//h2 | .//h3' : './*[local-name()="title"]');
            $summary = $get($format === 'html' ? './/p' : './*[local-name()="description" or local-name()="summary" or local-name()="content"]');
            $reference = $get($format === 'html' ? './/a[@rel="bookmark"]/@href' : './*[local-name()="link"]/@href | ./*[local-name()="link"]/text()');
            $date = $get($format === 'html' ? './/time/@datetime' : './*[local-name()="pubDate" or local-name()="published" or local-name()="updated"]');
            $timestamp = $date === '' ? false : strtotime($date);
            if (Store::text($title, 220) === null || Store::text($summary, 8000) === null) {
                continue;
            }
            $records[] = ['title'=>$title,'summary'=>$summary,'reference'=>$reference,'published'=>$timestamp === false ? null : date('Y-m-d',$timestamp)];
        }
        if (!$records) {
            throw new Http(422, 'Tidak ada entri advisori yang dikenali.');
        }
        return $records;
    }
}
