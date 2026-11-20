<?php
declare(strict_types=1);
namespace Sentinel\Services\Threat;

use Sentinel\Core\Http;

final class DesktopResults
{
    public static function receive(array $input, int $client): array
    {
        $limits = ['revision'=>1000000,'score'=>100,'coverage'=>100,'finding_count'=>100000,'tasks_total'=>32,'tasks_completed'=>32];
        $keys = ['schema','asset_code','session_id','report_sha256',...array_keys($limits)];
        if (count($input) !== count($keys) || array_diff(array_keys($input), $keys) || ($input['schema'] ?? null) !== 'sentinel-inspection-v1'
            || !preg_match('~^[a-zA-Z0-9_.:/-]{2,80}$~D', text_input($input,'asset_code'))
            || !preg_match('/^[a-f0-9]{32}$/D', text_input($input,'session_id'))
            || !preg_match('/^[a-f0-9]{64}$/D', text_input($input,'report_sha256'))) {
            throw new Http(422, 'Ringkasan Desktop tidak valid.');
        }
        foreach ($limits as $key => $max) {
            $value = $input[$key];
            if ($key === 'score' && $value === null) {
                continue;
            }
            if (!is_int($value) || $value < 0 || $value > $max) {
                throw new Http(422, 'Angka ringkasan Desktop tidak valid.');
            }
        }
        if ($input['revision'] === 0 || $input['tasks_completed'] > $input['tasks_total']) {
            throw new Http(422, 'Revisi atau jumlah modul tidak valid.');
        }
        $assetCode = text_input($input,'asset_code');
        ksort($input);
        $fingerprint = hash('sha256', Store::json($input));
        return Store::transaction(static function () use ($input,$client,$assetCode,$fingerprint): array {
            $asset = query('SELECT id FROM institutional_assets WHERE code=? FOR UPDATE', [$assetCode])->fetchColumn();
            if (!$asset) {
                throw new Http(404, 'Kode aset tidak terdaftar di unit ini.');
            }
            $previous = query('SELECT asset_id,client_id FROM ti_desktop_results WHERE session_id=? ORDER BY revision LIMIT 1 FOR UPDATE',
                [$input['session_id']])->fetch();
            if ($previous && ((int) $previous['asset_id'] !== (int) $asset || (int) $previous['client_id'] !== $client)) {
                throw new Http(409, 'Sesi Desktop terdaftar pada aset atau klien berbeda.');
            }
            $insert = query('INSERT INTO ti_desktop_results (asset_id,client_id,session_id,revision,report_sha256,payload_sha256,
                score,coverage,finding_count,tasks_total,tasks_completed) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id)',
                [$asset,$client,$input['session_id'],$input['revision'],$input['report_sha256'],$fingerprint,
                    $input['score'],$input['coverage'],$input['finding_count'],$input['tasks_total'],$input['tasks_completed']]);
            $id = (int) db()->lastInsertId();
            $stored = query('SELECT payload_sha256 FROM ti_desktop_results WHERE id=?', [$id])->fetchColumn();
            if ($stored !== $fingerprint) {
                throw new Http(409, 'Revisi Desktop yang sama sudah tersimpan dengan isi berbeda.');
            }
            return ['id'=>$id,'state'=>$insert->rowCount() === 1 ? 'received' : 'already_received'];
        });
    }
}
