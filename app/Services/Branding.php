<?php
declare(strict_types=1);
namespace Sentinel\Services;

use Sentinel\Core\Http;

final class Branding
{
    public static function upload(array $file): void
    {
        if (($file['error'] ?? null) !== UPLOAD_ERR_OK || !is_uploaded_file($file['tmp_name']) || $file['size'] > 200000) {
            throw new Http(422, 'Pilih logo PNG atau JPEG dengan ukuran maksimal 200 KB.');
        }
        $path = $file['tmp_name'];
        $image = @getimagesize($path);
        $mime = (new \finfo(FILEINFO_MIME_TYPE))->file($path);
        if ($image === false || $image['mime'] !== $mime || !in_array($mime, ['image/png', 'image/jpeg'], true)
            || $image[0] > 1024 || $image[1] > 1024) {
            throw new Http(422, 'Logo harus berupa PNG atau JPEG dengan dimensi maksimal 1024 × 1024.');
        }
        $decoded = $mime === 'image/png' ? @imagecreatefrompng($path) : @imagecreatefromjpeg($path);
        if ($decoded === false) {
            throw new Http(422, 'Data gambar tidak dapat dibaca.');
        }
        ob_start();
        if ($mime === 'image/png') {
            imagealphablending($decoded, false);
            imagesavealpha($decoded, true);
            $written = imagepng($decoded);
        } else {
            $written = imagejpeg($decoded, null, 90);
        }
        $data = ob_get_clean();
        if (!$written || !is_string($data) || strlen($data) > 300000) {
            throw new Http(422, 'Logo hasil validasi terlalu besar atau tidak dapat dibaca.');
        }
        $payload = $mime . ';base64,' . base64_encode($data);
        query("INSERT INTO system_settings (title,value) VALUES ('institution_logo', ?) ON DUPLICATE KEY UPDATE value=VALUES(value)", [$payload]);
    }

    public static function dataUri(): string
    {
        $data = query("SELECT value FROM system_settings WHERE title='institution_logo'")->fetchColumn();
        return is_string($data) && preg_match('~^image/(?:png|jpeg);base64,[A-Za-z0-9+/]+={0,2}$~D', $data)
            ? 'data:' . $data : '';
    }

    public static function send(): never
    {
        $uri = self::dataUri();
        if ($uri === '') {
            throw new Http(404, 'Logo belum dikonfigurasi.');
        }
        [$mime, $data] = explode(';base64,', substr($uri, 5), 2);
        header('Content-Type: ' . $mime);
        echo base64_decode($data, true);
        exit;
    }
}
