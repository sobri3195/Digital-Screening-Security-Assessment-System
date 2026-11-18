<?php
declare(strict_types=1);
require dirname(__DIR__) . '/app/Core/bootstrap.php';

use Sentinel\Core\Http;
use Sentinel\Services\Inspection;
use Sentinel\Services\Secrets;
use Sentinel\Services\Totp;

$count = 0;
function expect(bool $condition, string $description): void
{
    global $count;
    if (!$condition) {
        throw new RuntimeException($description);
    }
    echo 'PASS ', $description, PHP_EOL;
    $count++;
}

$result = Inspection::url('http://name:token@127.0.0.1/login?password=secret#anchor');
expect($result['title'] === 'http://127.0.0.1/login', 'URL redacts credentials, query, and fragment');
expect(str_contains($result['indicators'], 'alamat IP') && str_contains($result['indicators'], 'userinfo'), 'URL identifies IP and obfuscation indicators');
expect(str_contains(Inspection::url('https://xn--bcher-kva.example/%61')['indicators'], 'punycode'), 'Punycode identified');
foreach (['file:///etc/passwd', 'javascript:alert(1)', 'https://example.org/with spaces'] as $invalid) {
    try {
        Inspection::url($invalid);
        throw new RuntimeException('URL unexpectedly accepted.');
    } catch (Http $error) {
        expect($error->status === 422, 'URL refused: ' . $invalid);
    }
}
$seed = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
expect(Totp::verify($seed, '287082', -1, 59) === 1, 'RFC 6238 TOTP vector truncated to six digits');
expect(Totp::verify($seed, '287082', 1, 59) === null, 'TOTP replay rejected');
expect(Totp::verify($seed, '12345', -1, 59) === null, 'Malformed TOTP rejected');
putenv('APP_KEY=' . bin2hex(random_bytes(32)));
$cipher = Secrets::seal('sentinel-test');
expect($cipher !== 'sentinel-test' && Secrets::open($cipher) === 'sentinel-test', 'Authenticated encryption round trip');
$binary = base64_decode($cipher, true);
$binary[-1] = chr(ord($binary[-1]) ^ 1);
try {
    Secrets::open(base64_encode($binary));
} catch (RuntimeException $error) {
    expect($error->getMessage() === 'Verifikasi data terenkripsi gagal.', 'Tampered ciphertext rejected');
}
if ($count !== 11) {
    throw new RuntimeException('A check was skipped.');
}
echo "$count checks passed.\n";
