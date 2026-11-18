<?php
declare(strict_types=1);
namespace Sentinel\Core;

use Sentinel\Services\Secrets;
use Sentinel\Services\Totp;

final class Auth
{
    private static ?array $permissions = null;

    public static function start(): void
    {
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        session_name('SENTINEL');
        session_set_cookie_params([
            'lifetime' => 0, 'path' => '/', 'secure' => config('APP_SECURE_COOKIE', '1') === '1',
            'httponly' => true, 'samesite' => 'Strict',
        ]);
        session_start();
    }

    public static function csrf(): string
    {
        return $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
    }

    public static function verifyCsrf(): void
    {
        if (!hash_equals(self::csrf(), text_input($_POST, '_csrf'))) {
            throw new Http(403, 'Permintaan tidak dapat diverifikasi.');
        }
    }

    private static function sessionKey(): string
    {
        return hash('sha256', session_id());
    }

    public static function user(): ?array
    {
        if (!isset($_SESSION['user_id'])) {
            return null;
        }
        $user = query('SELECT users.* FROM users JOIN user_sessions s ON s.user_id = users.id WHERE users.id = ? AND users.active = 1 AND users.auth_version = ? AND s.id = ? AND s.last_seen >= NOW() - INTERVAL 30 MINUTE',
            [$_SESSION['user_id'], $_SESSION['auth_version'], self::sessionKey()])->fetch();
        if (!$user) {
            $_SESSION = [];
            session_regenerate_id(true);
            return null;
        }
        query('UPDATE user_sessions SET last_seen = NOW() WHERE id = ?', [self::sessionKey()]);
        return $user;
    }

    public static function allows(array $user, string $permission): bool
    {
        self::$permissions ??= query('SELECT rp.permission_code FROM user_roles ur JOIN role_permissions rp ON rp.role_id = ur.role_id WHERE ur.user_id = ?', [$user['id']])->fetchAll(\PDO::FETCH_COLUMN);
        return in_array($permission, self::$permissions, true);
    }

    public static function require(array $user, string $permission): void
    {
        if (!self::allows($user, $permission)) {
            throw new Http(403, 'Anda tidak memiliki izin untuk tindakan ini.');
        }
    }

    public static function signIn(): void
    {
        $username = text_input($_POST, 'username');
        $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
        $address = hash('sha256', $_SERVER['REMOTE_ADDR'] ?? '');
        $subject = hash('sha256', strtolower($username));
        Http::limit('login-address:' . $address, 30);
        Http::limit('login-user:' . $subject, 8, 900);
        $user = preg_match('/^[a-zA-Z0-9_.-]{3,100}$/D', $username)
            ? query('SELECT * FROM users WHERE username = ?', [$username])->fetch() : false;
        $fallback = '$2y$12$Q0vZV6F2I0X5qPKUclz6VOuq.SrjeTT9AcXBHaqIJ5hXx37j1AQIS';
        $validPassword = strlen($password) <= 72 && password_verify($password, $user['password_hash'] ?? $fallback);
        $valid = $user && $user['active'] && $validPassword;
        if ($valid && $user['totp_secret'] !== null) {
            $counter = Totp::verify(Secrets::open($user['totp_secret']), text_input($_POST, 'totp'), (int) $user['totp_counter']);
            $valid = $counter !== null && query('UPDATE users SET totp_counter = ? WHERE id = ? AND totp_counter < ? AND auth_version = ?',
                [$counter, $user['id'], $counter, $user['auth_version']])->rowCount() === 1;
        }
        query('INSERT INTO login_attempts (subject, address, successful) VALUES (?, ?, ?)', [$subject, $address, (int) $valid]);
        if (!$valid) {
            audit($user ? (int) $user['id'] : null, 'login', 'auth', 'gagal');
            throw new Http(401, 'Login gagal. Periksa nama pengguna, kata sandi, dan kode TOTP bila aktif.');
        }
        session_regenerate_id(true);
        $_SESSION = ['user_id' => (int) $user['id'], 'auth_version' => (int) $user['auth_version']];
        query('INSERT INTO user_sessions VALUES (?, ?, NOW())', [self::sessionKey(), $user['id']]);
        audit((int) $user['id'], 'login', 'auth');
    }

    public static function signOut(array $user): void
    {
        query('DELETE FROM user_sessions WHERE id = ?', [self::sessionKey()]);
        audit((int) $user['id'], 'logout', 'auth');
        $_SESSION = [];
        session_regenerate_id(true);
    }

    public static function setPassword(int $id, string $password): void
    {
        if (strlen($password) < 12 || strlen($password) > 72 || str_contains($password, "\0")) {
            throw new Http(422, 'Kata sandi baru harus berisi 12–72 byte.');
        }
        query('UPDATE users SET password_hash = ?, auth_version = auth_version + 1 WHERE id = ?', [password_hash($password, PASSWORD_DEFAULT), $id]);
        query('DELETE FROM user_sessions WHERE user_id = ?', [$id]);
    }
}
