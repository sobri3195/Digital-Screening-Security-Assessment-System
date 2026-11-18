<?php
declare(strict_types=1);
namespace Sentinel\Controllers;

use Sentinel\Core\Auth;
use Sentinel\Core\Http;
use Sentinel\Services\Totp;
use Sentinel\Services\Secrets;

final class Profile
{
    public static function handle(array $user): array
    {
        $id = (int) $user['id'];
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $action = text_input($_POST, 'action');
            $password = is_string($_POST['current'] ?? null) ? $_POST['current'] : '';
            Http::limit('profile:' . $id, 10);
            if (strlen($password) > 72 || !password_verify($password, $user['password_hash'])) {
                throw new Http(422, 'Kata sandi saat ini tidak cocok.');
            }
            if ($action === 'name') {
                $name = text_input($_POST, 'title');
                if ($name === '' || mb_strlen($name) > 160) {
                    throw new Http(422, 'Nama tidak valid.');
                }
                query('UPDATE users SET title = ? WHERE id = ?', [$name, $id]);
            } elseif ($action === 'password') {
                Auth::setPassword($id, is_string($_POST['new'] ?? null) ? $_POST['new'] : '');
                Auth::signOut($user);
                Http::redirect('/login');
            } elseif ($action === 'totp-start' && $user['totp_secret'] === null) {
                $_SESSION['totp_setup'] = Totp::generate();
            } elseif ($action === 'totp-confirm' && isset($_SESSION['totp_setup']) && $user['totp_secret'] === null) {
                $secret = $_SESSION['totp_setup'];
                $counter = Totp::verify($secret, text_input($_POST, 'totp'), -1);
                if ($counter === null) {
                    throw new Http(422, 'Kode TOTP tidak cocok.');
                }
                query('UPDATE users SET totp_secret = ?, totp_counter = ?, auth_version = auth_version + 1 WHERE id = ? AND totp_secret IS NULL',
                    [Secrets::seal($secret), $counter, $id]);
                unset($_SESSION['totp_setup']);
                query('DELETE FROM user_sessions WHERE user_id = ?', [$id]);
                audit($id, 'totp-aktif', 'profil');
                Auth::signOut($user);
                Http::redirect('/login');
            } else {
                throw new Http(422, 'Tindakan profil tidak tersedia.');
            }
            audit($id, $action, 'profil');
            $_SESSION['notice'] = 'Profil diperbarui.';
            Http::redirect('/profile');
        }
        $history = query("SELECT result,created_at FROM audit_logs WHERE user_id = ? AND module = 'auth' AND action = 'login' ORDER BY id DESC LIMIT 15", [$id])->fetchAll();
        return ['history' => $history, 'setup' => $_SESSION['totp_setup'] ?? null];
    }
}
