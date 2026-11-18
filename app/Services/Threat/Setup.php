<?php
declare(strict_types=1);
namespace Sentinel\Services\Threat;

final class Setup
{
    public static function seed(): void
    {
        $name = 'threat_permissions_and_providers_v1';
        if (query('SELECT 1 FROM schema_migrations WHERE name = ?', [$name])->fetchColumn()) {
            return;
        }
        $config = require BASE . '/config/threat.php';
        Store::transaction(static function () use ($name, $config): void {
            query('INSERT INTO schema_migrations VALUES (?)', [$name]);
            foreach ($config['permissions'] as $permission) {
                query('INSERT IGNORE INTO permissions VALUES (?)', [$permission]);
                query("INSERT IGNORE INTO role_permissions SELECT id, ? FROM roles WHERE title='Super Administrator'", [$permission]);
            }
            foreach ($config['roles'] as $role => $permissions) {
                foreach ($permissions as $permission) {
                    query('INSERT IGNORE INTO role_permissions SELECT id, ? FROM roles WHERE title = ?', ['threat.' . $permission, $role]);
                }
            }
            foreach ($config['providers'] as $code => [$title, $interval]) {
                query('INSERT IGNORE INTO ti_providers (code,title,interval_minutes) VALUES (?,?,?)', [$code, $title, $interval]);
            }
            query("INSERT IGNORE INTO ti_settings VALUES ('history_days','90'), ('alert_priority','70')");
        });
    }
}
