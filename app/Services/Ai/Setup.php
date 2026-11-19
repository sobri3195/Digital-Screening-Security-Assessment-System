<?php
declare(strict_types=1);

namespace Sentinel\Services\Ai;

use Sentinel\Services\Threat\Store;

final class Setup
{
    public static function seed(): void
    {
        $migration = 'ai_permissions_v1';
        if (query('SELECT 1 FROM schema_migrations WHERE name=?', [$migration])->fetchColumn()) {
            return;
        }
        $rules = require BASE . '/config/ai.php';
        Store::transaction(static function () use ($migration, $rules): void {
            query('INSERT INTO schema_migrations VALUES (?)', [$migration]);
            foreach ($rules['permissions'] as $permission) {
                query('INSERT IGNORE INTO permissions VALUES (?)', [$permission]);
                query("INSERT IGNORE INTO role_permissions SELECT id, ? FROM roles WHERE title='Super Administrator'", [$permission]);
            }
            foreach ($rules['roles'] as $role => $grants) {
                foreach ($grants as $permission) {
                    query('INSERT IGNORE INTO role_permissions SELECT id, ? FROM roles WHERE title=?', ['ai.' . $permission, $role]);
                }
            }
        });
    }
}
