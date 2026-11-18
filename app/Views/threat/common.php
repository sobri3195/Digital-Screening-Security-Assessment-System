<?php
use Sentinel\Core\Auth;
use Sentinel\Services\Threat\{Indicator, Store};

$route = $data['route'];
$base = '/threat/' . $route;
$csrf = escape(Auth::csrf());
$can = static fn (string $permission): bool => Auth::allows($user, 'threat.' . $permission);
$value = static fn (string $key): string => escape(text_input($_GET, $key));
$field = static function (string $label, string $key, array $options) use ($value): void { ?>
    <label><?= escape($label) ?><select class="form-select" name="<?= escape($key) ?>"><option value="">Semua</option>
        <?php foreach ($options as $option): ?><option value="<?= escape($option) ?>" <?= $value($key) === escape($option) ? 'selected' : '' ?>><?= escape($option) ?></option><?php endforeach ?>
    </select></label>
<?php };
$input = static function (string $label, string $name, string $type = 'text', string|int|null $current = '', bool $required = false): void { ?>
    <label><?= escape($label) ?><input class="form-control" type="<?= escape($type) ?>" name="<?= escape($name) ?>" value="<?= escape($current) ?>" <?= $required ? 'required' : '' ?>></label>
<?php };
$select = static function (string $label, string $name, array $options, string|int|null $selected = null): void { ?>
    <label><?= escape($label) ?><select class="form-select" name="<?= escape($name) ?>">
        <?php foreach ($options as $option): ?><option value="<?= escape($option) ?>" <?= (string) $selected === (string) $option ? 'selected' : '' ?>><?= escape(str_replace('_', ' ', $option)) ?></option><?php endforeach ?>
    </select></label>
<?php };
$listing = static function (array $rows, array $columns, ?callable $actions = null): void { ?>
    <?php if (!$rows): ?><p class="empty">Belum ada data yang cocok.</p><?php else: ?>
    <div class="table-responsive"><table class="table align-middle">
        <thead><tr><?php foreach ($columns as $title): ?><th scope="col"><?= escape($title) ?></th><?php endforeach ?>
        <?php if ($actions): ?><th scope="col">Tindakan</th><?php endif ?></tr></thead>
        <tbody><?php foreach ($rows as $row): ?><tr>
            <?php foreach ($columns as $key => $title): ?><td><?= escape(isset($row[$key]) ? mb_strimwidth((string) $row[$key], 0, 100, '…') : '—') ?></td><?php endforeach ?>
            <?php if ($actions): ?><td><?php $actions($row); ?></td><?php endif ?>
        </tr><?php endforeach ?></tbody>
    </table></div><?php endif ?>
<?php };
$details = static function (array $row, array $labels): void { ?>
    <dl class="detail-grid">
    <?php foreach ($labels as $key => $label): ?><dt><?= escape($label) ?></dt><dd><?= escape(isset($row[$key]) ? (string) $row[$key] : '—') ?></dd><?php endforeach ?>
    </dl>
<?php };
?>
<div class="page-heading"><div><p class="eyebrow">Threat Intelligence</p><h1><?= escape($data['title']) ?></h1></div>
    <?php if ($route === 'dashboard'): ?><span class="status">Sinkronisasi terakhir: <?= escape($data['freshness'] ?: 'belum tercatat') ?></span><?php endif ?>
</div>
