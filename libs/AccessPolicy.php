<?php
declare(strict_types=1);

final class SMCPAccessPolicy
{
    private int $workspace;
    private array $readRoots;
    private array $deniedRoots;
    private int $instanceID;

    public function __construct(int $workspace, string $readRows, string $deniedRows, int $instanceID)
    {
        $this->workspace = $workspace;
        $this->readRoots = self::categories($readRows);
        $this->deniedRoots = self::categories($deniedRows);
        $this->instanceID = $instanceID;
        foreach (array_unique(array_merge($workspace > 0 ? [$workspace] : [], $this->readRoots, $this->deniedRoots)) as $id) {
            if (!IPS_ObjectExists($id) || IPS_GetObject($id)['ObjectType'] !== 0) {
                throw new RuntimeException('Access configuration contains a missing or invalid category');
            }
        }
        if ($workspace < 0 || ($workspace === 0 && $this->readRoots === [])) {
            throw new RuntimeException('Configure a workspace or at least one read-only category');
        }
    }

    private static function categories(string $json): array
    {
        try { $rows = json_decode($json, true, 32, JSON_THROW_ON_ERROR); }
        catch (Throwable $e) { throw new RuntimeException('Invalid category list'); }
        if (!is_array($rows) || !array_is_list($rows)) { throw new RuntimeException('Invalid category list'); }
        $ids = [];
        foreach ($rows as $row) {
            $value = is_array($row) ? ($row['CategoryID'] ?? null) : null;
            if ((!is_int($value) && !is_string($value)) || filter_var($value, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]) === false) {
                throw new RuntimeException('Every category row requires a positive category ID');
            }
            $ids[] = (int)$value;
        }
        return array_values(array_unique($ids));
    }

    // Priority: denied (including this module) > explicitly read-only > workspace.
    // Every configured category applies to its entire subtree. No links are followed.
    public function level(int $id): string
    {
        if ($id <= 0 || !IPS_ObjectExists($id)) { return 'none'; }
        $workspace = false; $read = false; $seen = [];
        for ($cursor = $id; $cursor > 0; $cursor = IPS_GetParent($cursor)) {
            if (isset($seen[$cursor]) || count($seen) >= 256 || !IPS_ObjectExists($cursor)) { return 'none'; }
            $seen[$cursor] = true;
            if ($cursor === $this->instanceID || in_array($cursor, $this->deniedRoots, true)) { return 'none'; }
            if (in_array($cursor, $this->readRoots, true)) { $read = true; }
            if ($cursor === $this->workspace) { $workspace = true; }
        }
        return $read ? 'read' : ($workspace ? 'write' : 'none');
    }

    public function canRead(int $id): bool { return $this->level($id) !== 'none'; }
    public function canWrite(int $id): bool { return $this->level($id) === 'write'; }
    public function workspace(): int { return $this->workspace; }
    public function readableRoots(): array
    {
        return array_values(array_filter(array_unique(array_merge($this->workspace > 0 ? [$this->workspace] : [], $this->readRoots)), fn(int $id): bool => $this->canRead($id)));
    }
}
