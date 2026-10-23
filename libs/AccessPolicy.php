<?php
declare(strict_types=1);

require_once __DIR__ . '/InstanceReader.php';

final class SMCPAccessPolicy
{
    private int $workspace;
    private array $readRoots;
    private array $deniedRoots;
    private array $readInstances;
    private array $writeRoots = [];
    private array $writeInstances = [];
    private array $deniedInstances = [];
    private int $instanceID;

    public function __construct(int $workspace, string $readRows, string $deniedRows, int $instanceID, string $instanceRows = '[]')
    {
        $this->workspace = $workspace;
        $categoryIDs = self::categories($readRows);
        $this->readRoots = [];
        $this->deniedRoots = self::categories($deniedRows);
        $this->instanceID = $instanceID;
        $instanceIDs = array_keys(SMCPInstanceReader::grants($instanceRows));
        $this->readInstances = [];
        foreach (json_decode($readRows, true, 32, JSON_THROW_ON_ERROR) as $row) {
            $access = self::access($row); $id = (int)$row['CategoryID'];
            if ($access === 'write') { $this->writeRoots[] = $id; }
            elseif ($access === 'read') { $this->readRoots[] = $id; }
            else { $this->deniedRoots[] = $id; }
        }
        foreach (json_decode($instanceRows, true, 32, JSON_THROW_ON_ERROR) as $row) {
            $access = self::access($row); $id = (int)$row['InstanceID'];
            if ($access === 'write') { $this->writeInstances[] = $id; }
            elseif ($access === 'read') { $this->readInstances[] = $id; }
            else { $this->deniedInstances[] = $id; }
        }
        foreach ($instanceIDs as $id) {
            if (!IPS_ObjectExists($id) || IPS_GetObject($id)['ObjectType'] !== 1) {
                throw new RuntimeException('Instance access configuration contains a missing or invalid instance');
            }
        }
        foreach (array_unique(array_merge($workspace > 0 ? [$workspace] : [], $categoryIDs, $this->deniedRoots)) as $id) {
            if (!IPS_ObjectExists($id) || IPS_GetObject($id)['ObjectType'] !== 0) {
                throw new RuntimeException('Access configuration contains a missing or invalid category');
            }
        }
        if ($workspace < 0 || ($workspace === 0 && $this->readRoots === [] && $this->readInstances === [] && $this->writeRoots === [] && $this->writeInstances === [])) {
            throw new RuntimeException('Configure a workspace, read-only category or instance');
        }
    }

    public static function access(array $row): string
    {
        // Missing fields from previous versions remain read-only.
        $access = array_key_exists('Access', $row) ? $row['Access'] : 'read';
        if (!is_string($access) || !in_array($access, ['none','read','write'], true)) {
            throw new RuntimeException('Invalid access selection');
        }
        return $access;
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

    // Priority: denied (including this module) > explicitly read-only > write grants.
    // Category and instance grants apply to entire subtrees. No links are followed.
    public function level(int $id): string
    {
        if ($id <= 0 || !IPS_ObjectExists($id)) { return 'none'; }
        $workspace = false; $read = false; $seen = [];
        for ($cursor = $id; $cursor > 0; $cursor = IPS_GetParent($cursor)) {
            if (isset($seen[$cursor]) || count($seen) >= 256 || !IPS_ObjectExists($cursor)) { return 'none'; }
            $seen[$cursor] = true;
            if ($cursor === $this->instanceID || in_array($cursor, $this->deniedRoots, true) || in_array($cursor, $this->deniedInstances, true)) { return 'none'; }
            if (in_array($cursor, $this->readRoots, true) || in_array($cursor, $this->readInstances, true)) { $read = true; }
            if ($cursor === $this->workspace || in_array($cursor, $this->writeRoots, true) || in_array($cursor, $this->writeInstances, true)) { $workspace = true; }
        }
        return $read ? 'read' : ($workspace ? 'write' : 'none');
    }

    public function canRead(int $id): bool { return $this->level($id) !== 'none'; }
    public function canWrite(int $id): bool { return $this->level($id) === 'write'; }
    public function workspace(): int { return $this->workspace; }
    public function readableRoots(): array
    {
        return array_values(array_filter(array_unique(array_merge($this->workspace > 0 ? [$this->workspace] : [], $this->readRoots, $this->readInstances, $this->writeRoots, $this->writeInstances)), fn(int $id): bool => $this->canRead($id)));
    }
    public function writableRoots(): array
    {
        return array_values(array_filter($this->readableRoots(), fn(int $id): bool => $this->canWrite($id)));
    }
}
