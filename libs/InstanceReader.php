<?php
declare(strict_types=1);

// Read only explicitly named configuration properties, never the entire configuration.
final class SMCPInstanceReader
{
    public static function grants(string $json): array
    {
        try { $rows = json_decode($json, true, 32, JSON_THROW_ON_ERROR); }
        catch (Throwable $e) { throw new RuntimeException('Invalid instance list'); }
        if (!is_array($rows) || !array_is_list($rows)) { throw new RuntimeException('Invalid instance list'); }
        $grants = [];
        foreach ($rows as $row) {
            $id = is_array($row) ? ($row['InstanceID'] ?? null) : null;
            if ((!is_int($id) && !is_string($id)) || filter_var($id, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]) === false
                || !is_string($row['Properties'] ?? '')) {
                throw new RuntimeException('Every instance row requires a positive instance ID and property names');
            }
            $id = (int)$id;
            if (isset($grants[$id])) { throw new RuntimeException('Duplicate instance selection'); }
            $properties = array_values(array_unique(array_filter(array_map('trim', explode(',', $row['Properties'] ?? '')), fn($p) => $p !== '')));
            foreach ($properties as $property) {
                if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/D', $property) !== 1
                    || preg_match('/pass|token|secret|credential|auth|api.?key|private.?key|cookie|certificate|certdata|client.?key/i', $property)) {
                    throw new RuntimeException('Sensitive or invalid instance property selection');
                }
            }
            $grants[$id] = $properties;
        }
        return $grants;
    }

    public static function metadata(int $id, callable $canRead): array
    {
        $instance = IPS_GetInstance($id);
        $module = $instance['ModuleInfo'] ?? [];
        $out = ['InstanceID'=>$id,'InstanceStatus'=>$instance['InstanceStatus'] ?? null,
            'ModuleInfo'=>array_intersect_key($module,array_flip(['ModuleID','ModuleName','ModuleType']))];
        $connection = (int)($instance['ConnectionID'] ?? 0);
        // A connection never grants access to its target.
        $out['ConnectionID'] = $connection === 0 ? 0 : ($canRead($connection) ? $connection : null);
        return $out;
    }

    public static function properties(int $id, array $names): array
    {
        $values = [];
        foreach ($names as $name) {
            $path = explode('.', $name); $property = array_shift($path);
            try {
                $value = IPS_GetProperty($id, $property);
                if ($path !== [] && is_string($value)) { $value = json_decode($value, true, 16, JSON_THROW_ON_ERROR); }
                foreach ($path as $key) {
                    if (!is_array($value) || !array_key_exists($key, $value)) { throw new RuntimeException('Missing selected field'); }
                    $value = $value[$key];
                }
            }
            catch (Throwable $e) { throw new RuntimeException('Selected instance property unavailable'); }
            // No arbitrary JSON, credential URLs or other free text from configuration.
            if (!is_bool($value) && !is_int($value) && !is_float($value)) {
                $values[$name] = ['withheld'=>'Only numeric and boolean configuration values are exposed'];
                continue;
            }
            $values[$name] = $value;
        }
        return $values;
    }
}
