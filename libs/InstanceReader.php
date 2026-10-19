<?php
declare(strict_types=1);

// Configuration requires an explicit per-instance grant. Category access alone never suffices.
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
                || !is_string($row['Properties'] ?? '')
                || (array_key_exists('ReadConfiguration', $row) && !is_bool($row['ReadConfiguration']))) {
                throw new RuntimeException('Invalid instance ID or configuration checkbox');
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
            // Legacy 0.3.0 rows keep their exact allowlist until the new checkbox is saved.
            // An explicit false always overrides old Properties, including a nonempty list.
            $grants[$id] = array_key_exists('ReadConfiguration', $row) ? $row['ReadConfiguration'] : $properties;
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

    public static function configuration(int $id, $grant): array
    {
        if (is_array($grant)) { return self::properties($id, $grant); }
        if ($grant !== true) { return []; }
        try {
            $json = @IPS_GetConfiguration($id);
            if (strlen($json) > 1048576) { throw new RuntimeException('Configuration too large'); }
            $value = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($value)) { throw new RuntimeException('Invalid configuration'); }
            return self::filter($value);
        } catch (Throwable $e) {
            // Exceptions from modules must not disclose credentials or raw configuration.
            throw new RuntimeException('Instance configuration unavailable');
        }
    }

    private static function sensitive(string $key): bool
    {
        $key = preg_replace('/[^a-z0-9]/', '', strtolower($key));
        return preg_match('/pass|pwd|token|secret|credential|auth|apikey|accesskey|privatekey|clientkey|cookie|certificate|certdata|username|login|session|pincode|^(?:pin|user|key)$/', $key) === 1;
    }

    private static function filter(array $value, int $depth = 0): array
    {
        if ($depth >= 16) { return ['withheld'=>'Maximum configuration nesting reached']; }
        // Some modules store credentials as [{Name: "Password", Value: "..."}].
        foreach ($value as $key=>$label) {
            if (is_string($label) && in_array(strtolower((string)$key), ['name','key','property','header'], true)
                && self::sensitive($label)) { return ['withheld'=>'[REDACTED]']; }
        }
        $out = [];
        foreach ($value as $key=>$item) {
            if (self::sensitive((string)$key)) { $out[$key] = '[REDACTED]'; continue; }
            if (is_array($item)) { $out[$key] = self::filter($item, $depth + 1); continue; }
            if (is_string($item)) {
                if (strlen($item) > 65536) { $out[$key] = '[WITHHELD: value too large]'; continue; }
                $trim = trim($item);
                if ($trim !== '' && in_array($trim[0], ['{','['], true)) {
                    try {
                        $decoded = json_decode($trim, true, 32, JSON_THROW_ON_ERROR);
                        if (is_array($decoded)) { $out[$key] = self::filter($decoded, $depth + 1); continue; }
                    } catch (Throwable $e) {}
                    // Opaque/malformed JSON may hide nested credentials.
                    $out[$key] = '[WITHHELD: invalid JSON]'; continue;
                }
                if (preg_match('/\b(?:Bearer|Basic)\s+\S+|-----BEGIN [A-Z ]*(?:PRIVATE KEY|CERTIFICATE)-----/i', $item)) {
                    $out[$key] = '[REDACTED]'; continue;
                }
                $url = @parse_url($trim);
                if (is_array($url) && isset($url['scheme'])) {
                    $redact = isset($url['user']) || isset($url['pass']) || isset($url['fragment']);
                    foreach (explode('&', $url['query'] ?? '') as $pair) {
                        if (self::sensitive(urldecode(explode('=', $pair, 2)[0]))) { $redact = true; }
                    }
                    if ($redact) { $out[$key] = '[REDACTED]'; continue; }
                }
            }
            $out[$key] = $item;
        }
        return $out;
    }
}
