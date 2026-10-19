<?php
declare(strict_types=1);

require_once __DIR__ . '/../libs/TokenAuth.php';
require_once __DIR__ . '/../libs/MediaReader.php';
require_once __DIR__ . '/../libs/AccessPolicy.php';
require_once __DIR__ . '/../libs/InstanceReader.php';

class SymconMCPWerkstatt extends IPSModuleStrict
{
    public function Create(): void
    {
        parent::Create();
        $this->RegisterPropertyBoolean('Enabled', false);
        $this->RegisterPropertyString('Token', '');
        $this->RegisterPropertyBoolean('AllowTokenInPath', false);
        $this->RegisterPropertyInteger('RootID', 0);
        $this->RegisterPropertyString('ReadOnlyCategories', '[]');
        $this->RegisterPropertyString('DeniedCategories', '[]');
        $this->RegisterPropertyString('ReadOnlyInstances', '[]');
        $this->RegisterPropertyBoolean('AllowScriptSourceRead', false);
        $this->RegisterPropertyBoolean('AllowMediaContentRead', false);
        $this->RegisterPropertyBoolean('AllowWrite', false);
        $this->RegisterPropertyBoolean('AllowExecute', false);
        $this->RegisterPropertyString('Origins', '');
        $this->RegisterPropertyBoolean('DebugEnabled', true);
        $this->RegisterHook('symcon-mcp-' . $this->InstanceID);
    }

    public function ApplyChanges(): void
    {
        parent::ApplyChanges();
        try { $valid = $this->policy()->readableRoots() !== []; }
        catch (Throwable $e) { $valid = false; }
        $this->SetStatus(!$this->ReadPropertyBoolean('Enabled') ? 104 :
            ((strlen($this->ReadPropertyString('Token')) >= 32 && $valid) ? 102 : 200));
        $this->SetSummary('/hook/symcon-mcp-' . $this->InstanceID);
    }

    public function UIGenerateToken(): void
    {
        // Draft only: existing connections remain valid until the user clicks Apply.
        $token = bin2hex(random_bytes(32));
        $this->UpdateFormField('Token', 'value', $token);
        $this->showCopy('Neuer Token – zum Aktivieren Änderungen übernehmen. Feld anklicken, Strg+A, Strg+C.', $token);
    }

    public function UIShowToken(): void
    {
        $this->showCopy('Gespeicherter Token – Feld anklicken, Strg+A, Strg+C.', $this->ReadPropertyString('Token'));
    }

    public function UIShowChatGPTAddress(): void
    {
        if (!$this->ReadPropertyBoolean('AllowTokenInPath')) {
            $this->showCopy('Zuerst „Token auch in der Adresse“ aktivieren und Änderungen übernehmen.', '');
            return;
        }
        $token = $this->ReadPropertyString('Token');
        if (strlen($token) < 32 || preg_match('/[\s\/\x00]/', $token)) {
            $this->showCopy('Bitte einen gültigen URL-tauglichen Token erzeugen und übernehmen.', '');
            return;
        }
        $base = '';
        try {
            foreach (IPS_GetInstanceListByModuleID('{9486D575-BE8C-4ED8-B5B5-20930E26DE6F}') as $connectID) {
                if (IPS_GetInstance($connectID)['InstanceStatus'] !== 102) { continue; }
                $url = CC_GetConnectURL($connectID);
                $parts = parse_url($url);
                // Connect may return http; always use the encrypted public endpoint.
                if (!is_array($parts) || !isset($parts['host']) || isset($parts['user']) || isset($parts['pass'])) { continue; }
                $host = strtolower($parts['host']);
                if (preg_match('/^[a-z0-9-]+\.ipmagic\.de$/D', $host) !== 1) { continue; }
                $base = 'https://' . $host;
                break;
            }
        } catch (Throwable $e) {
            // Do not put URL or secrets from failures into Debug.
            $this->trace('Connect-Adresse nicht verfügbar');
        }
        if ($base === '') {
            $this->showCopy('Keine aktive Symcon-Connect-Adresse gefunden. Connect Control prüfen.', '');
            return;
        }
        $url = $base . '/hook/symcon-mcp-' . $this->InstanceID . '/' . rawurlencode($token);
        $this->showCopy('ChatGPT: MCP-Adresse mit gespeichertem Token. Anmeldung „Keine Anmeldung“. Feld anklicken, Strg+A, Strg+C.', $url);
    }

    private function showCopy(string $caption, string $value): void
    {
        $this->UpdateFormField('CopyCaption', 'caption', $caption);
        $this->UpdateFormField('CopyValue', 'value', $value);
        $this->UpdateFormField('CopyPopup', 'visible', true);
    }

    private function trace(string $event, array $data = []): void
    {
        if ($this->ReadPropertyBoolean('DebugEnabled')) {
            // Only internal labels, known method/tool names, numeric IDs and timings.
            // Never include raw requests, paths, headers, source code, values or exceptions.
            $this->SendDebug($event, json_encode($data, JSON_UNESCAPED_UNICODE), 0);
        }
    }

    protected function ProcessHookData(): void
    {
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        if ($this->GetStatus() !== 102) { $this->trace('HTTP', ['status'=>503]); http_response_code(503); return; }
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        $origins = array_filter(array_map('trim', explode(',', $this->ReadPropertyString('Origins'))));
        if ($origin !== '' && !in_array($origin, $origins, true)) { $this->trace('Origin abgewiesen', ['status'=>403]); http_response_code(403); return; }
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (!SMCPTokenAuth::accepts(
            $this->ReadPropertyString('Token'),
            $this->ReadPropertyBoolean('AllowTokenInPath'),
            $auth,
            $_SERVER['REQUEST_URI'] ?? '',
            '/hook/symcon-mcp-' . $this->InstanceID
        )) {
            $this->trace('Anmeldung abgewiesen', ['status'=>401]);
            header('WWW-Authenticate: Bearer'); http_response_code(401); return;
        }
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            $this->trace('HTTP-Methode abgewiesen', ['status'=>405]);
            header('Allow: POST'); http_response_code(405); return;
        }
        // Symcon may expose Content-Type as HTTP_CONTENT_TYPE instead of CONTENT_TYPE.
        $contentType = $_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '';
        if (strtolower(trim(explode(';', $contentType, 2)[0])) !== 'application/json') {
            $this->trace('Content-Type abgewiesen', ['status'=>415]);
            http_response_code(415);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['error'=>'Content-Type must be application/json']);
            return;
        }
        $raw = file_get_contents('php://input', false, null, 0, 1048577);
        if (strlen($raw) > 1048576) { $this->trace('Anfrage zu gross', ['status'=>413]); http_response_code(413); return; }
        try { $request = json_decode($raw, true, 64, JSON_THROW_ON_ERROR); }
        catch (Throwable $e) { $this->trace('JSON ungueltig', ['code'=>-32700]); $this->reply(null, null, -32700, 'Invalid JSON'); return; }
        $reply = $this->dispatch($request);
        if ($reply === null) { http_response_code(202); return; }
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($reply, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    }

    private function reply($id, $result, int $code, string $message): void
    {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['jsonrpc'=>'2.0', 'id'=>$id, 'error'=>['code'=>$code,'message'=>$message]]);
    }

    private function dispatch($r): ?array
    {
        if (!is_array($r) || ($r['jsonrpc'] ?? '') !== '2.0' || !is_string($r['method'] ?? null)) {
            return ['jsonrpc'=>'2.0','id'=>null,'error'=>['code'=>-32600,'message'=>'Invalid request']];
        }
        $id = $r['id'] ?? null;
        $method = $r['method'];
        $knownMethods = ['initialize','ping','tools/list','tools/call','notifications/initialized'];
        $this->trace('MCP Anfrage', ['method'=>in_array($method, $knownMethods, true) ? $method : 'unknown']);
        // Notifications never execute tools.
        if (!array_key_exists('id', $r)) { return null; }
        try {
            $p = $r['params'] ?? [];
            if (!is_array($p)) { throw new InvalidArgumentException('Invalid params'); }
            switch ($method) {
                case 'initialize':
                    $versions = ['2025-03-26','2025-06-18','2025-11-25'];
                    $version = in_array($p['protocolVersion'] ?? '', $versions, true) ? $p['protocolVersion'] : '2025-03-26';
                    $result = ['protocolVersion'=>$version,'capabilities'=>['tools'=>['listChanged'=>false]],
                        'serverInfo'=>['name'=>'Symcon MCP Werkstatt','version'=>'0.3.1'],
                        'instructions'=>'Use workspace_info for readable roots and write permissions; use instances_list and instance_read for permitted instances including selected core instances. Instance configuration requires an explicit per-instance checkbox; known credential fields are redacted. Denied categories are invisible; read-only categories and selected instances cannot be modified or executed, including overlaps. Source and media contents require separate grants. Omit parent_id to create in the workspace. Arbitrary PHP execution is NOT sandboxed and can bypass object restrictions.'];
                    break;
                case 'ping': $result = new stdClass(); break;
                case 'tools/list': $result = ['tools'=>$this->tools()]; break;
                case 'tools/call':
                    $name = $p['name'] ?? '';
                    $definitions = array_column($this->tools(), null, 'name');
                    if (!isset($definitions[$name])) { throw new InvalidArgumentException('Unknown or disabled tool'); }
                    $args = $p['arguments'] ?? [];
                    $this->validate($definitions[$name]['inputSchema'], $args);
                    $started = microtime(true);
                    $this->trace('Werkzeug Start', ['tool'=>$name]);
                    try {
                        $value = $this->call($name, $args);
                        $this->trace('Werkzeug OK', ['tool'=>$name,'duration_ms'=>(int)round((microtime(true)-$started)*1000)]);
                        $result = ['content'=>[['type'=>'text','text'=>json_encode($value, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)]], 'isError'=>false];
                    } catch (Throwable $e) {
                        $this->trace('Werkzeug Fehler', ['tool'=>$name,'duration_ms'=>(int)round((microtime(true)-$started)*1000)]);
                        $result = ['content'=>[['type'=>'text','text'=>$e->getMessage()]],'isError'=>true];
                    }
                    break;
                default: return ['jsonrpc'=>'2.0','id'=>$id,'error'=>['code'=>-32601,'message'=>'Method not found']];
            }
            return ['jsonrpc'=>'2.0','id'=>$id,'result'=>$result];
        } catch (Throwable $e) {
            $this->trace('MCP Fehler', ['code'=>-32602]);
            return ['jsonrpc'=>'2.0','id'=>$id,'error'=>['code'=>-32602,'message'=>$e->getMessage()]];
        }
    }

    private function tools(): array
    {
        $int = ['type'=>'integer','minimum'=>1]; $str = ['type'=>'string'];
        $defs = [
            ['workspace_info','Return workspace and readable category roots with permissions. Blocked categories are not disclosed.', [], [], false],
            ['objects_list','Return visible direct children with read/write access labels. Blocked children are excluded. Omit parent_id for the workspace, or readable roots if no workspace is available.', ['parent_id'=>$int], [], false],
            ['object_read','Read accessible metadata, variable values and instance information. Instance configuration needs a separate per-instance grant and filters known credential fields. Source and media require separate grants. Denied children and link targets stay hidden.', ['id'=>$int], ['id'], false],
            ['instances_list','List permitted instances including explicitly selected core instances; optionally filter by module GUID. Denied instances stay hidden.', ['module_id'=>$str], [], false],
            ['instance_read','Read permitted instance status, module identity, filtered connection ID and configuration when explicitly granted per instance. Known credential fields are redacted. No configuration writes.', ['id'=>$int], ['id'], false]
        ];
        if ($this->ReadPropertyBoolean('AllowMediaContentRead')) {
            $defs[] = ['media_read','Read a media file from accessible categories; requires separate media-content permission. Returns UTF-8 or Base64 chunks and SHA256. Default 8192 bytes, max 65536 per reply, max file 32 MiB. Use next_offset and expected_sha256.', ['id'=>$int,'offset'=>['type'=>'integer','minimum'=>0],'limit'=>['type'=>'integer','minimum'=>1,'maximum'=>65536],'expected_sha256'=>$str], ['id'], false];
        }
        if ($this->ReadPropertyBoolean('AllowWrite') && $this->hasWritableWorkspace()) {
            $defs[] = ['category_create','Create category; omit parent_id to use workspace root.', ['parent_id'=>$int,'name'=>$str], ['name'], true];
            $defs[] = ['variable_create','Create variable; omit parent_id for workspace root. type: 0 boolean, 1 integer, 2 float, 3 string.', ['parent_id'=>$int,'name'=>$str,'type'=>['type'=>'integer','minimum'=>0,'maximum'=>3]], ['name','type'], true];
            $defs[] = ['variable_set','Set stored variable value, without device action.', ['id'=>$int,'value'=>['type'=>['boolean','integer','number','string']]], ['id','value'], true];
            $defs[] = ['script_put','Create PHP script (omit parent_id for workspace root) or replace source. For updates provide expected_sha256 from object_read. PHP has full system privileges when executed.', ['parent_id'=>$int,'id'=>$int,'name'=>$str,'source'=>$str,'expected_sha256'=>$str], ['source'], true];
            if ($this->ReadPropertyBoolean('AllowExecute')) {
                $defs[] = ['event_interval','Create inactive cyclic event under a PHP script, or update one. seconds 1..86400. Enabling permits full-privilege execution.', ['script_id'=>$int,'event_id'=>$int,'seconds'=>['type'=>'integer','minimum'=>1,'maximum'=>86400],'active'=>['type'=>'boolean']], ['script_id','seconds','active'], true];
            }
        }
        if ($this->ReadPropertyBoolean('AllowExecute') && $this->hasWritableWorkspace()) {
            $defs[] = ['script_run','Execute PHP script asynchronously with full Symcon privileges; returns acceptance, not script result.', ['id'=>$int], ['id'], true];
        }
        $out = [];
        foreach ($defs as [$name,$desc,$props,$required,$write]) {
            $out[] = ['name'=>$name,'description'=>$desc,'inputSchema'=>['type'=>'object','properties'=>(object)$props,'required'=>$required,'additionalProperties'=>false],
                'annotations'=>['readOnlyHint'=>!$write,'destructiveHint'=>$write,'idempotentHint'=>false,'openWorldHint'=>$write]];
        }
        return $out;
    }

    private function validate(array $schema, $a): void
    {
        if (!is_array($a)) { throw new InvalidArgumentException('Arguments must be an object'); }
        foreach ($schema['required'] as $key) { if (!array_key_exists($key,$a)) { throw new InvalidArgumentException('Missing: '.$key); } }
        $props = (array)$schema['properties'];
        foreach ($a as $key=>$v) {
            if (!isset($props[$key])) { throw new InvalidArgumentException('Unknown argument: '.$key); }
            $s = $props[$key]; $ok = false;
            foreach ((array)$s['type'] as $t) {
                $ok = $ok || ($t === 'integer' && is_int($v)) || ($t === 'number' && (is_float($v)||is_int($v))) || ($t === 'boolean' && is_bool($v)) || ($t === 'string' && is_string($v));
            }
            if (!$ok || (isset($s['minimum']) && $v < $s['minimum']) || (isset($s['maximum']) && $v > $s['maximum'])) { throw new InvalidArgumentException('Invalid: '.$key); }
        }
    }

    private function policy(): SMCPAccessPolicy
    {
        return new SMCPAccessPolicy($this->ReadPropertyInteger('RootID'),
            $this->ReadPropertyString('ReadOnlyCategories'),
            $this->ReadPropertyString('DeniedCategories'), $this->InstanceID,
            $this->ReadPropertyString('ReadOnlyInstances'));
    }

    private function hasWritableWorkspace(): bool
    {
        $policy = $this->policy();
        return $policy->workspace() > 0 && $policy->canWrite($policy->workspace());
    }

    private function check(int $id, ?int $type = null, bool $write = false): array
    {
        $policy = $this->policy();
        if (!$policy->canRead($id)) { throw new RuntimeException('Object unavailable or not permitted'); }
        if ($write && !$policy->canWrite($id)) { throw new RuntimeException('Read-only category: write and execution denied'); }
        $o = IPS_GetObject($id);
        if ($type !== null && $o['ObjectType'] !== $type) { throw new RuntimeException('Wrong object type'); }
        return $o;
    }

    private function visibleChildren(int $id, SMCPAccessPolicy $policy): array
    {
        return array_values(array_filter(IPS_GetChildrenIDs($id), fn(int $child): bool => $policy->canRead($child)));
    }

    private function safeObject(int $id): array
    {
        $policy = $this->policy(); $o = $this->check($id);
        $children = $this->visibleChildren($id, $policy);
        $o['ChildrenIDs'] = $children; $o['HasChildren'] = $children !== [];
        if (isset($o['ParentID']) && !$policy->canRead($o['ParentID'])) { $o['ParentID'] = null; }
        return $o;
    }

    private function visibleChildrenForList(int $id, SMCPAccessPolicy $policy): array
    {
        $this->check($id);
        return $this->visibleChildren($id, $policy);
    }

    private function objectSummary(int $id, SMCPAccessPolicy $policy): array
    {
        $o = $this->check($id);
        return ['id'=>$id,'name'=>$o['ObjectName'],'ident'=>$o['ObjectIdent'],'type'=>$o['ObjectType'],
            'has_children'=>$this->visibleChildren($id, $policy) !== [], 'access'=>$policy->level($id)];
    }

    private function call(string $name, array $a)
    {
        if ($name === 'instances_list') {
            $policy = $this->policy(); $out = [];
            if (isset($a['module_id']) && preg_match('/^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$/iD', $a['module_id']) !== 1) {
                throw new InvalidArgumentException('Invalid module GUID');
            }
            $ids = IPS_GetInstanceList(); sort($ids, SORT_NUMERIC);
            foreach ($ids as $id) {
                if (!$policy->canRead($id)) { continue; }
                $instance = SMCPInstanceReader::metadata($id, fn(int $target): bool => $policy->canRead($target));
                if (isset($a['module_id']) && strcasecmp($instance['ModuleInfo']['ModuleID'] ?? '', $a['module_id']) !== 0) { continue; }
                $out[] = array_merge($this->objectSummary($id, $policy), ['instance'=>$instance]);
            }
            return ['instances'=>$out];
        }
        if ($name === 'instance_read') {
            $this->check($a['id'], 1);
            return $this->call('object_read', ['id'=>$a['id']]);
        }
        if ($name === 'workspace_info') {
            $policy = $this->policy(); $root = $policy->workspace();
            $rootReadable = $policy->canRead($root); $writable = $rootReadable && $policy->canWrite($root);
            $roots = [];
            foreach ($policy->readableRoots() as $id) { $roots[] = $this->objectSummary($id, $policy); }
            return ['root_id'=>$rootReadable ? $root : null,
                'root_name'=>$rootReadable ? IPS_GetName($root) : null,'readable_roots'=>$roots,
                'allow_write'=>$writable && $this->ReadPropertyBoolean('AllowWrite'),
                'allow_execute'=>$writable && $this->ReadPropertyBoolean('AllowExecute'),
                'allow_script_source_read'=>$this->ReadPropertyBoolean('AllowScriptSourceRead'),
                'allow_media_content_read'=>$this->ReadPropertyBoolean('AllowMediaContentRead'),
                'instance_configuration_policy'=>'Explicit per-instance checkbox; known credential fields redacted; legacy property allowlists remain restricted',
                'php_execution_sandboxed'=>false];
        }
        if ($name === 'objects_list') {
            $policy = $this->policy(); $root = $policy->workspace();
            $id = $a['parent_id'] ?? ($policy->canRead($root) ? $root : null);
            $ids = $id === null ? $policy->readableRoots() : $this->visibleChildrenForList($id, $policy);
            $out = [];
            foreach ($ids as $child) { $out[] = $this->objectSummary($child, $policy); }
            return ['root_id'=>$policy->canRead($root) ? $root : null,'parent_id'=>$id,'objects'=>$out];
        }
        if ($name === 'media_read') {
            if (!$this->ReadPropertyBoolean('AllowMediaContentRead')) { throw new RuntimeException('Media content reading disabled'); }
            $this->check($a['id'],5);
            return SMCPMediaReader::read($a['id'],$a['offset'] ?? 0,$a['limit'] ?? 8192,$a['expected_sha256'] ?? '');
        }
        if ($name === 'object_read') {
            $id = $a['id']; $o = $this->safeObject($id);
            $out = ['id'=>$id,'object'=>$o,'access'=>$this->policy()->level($id)];
            if ($o['ObjectType'] === 1) {
                $policy = $this->policy();
                $out['instance'] = SMCPInstanceReader::metadata($id, fn(int $target): bool => $policy->canRead($target));
                $grants = SMCPInstanceReader::grants($this->ReadPropertyString('ReadOnlyInstances'));
                $grant = $grants[$id] ?? false;
                $out['configuration_readable'] = $grant === true || (is_array($grant) && $grant !== []);
                $out['configuration'] = (object)SMCPInstanceReader::configuration($id, $grant);
            }
            if ($o['ObjectType'] === 2) { $out['variable'] = IPS_GetVariable($id); $out['value'] = GetValue($id); }
            if ($o['ObjectType'] === 3) {
                $out['source_readable'] = $this->ReadPropertyBoolean('AllowScriptSourceRead');
                if ($out['source_readable']) { $out['source'] = IPS_GetScriptContent($id); $out['sha256'] = hash('sha256',$out['source']); }
            }
            if ($o['ObjectType'] === 4) {
                $event = IPS_GetEvent($id); $source = $this->ReadPropertyBoolean('AllowScriptSourceRead');
                $out['event'] = $source ? $event : array_intersect_key($event, array_flip(['EventID','EventType','EventActive','EventLastRun','EventNextRun','LastRun','NextRun']));
                $out['source_readable'] = $source;
            }
            if ($o['ObjectType'] === 5) {
                // Stream URLs and filenames can contain credentials, so metadata does not disclose paths.
                $out['media'] = array_intersect_key(IPS_GetMedia($id),array_flip(['MediaID','MediaType','MediaSize','MediaUpdated','MediaCRC','MediaIsAvailable','MediaIsCached']));
                $out['content_readable'] = $this->ReadPropertyBoolean('AllowMediaContentRead');
            }
            if ($o['ObjectType'] === 6) {
                $target = (int)IPS_GetLink($id)['TargetID'];
                $readable = $this->policy()->canRead($target);
                $out['link'] = ['target_readable'=>$readable];
                if ($readable) { $out['link']['target_id'] = $target; }
            }
            return $out;
        }
        $a['parent_id'] = $a['parent_id'] ?? $this->ReadPropertyInteger('RootID');
        // Permission checks are repeated here, not just in the advertised tools.
        if ($name !== 'script_run' && !$this->ReadPropertyBoolean('AllowWrite')) { throw new RuntimeException('Writes disabled'); }
        if (in_array($name,['script_run','event_interval'],true) && !$this->ReadPropertyBoolean('AllowExecute')) { throw new RuntimeException('Execution disabled'); }
        if (!IPS_SemaphoreEnter('MCPDeveloper_'.$this->InstanceID,5000)) { throw new RuntimeException('Busy, retry'); }
        try {
            $id = 0;
            switch ($name) {
                case 'category_create': case 'variable_create':
                    $this->check($a['parent_id'],0,true);
                    $id = $name === 'category_create' ? IPS_CreateCategory() : IPS_CreateVariable($a['type']);
                    IPS_SetParent($id,$a['parent_id']); IPS_SetName($id,$a['name']); break;
                case 'variable_set':
                    $id=$a['id']; $this->check($id,2,true); $type=IPS_GetVariable($id)['VariableType']; $v=$a['value'];
                    if (!(($type===0 && is_bool($v)) || ($type===1 && is_int($v)) || ($type===2 && (is_int($v)||is_float($v))) || ($type===3 && is_string($v)))) { throw new RuntimeException('Value type mismatch'); }
                    SetValue($id,$v); break;
                case 'script_put':
                    if (isset($a['id'])) {
                        $id=$a['id']; $this->check($id,3,true);
                        if (IPS_GetScript($id)['ScriptType'] !== 0) { throw new RuntimeException('Only PHP scripts'); }
                        if (!hash_equals(hash('sha256',IPS_GetScriptContent($id)),$a['expected_sha256'] ?? '')) { throw new RuntimeException('Source changed; read again'); }
                        // Updating an active script can execute new code through existing events.
                        if (!$this->ReadPropertyBoolean('AllowExecute')) { throw new RuntimeException('Updating existing PHP requires execution permission'); }
                    } else {
                        if (!isset($a['name'])) { throw new RuntimeException('Create requires name'); }
                        $this->check($a['parent_id'],0,true); $id=IPS_CreateScript(0); IPS_SetParent($id,$a['parent_id']); IPS_SetName($id,$a['name']);
                    }
                    IPS_SetScriptContent($id,$a['source']); break;
                case 'script_run':
                    $id=$a['id']; $this->check($id,3,true);
                    if (IPS_GetScript($id)['ScriptType'] !== 0) { throw new RuntimeException('Only PHP scripts'); }
                    if (!IPS_RunScript($id)) { throw new RuntimeException('Script could not be started'); } break;
                case 'event_interval':
                    $this->check($a['script_id'],3,true);
                    if (IPS_GetScript($a['script_id'])['ScriptType'] !== 0) { throw new RuntimeException('Only PHP scripts'); }
                    if (isset($a['event_id'])) {
                        $id=$a['event_id']; $this->check($id,4,true);
                        if (IPS_GetParent($id) !== $a['script_id'] || IPS_GetEvent($id)['EventType'] !== 1) { throw new RuntimeException('Wrong event'); }
                    } else { $id=IPS_CreateEvent(1); IPS_SetParent($id,$a['script_id']); IPS_SetName($id,'MCP Interval'); }
                    IPS_SetEventActive($id,false);
                    IPS_SetEventCyclic($id,0,0,0,0,1,$a['seconds']);
                    IPS_SetEventScript($id,'IPS_RunScript('.$a['script_id'].');');
                    IPS_SetEventActive($id,$a['active']); break;
                default: throw new RuntimeException('Unknown tool');
            }
            $this->trace('Objekt geschrieben', ['tool'=>$name,'object_id'=>$id]);
            IPS_LogMessage('Symcon MCP','Tool '.$name.' object '.$id);
            return ['id'=>$id,'accepted'=>true];
        } finally { IPS_SemaphoreLeave('MCPDeveloper_'.$this->InstanceID); }
    }
}
