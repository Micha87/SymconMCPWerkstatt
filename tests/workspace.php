<?php
// Standalone test doubles, never run inside Symcon.
class IPSModuleStrict
{
    public int $InstanceID = 23968;
    public array $props = ['RootID'=>14846,'AllowWrite'=>true,'AllowExecute'=>false,'DebugEnabled'=>true,'Token'=>'existing-token-kept-until-apply'];
    public array $fields = [];
    public array $debug = [];
    public function Create(): void {}
    public function ApplyChanges(): void {}
    protected function ReadPropertyInteger(string $n): int { return $this->props[$n]; }
    protected function ReadPropertyBoolean(string $n): bool { return $this->props[$n]; }
    protected function ReadPropertyString(string $n): string { return $this->props[$n]; }
    protected function UpdateFormField(string $n, string $p, $v): void { $this->fields[$n][$p] = $v; }
    protected function SendDebug(string $n, string $v, int $format): void { $this->debug[] = [$n,$v]; }
}
$GLOBALS['objects'] = [14846=>['ObjectType'=>0,'ObjectName'=>'MCP Arbeitsbereich','ObjectIdent'=>'','HasChildren'=>false]];
function IPS_ObjectExists($id) { return isset($GLOBALS['objects'][$id]); }
function IPS_GetObject($id) { return $GLOBALS['objects'][$id]; }
function IPS_GetParent($id) { return $GLOBALS['objects'][$id]['ParentID'] ?? 0; }
function IPS_GetChildrenIDs($id) { return []; }
function IPS_SemaphoreEnter($name,$timeout) { return true; }
function IPS_SemaphoreLeave($name) {}
function IPS_CreateScript($type) { $GLOBALS['objects'][49352]=['ObjectType'=>3];return 49352; }
function IPS_SetParent($id,$parent) { $GLOBALS['objects'][$id]['ParentID']=$parent; }
function IPS_SetName($id,$name) { $GLOBALS['objects'][$id]['ObjectName']=$name; }
function IPS_SetScriptContent($id,$source) { $GLOBALS['objects'][$id]['source']=$source; }
function IPS_LogMessage($sender,$message) {}
$GLOBALS['connect_active'] = true;
function IPS_GetInstanceListByModuleID($id) { return [90000]; }
function IPS_GetInstance($id) { return ['InstanceStatus'=>$GLOBALS['connect_active'] ? 102 : 104]; }
function CC_GetConnectURL($id) { return 'http://test-connect.ipmagic.de/'; }
require_once __DIR__ . '/../MCPDeveloper/module.php';
$m = new SymconMCPWerkstatt();
$dispatch = new ReflectionMethod($m,'dispatch');
function rpcTest($method,$params=[]) {
    global $m,$dispatch;
    return $dispatch->invoke($m,['jsonrpc'=>'2.0','id'=>1,'method'=>$method,'params'=>$params]);
}
function toolTest($name,$args=[]) { return rpcTest('tools/call',['name'=>$name,'arguments'=>$args]); }
function expectTest($v,$message) { if (!$v) { throw new RuntimeException($message); } }
$r=toolTest('workspace_info');$v=json_decode($r['result']['content'][0]['text'],true);
expectTest($v['root_id']===14846 && $v['root_name']==='MCP Arbeitsbereich','Workspace identity');
expectTest($v['allow_write'] && !$v['allow_execute'],'Permissions');
$r=toolTest('objects_list');$v=json_decode($r['result']['content'][0]['text'],true);
expectTest($v===['root_id'=>14846,'parent_id'=>14846,'objects'=>[]],'Empty root discovery');
$r=rpcTest('initialize',['protocolVersion'=>'2025-03-26']);
expectTest(str_contains($r['result']['instructions'],'14846'),'Initialize root ID');
$r=toolTest('script_put',['name'=>'Hello World','source'=>'<?php echo "SECRET-SOURCE";']);
expectTest(!$r['result']['isError'] && $GLOBALS['objects'][49352]['ParentID']===14846,'Create with default root');
$r=toolTest('script_put',['name'=>'Outside','source'=>'SECRET-SOURCE','parent_id'=>77777]);
expectTest($r['result']['isError'],'Reject outside parent');
$before=$m->props['Token'];$m->UIGenerateToken();$generated=$m->fields['Token']['value'];
expectTest(strlen($generated)===64 && ctype_xdigit($generated),'Random hex token');
expectTest($m->props['Token']===$before,'Generation does not rotate saved token');
expectTest($m->fields['CopyValue']['value']===$generated && $m->fields['CopyPopup']['visible'],'New token copy dialog');
$m->UIShowToken();expectTest($m->fields['CopyValue']['value']===$before,'Show saved token');
$r=rpcTest('SECRET-METHOD');expectTest($r['error']['code']===-32601,'Unknown method');
$logs=json_encode($m->debug);
foreach ([$generated,$before,'SECRET-SOURCE','SECRET-METHOD'] as $secret) { expectTest(!str_contains($logs,$secret),'Secrets absent in debug'); }
$n=count($m->debug);$m->props['DebugEnabled']=false;toolTest('workspace_info');
expectTest(count($m->debug)===$n,'Disable debug');
$m->props['AllowWrite']=false;
$r=toolTest('script_put',['name'=>'Blocked','source'=>'<?php']);expectTest(isset($r['error']),'Writes gated');
echo "Workspace, default parent, token UI, debug redaction and permissions: all checks passed\n";

$m->props['Token']=str_repeat('b2',32);
$m->props['AllowTokenInPath']=true;
$m->UIShowChatGPTAddress();
expectTest($m->fields['CopyValue']['value']==='https://test-connect.ipmagic.de/hook/symcon-mcp-23968/'.str_repeat('b2',32),'Full HTTPS ChatGPT URL');
expectTest(!str_contains(json_encode($m->debug),'test-connect.ipmagic.de'),'URL absent in debug');
$m->props['AllowTokenInPath']=false;$m->UIShowChatGPTAddress();expectTest($m->fields['CopyValue']['value']==='','No token URL without path opt-in');
$m->props['AllowTokenInPath']=true;$GLOBALS['connect_active']=false;$m->UIShowChatGPTAddress();expectTest($m->fields['CopyValue']['value']==='','No stale address when Connect inactive');
echo "ChatGPT copy-address tests passed\n";

$GLOBALS['objects'][41728]=['ObjectType'=>5,'ObjectName'=>'24_TP','ParentID'=>14846];
$GLOBALS['media_bytes']='{"pages":[{"name":"Test"}]}';
$GLOBALS['media_available']=true;
$GLOBALS['media_size_override']=null;
$GLOBALS['media_raw_override']=null;
$GLOBALS['media_reads']=0;
function IPS_GetMedia($id) { return ['MediaID'=>$id,'MediaFile'=>'media/41728.bin','MediaType'=>5,'MediaSize'=>$GLOBALS['media_size_override'] ?? strlen($GLOBALS['media_bytes']),'MediaIsAvailable'=>$GLOBALS['media_available']]; }
function IPS_GetMediaContent($id) { $GLOBALS['media_reads']++;return $GLOBALS['media_raw_override'] ?? base64_encode($GLOBALS['media_bytes']); }
$r=toolTest('media_read',['id'=>41728,'limit'=>10]);$v=json_decode($r['result']['content'][0]['text'],true);
expectTest(!$r['result']['isError'] && $v['format_hint']==='json-like' && $v['encoding']==='utf-8','Readable text media');
expectTest($v['content']===substr($GLOBALS['media_bytes'],0,10) && $v['has_more'] && $v['next_offset']===10,'Media pagination');
$hash=$v['sha256'];
$r=toolTest('media_read',['id'=>41728,'offset'=>10,'expected_sha256'=>$hash]);$v=json_decode($r['result']['content'][0]['text'],true);
expectTest($v['content']===substr($GLOBALS['media_bytes'],10) && !$v['has_more'],'Remainder');
$r=toolTest('media_read',['id'=>41728,'expected_sha256'=>'wrong']);expectTest($r['result']['isError'],'Stale file rejected');
$r=toolTest('media_read',['id'=>41728,'offset'=>999]);expectTest($r['result']['isError'],'Offset bounds');
$r=toolTest('media_read',['id'=>41728,'limit'=>65537]);expectTest(isset($r['error']),'Response limit');
$r=toolTest('media_read',['id'=>14846]);expectTest($r['result']['isError'],'Wrong object type');
$GLOBALS['objects'][77777]=['ObjectType'=>5,'ParentID'=>0];
$r=toolTest('media_read',['id'=>77777]);expectTest($r['result']['isError'],'Media outside workspace rejected');
$GLOBALS['media_bytes']="PK\x03\x04\0\xff";
$r=toolTest('media_read',['id'=>41728]);$v=json_decode($r['result']['content'][0]['text'],true);
expectTest($v['format_hint']==='zip' && $v['encoding']==='base64' && base64_decode($v['content'])===$GLOBALS['media_bytes'],'Binary media lossless');
$GLOBALS['media_size_override']=33554433;$n=$GLOBALS['media_reads'];
$r=toolTest('media_read',['id'=>41728]);expectTest($r['result']['isError'] && $GLOBALS['media_reads']===$n,'Oversize precheck');
$GLOBALS['media_size_override']=null;$GLOBALS['media_available']=false;
$r=toolTest('media_read',['id'=>41728]);expectTest($r['result']['isError'],'Unavailable media');
$GLOBALS['media_available']=true;$GLOBALS['media_raw_override']='!!not-base64!!';
$r=toolTest('media_read',['id'=>41728]);expectTest($r['result']['isError'],'Invalid content rejected');
$GLOBALS['media_raw_override']=null;$GLOBALS['media_bytes']='';
$r=toolTest('media_read',['id'=>41728]);$v=json_decode($r['result']['content'][0]['text'],true);
expectTest($v['size_bytes']===0 && $v['content']==='' && !$v['has_more'],'Empty media');
echo "13 media checks passed\n";
