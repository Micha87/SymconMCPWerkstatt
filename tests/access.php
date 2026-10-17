<?php
require_once __DIR__ . '/workspace.php';

function addAccessObject(int $id, int $parent, int $type, string $name): void
{
    $GLOBALS['objects'][$id] = ['ObjectID'=>$id,'ObjectType'=>$type,'ObjectName'=>$name,
        'ObjectIdent'=>'','ParentID'=>$parent,'ChildrenIDs'=>[],'HasChildren'=>false];
}
function accessValue(array $reply): array { return json_decode($reply['result']['content'][0]['text'],true,512,JSON_THROW_ON_ERROR); }
function accessDenied(array $reply): bool { return isset($reply['error']) || ($reply['result']['isError'] ?? false); }
function setAccessRows(string $key, array $ids): void { global $m; $m->props[$key]=json_encode(array_map(fn($id)=>['CategoryID'=>$id],$ids)); }

foreach ($GLOBALS['objects'] as $id => &$obj) { $obj += ['ObjectID'=>$id,'ObjectName'=>'Object '.$id,'ObjectIdent'=>'','ParentID'=>0,'HasChildren'=>false]; }
unset($obj);
$GLOBALS['script_reads']=0;$GLOBALS['executions']=[];$GLOBALS['variable_writes']=[];
function IPS_GetScriptContent($id) { $GLOBALS['script_reads']++; return $GLOBALS['objects'][$id]['source'] ?? '<?php /* SOURCE-SECRET */'; }
function IPS_GetScript($id) { return ['ScriptType'=>0]; }
function IPS_GetVariable($id) { return ['VariableType'=>1,'VariableValue'=>17]; }
function GetValue($id) { return 17; }
function SetValue($id,$value) { $GLOBALS['variable_writes'][$id]=$value; }
function IPS_RunScript($id) { $GLOBALS['executions'][]=$id;return true; }
function IPS_GetEvent($id) { return ['EventID'=>$id,'EventType'=>1,'EventActive'=>true,'EventScript'=>'EVENT-SOURCE-SECRET','EventActionParameters'=>['password'=>'EVENT-PARAM-SECRET']]; }
function IPS_GetLink($id) { return ['TargetID'=>$GLOBALS['objects'][$id]['target']]; }
function IPS_CreateCategory() { addAccessObject(51001,0,0,'new');return 51001; }
function IPS_CreateVariable($type) { addAccessObject(51002,0,2,'new');return 51002; }

$m->props['AllowWrite']=true;$m->props['AllowExecute']=true;
$m->props['AllowScriptSourceRead']=false;$m->props['AllowMediaContentRead']=false;
addAccessObject(100,0,0,'System');
addAccessObject(200,100,0,'Read only');
addAccessObject(210,200,2,'Measurement');
addAccessObject(220,200,3,'Read-only script');
addAccessObject(230,200,4,'Read-only event');
addAccessObject(240,200,5,'Read-only media');
addAccessObject(300,200,0,'DENIED-SECRET-CATEGORY');
addAccessObject(310,300,2,'DENIED-SECRET-VARIABLE');
addAccessObject(400,14846,0,'Read only inside workspace');
addAccessObject(410,400,2,'Nested read-only measurement');
addAccessObject(420,400,3,'Nested read-only script');
addAccessObject(500,14846,0,'Denied inside workspace');
addAccessObject(510,500,3,'Denied script');
addAccessObject(520,500,5,'Denied media');
addAccessObject(600,14846,2,'Writable measurement');
addAccessObject(610,14846,3,'Writable script');
addAccessObject(620,14846,4,'Writable event');
addAccessObject(630,14846,6,'Link to blocked object');$GLOBALS['objects'][630]['target']=310;
addAccessObject(631,14846,6,'Link to readable object');$GLOBALS['objects'][631]['target']=210;
addAccessObject(632,14846,6,'Link to outside object');$GLOBALS['objects'][632]['target']=77777;
addAccessObject(23968,14846,1,'Werkstatt instance');
addAccessObject(23969,23968,2,'Module child');
setAccessRows('ReadOnlyCategories',[200,400]);setAccessRows('DeniedCategories',[300,500]);

$policy = new SMCPAccessPolicy(14846,$m->props['ReadOnlyCategories'],$m->props['DeniedCategories'],23968);
foreach([14846=>'write',600=>'write',200=>'read',210=>'read',400=>'read',410=>'read',300=>'none',310=>'none',500=>'none',510=>'none',100=>'none',77777=>'none',23968=>'none',23969=>'none',0=>'none'] as $id=>$level) {
    expectTest($policy->level($id)===$level,'Policy level '.$id);
}
$r=toolTest('object_read',['id'=>210]);$v=accessValue($r);expectTest($v['value']===17 && $v['access']==='read','Read measurement');
foreach([300,310,500,510,77777,23968,23969] as $id) expectTest(accessDenied(toolTest('object_read',['id'=>$id])),'Deny direct read '.$id);
$children=accessValue(toolTest('objects_list',['parent_id'=>200]));
expectTest(!in_array(300,array_column($children['objects'],'id'),true),'Hidden category in list');
$o=accessValue(toolTest('object_read',['id'=>200]));
expectTest(!in_array(300,$o['object']['ChildrenIDs'],true),'Hidden child IDs');
expectTest($o['object']['ParentID']===null,'Inaccessible parent hidden');
$ws=accessValue(toolTest('objects_list'));
foreach([500,23968] as $id)expectTest(!in_array($id,array_column($ws['objects'],'id'),true),'Hidden workspace child');
foreach([300,500] as $id)expectTest(accessDenied(toolTest('objects_list',['parent_id'=>$id])),'Denied enumeration');
$info=accessValue(toolTest('workspace_info'));
expectTest(array_column($info['readable_roots'],'id')===[14846,200,400],'Discover allowed roots only');
expectTest(!str_contains(json_encode($info),'DENIED-SECRET'),'No denied metadata');

$before=$GLOBALS['script_reads'];$r=accessValue(toolTest('object_read',['id'=>220]));
expectTest(!$r['source_readable'] && !isset($r['source'],$r['sha256']) && $GLOBALS['script_reads']===$before,'Source disabled does not fetch code');
$event=accessValue(toolTest('object_read',['id'=>230]));
expectTest(!str_contains(json_encode($event),'EVENT-SOURCE-SECRET') && !str_contains(json_encode($event),'EVENT-PARAM-SECRET'),'Event code hidden');
$media=accessValue(toolTest('object_read',['id'=>240]));
expectTest(!$media['content_readable'] && !isset($media['media']['MediaFile']),'Media metadata without path');
$reads=$GLOBALS['media_reads'];expectTest(accessDenied(toolTest('media_read',['id'=>240])) && $reads===$GLOBALS['media_reads'],'Cached media tool denied');
$m->props['AllowScriptSourceRead']=true;
expectTest(isset(accessValue(toolTest('object_read',['id'=>220]))['source']),'Separate source grant');
expectTest(str_contains(json_encode(accessValue(toolTest('object_read',['id'=>230]))),'EVENT-SOURCE-SECRET'),'Explicit event source grant');
$m->props['AllowMediaContentRead']=true;
expectTest(!accessDenied(toolTest('media_read',['id'=>240])),'Read-only media with explicit content grant');
expectTest(accessDenied(toolTest('media_read',['id'=>520])),'Media grant never overrides deny');

foreach([210,310,410] as $id)expectTest(accessDenied(toolTest('variable_set',['id'=>$id,'value'=>9])),'Reject read/deny variable write');
expectTest($GLOBALS['variable_writes']===[],'No forbidden variable side effect');
foreach([200,300,400,500] as $parent) {
    expectTest(accessDenied(toolTest('category_create',['parent_id'=>$parent,'name'=>'NO'])),'Category write boundary');
    expectTest(accessDenied(toolTest('variable_create',['parent_id'=>$parent,'name'=>'NO','type'=>1])),'Variable create boundary');
    expectTest(accessDenied(toolTest('script_put',['parent_id'=>$parent,'name'=>'NO','source'=>'<?php'])),'Script create boundary');
}
foreach([220,420,510] as $id) {
    expectTest(accessDenied(toolTest('script_run',['id'=>$id])),'No execution in read/deny scope');
    expectTest(accessDenied(toolTest('script_put',['id'=>$id,'expected_sha256'=>hash('sha256','<?php /* SOURCE-SECRET */'),'source'=>'<?php'])),'No source overwrite in read/deny scope');
    expectTest(accessDenied(toolTest('event_interval',['script_id'=>$id,'seconds'=>30,'active'=>false])),'No event configuration in read/deny scope');
}
expectTest($GLOBALS['executions']===[],'No forbidden execution side effect');
$r=toolTest('event_interval',['script_id'=>610,'event_id'=>230,'seconds'=>30,'active'=>false]);expectTest(accessDenied($r) && str_contains(json_encode($r),'Read-only category'),'Writable script cannot modify read-only event');
expectTest(!accessDenied(toolTest('variable_set',['id'=>600,'value'=>9])) && $GLOBALS['variable_writes'][600]===9,'Workspace still writable');
expectTest(!accessDenied(toolTest('script_run',['id'=>610])) && $GLOBALS['executions']===[610],'Workspace still executable');
foreach([630,632] as $id) { $link=accessValue(toolTest('object_read',['id'=>$id]))['link']; expectTest(!$link['target_readable'] && !isset($link['target_id']),'Blocked/unreleased link target hidden'); }
$link=accessValue(toolTest('object_read',['id'=>631]))['link'];expectTest($link['target_readable'] && $link['target_id']===210,'Accessible link target');
expectTest(accessDenied(toolTest('variable_set',['id'=>631,'value'=>1])),'Cannot write through link');

// A read-only ancestor also makes the workspace read-only, independent of traversal order.
$GLOBALS['objects'][14846]['ParentID']=100;setAccessRows('ReadOnlyCategories',[100]);
$info=accessValue(toolTest('workspace_info'));expectTest(!$info['allow_write'] && !$info['allow_execute'],'Read-only ancestor precedence');
$names=array_column(rpcTest('tools/list')['result']['tools'],'name');expectTest(!in_array('script_run',$names,true) && !in_array('variable_set',$names,true),'No write tools in wholly read-only workspace');
$GLOBALS['objects'][14846]['ParentID']=0;setAccessRows('ReadOnlyCategories',[200]);
// Deny wins over an explicitly selected nested read root and the workspace itself.
setAccessRows('DeniedCategories',[200,14846]);
$info=accessValue(toolTest('workspace_info'));expectTest($info['root_id']===null && $info['readable_roots']===[],'Denied roots hidden');
expectTest(accessDenied(toolTest('object_read',['id'=>210])),'Denied read root');
// Read-only-only deployment, no workspace and no mutation tools.
setAccessRows('DeniedCategories',[300]);$m->props['RootID']=0;
$info=accessValue(toolTest('workspace_info'));expectTest($info['root_id']===null && !$info['allow_write'],'Read-only-only info');
$list=accessValue(toolTest('objects_list'));expectTest($list['parent_id']===null && array_column($list['objects'],'id')===[200],'Read-only-only default discovery');
expectTest(!accessDenied(toolTest('object_read',['id'=>210])),'Read-only-only variable read');
// Invalid, deleted or zero selections fail closed.
foreach(['broken','{}','[0]','[{"CategoryID":0}]','[{"CategoryID":999999}]','[{"CategoryID":210}]'] as $bad) {
    $m->props['ReadOnlyCategories']=$bad;
    expectTest(accessDenied(toolTest('object_read',['id'=>210])),'Invalid read configuration closed');
}
setAccessRows('ReadOnlyCategories',[200]);$m->props['DeniedCategories']='broken';
expectTest(accessDenied(toolTest('object_read',['id'=>210])),'Invalid deny configuration closed');
// Policy resolves the current ancestry each time, including moved objects and cycles.
$m->props['RootID']=14846;setAccessRows('ReadOnlyCategories',[200]);setAccessRows('DeniedCategories',[300]);
$GLOBALS['objects'][600]['ParentID']=300;expectTest(accessDenied(toolTest('object_read',['id'=>600])),'Moved under denied root');
$GLOBALS['objects'][600]['ParentID']=14846;
$GLOBALS['objects'][200]['ParentID']=210;expectTest(accessDenied(toolTest('object_read',['id'=>210])),'Ancestry cycle rejected');
$GLOBALS['objects'][200]['ParentID']=100;
echo "Access policy and all read/write/execution boundary checks passed\n";
