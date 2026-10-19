<?php
require_once __DIR__ . '/access.php';

function IPS_GetInstanceList() {
    return array_keys(array_filter($GLOBALS['objects'],fn($o)=>$o['ObjectType']===1));
}
function IPS_GetProperty($id,$name) {
    $GLOBALS['property_reads'][]=[$id,$name];
    if (!array_key_exists($name,$GLOBALS['properties'][$id] ?? [])) throw new RuntimeException('PRIVATE-ERROR-SECRET');
    return $GLOBALS['properties'][$id][$name];
}
$guid='{12345678-1234-1234-1234-123456789ABC}';
foreach ([700=>0,710=>700,720=>200,730=>300,740=>0,750=>14846] as $id=>$parent) {
    addAccessObject($id,$parent,1,'Instance '.$id);
    $GLOBALS['instances'][$id]=['InstanceStatus'=>102,'ConnectionID'=>740,
        'ModuleInfo'=>['ModuleID'=>$guid,'ModuleName'=>'Test module','ModuleType'=>0],
        'UndocumentedSecret'=>'INSTANCE-SECRET'];
}
addAccessObject(701,700,2,'Selected instance child');
$GLOBALS['properties'][700]=['Location'=>'{"latitude":52.1,"longitude":13.2,"token":"JSON-TOKEN-SECRET"}',
    'Enabled'=>true,'Port'=>80,'Address'=>'http://user:URL-SECRET@example.org', 'Other'=>'PLAIN-SECRET'];
$GLOBALS['property_reads']=[];
$m->props['ReadOnlyInstances']='[]';
expectTest(accessDenied(toolTest('instance_read',['id'=>700])),'Unselected core instance denied');
$list=accessValue(toolTest('instances_list'));
expectTest(array_column($list['instances'],'id')===[720,750],'Category grants still bound instance list');
expectTest($GLOBALS['property_reads']===[],'Listing never reads configuration');
$v=accessValue(toolTest('instance_read',['id'=>720]));
expectTest(!$v['configuration_readable'] && $v['configuration']===[],'Metadata has no configuration by default');
expectTest($v['instance']['ConnectionID']===null && !str_contains(json_encode($v),'INSTANCE-SECRET'),'Hidden connection and unknown fields');
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>700,'Properties'=>'Location.latitude,Location.longitude,Enabled,Port,Address,Other']]);
$v=accessValue(toolTest('instance_read',['id'=>700]));
expectTest($v['access']==='read' && $v['instance']['InstanceStatus']===102,'Selected core instance readable');
expectTest($v['configuration']['Location.latitude']===52.1 && $v['configuration']['Location.longitude']===13.2,'Explicit JSON leaves');
expectTest($v['configuration']['Enabled']===true && $v['configuration']['Port']===80,'Explicit numeric and boolean properties');
foreach (['URL-SECRET','PLAIN-SECRET','JSON-TOKEN-SECRET','INSTANCE-SECRET'] as $secret) expectTest(!str_contains(json_encode($v),$secret),'Secret not disclosed');
expectTest($v['object']['ParentID']===null,'Root parent hidden');
expectTest(!accessDenied(toolTest('object_read',['id'=>701])),'Selected instance children readable');
expectTest(accessDenied(toolTest('variable_set',['id'=>701,'value'=>99])),'Selected instance children never writable');
expectTest(!accessDenied(toolTest('object_read',['id'=>700])),'Generic read supports instances');
expectTest(array_column(accessValue(toolTest('instances_list',['module_id'=>strtolower($guid)]))['instances'],'id')===[700,710,720,750],'Case-insensitive module filter');
expectTest(accessDenied(toolTest('instances_list',['module_id'=>'invalid'])),'Invalid GUID rejected');
expectTest(accessDenied(toolTest('instance_read',['id'=>14846])),'Instance read rejects category');
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>730,'Properties'=>''],['InstanceID'=>23968,'Properties'=>'']]);
expectTest(accessDenied(toolTest('instance_read',['id'=>730])),'Denied category wins over explicit instance');
expectTest(accessDenied(toolTest('instance_read',['id'=>23968])),'Module itself remains denied');
expectTest(!in_array(730,array_column(accessValue(toolTest('instances_list'))['instances'],'id'),true),'Denied instance invisible');
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>750,'Properties'=>'']]);
expectTest(accessValue(toolTest('instance_read',['id'=>750]))['access']==='read','Explicit read-only overrides workspace');
$m->props['RootID']=0;$m->props['ReadOnlyCategories']='[]';
$info=accessValue(toolTest('workspace_info'));
expectTest(!$info['allow_write'] && array_column($info['readable_roots'],'id')===[750],'Instance-only deployment');
foreach (['broken','{}','[{"InstanceID":0}]','[{"InstanceID":14846}]','[{"InstanceID":999999}]',
    '[{"InstanceID":750,"Properties":"Password"}]','[{"InstanceID":750,"Properties":"Settings.apiKey"}]',
    '[{"InstanceID":750},{"InstanceID":750}]','[{"InstanceID":750,"Properties":[]} ]'] as $bad) {
    $m->props['ReadOnlyInstances']=$bad;
    expectTest(accessDenied(toolTest('instance_read',['id'=>750])),'Invalid instance grants fail closed');
}
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>700,'Properties'=>'Missing']]);
$v=toolTest('instance_read',['id'=>700]);
expectTest(accessDenied($v) && !str_contains(json_encode($v),'PRIVATE-ERROR-SECRET'),'Sanitized property error');
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>700,'Properties'=>'']]);
$GLOBALS['objects'][700]['ParentID']=300;
expectTest(accessDenied(toolTest('instance_read',['id'=>700])),'Moved instance checked against deny dynamically');
echo "Instance discovery, explicit grants, configuration allowlist and deny-boundary tests passed\n";
