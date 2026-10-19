<?php
require_once __DIR__ . '/instances.php';

$GLOBALS['configuration_reads']=0;
function IPS_GetConfiguration($id) {
    $GLOBALS['configuration_reads']++;
    if ($GLOBALS['configuration_error'] ?? false) throw new RuntimeException('CONFIG-EXCEPTION-SECRET');
    return $GLOBALS['configurations'][$id];
}
$GLOBALS['objects'][700]['ParentID']=0;
$m->props['RootID']=14846;
$m->props['ReadOnlyCategories']='[]';
$GLOBALS['configurations'][700]=json_encode([
    'Location'=>'{"latitude":52.1,"longitude":13.2,"token":"NESTED-SECRET"}',
    'Host'=>'192.168.1.1','Port'=>443,'Open'=>true,'Password'=>'PASSWORD-SECRET',
    'Api_Key'=>'API-SECRET','UserName'=>'USER-SECRET',
    'Headers'=>['Authorization'=>'Bearer HEADER-SECRET'],
    'Devices'=>'[{"name":"Door","Password":"DEVICE-SECRET","on":true}]',
    'CredentialURL'=>'https://example.org/?token=CREDENTIAL-SECRET',
    'StreamURL'=>'https://user:URL-SECRET@example.org/path',
    'Feed'=>'https://example.org/?api_key=QUERY-SECRET',
    'Opaque'=>'{"password":"MALFORMED-SECRET"',
    'Value'=>'Bearer FREEFORM-SECRET',
    'OrdinaryText'=>'Living room','Nested'=>['session'=>'SESSION-SECRET','count'=>2],
    'Options'=>[['Name'=>'Password','Value'=>'NAME-VALUE-SECRET'],['Key'=>'Authorization','Value'=>'HEADER-VALUE-SECRET']],
    'PIN'=>123456,'Pass'=>'PASS-SECRET','User'=>'BARE-USER-SECRET'
]);
foreach ([[],[['InstanceID'=>700]], [['InstanceID'=>700,'ReadConfiguration'=>false]],
    [['InstanceID'=>700,'ReadConfiguration'=>false,'Properties'=>'Location.latitude']]] as $rows) {
    $m->props['ReadOnlyInstances']=json_encode($rows);
    $before=$GLOBALS['configuration_reads'];
    $r=toolTest('instance_read',['id'=>700]);
    if ($rows!==[]) {
        $v=accessValue($r);
        expectTest(!$v['configuration_readable'] && $v['configuration']===[],'No configuration without checked permission');
    } else expectTest(accessDenied($r),'Empty instance list grants nothing');
    expectTest($GLOBALS['configuration_reads']===$before,'Unchecked permission never fetches configuration');
}
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>700,'ReadConfiguration'=>true]]);
$v=accessValue(toolTest('instance_read',['id'=>700]));
expectTest($v['configuration_readable'] && $GLOBALS['configuration_reads']===1,'Checkbox grants configuration read');
expectTest($v['configuration']['Location']['latitude']===52.1 && $v['configuration']['Location']['longitude']===13.2,'Location JSON expanded');
expectTest($v['configuration']['Host']==='192.168.1.1' && $v['configuration']['OrdinaryText']==='Living room','Ordinary configuration readable');
expectTest($v['configuration']['Port']===443 && $v['configuration']['Open']===true,'Scalar types preserved');
expectTest($v['configuration']['Devices'][0]['name']==='Door','JSON list expanded');
foreach (['NESTED-SECRET','PASSWORD-SECRET','API-SECRET','USER-SECRET','HEADER-SECRET','DEVICE-SECRET',
    'CREDENTIAL-SECRET','URL-SECRET','QUERY-SECRET','MALFORMED-SECRET','FREEFORM-SECRET','SESSION-SECRET',
    'NAME-VALUE-SECRET','HEADER-VALUE-SECRET','PASS-SECRET','BARE-USER-SECRET'] as $secret) {
    expectTest(!str_contains(json_encode($v),$secret),'Credential filtered: '.$secret);
    expectTest(!str_contains(json_encode($m->debug),$secret),'Credential absent in debug');
}
expectTest($v['configuration']['PIN']==='[REDACTED]','Numeric PIN redacted');
expectTest(accessValue(toolTest('object_read',['id'=>700]))['configuration']===$v['configuration'],'Generic instance read uses same filter');
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>700,'ReadConfiguration'=>'true']]);
expectTest(accessDenied(toolTest('instance_read',['id'=>700])),'Invalid checkbox fails closed');
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>730,'ReadConfiguration'=>true]]);
$before=$GLOBALS['configuration_reads'];
expectTest(accessDenied(toolTest('instance_read',['id'=>730])) && $GLOBALS['configuration_reads']===$before,'Deny wins before configuration fetch');
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>23968,'ReadConfiguration'=>true]]);
expectTest(accessDenied(toolTest('instance_read',['id'=>23968])),'Own module remains blocked');
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>700,'ReadConfiguration'=>true]]);
$GLOBALS['configuration_error']=true;
$r=toolTest('instance_read',['id'=>700]);
expectTest(accessDenied($r) && !str_contains(json_encode($r),'CONFIG-EXCEPTION-SECRET'),'Configuration exception sanitized');
$GLOBALS['configuration_error']=false;
$GLOBALS['configurations'][700]='{"token":"BROKEN-JSON-SECRET"';
$r=toolTest('instance_read',['id'=>700]);
expectTest(accessDenied($r) && !str_contains(json_encode($r),'BROKEN-JSON-SECRET'),'Broken configuration fails closed');
echo "Per-instance checkbox, opt-in, JSON parsing and credential filtering tests passed\n";
