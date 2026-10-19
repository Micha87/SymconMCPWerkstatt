<?php
require_once __DIR__ . '/instance_checkbox.php';

$GLOBALS['configurations'][700]=json_encode([
    'Location'=>'{"latitude":52.1,"longitude":13.2}',
    'Host'=>'192.168.1.1','Port'=>443,'Open'=>true,'Password'=>'SELECT-SECRET',
    'Devices'=>[['Name'=>'Door','Enabled'=>true]],
    'URL'=>'https://user:SELECT-URL-SECRET@example.org/path'
]);
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>700,'ReadConfiguration'=>true,'AllProperties'=>false,
    'PropertySelection'=>[
        ['Property'=>'Location.latitude','Allowed'=>true],
        ['Property'=>'Location.longitude','Allowed'=>false],
        ['Property'=>'Host','Allowed'=>true]
    ]]]);
$v=accessValue(toolTest('instance_read',['id'=>700]));
expectTest($v['configuration_readable'] && $v['configuration']===['Location.latitude'=>52.1,'Host'=>'192.168.1.1'],'Only checked properties returned');
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>700,'ReadConfiguration'=>true,'AllProperties'=>false,'PropertySelection'=>[]]]);
$before=$GLOBALS['configuration_reads'];
$v=accessValue(toolTest('instance_read',['id'=>700]));
expectTest(!$v['configuration_readable'] && $v['configuration']===[] && $GLOBALS['configuration_reads']===$before,'Empty selection never grants all or fetches configuration');
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>700,'ReadConfiguration'=>true,'AllProperties'=>true,'PropertySelection'=>[]]]);
$v=accessValue(toolTest('instance_read',['id'=>700]));
expectTest($v['configuration']['Location']['longitude']===13.2 && $v['configuration']['Password']==='[REDACTED]','All mode still redacts credentials');
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>700,'ReadConfiguration'=>true,'AllProperties'=>false,'PropertySelection'=>[['Property'=>'Password','Allowed'=>true]]]]);
expectTest(accessDenied(toolTest('instance_read',['id'=>700])),'Selected credential cannot bypass filter');
foreach ([['AllProperties'=>'true'],['AllProperties'=>false,'PropertySelection'=>'broken'],
    ['AllProperties'=>false,'PropertySelection'=>[['Property'=>'Host','Allowed'=>'yes']]]] as $extra) {
    $m->props['ReadOnlyInstances']=json_encode([array_merge(['InstanceID'=>700,'ReadConfiguration'=>true],$extra)]);
    expectTest(accessDenied(toolTest('instance_read',['id'=>700])),'Malformed selection fails closed');
}
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>700,'ReadConfiguration'=>true]]);
$form=json_decode($m->UIInstanceAccessForm(700,true,false,json_encode([['Property'=>'Location.latitude','Allowed'=>true]])),true);
$fields=array_column($form,null,'name');
expectTest(!isset($fields['Properties']) && isset($fields['AllProperties'],$fields['PropertySelection']),'No legacy text input in editor');
expectTest($fields['PropertySelection']['visible'] && $fields['PropertySelection']['columns'][0]['edit']['type']==='CheckBox','Per-property checkbox list');
$rows=$fields['PropertySelection']['values'];$names=array_column($rows,'Property');
expectTest(in_array('Location.latitude',$names,true) && in_array('Devices.0.Enabled',$names,true),'Discover nested properties automatically');
expectTest(!in_array('Password',$names,true) && !in_array('URL',$names,true),'Credential fields not selectable');
expectTest(!str_contains(json_encode($form),'SELECT-SECRET') && !str_contains(json_encode($form),'192.168.1.1'),'Editor lists names without values');
$checks=array_column($rows,'Allowed','Property');expectTest($checks['Location.latitude'] && !$checks['Location.longitude'],'Checkbox states preserved');
$before=$GLOBALS['configuration_reads'];
$blocked=json_decode($m->UIInstanceAccessForm(730,true,false,'[]'),true);
expectTest($blocked[4]['values']===[] && $GLOBALS['configuration_reads']===$before,'Editor honors denied categories before fetching');
$m->UIInstanceModeChanged(true,true);
expectTest(!$m->fields['PropertySelection']['visible'],'All mode hides checkbox selection');
$m->UIInstanceModeChanged(true,false);
expectTest($m->fields['PropertySelection']['visible'],'Selected mode shows checkbox selection');
$m->UIInstanceChanged(700);
expectTest(!$m->fields['ReadConfiguration']['value'] && $m->fields['AllProperties']['value'],'Changing instance resets configuration permission');
$static=json_decode(file_get_contents(__DIR__.'/../MCPDeveloper/form.json'),true);
$list=array_values(array_filter($static['elements'],fn($e)=>($e['name']??'')==='ReadOnlyInstances'))[0];
expectTest(is_string($list['form']) && str_contains($list['form'],'UIInstanceAccessForm'),'Dynamic row form wired');
echo "All/selected modes, property checkboxes, editor discovery and migration tests passed\n";
