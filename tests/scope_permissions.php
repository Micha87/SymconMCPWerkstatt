<?php
require_once __DIR__ . '/instance_selection.php';

foreach ([800=>[0,0],801=>[800,2],802=>[800,3],810=>[0,0],811=>[810,2],820=>[0,0],821=>[820,2],
    830=>[0,1],831=>[830,2],840=>[830,1],841=>[840,2]] as $id=>$spec) addAccessObject($id,$spec[0],$spec[1],'Permission '.$id);
$GLOBALS['instances'][830]=['InstanceStatus'=>102,'ConnectionID'=>0,'ModuleInfo'=>[]];
$GLOBALS['instances'][840]=['InstanceStatus'=>102,'ConnectionID'=>0,'ModuleInfo'=>[]];
$m->props['RootID']=0;$m->props['AllowWrite']=true;$m->props['AllowExecute']=true;
$m->props['ReadOnlyCategories']=json_encode([
    ['CategoryID'=>800,'Access'=>'write'],['CategoryID'=>810,'Access'=>'read'],['CategoryID'=>820,'Access'=>'none']
]);
$m->props['ReadOnlyInstances']='[]';setAccessRows('DeniedCategories',[300]);
$info=accessValue(toolTest('workspace_info'));
expectTest($info['root_id']===null && $info['allow_write'] && $info['allow_execute'],'Additional write scope without default workspace');
expectTest(array_column($info['writable_roots'],'id')===[800],'Writable scopes discoverable');
$names=array_column(rpcTest('tools/list')['result']['tools'],'name');
expectTest(in_array('variable_set',$names,true) && in_array('script_run',$names,true),'Write tools advertised without workspace');
expectTest(!accessDenied(toolTest('variable_set',['id'=>801,'value'=>2])),'Write additional category');
expectTest(!accessDenied(toolTest('script_run',['id'=>802])),'Execute writable category script');
expectTest(!accessDenied(toolTest('script_put',['parent_id'=>800,'name'=>'Scoped script','source'=>'<?php'])),'Create script in additional category');
expectTest(!accessDenied(toolTest('category_create',['parent_id'=>800,'name'=>'Scoped category'])),'Create category in additional scope');
expectTest(!accessDenied(toolTest('variable_create',['parent_id'=>802,'name'=>'State','type'=>1])),'Create variable under writable script');
expectTest(accessDenied(toolTest('variable_create',['parent_id'=>801,'name'=>'Bad','type'=>1])),'Reject variable as parent');
expectTest(accessDenied(toolTest('script_put',['name'=>'No default','source'=>'<?php'])),'No implicit target without workspace');
expectTest(!accessDenied(toolTest('object_read',['id'=>811])) && accessDenied(toolTest('variable_set',['id'=>811,'value'=>2])),'Read-only category enforced');
expectTest(accessDenied(toolTest('object_read',['id'=>821])),'None category invisible');
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>830,'Access'=>'write'],['InstanceID'=>840,'Access'=>'read']]);
expectTest(accessValue(toolTest('instance_read',['id'=>830]))['access']==='write','Instance write grant reported');
expectTest(!accessDenied(toolTest('variable_set',['id'=>831,'value'=>3])),'Write instance child');
expectTest(!accessDenied(toolTest('variable_create',['parent_id'=>830,'name'=>'Child','type'=>1])),'Create variable under writable instance');
expectTest(!accessDenied(toolTest('script_put',['parent_id'=>830,'name'=>'Child script','source'=>'<?php'])),'Create script under writable instance');
expectTest(accessDenied(toolTest('variable_set',['id'=>841,'value'=>2])),'Nested read-only instance overrides write');
expectTest(!accessValue(toolTest('instance_read',['id'=>830]))['configuration_readable'],'Write access does not grant configuration read');
$GLOBALS['objects'][830]['ParentID']=810;
expectTest(accessDenied(toolTest('variable_set',['id'=>831,'value'=>3])),'Read-only ancestor overrides instance write');
$GLOBALS['objects'][830]['ParentID']=820;
expectTest(accessDenied(toolTest('instance_read',['id'=>830])),'Denied ancestor overrides instance write');
$GLOBALS['objects'][830]['ParentID']=0;
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>830,'Access'=>'none','ReadConfiguration'=>true]]);
$before=$GLOBALS['configuration_reads'];
expectTest(accessDenied(toolTest('instance_read',['id'=>830])) && $GLOBALS['configuration_reads']===$before,'None instance blocks configuration before fetch');
expectTest(accessDenied(toolTest('object_read',['id'=>831])),'None instance blocks descendants');
expectTest(!in_array(830,array_column(accessValue(toolTest('instances_list'))['instances'],'id'),true),'None instance absent from lists');
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>23968,'Access'=>'write']]);
expectTest(accessDenied(toolTest('instance_read',['id'=>23968])),'Own module remains blocked even with write grant');
$m->props['ReadOnlyInstances']='[]';
foreach ([null,false,'admin',''] as $bad) {
    $m->props['ReadOnlyCategories']=json_encode([['CategoryID'=>800,'Access'=>$bad]]);
    expectTest(accessDenied(toolTest('object_read',['id'=>801])),'Invalid category permission fails closed');
}
$m->props['ReadOnlyCategories']=json_encode([['CategoryID'=>800,'Access'=>'write']]);
foreach ([null,false,'admin',''] as $bad) {
    $m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>830,'Access'=>$bad]]);
    expectTest(accessDenied(toolTest('instance_read',['id'=>830])),'Invalid instance permission fails closed');
}
$m->props['ReadOnlyInstances']='[]';$m->props['AllowWrite']=false;
expectTest(accessDenied(toolTest('variable_set',['id'=>801,'value'=>5])),'Global write permission still required');
$m->props['AllowExecute']=false;
expectTest(accessDenied(toolTest('script_run',['id'=>802])),'Global execution permission still required');
$m->props['AllowWrite']=true;$m->props['AllowExecute']=true;setAccessRows('DeniedCategories',[800]);
expectTest(accessDenied(toolTest('variable_set',['id'=>801,'value'=>4])),'Explicit deny overrides category write');
setAccessRows('DeniedCategories',[300]);
$m->props['ReadOnlyCategories']=json_encode([['CategoryID'=>800]]);
$m->props['ReadOnlyInstances']=json_encode([['InstanceID'=>830]]);
$info=accessValue(toolTest('workspace_info'));expectTest(!$info['allow_write'] && $info['writable_roots']===[],'Legacy rows stay read-only');
$form=json_decode($m->GetConfigurationForm(),true);$fields=array_column($form['elements'],null,'name');
expectTest($fields['ReadOnlyCategories']['values'][0]['Access']==='read' && $fields['ReadOnlyInstances']['values'][0]['Access']==='read','Legacy rows show correct UI defaults');
$cols=array_column($fields['ReadOnlyCategories']['columns'],null,'name');
expectTest($cols['Access']['add']==='read','New category defaults to read-only');
$dialog=json_decode($m->UIInstanceAccessForm(830,false,true,'[]','write'),true);$fields=array_column($dialog,null,'name');
expectTest($fields['Access']['value']==='write','Instance dialog includes access selection');
$m->UIInstanceChanged(830);expectTest($m->fields['Access']['value']==='read','Instance change resets write permission');
echo "Category/instance none-read-write permissions, multi-scope writes, migration and global gate tests passed\n";
