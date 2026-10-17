<?php
require_once __DIR__ . '/../libs/TokenAuth.php';
$t = str_repeat('a1', 32); $e = '/hook/symcon-mcp-23968';
$cases = [
    [true, false, 'Bearer '.$t, $e],
    [true, false, 'bearer '.$t, $e.'/'],
    [false, false, '', $e],
    [false, false, '', $e.'/'.$t],
    [true, true, '', $e.'/'.$t],
    [true, true, '', $e.'/'.$t.'?test=1'],
    [false, true, '', $e.'/wrong'],
    [false, true, '', $e.'/'.$t.'/extra'],
    [false, true, '', $e.'/'.$t.'%2Fextra'],
    [false, true, 'Bearer wrong', $e.'/'.$t],
    [false, true, 'Basic '.$t, $e.'/'.$t],
    [false, true, '', $e.'-other/'.$t],
    [false, true, '', $e.'//'.$t],
    [false, true, '', $e.'/?token='.$t],
    [true, true, 'Bearer '.$t, $e],
    [false, false, 'Bearer '.$t, $e.'/extra']
];
foreach ($cases as $i => [$expected,$allow,$header,$uri]) {
    if (SMCPTokenAuth::accepts($t,$allow,$header,$uri,$e) !== $expected) { throw new RuntimeException('Case '.$i.' failed'); }
}
if (SMCPTokenAuth::accepts('',true,'',$e.'/',$e)) { throw new RuntimeException('Empty token accepted'); }
echo count($cases)+1, " authentication tests passed\n";
