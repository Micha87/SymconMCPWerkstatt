"""Read-only MCP smoke test. Python 3, no dependencies."""
import json, os, urllib.request, urllib.error
url = input('MCP URL (https://.../hook/symcon-mcp-ID): ').strip()
import getpass
token = getpass.getpass('Bearer token: ')
def rpc(method, params):
    body=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode()
    req=urllib.request.Request(url,body,{'Authorization':'Bearer '+token,'Content-Type':'application/json','Accept':'application/json, text/event-stream'})
    with urllib.request.urlopen(req,timeout=30) as r: reply=json.load(r)
    if 'error' in reply: raise RuntimeError(reply['error'])
    return reply['result']
print(json.dumps(rpc('initialize',{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'Symcon smoke test','version':'1'}}),indent=2))
print(json.dumps(rpc('tools/list',{}),indent=2))
print(json.dumps(rpc('tools/call',{'name':'objects_list','arguments':{}}),indent=2))
print('Read-only connection test completed.')
