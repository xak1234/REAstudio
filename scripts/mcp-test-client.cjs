// Official client against the real listener in an isolated desktop test profile.
const assert=require('node:assert/strict');
const path=require('node:path');
const net=require('node:net');
const {version}=require('./version.cjs');
module.exports=async function connectAppMcp(page){
  const sdk=process.env.REA_STUDIO_TEST_SDK;
  assert(sdk,'Set REA_STUDIO_TEST_SDK to the official MCP SDK package directory');
  const {Client}=require(path.join(sdk,'dist/cjs/client/index.js'));
  const {StreamableHTTPClientTransport}=require(path.join(sdk,'dist/cjs/client/streamableHttp.js'));
  const native=(route,data={})=>page.evaluate(async({route,data})=>{
    const r=await fetch('/api/quixi/mcp/'+route,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    const v=await r.json();if(!r.ok)throw Error(v.error || String(r.status));return v;
  },{route,data});
  assert.equal((await native('status')).enabled,false,'Use a separate test profile with MCP disabled');
  const probe=net.createServer();
  const port=await new Promise((resolve,reject)=>{probe.once('error',reject);probe.listen(0,'127.0.0.1',()=>resolve(probe.address().port));});
  await new Promise(resolve=>probe.close(resolve));
  const client=new Client({name:'rea-studio-live-integration-check',version});
  try{
    await native('enable',{port});
    const config=(await native('config')).mcpServers['rea-studio'];
    await client.connect(new StreamableHTTPClientTransport(new URL(config.url),{requestInit:{headers:config.headers}}));
    assert.equal((await client.listTools()).tools.length,27);
    return {
      client,
      call:async(name,args={})=>{
        const r=await client.callTool({name,arguments:args},undefined,{timeout:240000});
        assert.equal(r.isError,false,JSON.stringify(r));return r.structuredContent || JSON.parse(r.content[0].text);
      },
      close:async()=>{await client.close();await native('disable');},
    };
  }catch(error){await client.close().catch(()=>{});await native('disable').catch(()=>{});throw error;}
};
