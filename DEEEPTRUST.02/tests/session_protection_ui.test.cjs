const fs=require('fs'),vm=require('vm'),assert=require('assert/strict');
const path=require('path');
const root=path.resolve(__dirname,'..');
const code=fs.readFileSync(path.join(root,'client/js/sessionMonitor.js'),'utf8').replace('export function','function');
function setup(status=200,remaining=30){
 let now=0,unauthorized=0;const requests=[],timers=[],listeners={};
 const notice={hidden:true,style:{},setAttribute(){},remove(){}};
 const document={hidden:false,createElement:()=>notice,body:{appendChild(){}},addEventListener:(name,fn)=>listeners[name]=fn,removeEventListener(){}};
 const context={document,navigator:{webdriver:false},performance:{now:()=>now},
 fetch:async(url,opts)=>{requests.push({url,payload:JSON.parse(opts.body)});return {status,ok:status===200,json:async()=>({expires_in_seconds:remaining})};},
 setInterval:(fn,ms)=>{timers.push({fn,ms});return timers.length;},clearInterval(){}};
 vm.createContext(context);vm.runInContext(code,context);
 const stop=context.startSessionMonitor({getAuthorizationHeader:()=>({Authorization:'Bearer test'}),onUnauthorized:()=>unauthorized++});
 return {requests,timers,listeners,notice,document,stop,setTime:v=>now=v,unauthorized:()=>unauthorized};
}
(async()=>{
 let c=setup();await new Promise(resolve=>setImmediate(resolve));assert.equal(c.notice.hidden,false);assert(c.notice.textContent.includes('30s'));
 c.document.hidden=true;c.setTime(20000);await c.timers.find(t=>t.ms===5000).fn();assert.equal(c.requests.at(-1).payload.has_activity,false);
 c.document.hidden=false;c.listeners.pointermove({isTrusted:true,clientX:10,clientY:10});await c.timers.find(t=>t.ms===5000).fn();assert.equal(c.requests.at(-1).payload.has_activity,true);
 c.setTime(40000);c.listeners.click({isTrusted:false});await c.timers.find(t=>t.ms===5000).fn();assert.equal(c.requests.at(-1).payload.has_activity,false);
 c.stop();
 c=setup(401);await new Promise(resolve=>setImmediate(resolve));assert.equal(c.unauthorized(),1);c.stop();
 c=setup(200,120);await new Promise(resolve=>setImmediate(resolve));assert.equal(c.notice.hidden,true);c.stop();
 console.log('6 session protection warning, hidden-tab, trusted-activity and revoke scenarios passed');
})();
