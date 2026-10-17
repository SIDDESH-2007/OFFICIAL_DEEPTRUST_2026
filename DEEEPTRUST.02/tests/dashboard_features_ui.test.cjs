const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs'),vm=require('vm');
const source=fs.readFileSync('client/js/dashboardFeatures.js','utf8').replace('export function','function');
function setup(){
 const listeners={},elements={},requests=[],opened=[];
 class Element {
  constructor(){this.dataset={};this.children=[];this.textContent='';this.disabled=false;this.classList={remove:()=>{}};}
  appendChild(child){this.children.push(child);if(child.id)elements[child.id]=child;return child;}
  querySelector(){return null;}querySelectorAll(){return [];}before(child){this.beforeElement=child;}remove(){delete elements[this.id];}
 }
 const footer=new Element(),drawer=new Element(),timeline=new Element();drawer.querySelector=()=>footer;elements.sessionDetailsDrawer=drawer;elements.drawerAuditTimeline=timeline;
 const document={getElementById:id=>elements[id]||null,createElement:()=>new Element(),querySelectorAll:()=>[],addEventListener:(name,cb)=>listeners[name]=cb,body:new Element()};
 const context={document,console,Date,URL,URLSearchParams,setTimeout,confirm:()=>true,alert:()=>{},fetch:async(path,options)=>{requests.push({path,options});return {ok:true,json:async()=>path.includes('timeline')?{authentication_timeline:[{timestamp:null,event_type:'MFA_STATE',action:'Not recorded'}],activity_timeline:[]}:{organizations:[]}};}};
 vm.createContext(context);vm.runInContext(source,context);
 context.initDashboardFeatures({headers:()=>({Authorization:'Bearer fixture'}),escapeHtml:x=>String(x).replaceAll('<','&lt;'),openSession:sid=>opened.push(sid)});
 return {listeners,elements,requests,opened,footer,timeline};
}
test('reverification is disabled for inactive sessions',()=>{
 const s=setup();s.listeners['deeptrust:session']({detail:{session_id:'ended',status:'LOGGED_OUT'}});assert.equal(s.elements.sessionDrawerReverifyBtn.disabled,true);
});
test('reverification uses the selected session and authenticated POST',async()=>{
 const s=setup();s.listeners['deeptrust:session']({detail:{session_id:'session /1',status:'ACTIVE'}});await s.elements.sessionDrawerReverifyBtn.onclick();
 const r=s.requests.find(r=>r.options?.method==='POST');assert.equal(r.path,'/api/v1/admin/sessions/session%20%2F1/reverify');assert.equal(r.options.headers.Authorization,'Bearer fixture');assert.deepEqual(s.opened,['session /1']);
});
test('uncorrelated alert has no fabricated session or audit link',()=>{
 const s=setup();s.listeners['deeptrust:alert']({detail:{}});assert.equal(s.timeline.beforeElement.children.length,1);assert.match(s.timeline.beforeElement.children[0].textContent,/No completed login session/);
});
test('alert links target its exact session and recorded audit',async()=>{
 const s=setup();s.listeners['deeptrust:alert']({detail:{auth_session_id:'a/1',identity_id:'user/1'}});
 const controls=s.timeline.beforeElement.children;controls[1].onclick();assert.deepEqual(s.opened,['a/1']);await controls[2].onclick();
 assert.ok(s.requests.some(r=>r.path==='/api/v1/admin/audit/identity/user%2F1/session/a%2F1/timeline'));assert.match(s.timeline.innerHTML,/Not recorded/);assert.doesNotMatch(s.timeline.innerHTML,/undefined/);
});
test('CSV gateway accepts file response without trying JSON parsing',()=>{
 const gateway=fs.readFileSync('server/app.js','utf8');const condition=gateway.match(/if \((contentType.includes\('application\/pdf'\).*?)\) \{/)[1];
 assert.equal(vm.runInNewContext(condition,{contentType:'text/csv; charset=utf-8'}),true);
});
test('audit header reads the actual backend session projection',()=>{
 const dashboard=fs.readFileSync('client/js/dashboard.js','utf8');const fn=dashboard.slice(dashboard.indexOf('async function openSessionAuditTimeline('));assert.match(fn,/data.session_info \|\| data.session/);
});
