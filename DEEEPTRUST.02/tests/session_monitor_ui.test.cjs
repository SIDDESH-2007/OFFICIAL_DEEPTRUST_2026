const fs=require('fs'),path=require('path'),vm=require('vm'),assert=require('assert/strict');
const root=path.resolve(__dirname,'..');
const source=fs.readFileSync(path.join(root,'client/js/dashboard.js'),'utf8');
const code=source.slice(source.indexOf('let sessionControlBusy'),source.indexOf('async function revokeAdminSession'));
const elements=new Map();const clocks=[];const table={innerHTML:'',querySelectorAll:()=>[]};
let now=100000,response;
const RealDate=Date;class TestDate extends RealDate{static now(){return now;}}
function el(id){if(!elements.has(id))elements.set(id,{textContent:'',innerHTML:'',style:{},classList:{add(){},remove(){},contains(){return true;}}});return elements.get(id);}
const ctx={CustomEvent:class {constructor(type,options){this.type=type;this.detail=options.detail;}},Date:TestDate,document:{dispatchEvent(){},getElementById:el,querySelector:()=>table,querySelectorAll:selector=>selector==='[data-live-duration]'?clocks:[]},
    getAuthorizationHeader:()=>({Authorization:'Bearer fake'}),escapeHtml:x=>String(x??'').replace(/[<>&"]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c])),
    fetch:async()=>({ok:true,json:async()=>response}),console,switchView(){},openSessionAuditTimeline(){}};
vm.createContext(ctx);vm.runInContext(code,ctx);
(async()=>{
    response={summary:{active_sessions:1},sessions:[{session_id:'a',identity_id:'alice',email:'a@example.test',duration_seconds:59,duration_formatted:'00:00:59',duration_running:true,
        login_time_iso:'2026-10-06T10:00:00+00:00',ip_masked:'192.168.**.**',browser:'Firefox',device_formatted:'Firefox / Linux',status:'ACTIVE',current_view:'admin-overview'}]};
    await ctx.loadAdminSessionControl();
    assert(table.innerHTML.includes('session-email-link btn-session-detail'));
    assert(table.innerHTML.includes('192.168.**.**'));assert(table.innerHTML.includes('Firefox / Linux'));
    assert(table.innerHTML.includes('data-duration-running="true"'));
    const preserved=table.innerHTML;await ctx.loadAdminSessionControl();assert.equal(table.innerHTML,preserved);
    response.sessions[0].status='LOGGED_OUT';response.sessions[0].duration_running=false;
    response.summary.active_sessions=0;await ctx.loadAdminSessionControl();assert(table.innerHTML.includes('LOGGED_OUT'));
    assert.equal(el('scKpiActive').textContent,0);
    clocks.push({dataset:{liveDuration:'59',durationCaptured:'100000',durationRunning:'true'}});
    clocks.push({dataset:{liveDuration:'59',durationCaptured:'100000',durationRunning:'false'}});
    now+=2000;ctx.tickSessionDurations();assert.equal(clocks[0].textContent,'00:01:01');assert.equal(clocks[1].textContent,'00:00:59');
    response={session:{session_id:'a',email:'a@example.test',organization_name:'Hospital',duration_seconds:20,duration_formatted:'00:00:20',duration_running:true,login_time_iso:'2026-10-06T10:00:00Z'},
        network_context:{ip_masked:'10.0.**.**'},device_context:{browser:'Firefox',os:'Linux'},assurance:{face:'NOT_RECORDED'},behavior:{status:'DEVIATION',assessment:'Suspicious interaction indicators',reason_codes:['CLIENT_AUTOMATION_INDICATOR']}};
    await ctx.openSessionDetailsDrawer('a');assert.equal(el('sdIpAddress').textContent,'10.0.**.**');assert.equal(el('sdAssuranceFace').textContent,'NOT_RECORDED');
    assert(el('sdBehavior').innerHTML.includes('Browser automation or synthetic-event indicator'));assert(el('sdBehavior').innerHTML.includes('Touch swipes'));assert(el('sdBehavior').innerHTML.includes('Last measured'));assert(el('sdDuration').innerHTML.includes('00:00:20'));
    console.log('7 Session Control UI/data/clock scenarios passed');
})();
