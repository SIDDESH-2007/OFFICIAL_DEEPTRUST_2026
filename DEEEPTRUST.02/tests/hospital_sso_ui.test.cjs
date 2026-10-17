const fs=require('fs'),vm=require('vm'),assert=require('assert/strict'),path=require('path');
const root=path.resolve(__dirname,'..');
const source=fs.readFileSync(root+'/client/js/app_rework.js','utf8');
const start=source.indexOf('function initOAuthFlowDetection()');
const end=source.indexOf('/* ============================================================',start);
function oauth(search) {
 const elements={'input-email':{value:''},'input-password':{value:'previous-password'},'login-portal-name':{},'login-title':{}};
 const values=new Map();
 const context=vm.createContext({window:{location:{search}},URLSearchParams,currentSelectedAccessType:'DEEPTRUST_OWNER',sessionStorage:{setItem:(k,v)=>values.set(k,v),getItem:k=>values.get(k),removeItem:k=>values.delete(k)},document:{getElementById:id=>elements[id]},switchAuthView:()=>{},setTimeout:fn=>fn()});
 vm.runInContext(source.slice(start,end),context);vm.runInContext('initOAuthFlowDetection()',context);
 return {context,elements,values};
}
const roleOnly=oauth('?oauth_client=client&redirect_uri=http%3A%2F%2Flocalhost%3A5176&role=doctor');
assert.equal(roleOnly.elements['input-email'].value,'');assert.equal(roleOnly.elements['input-password'].value,'');assert.equal(roleOnly.context.currentSelectedAccessType,'HOSPITAL_ADMIN');
const personal=oauth('?oauth_client=client&redirect_uri=http%3A%2F%2Flocalhost%3A5176&role=nurse&email=person%40gmail.com');
assert.equal(personal.elements['input-email'].value,'person@gmail.com');assert.equal(personal.elements['input-password'].value,'');
const dashboard=fs.readFileSync(root+'/client/js/dashboard.js','utf8');
const a=dashboard.indexOf('let notificationSyncBusy = false;'),b=dashboard.indexOf('// ',dashboard.indexOf('async function syncNotifications()',a));
const badge={style:{}},body={innerHTML:''},popups=[];
let rows=[],requests=0;
const context=vm.createContext({console,document:{hidden:false,getElementById:id=>id==='unreadNotifCount'?badge:body},getAuthorizationHeader:()=>({Authorization:'Bearer token'}),fetch:async()=>{requests++;return {ok:true,json:async()=>({notifications:rows,unread_count:rows.length})}},escapeHtml:s=>String(s||'').replaceAll('<','&lt;'),popups,Set,Date});
vm.runInContext(dashboard.slice(a,b),context);vm.runInContext('showStaffLoginPopup = n => popups.push(n)',context);
(async()=>{
 rows=[{notification_id:'historical',type:'HOSPITAL_STAFF_LOGIN',title:'old',message:'old',timestamp:new Date().toISOString()}];
 await vm.runInContext('syncNotifications()',context);assert.equal(popups.length,0);
 rows.unshift({notification_id:'new',type:'HOSPITAL_STAFF_LOGIN',title:'New login',message:'person@gmail.com • Doctor • Risk: 21/100 (LOW)',timestamp:new Date().toISOString()});
 await vm.runInContext('syncNotifications()',context);assert.equal(popups.length,1);assert.match(body.innerHTML,/person@gmail.com/);assert.equal(badge.textContent,2);
 await vm.runInContext('syncNotifications()',context);assert.equal(popups.length,1);
 context.document.hidden=true;const before=requests;await vm.runInContext('syncNotifications()',context);assert.equal(requests,before);
 context.document.hidden=false;
 let release;context.fetch=()=>new Promise(resolve=>{release=resolve;requests++});
 const pending=vm.runInContext('syncNotifications()',context);const count=requests;await vm.runInContext('syncNotifications()',context);assert.equal(requests,count);
 release({ok:true,json:async()=>({notifications:rows,unread_count:2})});await pending;
 console.log('Hospital UI checks passed: no demo autofill, personal email, staff flow, new-login popup, no historical/duplicate popups, hidden pause and overlapping poll protection.');
})().catch(error=>{console.error(error);process.exitCode=1});
