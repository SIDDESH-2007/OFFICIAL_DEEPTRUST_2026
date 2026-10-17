const fs=require('fs'),vm=require('vm'),assert=require('assert/strict'),path=require('path');
const source=fs.readFileSync(path.resolve(__dirname,'../client/js/app_rework.js'),'utf8');
const a=source.indexOf('async function handleLoginSubmit()'),b=source.indexOf('let faceMeshInstance',a);
async function submit(oauth) {
 let payload;
 const context=vm.createContext({document:{getElementById:id=>id==='input-email'?{value:'admin@novacaremedical.org'}:id==='input-password'?{value:'user-chosen-password'}:null},currentSelectedAccessType:'DEEPTRUST_OWNER',sessionStorage:{getItem:k=>oauth&&k==='dt_oauth_params'?'{}':null},fetch:async(url,request)=>{payload=JSON.parse(request.body);return {ok:false,json:async()=>({detail:'Invalid test credentials'})}},alert:()=>{}});
 vm.runInContext(source.slice(a,b),context);await vm.runInContext('handleLoginSubmit()',context);return payload;
}
(async()=>{assert.equal((await submit(true)).selected_access_type,'HOSPITAL_ADMIN');assert.equal((await submit(false)).selected_access_type,'DEEPTRUST_OWNER');console.log('Portal-submit regression passed: hospital SSO cannot inherit the platform admin portal type; standalone platform login preserved.');})().catch(e=>{console.error(e);process.exitCode=1});
