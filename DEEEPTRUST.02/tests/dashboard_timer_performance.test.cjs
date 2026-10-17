const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../client/js/dashboard.js'),'utf8');
const functionSource=source.slice(source.indexOf('function tickSessionDurations() {'),source.indexOf('\nasync function loadAdminSessionControl()'));
test('Live timer pauses hidden tabs and never scans inactive views',()=>{
 const document={hidden:true,querySelectorAll(){throw Error('Hidden page must not scan timers');}};
 new Function('document',functionSource+';tickSessionDurations();')(document);
 let selector='';document.hidden=false;document.querySelectorAll=value=>{selector=value;return [];};
 new Function('document',functionSource+';tickSessionDurations();')(document);
 assert.match(selector,/\.view-section\.active \[data-live-duration\]/);
 assert.match(selector,/\.investigation-drawer\.open \[data-live-duration\]/);
});
test('Duration stays exact while unchanged ticks avoid DOM writes',()=>{
 let writes=0,text='00:00:04';const node={dataset:{liveDuration:'4',durationRunning:'true',durationCaptured:'1000'},get textContent(){return text;},set textContent(value){text=value;writes++;}};
 const document={hidden:false,querySelectorAll:()=>[node]};
 const tick=new Function('document','Date',functionSource+';tickSessionDurations();');
 tick(document,{now:()=>1000});assert.equal(writes,0);
 tick(document,{now:()=>3000});assert.equal(text,'00:00:06');assert.equal(writes,1);
 tick(document,{now:()=>3000});assert.equal(writes,1);
});
