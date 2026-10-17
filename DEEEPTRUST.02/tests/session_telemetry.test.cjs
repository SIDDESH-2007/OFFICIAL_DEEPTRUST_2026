const fs=require('fs'),path=require('path'),vm=require('vm'),assert=require('assert/strict');
const root=path.resolve(__dirname,'..');
const code=fs.readFileSync(path.join(root,'client/js/sessionMonitor.js'),'utf8').replace('export function','function');
const listeners={},timers=[],requests=[];let now=0;
const ctx={performance:{now:()=>now},document:{hidden:false,createElement:()=>({setAttribute(){},style:{},remove(){}}),body:{appendChild(){}},addEventListener:(name,fn)=>listeners[name]=fn,removeEventListener(){}},
    navigator:{webdriver:false},fetch:async(url,opts)=>{requests.push({url,data:JSON.parse(opts.body)});return {status:200};},
    setInterval:(fn,ms)=>{timers.push({fn,ms});return timers.length;},clearInterval(){}};
vm.createContext(ctx);vm.runInContext(code,ctx);
(async()=>{
    ctx.startSessionMonitor({getAuthorizationHeader:()=>({Authorization:'Bearer test'})});
    await Promise.resolve();
    for(let i=0;i<10;i++){now+=100;listeners.pointermove({isTrusted:true,clientX:i*20,clientY:10});}
    listeners.click({isTrusted:false});listeners.keydown({isTrusted:true,key:'PRIVATE_PASSWORD'});
    now=15000;await timers.find(t=>t.ms===15000).fn();
    const row=requests.find(r=>r.url.includes('behavior-summary')).data;
    assert.equal(row.sample_count,9);assert.equal(row.synthetic_events,1);assert.equal(row.trusted_events,11);
    assert(row.average_velocity>0);assert(!JSON.stringify(requests).includes('PRIVATE_PASSWORD'));
    assert(!('clientX' in row));assert(!('key' in row));
    assert.equal(requests[0].url,'/api/v1/session/activity');
    for(let i=0;i<240;i++){now+=1000/240;listeners.pointermove({isTrusted:true,clientX:i*4,clientY:10});}
    for(let i=0;i<4;i++){listeners.wheel({isTrusted:true});listeners.scroll({isTrusted:true});}
    listeners.pointerdown({isTrusted:true,pointerType:'touch',pointerId:1,clientX:0,clientY:0});
    now+=300;listeners.pointerup({isTrusted:true,pointerType:'touch',pointerId:1,clientX:0,clientY:100});
    now=30000;await timers.find(t=>t.ms===15000).fn();
    const fast=requests.filter(r=>r.url.includes('behavior-summary')).at(-1).data;
    assert(fast.sample_count>=100,'240 Hz movement must not lose every sample');
    assert.equal(fast.scroll_events,4);assert.equal(fast.wheel_events,4);assert.equal(fast.swipe_count,1);
    assert(fast.is_touch_device);assert(fast.path_segments>0);
    assert(!JSON.stringify(fast).includes('clientX'));assert(!JSON.stringify(fast).includes('PRIVATE_PASSWORD'));
    now=32000;
    listeners.pointerdown({isTrusted:true,pointerType:'touch',pointerId:2,clientX:0,clientY:0});
    listeners.touchstart({isTrusted:true,touches:[{identifier:2,clientX:0,clientY:0}]});
    listeners.pointercancel({pointerId:2});
    now+=300;listeners.touchend({isTrusted:true,changedTouches:[{identifier:2,clientX:0,clientY:100}]});
    listeners.pointerup({isTrusted:true,pointerType:'touch',pointerId:2,clientX:0,clientY:100});
    listeners.touchstart({isTrusted:true,touches:[{identifier:3,clientX:0,clientY:0}]});
    now+=200;listeners.touchend({isTrusted:true,changedTouches:[{identifier:3,clientX:1,clientY:1}]});
    listeners.touchstart({isTrusted:true,touches:[{identifier:4,clientX:0,clientY:0}]});
    listeners.touchcancel();
    listeners.touchend({isTrusted:true,changedTouches:[{identifier:4,clientX:0,clientY:200}]});
    now=45000;await timers.find(t=>t.ms===15000).fn();
    const native=requests.filter(r=>r.url.includes('behavior-summary')).at(-1).data;
    assert.equal(native.swipe_count,1,'Native scroll must count once; taps and cancellations must not count');
    now=45010;listeners.pointermove({isTrusted:true,clientX:0,clientY:0});
    now=46010;listeners.pointermove({isTrusted:true,clientX:100,clientY:0});
    now=46020;listeners.pointermove({isTrusted:true,clientX:104,clientY:0});
    now=60000;await timers.find(t=>t.ms===15000).fn();
    const resumed=requests.filter(r=>r.url.includes('behavior-summary')).at(-1).data;
    assert.equal(resumed.sample_count,1,'Long idle gap must not be a movement sample');
    assert.equal(resumed.is_touch_device,false,'Previous touch use must not suppress later mouse checks');
    console.log('High refresh-rate, native swipe, cancellation, pause and privacy telemetry checks passed');
})();
