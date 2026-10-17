// Aggregate interaction signals only. Never record key values, page text or pointer coordinates.
export function startSessionMonitor({getAuthorizationHeader, onUnauthorized}) {
    let lastInput=performance.now(), previous=null, started=performance.now();
    let samples=[], intervals=[], movements=0, clicks=0, trusted=0, synthetic=0, touch=false;
    let scrolls=0, wheels=0, swipes=0, swipeStart=null, segment=null, straightness=[];
    let heartbeatBusy=false, summaryBusy=false, deadline=Infinity;
    const notice=document.createElement('div');
    notice.setAttribute('role','status');notice.hidden=true;
    notice.style.cssText='position:fixed;bottom:20px;right:20px;z-index:10000;padding:14px 18px;max-width:360px;background:var(--surface-card);color:var(--warning-amber);border:1px solid var(--warning-amber);border-radius:10px';
    document.body.appendChild(notice);
    const observe=(event)=>{
        if (event.isTrusted) { trusted++; lastInput=performance.now(); } else synthetic++;
    };
    const move=(event)=>{
        observe(event);movements++;
        const now=performance.now();
        if(event.pointerType==='touch')touch=true;
        if(previous && (now-previous.t>250 || previous.type!==(event.pointerType||'mouse'))) {
            previous=null;segment=null;
        }
        if(previous && now-previous.t<8)return;
        if(previous && samples.length<5000) {
            const distance=Math.hypot(event.clientX-previous.x,event.clientY-previous.y);
            const elapsed=now-previous.t;
            const velocity=distance/(elapsed/1000);
            if(Number.isFinite(velocity)) {samples.push(velocity);intervals.push(elapsed);}
            if(!segment)segment={x:previous.x,y:previous.y,path:0,count:0};
            segment.path+=distance;segment.count++;
            if(segment.count>=12) {
                if(segment.path>=80)straightness.push(Math.min(1,Math.hypot(event.clientX-segment.x,event.clientY-segment.y)/segment.path));
                segment=null;
            }
        }
        previous={x:event.clientX,y:event.clientY,t:now,type:event.pointerType||'mouse'};
    };
    const click=(event)=>{observe(event);clicks++;};
    const finishSwipe=(point)=>{
        if(swipeStart && Number.isFinite(point?.clientX) && Number.isFinite(point?.clientY) &&
            Math.hypot(point.clientX-swipeStart.x,point.clientY-swipeStart.y)>=40 &&
            performance.now()-swipeStart.t<=2000)swipes++;
        swipeStart=null;
    };
    const touched=(event)=>{
        touch=true;observe(event);
        if(event.touches?.length===1) {
            const point=event.touches[0];
            swipeStart={x:point.clientX,y:point.clientY,t:performance.now(),id:point.identifier,source:'touch'};
        } else if(event.touches?.length>1)swipeStart=null;
    };
    const touchMove=(event)=>{observe(event);if(event.touches?.length>1)swipeStart=null;};
    const touchEnd=(event)=>{
        observe(event);
        if(swipeStart?.source==='touch') {
            const point=Array.from(event.changedTouches||[]).find(item=>item.identifier===swipeStart.id);
            if(point)finishSwipe(point);
        }
    };
    const touchCancel=()=>{swipeStart=null;};
    const scroll=(event)=>{observe(event);scrolls++;};
    const wheel=(event)=>{observe(event);wheels++;};
    const down=(event)=>{if(event.pointerType==='touch'){touch=true;observe(event);swipeStart={x:event.clientX,y:event.clientY,t:performance.now(),id:event.pointerId,source:'pointer'};}};
    const up=(event)=>{
        if(event.pointerType==='touch')observe(event);
        if(swipeStart?.source==='pointer' && swipeStart.id===event.pointerId)finishSwipe(event);
    };
    document.addEventListener('pointermove',move,{passive:true});
    document.addEventListener('click',click,{passive:true});
    document.addEventListener('keydown',observe,{passive:true});
    document.addEventListener('scroll',scroll,{passive:true,capture:true});
    document.addEventListener('wheel',wheel,{passive:true});
    document.addEventListener('pointerdown',down,{passive:true});
    document.addEventListener('pointerup',up,{passive:true});
    const pointerCancel=()=>{if(swipeStart?.source==='pointer')swipeStart=null;};
    document.addEventListener('pointercancel',pointerCancel,{passive:true});
    document.addEventListener('touchstart',touched,{passive:true});
    document.addEventListener('touchmove',touchMove,{passive:true});
    document.addEventListener('touchend',touchEnd,{passive:true});
    document.addEventListener('touchcancel',touchCancel,{passive:true});
    async function send(path,payload) {
        const headers=getAuthorizationHeader();
        if(!headers.Authorization)return;
        const response=await fetch(path,{method:'POST',headers:{...headers,'Content-Type':'application/json'},body:JSON.stringify(payload),keepalive:true});
        if(response.status===401 || response.status===403) {onUnauthorized?.();return;}
        if(response.ok && path==='/api/v1/session/activity') {
            const data=await response.json();
            if(Number.isFinite(data.expires_in_seconds))deadline=performance.now()+data.expires_in_seconds*1000;
            const remaining=Math.ceil((deadline-performance.now())/1000);
            notice.hidden=remaining>60 || remaining<0;
            if(!notice.hidden)notice.textContent=`Session expires in ${remaining}s. Interact with the page to stay signed in.`;
        }
    }
    async function heartbeat() {
        if(heartbeatBusy)return;
        heartbeatBusy=true;
        try {await send('/api/v1/session/activity',{has_activity:!document.hidden && performance.now()-lastInput<10000});}
        catch {} finally {heartbeatBusy=false;}
    }
    async function summary() {
        if(summaryBusy || document.hidden)return;
        summaryBusy=true;
        const elapsed=Math.max(1,(performance.now()-started)/1000);
        const mean=samples.reduce((a,b)=>a+b,0)/(samples.length||1);
        const variance=samples.reduce((a,b)=>a+(b-mean)**2,0)/(samples.length||1);
        const intervalMean=intervals.reduce((a,b)=>a+b,0)/(intervals.length||1);
        const intervalCv=intervalMean ? Math.sqrt(intervals.reduce((a,b)=>a+(b-intervalMean)**2,0)/(intervals.length||1))/intervalMean : 0;
        const pathMean=straightness.reduce((a,b)=>a+b,0)/(straightness.length||1);
        const payload={scroll_events:Math.min(100000,scrolls),wheel_events:Math.min(100000,wheels),swipe_count:Math.min(100000,swipes),
            pointer_interval_cv:Math.min(100,intervalCv),path_straightness:pathMean,path_segments:straightness.length,
            average_velocity:Math.min(100000,mean),velocity_variance:Math.min(1e10,variance),
            movement_rate:Math.min(10000,movements/elapsed),click_rate:Math.min(10000,clicks/elapsed),
            idle_ratio:Math.min(1,(performance.now()-lastInput)/(elapsed*1000)),sample_count:samples.length,
            trusted_events:Math.min(100000,trusted),synthetic_events:Math.min(100000,synthetic),
            window_seconds:Math.min(120,elapsed),webdriver:navigator.webdriver===true,is_touch_device:touch};
        samples=[];intervals=[];straightness=[];segment=null;scrolls=0;wheels=0;swipes=0;swipeStart=null;touch=false;movements=0;clicks=0;trusted=0;synthetic=0;previous=null;started=performance.now();
        try {await send('/api/v1/session/behavior-summary',payload);}
        catch {} finally {summaryBusy=false;}
    }
    const wake=()=>{if(!document.hidden){started=performance.now();samples=[];intervals=[];straightness=[];segment=null;scrolls=0;wheels=0;swipes=0;swipeStart=null;touch=false;movements=0;clicks=0;trusted=0;synthetic=0;previous=null;heartbeat();}};
    document.addEventListener('visibilitychange',wake);
    heartbeat();
    const heartTimer=setInterval(heartbeat,5000),summaryTimer=setInterval(summary,15000);
    return ()=>{
        clearInterval(heartTimer);clearInterval(summaryTimer);notice.remove();
        document.removeEventListener('scroll',scroll,true);
        for(const [name,handler] of [['pointermove',move],['click',click],['keydown',observe],['wheel',wheel],['pointerdown',down],['pointerup',up],['pointercancel',pointerCancel],['touchstart',touched],['touchmove',touchMove],['touchend',touchEnd],['touchcancel',touchCancel],['visibilitychange',wake]])document.removeEventListener(name,handler);
    };
}
