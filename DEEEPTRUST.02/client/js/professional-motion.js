// Visual feedback only: never changes authentication state, requests or media.
(() => {
    const preference=window.matchMedia('(prefers-reduced-motion: reduce)');
    const running=new Set(),byElement=new WeakMap();
    function animate(element,frames,options) {
        if(!element || preference.matches || typeof element.animate!=='function')return;
        byElement.get(element)?.cancel();
        const animation=element.animate(frames,options);byElement.set(element,animation);running.add(animation);
        animation.finished.then(()=>running.delete(animation),()=>running.delete(animation));
    }
    function enter(element) {
        animate(element,[{opacity:0,transform:'translateY(10px)'},{opacity:1,transform:'translateY(0)'}],
            {duration:280,easing:'cubic-bezier(.2,.8,.2,1)'});
        element?.querySelectorAll(':scope > .view-header, :scope > .kpi-grid > .kpi-card, :scope > .card, :scope > .portal-access-card').forEach((child,index)=>{
            if(index>7)return;
            animate(child,[{opacity:0,transform:'translateY(6px)'},{opacity:1,transform:'translateY(0)'}],
                {duration:260,delay:Math.min(index*28,140),easing:'cubic-bezier(.2,.8,.2,1)',fill:'backwards'});
        });
    }
    preference.addEventListener?.('change',()=>{if(preference.matches){running.forEach(a=>a.cancel());running.clear();}});
    window.DeepTrustMotion={enter};
    document.addEventListener('DOMContentLoaded',()=>enter(document.querySelector('.auth-view.active')),{once:true});
})();
