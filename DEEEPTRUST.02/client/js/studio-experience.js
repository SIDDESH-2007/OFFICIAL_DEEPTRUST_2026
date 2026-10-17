// Presentation only. No auth/session access, requests, media, or synthetic pointer events.
(() => {
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  const animations = new Set(), active = new WeakMap();
  const ease = 'cubic-bezier(.2,.75,.2,1)';
  function animate(element, frames, options) {
    if (!element || reduced.matches || typeof element.animate !== 'function') return;
    active.get(element)?.cancel();
    const animation = element.animate(frames, options);
    active.set(element, animation); animations.add(animation);
    animation.finished.then(() => animations.delete(animation), () => animations.delete(animation));
  }
  function enter(element) {
    if (!element) return;
    animate(element, [{opacity:0,transform:'translateY(12px)'},{opacity:1,transform:'translateY(0)'}], {duration:340,easing:ease});
    element.querySelectorAll(':scope > .view-header, :scope > .kpi-grid > .kpi-card, :scope > .card, :scope > .portal-access-card').forEach((item,index) => {
      if (index > 9) return;
      animate(item, [{opacity:0,transform:'translateY(8px)'},{opacity:1,transform:'translateY(0)'}], {duration:320,delay:Math.min(index*35,175),easing:ease,fill:'backwards'});
    });
  }
  // The existing controllers call this after selecting a view; no timing delay is added.
  window.DeepTrustMotion = {enter};
  reduced.addEventListener?.('change', () => {
    if (reduced.matches) { animations.forEach(animation => animation.cancel()); animations.clear(); }
  });
  document.addEventListener('visibilitychange', () => document.body.classList.toggle('studio-paused',document.hidden));
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.portal-selectable-card, .nav-item[data-view]').forEach(item => {
      item.tabIndex = 0; item.setAttribute('role','button');
      item.addEventListener('keydown',event => {
        if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); item.click(); }
      });
    });
    enter(document.querySelector('.auth-view.active, .view-section.active'));
    document.querySelectorAll('.brand-header,.brand-hero,.studio-scene,.pipeline-container').forEach((item,index) =>
      animate(item,[{opacity:0,transform:'translateY(14px)'},{opacity:1,transform:'translateY(0)'}],{duration:600,delay:index*75,easing:ease,fill:'backwards'}));
    document.addEventListener('click',event => {
      if (reduced.matches || !event.isTrusted) return;
      const host=event.target.closest('button:not(:disabled),.portal-selectable-card');
      if (!host || host.querySelector('.studio-ripple')) return;
      const bounds=host.getBoundingClientRect();
      const ripple=document.createElement('span'); ripple.className='studio-ripple'; ripple.setAttribute('aria-hidden','true');
      ripple.style.left=`${event.detail ? event.clientX-bounds.left : bounds.width/2}px`;
      ripple.style.top=`${event.detail ? event.clientY-bounds.top : bounds.height/2}px`;
      host.classList.add('studio-ripple-host'); host.appendChild(ripple);
      setTimeout(()=>{ripple.remove();host.classList.remove('studio-ripple-host');},500);
    });
  },{once:true});
})();
