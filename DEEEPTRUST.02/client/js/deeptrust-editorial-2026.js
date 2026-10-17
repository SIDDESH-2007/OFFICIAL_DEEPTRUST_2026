/* Presentation-only interaction: default the sole available portal and keep motion light. */
document.addEventListener('DOMContentLoaded', () => {
  const portal = document.getElementById('portal-card-admin');
  if (portal && document.getElementById('view-portal-select')?.classList.contains('active')) {
    portal.click();
  }
  const visual = document.querySelector('.brand-panel');
  if (!visual || !matchMedia('(pointer:fine) and (prefers-reduced-motion:no-preference)').matches) return;
  let frame = 0;
  visual.addEventListener('pointermove', event => {
    if (frame) return;
    const x = event.clientX, y = event.clientY;
    frame = requestAnimationFrame(() => {
      const bounds = visual.getBoundingClientRect();
      visual.style.setProperty('--guardian-x', `${Math.max(0, Math.min(100, (x - bounds.left) / bounds.width * 100))}%`);
      visual.style.setProperty('--guardian-y', `${Math.max(0, Math.min(100, (y - bounds.top) / bounds.height * 100))}%`);
      frame = 0;
    });
  }, {passive:true});
  visual.addEventListener('pointerleave', () => {
    visual.style.removeProperty('--guardian-x');
    visual.style.removeProperty('--guardian-y');
  });
});
