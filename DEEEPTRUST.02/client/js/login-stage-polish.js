(() => {
  'use strict';
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  const running = new Set();
  const stages = {
    'view-portal-select': ['Choose your workspace', 'SECURE ACCESS'],
    'view-login': ['Account credentials', 'STEP 01 / 05'],
    'view-verify': ['Face identity', 'STEP 02 / 05'],
    'view-voice': ['Voice identity', 'STEP 03 / 05'],
    'view-voice-recovery': ['Voice recovery', 'STEP 03 / 05'],
    'view-mfa': ['Authenticator code', 'STEP 04 / 05'],
    'view-complete': ['Verification complete', 'STEP 05 / 05'],
    'view-admin-register': ['Create your account', 'ACCOUNT SETUP'],
    'view-verify-email': ['Verify your email', 'ACCOUNT SETUP'],
    'view-setup-mfa': ['Set up your authenticator', 'ACCOUNT SECURITY'],
    'view-forgot-password': ['Recover your account', 'ACCOUNT RECOVERY']
  };
  const previous = window.DeepTrustMotion;
  function cancel() { running.forEach(animation => animation.cancel()); running.clear(); }
  function enter(view) {
    if (!view?.closest('.auth-panel')) { previous?.enter(view); return; }
    cancel();
    const panel = view.closest('.auth-panel');
    const caption = panel.querySelector('.studio-auth-caption');
    const wording = stages[view.id];
    if (caption && wording) {
      const labels = caption.querySelectorAll('span');
      if (labels[0]) { labels[0].textContent = wording[0]; labels[0].classList.add('stage-caption'); }
      if (labels[1]) { labels[1].textContent = wording[1]; labels[1].classList.add('login-stage-count'); }
    }
    view.querySelectorAll('.vstep-active,.stepper-step.active').forEach(step => step.setAttribute('aria-current', 'step'));
    if (reduced.matches || typeof view.animate !== 'function') return;
    // Short, cancellable entrances; no persistent opacity or changes to auth timing.
    const card = view.querySelector('.portal-access-card') || view;
    const items = [card, ...card.querySelectorAll(':scope > .voice-stepper-row,:scope > .stepper-nav,:scope > .view-header,:scope > form,:scope > .camera-container,:scope > .voice-panel,:scope > .verification-checks-grid')];
    items.forEach((item, index) => {
      const animation = item.animate([
        { opacity:0, transform:`translateY(${index ? 7 : 10}px)` },
        { opacity:1, transform:'translateY(0)' }
      ], { duration:index ? 260 : 320, delay:Math.min(index * 25, 125), easing:'cubic-bezier(.2,.8,.2,1)', fill:'backwards' });
      running.add(animation);
      animation.finished.then(() => running.delete(animation), () => running.delete(animation));
    });
  }
  window.DeepTrustMotion = { ...previous, enter };
  reduced.addEventListener('change', () => { if (reduced.matches) cancel(); });
  document.addEventListener('DOMContentLoaded', () => {
    ['login-error-msg','mfa-error-msg','voice-recovery-alert'].forEach(id => {
      const message = document.getElementById(id);
      if (message) { message.setAttribute('role', 'alert'); message.setAttribute('aria-atomic', 'true'); }
    });
  });
})();
