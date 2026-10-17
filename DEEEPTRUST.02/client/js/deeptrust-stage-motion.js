/* Decorative motion hooks only. No event is cancelled, delayed, or submitted here. */
document.addEventListener('DOMContentLoaded', () => {
  if (!document.body.classList.contains('dt-editorial')) return;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const pulse = (node, className, duration) => {
    if (!node || reduced.matches) return;
    node.classList.remove(className);
    requestAnimationFrame(() => node.classList.add(className));
    setTimeout(() => node.classList.remove(className), duration);
  };

  if (document.body.dataset.page === 'dashboard') {
    const reveal = () => {
      if (document.documentElement.style.visibility === 'hidden') return;
      observer.disconnect();
      requestAnimationFrame(() => document.body.classList.add('dt-dashboard-arrival'));
    };
    const observer = new MutationObserver(reveal);
    observer.observe(document.documentElement, {attributes:true,attributeFilter:['style']});
    reveal();
    return;
  }

  for (const id of ['btn-submit-login','btn-enable-camera','btn-enroll-face','btn-continue-voice',
    'btn-start-voice','btn-continue-mfa','btn-finalize-dashboard']) {
    const button = document.getElementById(id);
    button?.addEventListener('click', () => pulse(button, 'dt-tap-feedback', 500), {passive:true});
  }

  const camera = document.querySelector('#view-verify .camera-container');
  document.getElementById('btn-enable-camera')?.addEventListener('click', () => {
    pulse(camera, 'dt-camera-arming', 900);
  }, {passive:true});
  const video = document.getElementById('webcam-feed');
  video?.addEventListener('playing', () => camera?.classList.add('dt-camera-live'));
  for (const eventName of ['pause','ended','emptied']) {
    video?.addEventListener(eventName, () => camera?.classList.remove('dt-camera-live'));
  }

  const voice = document.getElementById('voice-mic-orb');
  document.getElementById('btn-start-voice')?.addEventListener('click', () => {
    pulse(voice, 'dt-voice-arming', 1000);
  }, {passive:true});
});
