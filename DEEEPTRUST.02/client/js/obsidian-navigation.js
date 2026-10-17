// Presentation-only shortcuts. Existing sidebar handlers remain the route authority.
(() => {
  'use strict';
  document.addEventListener('DOMContentLoaded', () => {
    if (document.body.dataset.page !== 'dashboard') return;
    const header = document.querySelector('.topbar');
    const search = header?.querySelector('.topbar-search');
    if (!header || !search || header.querySelector('.obsidian-nav')) return;
    const nav = document.createElement('nav');
    nav.className = 'obsidian-nav';
    nav.setAttribute('aria-label', 'Security console sections');
    const indicator = document.createElement('span');
    indicator.className = 'obsidian-nav-indicator';
    indicator.setAttribute('aria-hidden','true');
    nav.appendChild(indicator);
    const sections = [
      ['admin-overview','Overview'],['admin-session-control','Sessions'],
      ['admin-threat-investigation','Threats'],['admin-reports','Reports'],
      ['admin-audit-logs','Audit']
    ];
    for (const [view,label] of sections) {
      if (!document.querySelector(`#deeptrustAdminNav .nav-item[data-view="${view}"]`)) continue;
      const button = document.createElement('button');
      button.type = 'button'; button.textContent = label; button.dataset.view = view;
      button.addEventListener('click', () => {
        document.querySelector(`#deeptrustAdminNav .nav-item[data-view="${view}"]`)?.click();
      });
      nav.appendChild(button);
    }
    header.insertBefore(nav, search);
    const sync = view => {
      nav.querySelectorAll('button').forEach(button => {
        if (button.dataset.view === view) button.setAttribute('aria-current','page');
        else button.removeAttribute('aria-current');
      });
      const selected = nav.querySelector('button[aria-current="page"]');
      indicator.hidden = !selected;
      if (selected) {
        indicator.style.left = `${selected.offsetLeft}px`;
        indicator.style.width = `${selected.offsetWidth}px`;
      }
    };
    sync((location.hash || '#admin-overview').slice(1));
    document.addEventListener('deeptrust:view', event => sync(event.detail));
  }, {once:true});
})();
