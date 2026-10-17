/* Dashboard presentation only. No requests, credentials, storage, or telemetry writes. */
(() => {
  'use strict';
  if (document.body.dataset.page !== 'dashboard') return;
  const media = matchMedia('(prefers-reduced-motion: reduce)');
  const ease = 'cubic-bezier(.2,.75,.2,1)';
  const spring = 'cubic-bezier(.18,.9,.28,1.04)';
  const running = new Set(), channels = new WeakMap(), rows = new WeakMap();
  const signatures = new WeakMap(), values = new WeakMap(), chartValues = new Map();
  let frame = 0, navigationFrame = 0, source = null, selectedRow = null, forwarding = false;
  const dirty = new Set();
  const eligible = () => !media.matches && !document.hidden;
  const visible = node => node?.isConnected && node.getClientRects().length > 0;
  function motion(node, frames, options = {}, channel = 'entry') {
    if (running.size >= 16) return;
    if (!visible(node) || !eligible() || !node.animate) return;
    let map = channels.get(node); if (!map) channels.set(node, map = new Map());
    map.get(channel)?.cancel();
    const animation = node.animate(frames, {duration:180,easing:ease,...options});
    map.set(channel, animation); running.add(animation);
    const clean = () => { running.delete(animation); if (map.get(channel) === animation) map.delete(channel); };
    animation.finished.then(clean, clean); return animation;
  }
  function reveal(node, index = 0) {
    motion(node,[{opacity:.3,transform:'translateY(8px)'},{opacity:1,transform:'translateY(0)'}],
      {delay:Math.min(index*12,48),fill:'backwards'});
  }
  function changed(node, value) {
    if (signatures.get(node) === value) return false;
    signatures.set(node,value); return true;
  }
  function svg(markup, className) {
    const holder=document.createElement('span'); holder.className=className;
    holder.setAttribute('aria-hidden','true'); holder.innerHTML=markup; return holder;
  }
  const checkSvg='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path pathLength="1" d="m7 12 3 3 7-7"/></svg>';
  function verifyIcons(root) {
    root.querySelectorAll('#adminIdentitySecurityTable .status-pill, [id^="sdAssurance"]').forEach(node=>{
      const text=node.textContent.trim();
      if (!/^(Enrolled|Enabled|VERIFIED|GRANTED)/i.test(text)) return;
      if (!node.querySelector('.dt-verify-mark')) node.prepend(svg(checkSvg,'dt-verify-mark'));
      const path=node.querySelector('path');
      if(changed(node,text)) motion(path,[{strokeDasharray:'1',strokeDashoffset:'1'},{strokeDasharray:'1',strokeDashoffset:'0'}],{duration:360},'verification');
    });
  }
  function health(root) {
    root.querySelectorAll('.factor-health-item').forEach(row=>{
      const badge=row.querySelector('.factor-status-badge'); if(!badge)return;
      const state=badge.textContent.trim(), sig=state+'|'+row.textContent.trim();
      let ring=row.querySelector('.dt-health-ring');
      if(!ring){ring=svg('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle opacity=".2" cx="12" cy="12" r="9"/><circle class="dt-ring-arc" pathLength="1" cx="12" cy="12" r="9"/></svg>','dt-health-ring');
        row.querySelector('.factor-info-left')?.prepend(ring);}
      const pending=/checking|loading|busy/i.test(state);
      ring.dataset.state=pending?'checking':state==='Operational'?'healthy':'unavailable';
      if(changed(row,sig)){
        reveal(badge);
        motion(ring.querySelector('.dt-ring-arc'),[{strokeDasharray:'0 1'},{strokeDasharray:'1 0'}],{duration:420},'status');
      }
    });
  }
  function interpolateNumbers(root) {
    root.querySelectorAll('.kpi-value').forEach(node=>{
      const text=node.textContent.trim(), previous=values.get(node); values.set(node,text);
      if(previous===undefined || previous===text || !/^[\d,.]+%?$/.test(text))return;
      // Keep the exact backend number in the DOM; animate its presentation only.
      motion(node,[{opacity:.35,transform:'translateY(5px)'},{opacity:1,transform:'translateY(0)'}],{duration:240},'value');
    });
  }
  function rowKey(row) {
    return row.querySelector('[data-id],[data-session-id]')?.dataset.id ||
      row.querySelector('[data-session-id]')?.dataset.sessionId ||
      [...row.cells].slice(0,2).map(cell=>cell.textContent.trim()).join('|');
  }
  function lists(root) {
    root.querySelectorAll('tbody').forEach(body=>{
      if(!visible(body))return;
      const old=rows.get(body)||new Map(), next=new Map();
      // Read geometry once before animation writes, never alternate read/write per row.
      const snapshots=[...body.rows].slice(0,100).map(row=>({row,key:rowKey(row),top:row.offsetTop,
        text:row.textContent.trim().replace(/\b\d{2}:\d{2}:\d{2}\b/g,'<clock>')}));
      snapshots.forEach(({row,key,top,text},index)=>{
        const previous=old.get(key); next.set(key,{top,text});
        if(!previous){if(index<4)reveal(row,index);}
        else {
          const dy=previous.top-top;
          if(Math.abs(dy)>1 && Math.abs(dy)<500)motion(row,[{transform:`translateY(${dy}px)`},{transform:'translateY(0)'}],{duration:260},'layout');
          if(previous.text!==text && index<8)motion(row,[{opacity:.6},{opacity:1}],{duration:200},'update');
        }
        if(index<4 && body.closest('#adminThreatsTable') && changed(row,text)){
          const high=row.querySelector('.status-pill.high'); if(high)motion(high,[{opacity:.5},{opacity:1},{opacity:.65},{opacity:1}],{duration:500},'alert');
        }
      }); rows.set(body,next);
    });
    root.querySelectorAll('.timeline-list').forEach(list=>{
      [...list.children].slice(0,6).forEach((item,index)=>{if(changed(item,item.textContent))reveal(item,index);});
    });
  }
  function risk(root) {
    [...root.querySelectorAll('#adminRiskTable tbody tr, #adminThreatsTable tbody tr, #sdRiskScore')].slice(0,100).forEach(row=>{
      const match=row.textContent.match(/\b(\d+(?:\.\d+)?)\s*\/\s*100\b/); if(!match)return;
      const score=Number(match[1]); if(score<0||score>100)return;
      const host=row.id==='sdRiskScore'?row:row.querySelectorAll('td')[row.closest('#adminRiskTable')?2:4];
      if(!host)return;
      let gauge=host.querySelector('.dt-risk-track');
      if(!gauge){gauge=document.createElement('span');gauge.className='dt-risk-track';gauge.setAttribute('aria-hidden','true');gauge.append(document.createElement('span'));host.append(gauge);}
      const fill=gauge.firstElementChild, key=row.cells?rowKey(row):row.id;
      const previous=chartValues.get('risk:'+key)??0; chartValues.set('risk:'+key,score);
      fill.style.transform=`scaleX(${score/100})`; fill.dataset.level=score>70?'high':score>40?'medium':'low';
      if(changed(gauge,String(score)))motion(fill,[{transform:`scaleX(${previous/100})`},{transform:`scaleX(${score/100})`}],{duration:360},'gauge');
    });
  }
  function report(root) {
    const table=root.querySelector('#reportOrgSummaryTable'); if(!table)return;
    const data=[...table.tBodies[0]?.rows||[]].filter(row=>row.cells.length===5).slice(0,12).map(row=>({
      name:row.cells[0].textContent.trim(),success:Number(row.cells[2].textContent.trim()),blocked:Number(row.cells[3].textContent.trim())
    })).filter(row=>Number.isFinite(row.success)&&Number.isFinite(row.blocked));
    let chart=root.querySelector('.dt-report-chart');
    if(!data.length){chart?.remove();return;}
    if(!chart){chart=document.createElement('div');chart.className='dt-report-chart';chart.setAttribute('aria-label','Recorded successful and blocked access by organization');table.parentElement.before(chart);}
    if(!changed(chart,JSON.stringify(data)))return;
    const max=Math.max(1,...data.flatMap(row=>[row.success,row.blocked]));
    chart.replaceChildren();
    const title=document.createElement('small');title.textContent='Recorded access · successful / blocked';chart.append(title);
    for(const [index,item] of data.entries()){
      const row=document.createElement('div');row.className='dt-report-chart-row';
      const label=document.createElement('span');label.textContent=item.name;row.append(label);
      for(const [kind,n] of [['success',item.success],['blocked',item.blocked]]){
        const host=document.createElement('span');host.className='dt-report-bar';host.title=`${kind}: ${n}`;
        const fill=document.createElement('span');fill.dataset.kind=kind;const ratio=n/max;
        const old=chartValues.get('report:'+item.name+kind)??0;chartValues.set('report:'+item.name+kind,ratio);
        fill.style.transform=`scaleX(${ratio})`;host.append(fill);row.append(host);
        fill.dataset.previous=String(old);
      }chart.append(row);
      row.querySelectorAll('.dt-report-bar>span').forEach(fill=>motion(fill,[{transform:`scaleX(${fill.dataset.previous})`},{transform:fill.style.transform}],{duration:380,delay:index*15},'chart'));
    }
  }
  function copilot(root) {
    root.querySelectorAll('.copilot-message,.evidence-item,.recommendation-item').forEach((node,index)=>{
      const pending=node.classList.contains('agent') && /Analyzing MongoDB telemetry/.test(node.textContent);
      node.dataset.motionState=pending?'analysing':'ready';
      let dots=node.querySelector('.dt-thinking-dots');
      if(pending&&!dots){dots=document.createElement('span');dots.className='dt-thinking-dots';dots.setAttribute('aria-hidden','true');dots.innerHTML='<i></i><i></i><i></i>';node.append(dots);}
      if(!pending)dots?.remove();
      if(changed(node,node.textContent))reveal(node,index%5);
    });
  }
  function integrations(root) {
    root.querySelectorAll('#adminIntegrationsTable tbody tr').forEach(row=>{
      if(row.cells.length!==5)return;
      const badge=row.cells[3].querySelector('.status-pill');if(!badge)return;
      const state=badge.textContent.trim();
      let line=row.querySelector('.dt-handshake');
      if(!line){line=svg('<svg viewBox="0 0 72 14" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="5" cy="7" r="3"/><path pathLength="1" d="M9 7H63"/><circle cx="67" cy="7" r="3"/></svg>','dt-handshake');row.cells[3].append(line);}
      const confirmed=badge.classList.contains('low') && /connected|operational|active|healthy/i.test(state) && !/disconnected|inactive/i.test(state);
      line.dataset.connected=String(confirmed);
      if(changed(line,state)&&confirmed)motion(line.querySelector('path'),[{strokeDasharray:'1',strokeDashoffset:'1'},{strokeDasharray:'1',strokeDashoffset:'0'}],{duration:420},'connection');
    });
  }
  function behavior(root) {
    const host=root.querySelector('#sdBehavior');if(!host||!visible(host))return;
    // The existing privacy policy stores counts, not pointer coordinates. Never invent a trajectory.
    const text=host.textContent;
    const labels=['Pointer samples','Scroll events','Touch swipes'];
    const counts=labels.map(label=>{const match=text.match(new RegExp(label+':\\s*(\\d+)'));return match?Number(match[1]):null;});
    let box=host.querySelector('.dt-behavior-chart');
    if(counts.every(n=>n===null)){box?.remove();return;}
    if(!box){box=document.createElement('figure');box.className='dt-behavior-chart';
      const caption=document.createElement('figcaption');caption.textContent='Recorded interaction counts · no movement coordinates stored';
      const canvas=document.createElement('canvas');canvas.width=420;canvas.height=88;canvas.setAttribute('role','img');box.append(canvas,caption);host.append(box);}
    const status=host.querySelector('strong')?.textContent.trim()||'';
    if(!changed(box,JSON.stringify([counts,status])))return;
    const canvas=box.querySelector('canvas');canvas.setAttribute('aria-label',labels.map((l,i)=>`${l}: ${counts[i]??'Not recorded'}`).join(', '));
    const ctx=canvas.getContext('2d');if(!ctx)return;
    const max=Math.max(1,...counts.filter(n=>n!==null));
    ctx.clearRect(0,0,420,88);ctx.font='11px sans-serif';
    labels.forEach((label,index)=>{const y=index*28;ctx.fillStyle='#b8b3ad';ctx.fillText(label,0,y+17);
      ctx.fillStyle=/^(UNUSUAL|SUSPICIOUS|HIGH_RISK)/.test(status)?'#ef6464':'#d5b18c';ctx.fillRect(112,y+6,(counts[index]??0)/max*245,12);ctx.fillStyle='#b8b3ad';ctx.fillText(String(counts[index]??'—'),365,y+17);});
    reveal(canvas);
  }
  function connection(root) {
    if(root.id!=='sessionDetailsDrawer'||!root.classList.contains('open'))return;
    const ids=['sdIdentityEmail','sdBrowser','sdOrgName'];
    const labels=ids.map(id=>document.getElementById(id)?.textContent.trim()||'Not recorded');
    const state=document.getElementById('sdSessionStatus')?.textContent.trim()||'Not recorded';
    let map=root.querySelector('.dt-session-connection');
    if(!map){map=document.createElement('div');map.className='dt-session-connection';root.querySelector('.drawer-body')?.prepend(map);}
    if(!changed(map,labels.join('|')+state))return;
    map.replaceChildren();
    labels.forEach((label,index)=>{const node=document.createElement('span');node.textContent=label;map.append(node);
      if(index<2)map.append(svg('<svg viewBox="0 0 40 14" fill="none" stroke="currentColor" stroke-width="1.5"><path pathLength="1" d="M1 7H39"/></svg>','dt-session-link'));});
    map.dataset.active=String(/^(ACTIVE|IDLE)$/.test(state));
    for(const path of map.querySelectorAll('path'))motion(path,[{strokeDasharray:'1',strokeDashoffset:'1'},{strokeDasharray:'1',strokeDashoffset:'0'}],{duration:450},'connection');
  }
  function enhance(root) {
    if(!visible(root))return;
    // Own decorative DOM writes must not schedule another full enhancement pass.
    observer?.disconnect();
    try {
      if(root.querySelector('tbody,.timeline-list'))lists(root);
      interpolateNumbers(root);
      if(root.id==='view-admin-identity-sec'||root.id==='sessionDetailsDrawer')verifyIcons(root);
      if(root.querySelector('.factor-health-item'))health(root);
      if(['view-admin-risk-engine','view-admin-threat-investigation','sessionDetailsDrawer'].includes(root.id))risk(root);
      if(root.id==='view-admin-reports')report(root);
      if(root.id==='view-admin-copilot')copilot(root);
      if(root.id==='view-admin-integrations')integrations(root);
      if(root.id==='sessionDetailsDrawer'){behavior(root);connection(root);}
    root.querySelectorAll('.trend-bar-fill,.trend-bar').forEach(node=>{if(changed(node,node.style.height))motion(node,[{transform:'scaleY(0)'},{transform:'scaleY(1)'}],{duration:400},'chart');});
    } finally { observeContent(); }
  }
  function schedule(root) {
    if(!root || document.hidden)return;
    dirty.add(root);if(frame)return;
    frame=requestAnimationFrame(()=>{frame=0;const list=[...dirty];dirty.clear();list.forEach(enhance);});
  }
  function transfer(from,to) {
    if(!from || !visible(to) || !eligible())return;
    const end=to.getBoundingClientRect();if(!from.width||!end.width)return;
    const ghost=document.createElement('div');ghost.className='dt-motion-transfer';ghost.setAttribute('aria-hidden','true');
    // A border-only shared element never duplicates private data or interactive controls.
    const zoom=Number(getComputedStyle(document.body).zoom)||1;
    Object.assign(ghost.style,{left:end.left/zoom+'px',top:end.top/zoom+'px',width:end.width/zoom+'px',height:end.height/zoom+'px'});
    document.body.append(ghost);
    const anim=motion(ghost,[{opacity:.6,transform:`translate(${(from.left-end.left)/zoom}px,${(from.top-end.top)/zoom}px) scale(${from.width/end.width},${from.height/end.height})`},{opacity:0,transform:'none'}],{duration:320,easing:spring},'transfer');
    if(anim)anim.finished.then(()=>ghost.remove(),()=>ghost.remove());else ghost.remove();
  }
  function onView(event) {
    if(navigationFrame)cancelAnimationFrame(navigationFrame);
    // Cancel outgoing motion immediately; routing/data loading never wait for animation.
    running.forEach(animation=>animation.cancel());running.clear();
    const from=source;source=null;
    const accountDrawer=document.getElementById('dtAccountMotionDrawer');if(accountDrawer)accountDrawer.hidden=true;
    navigationFrame=requestAnimationFrame(()=>{
      navigationFrame=0;const view=document.getElementById('view-'+event.detail);
      if(!view?.classList.contains('active'))return;
      // Animate small heading/KPI surfaces, never composite an entire large table.
      const heading=view.querySelector('.view-header');if(heading)reveal(heading);
      [...view.querySelectorAll('.kpi-card')].slice(0,4).forEach(reveal);
      transfer(from,view.querySelector('.view-header'));schedule(view);
    });
  }
  function accountDetails(row) {
    const table=row.closest('table');if(row.cells.length<9)return;
    let drawer=document.getElementById('dtAccountMotionDrawer');
    if(!drawer){drawer=document.createElement('aside');drawer.id='dtAccountMotionDrawer';drawer.className='dt-account-motion-drawer';
      drawer.setAttribute('role','dialog');drawer.setAttribute('aria-modal','false');drawer.setAttribute('aria-label','Account details');
      const close=document.createElement('button');close.type='button';close.className='btn btn-secondary';close.textContent='Close account details';
      close.onclick=()=>{drawer.hidden=true;selectedRow?.focus();};drawer.append(close,document.createElement('dl'));document.body.append(drawer);}
    const dl=drawer.querySelector('dl');dl.replaceChildren();
    [...row.cells].slice(0,-1).forEach((cell,index)=>{
      const label=document.createElement('dt'),value=document.createElement('dd');
      label.textContent=table.tHead?.rows[0]?.cells[index]?.textContent.trim()||'Account';value.textContent=cell.textContent.trim();dl.append(label,value);
    });drawer.hidden=false;selectedRow=row;
    motion(drawer,[{opacity:.7,transform:'translateX(36px)'},{opacity:1,transform:'translateX(0)'}],{duration:320,easing:spring},'drawer');
    transfer(row.getBoundingClientRect(),drawer);
    drawer.querySelector('button').focus({preventScroll:true});
  }
  let observer=null;
  const observed=[];
  function observeContent(){for(const node of observed)observer.observe(node,{subtree:true,childList:true,characterData:true});}
  function init() {
    document.body.classList.add('dt-dashboard-motion');
    const cards={adminKpiOrgs:'admin-organizations',adminKpiIdentities:'admin-identity-sec',adminKpiTodayAuth:'admin-session-control',adminKpiAlerts:'admin-threat-investigation'};
    Object.entries(cards).forEach(([id,view])=>{
      const card=document.getElementById(id)?.closest('.kpi-card');if(!card)return;
      card.dataset.motionView=view;card.tabIndex=0;card.setAttribute('role','button');card.setAttribute('aria-label',`Open ${card.querySelector('.kpi-title')?.textContent||view}`);
    });
    document.addEventListener('click',event=>{
      if(!forwarding)source=null;
      const card=event.target.closest('[data-motion-view]');
      if(card && !event.target.closest('button,a,input,select')){
        source=card.getBoundingClientRect();forwarding=true;
        try{document.querySelector(`.nav-item[data-view="${card.dataset.motionView}"]`)?.click();}finally{forwarding=false;}
        return;
      }
      const row=event.target.closest('tr');
      if(row){source=row.getBoundingClientRect();
        if(selectedRow)selectedRow.classList.remove('dt-row-selected');row.classList.add('dt-row-selected');selectedRow=row;
        if(row.closest('#adminAccountsTable')&&!event.target.closest('button,a,input,select'))accountDetails(row);
      }
    },{capture:true,passive:true});
    document.addEventListener('keydown',event=>{
      if(event.key==='Escape'){const drawer=document.getElementById('dtAccountMotionDrawer');if(drawer&&!drawer.hidden){drawer.hidden=true;selectedRow?.focus();}}
      const target=event.target.closest('[data-motion-view],#adminAccountsTable tbody tr[data-motion-account]');
      if(target && event.target===target && (event.key==='Enter'||event.key===' ')){event.preventDefault();target.click();}
    });
    observer=new MutationObserver(records=>{
      for(const record of records){
        const target=record.target.nodeType===1?record.target:record.target.parentElement;
        // Live clocks, polling timestamps and button ripples carry no new motion data.
        if(target?.closest('[data-live-duration],#scMonitorUpdated,#scMonitorStatus,#scInteractionAlerts,.studio-ripple,.studio-ripple-host'))continue;
        if(target?.classList.contains('kpi-value') && values.get(target)===target.textContent.trim())continue;
        const root=target?.closest('.view-section,.investigation-drawer,.notification-drawer,#staff-login-popups');
        if(root&&(root.classList.contains('active')||root.classList.contains('open')))schedule(root);
      }
    });
    const content=document.getElementById('mainContentArea');
    if(content)observed.push(content);
    document.querySelectorAll('.investigation-drawer,.notification-drawer').forEach(drawer=>{
      observed.push(drawer);
      new MutationObserver(()=>{
        if(!drawer.classList.contains('open'))return;
        const from=source;source=null;
        requestAnimationFrame(()=>{transfer(from,drawer.querySelector('.drawer-header'));schedule(drawer);
          [...drawer.querySelectorAll('.detail-section-title')].slice(0,4).forEach(reveal);});
      }).observe(drawer,{attributes:true,attributeFilter:['class']});
    });
    observeContent();
    // Mark refreshed rows once; preserve all original action button handlers.
    const accounts=document.querySelector('#adminAccountsTable tbody');
    if(accounts)new MutationObserver(()=>{[...accounts.rows].forEach(row=>{
      if(row.cells.length<9||row.dataset.motionAccount)return;row.dataset.motionAccount='true';row.tabIndex=0;row.setAttribute('aria-label',`Account details: ${row.cells[1].textContent.trim()}`);
    });}).observe(accounts,{childList:true});
    const popups=new MutationObserver(records=>{
      for(const record of records)for(const node of record.addedNodes){
        if(node.nodeType!==1)continue;
        const host=node.id==='staff-login-popups'?node:node.closest('#staff-login-popups');if(!host)continue;
        if(node===host)popupObserver.observe(host,{childList:true});
        [...host.children].forEach((popup,index)=>{if(changed(popup,popup.textContent))motion(popup,[{opacity:0,transform:'translateX(24px) scale(.98)'},{opacity:1,transform:'none'}],{duration:280,delay:index*20},'toast');});
      }
    });
    const popupObserver=new MutationObserver(()=>{
      const host=document.getElementById('staff-login-popups');if(!host)return;
      listsForToasts(host);
    });
    function listsForToasts(host){
      const old=rows.get(host)||new Map(),next=new Map();
      [...host.children].forEach(popup=>{const top=popup.getBoundingClientRect().top,previous=old.get(popup);next.set(popup,top);
        if(previous===undefined)reveal(popup);
        else if(previous!==top)motion(popup,[{transform:`translateY(${previous-top}px)`},{transform:'none'}],{},'layout');
      });rows.set(host,next);
    }
    popups.observe(document.body,{childList:true});
    document.addEventListener('deeptrust:view',onView);
    document.addEventListener('visibilitychange',()=>{
      if(document.hidden){running.forEach(a=>a.cancel());running.clear();if(frame)cancelAnimationFrame(frame);frame=0;dirty.clear();}
      else schedule(document.querySelector('.view-section.active'));
    });
    media.addEventListener('change',()=>{if(media.matches){running.forEach(a=>a.cancel());running.clear();}});
    schedule(document.querySelector('.view-section.active'));
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init();
})();
