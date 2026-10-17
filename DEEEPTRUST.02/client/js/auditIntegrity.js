export function initAuditIntegrity({headers}) {
    let busy=false;
    async function check() {
        if(busy)return;
        busy=true;
        const status=document.querySelector('[data-audit-integrity-status]');
        if(!status){busy=false;return;}
        status.textContent='Checking audit signatures and sequence…';
        try {
            const response=await fetch('/api/v1/admin/audit/integrity',{headers:headers()});
            if(!response.ok)throw new Error(response.status===403?'Platform administrator access required.':'Integrity check unavailable.');
            const {integrity}=await response.json();
            status.style.color=integrity.status==='TAMPER_DETECTED'?'var(--danger-red)':'var(--text-secondary)';
            status.textContent=integrity.status==='TAMPER_DETECTED'
                ?'Warning: audit integrity failed. '+integrity.reason
                :`${integrity.status==='VERIFIED'?'Signed chain verified':'No signed records yet'} · ${integrity.signed_records || 0} signed · ${integrity.legacy_unsigned_records} historical unsigned records. Coverage begins when signing was enabled.`;
        } catch(error) {status.textContent=error.message;} finally {busy=false;}
    }
    document.querySelector('[data-check-audit-integrity]')?.addEventListener('click',check);
    document.addEventListener('deeptrust:view',event=>{if(event.detail==='admin-audit-logs')check();});
}
