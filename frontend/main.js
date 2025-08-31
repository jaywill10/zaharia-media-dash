import './style.css';
import QRCode from 'qrcode';

    const S = { token: null, me: null, sabPage: 1, sabPages: 1, sabTimer: null, npTimer: null, apps: [], resetToken: null };
    const $ = sel => document.querySelector(sel);

    function clearUrlParams(){ try { if (history.replaceState) history.replaceState(null, '', location.pathname); } catch {}
    }

    function toast(msg, kind='ok'){
      const wrap = $('#toasts'); const div = document.createElement('div');
      div.className = `toast ${kind==='ok'?'toast-ok':'toast-err'}`; div.textContent = msg;
      wrap.appendChild(div); setTimeout(()=> div.remove(), 3500);
    }

    // Modal helper
    const Modal = {
      open({ title, bodyHTML, confirmText='Confirm', onConfirm, onOpen }){
        $('#modalTitle').textContent = title || '';
        $('#modalBody').innerHTML = bodyHTML || '';
        $('#modalOk').textContent = confirmText;
        $('#modal').classList.remove('hidden');
        onOpen && onOpen();
        const ok = $('#modalOk'), cancel = $('#modalCancel');
        const close = ()=> $('#modal').classList.add('hidden');
        cancel.onclick = close;
        ok.onclick = async ()=>{ try{ await onConfirm?.(); } finally { close(); } };
      }
    };

    function show(id){
      for (const s of ["#view-login","#view-register","#view-forgot","#view-reset","#view-apps","#view-admin","#view-settings"]) {
        const el = $(s); if (el) el.classList.add("hidden");
      }
      const tgt = $(id); if (tgt) tgt.classList.remove("hidden");
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    const qs=new URLSearchParams(location.search);
    const rt=qs.get('token');
    if(rt){ S.resetToken=rt; show('#view-reset'); }

    // Time helpers
    function fmtTime(sec){ if (sec==null||!isFinite(sec)) return '0:00'; sec=Math.max(0,Math.floor(sec)); const h=Math.floor(sec/3600); const m=Math.floor((sec%3600)/60); const s=sec%60; return (h?`${h}:${String(m).padStart(2,'0')}`:`${m}`)+`:${String(s).padStart(2,'0')}`; }

    async function api(path, opts = {}){
      const res = await fetch(path, Object.assign({ headers: { 'Content-Type':'application/json', ...(S.token? { Authorization: 'Bearer '+S.token }:{}) } }, opts));
      const ct = res.headers.get('content-type') || ''; const text = await res.text(); let data;
      if (ct.includes('application/json')){ try{ data = JSON.parse(text); }catch{ throw { error:'Invalid JSON from server', raw:text }; } }
      else { throw { error: `Bad response (${res.status})`, body: text.slice(0,200) }; }
      if (!res.ok) throw data; return data;
    }

    // Brand click
    $('#brandLink').onclick = (e)=>{ e.preventDefault(); if (S.token) show('#view-apps'); else show('#view-login'); };

    // Tabs
    document.addEventListener('click', (e)=>{ const t=e.target.closest('.tab'); if(!t) return; document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active')); t.classList.add('active'); const k=t.dataset.tab; ['apps','users','invites'].forEach(name=> $('#tab-'+name)?.classList.toggle('hidden', name!==k)); });

    function renderQRTo(container, text){
      const box=$(container); if(!box) return;
      box.innerHTML="";
      const c=document.createElement("canvas");
      c.width=240; c.height=240;
      box.appendChild(c);
      QRCode.toCanvas(
        c,
        text,
        { width:240, margin:1, color:{ dark:'#000', light:'#fff' } },
        err=>{ if(err) console.error(err); }
      );
    }

    async function copyToClipboard(t){ try{ await navigator.clipboard.writeText(t); }catch{ const ta=document.createElement("textarea"); ta.value=t; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove(); } toast('Copied to clipboard'); }

    // Bootstrap token
    (function(){ const saved=localStorage.getItem('zm_token'); if(saved){ S.token=saved; api('/api/me').then(me=>{ S.me=me.user; clearUrlParams(); afterLogin(false); }).catch(()=>{ localStorage.removeItem('zm_token'); S.token=null; }); } })();

    // Login
    document.getElementById('loginForm').addEventListener('submit', async (e)=>{
      e.preventDefault(); const errBox=$('#loginError'); if(errBox) errBox.textContent='';
      const fd=new FormData(e.target); const remember=!!fd.get('remember'); const body={ username:fd.get('username'), password:fd.get('password'), remember };
      const otp=fd.get('otp'); if(otp) body.otp=otp;
      try{ const { token, user } = await api('/api/login',{ method:'POST', body: JSON.stringify(body) }); S.token=token; S.me=user; if(remember) localStorage.setItem('zm_token', token); else localStorage.removeItem('zm_token'); clearUrlParams(); afterLogin(); }
      catch(err){ if(err && err.error==='MFA code required'){ const w=$('#otpWrap'); if(w){ w.classList.remove('hidden'); w.querySelector('input[name="otp"]').focus(); } return; } (errBox||{}).textContent = (err && (err.error||err.message)) ? (err.error||err.message) : 'Login failed'; }
    });
    $('#btn-register').onclick = (e)=>{ e.preventDefault(); show('#view-register'); };
    $('#btn-forgot').onclick   = (e)=>{ e.preventDefault(); show('#view-forgot'); };

    // Register
    document.getElementById('registerForm').addEventListener('submit', async (e)=>{
      e.preventDefault();
      const fd=new FormData(e.target);
      const username=(fd.get('username')||'').trim();
      const password=fd.get('password');
      const email=(fd.get('email')||'').trim().toLowerCase();
      const body={ inviteCode:fd.get('inviteCode'), username, password, email, enableTotp:!!fd.get('enableTotp') };
      try{
        const { otpauth, secret } = await api('/api/register', { method:'POST', body: JSON.stringify(body) });
        if(otpauth){
          const sec = secret || (()=>{ try{ const u=new URL(otpauth); return new URLSearchParams(u.search).get('secret')||''; }catch{} return ''; })();
          e.target.classList.add('hidden');
          const wrap=$('#registerMfa');
          wrap.classList.remove('hidden');
          $('#otpauth').textContent = otpauth;
          $('#otpsecret').textContent = sec;
          $('#copyOtpauth').onclick = ()=>copyToClipboard(otpauth);
          $('#copySecret').onclick = ()=>copyToClipboard(sec);
          try{ renderQRTo('#qr', otpauth); }catch(err){ console.error(err); }
          const otpInput=$('#registerOtp');
          $('#registerVerify').onclick=async ()=>{
            const code=(otpInput.value||'').trim();
            if(!/^[0-9]{6}$/.test(code)) return toast('Enter the 6‑digit code from your app','err');
            try{
              const { token, user } = await api('/api/login',{ method:'POST', body: JSON.stringify({ username, password, otp: code }) });
              S.token=token; S.me=user; localStorage.setItem('zm_token', token);
              clearUrlParams();
              toast('Account created!');
              afterLogin();
            }catch(err){ toast(err.error||'Invalid or expired MFA code','err'); }
          };
        } else {
          toast('Account created! You can now sign in.');
          show('#view-login');
        }
      } catch(err){
        toast(err.error||'Registration failed','err');
      }
    });
    $('#btn-register-back').onclick = (e)=>{ e.preventDefault(); show('#view-login'); };

    // Forgot password
    document.getElementById('forgotForm').addEventListener('submit', async (e)=>{
      e.preventDefault(); const fd=new FormData(e.target);
      const email=(fd.get('email')||'').trim().toLowerCase();
      try{ await api('/api/forgot-password', { method:'POST', body: JSON.stringify({ email }) }); toast('If the email exists, a reset link has been sent.'); show('#view-login'); }
      catch(err){ toast(err.error||'Request failed','err'); }
    });
    $('#btn-forgot-back').onclick = (e)=>{ e.preventDefault(); show('#view-login'); };

    // Reset
    document.getElementById('resetForm').addEventListener('submit', async (e)=>{
      e.preventDefault(); const fd=new FormData(e.target);
      try{ await api('/api/reset', { method:'POST', body: JSON.stringify({ token: S.resetToken, newPassword: fd.get('password') }) }); toast('Password updated. Sign in.'); clearUrlParams(); show('#view-login'); }
      catch(err){ toast(err.error||'Reset failed','err'); }
    });
    $('#btn-reset-back').onclick = (e)=>{ e.preventDefault(); clearUrlParams(); show('#view-login'); };

    function initialsFor(u){ const fn=(u.firstName||'').trim(); const ln=(u.lastName||'').trim(); const un=(u.username||'').trim(); if(fn||ln){ return ((fn[0]||'')+(ln[0]||'')).toUpperCase() || (un[0]||'?').toUpperCase(); } return (un[0]||'?').toUpperCase(); }

    async function afterLogin(skipShow){
      const me = S.me || (await api('/api/me')).user; S.me = me;

      // Header user menu
      $('#navArea').classList.remove('hidden');
      const displayName = [S.me.firstName, S.me.lastName].filter(Boolean).join(' ') || S.me.username || '';
      $('#userName').textContent = displayName;
      const ua=$('#userAvatar'), ui=$('#userInitial');
      if (S.me.profileImage){ ua.src=S.me.profileImage; ua.classList.remove('hidden'); ui.classList.add('hidden'); }
      else { ui.textContent = initialsFor(S.me); ui.classList.remove('hidden'); ua.classList.add('hidden'); }
      if (S.me.role === 'admin') $('#ddAdmin').classList.remove('hidden');

      // Dropdown behavior
      const dd=$('#userMenu'); const btn=$('#userBtn');
      btn.onclick = (e)=>{ e.preventDefault(); dd.classList.toggle('open'); };
      document.addEventListener('click', (e)=>{ if (!dd.contains(e.target)) dd.classList.remove('open'); });
      $('#ddSettings').onclick = ()=>{ populateMeForm(); show('#view-settings'); dd.classList.remove('open'); };
      $('#ddAdmin').onclick = ()=>{ show('#view-admin'); dd.classList.remove('open'); };
      $('#ddLogout').onclick = async ()=>{ await api('/api/logout',{ method:'POST' }); localStorage.removeItem('zm_token'); location.reload(); };

      // Admin-only pref toggle visibility & state
      const prefRow=$('#prefNPRow'); const prefCb=$('#prefShowNP');
      if (S.me.role === 'admin'){ 
        prefRow.classList.remove('hidden');
        const showNP = (S.me.preferences && 'showNowPlaying' in S.me.preferences) ? !!S.me.preferences.showNowPlaying : true;
        prefCb.checked = showNP;
      } else { prefRow.classList.add('hidden'); }

      await loadApps();
      renderTiles();
      S.sabPage = 1; startSabPolling();
      startNowPlayingPolling();
      setupMfaUI();

      if (!skipShow) show('#view-apps');
    }

    // ----- Per-user app order helpers -----
    function applyAppOrder(apps, order){ if(!Array.isArray(order)||!order.length) return apps.slice(); const index=new Map(order.map((k,i)=>[k,i])); return apps.slice().sort((a,b)=>{ const ai=index.has(a.key)?index.get(a.key):Infinity; const bi=index.has(b.key)?index.get(b.key):Infinity; if(ai!==bi) return ai-bi; return (a.name||'').localeCompare(b.name||''); }); }
    async function saveAppOrder(order){ try{ await api('/api/me', { method:'PUT', body: JSON.stringify({ appOrder: order }) }); S.me.preferences=S.me.preferences||{}; S.me.preferences.appOrder=order.slice(); toast('App order saved'); }catch(e){ toast(e.error||'Failed to save order','err'); } }

    async function loadApps(){
      const { apps } = await api('/api/apps');
      const visible = (S.me.role === 'admin') ? apps : apps.filter(a => !a.hidden && !a._hidden);
      const order = (S.me.preferences && Array.isArray(S.me.preferences.appOrder)) ? S.me.preferences.appOrder : [];
      S.apps = applyAppOrder(visible, order);

      if (S.me.role === 'admin'){
        const wrap = $('#appsEditor');
        if (wrap){
          const renderEditor = (list)=>{
            wrap.className='apps-grid'; wrap.innerHTML='';
            for(const a of list){
              const row=document.createElement('div');
              row.className='app-card rounded-xl bg-white/5 border border-white/10 p-3';
              row.innerHTML = `
                <div class="flex items-center justify-between gap-3">
                  <div class="flex items-center gap-3 min-w-0">
                    <img id="logoPreview-${a.key}" src="${a.logo||''}" onerror="this.src='';this.classList.add('opacity-40');" class="h-10 w-10 object-contain rounded bg-white/10 p-1" alt="logo" />
                    <div class="min-w-0">
                      <div class="text-base font-semibold truncate">${a.name || '(unnamed app)'}</div>
                      <div class="text-xs text-neutral-300 truncate">${a.url || ''}</div>
                    </div>
                  </div>
                  <div class="flex items-center gap-2 shrink-0">
                    <label class="text-xs flex items-center gap-2 select-none">
                      <input data-k="hidden" data-key="${a.key}" type="checkbox" ${a.hidden?'checked':''}/>
                      <span>Hide</span>
                    </label>
                    <button class="px-2 py-1 bg-red-700/80 rounded text-xs" data-del="${a.key}">Delete</button>
                  </div>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-2 mt-3">
                  <div>
                    <label class="block text-xs mb-1">Name</label>
                    <input data-k="name" data-key="${a.key}" class="w-full px-2 py-1 rounded bg-black/30 border border-white/10" value="${a.name||''}">
                  </div>
                  <div>
                    <label class="block text-xs mb-1">App URL</label>
                    <input data-k="url" data-key="${a.key}" class="w-full px-2 py-1 rounded bg-black/30 border border-white/10" value="${a.url||''}">
                  </div>
                  <div>
                    <label class="block text-xs mb-1">Logo URL</label>
                    <input data-k="logo" data-key="${a.key}" class="w-full px-2 py-1 rounded bg-black/30 border border-white/10" value="${a.logo||''}">
                  </div>
                </div>`;
              wrap.appendChild(row);
            }

            // Live logo preview
            wrap.querySelectorAll('input[data-k="logo"]').forEach(inp=>{
              inp.addEventListener('input', (e)=>{ const key=e.target.getAttribute('data-key'); const img=document.getElementById('logoPreview-'+key); if(img) img.src=e.target.value.trim(); });
            });

            // Delete buttons (delegated)
            wrap.querySelectorAll('button[data-del]').forEach(btn=>{
              btn.onclick = ()=>{
                const id = btn.getAttribute('data-del');
                const nameInput = wrap.querySelector(`input[data-k="name"][data-key="${id}"]`);
                const appName = nameInput?.value?.trim() || '';
                Modal.open({
                  title: 'Delete App',
                  bodyHTML: 'Are you sure you want to delete "<span id="delAppName"></span>"?',
                  confirmText: 'Delete',
                  onOpen: ()=>{ $('#delAppName').textContent = appName; },
                  onConfirm: async ()=>{
                    try {
                      await api('/api/apps/'+encodeURIComponent(id), { method:'DELETE' });
                      toast('App deleted');
                      await loadApps();
                      renderTiles();
                    } catch(e){
                      toast(e.error||'Delete failed','err');
                    }
                  }
                });
              };
            });
          };

          renderEditor(apps);

          // Add App button
          $('#addApp').onclick = ()=>{ const newApp={ key: randKey(), name:'', url:'', logo:'', hidden:false }; apps.push(newApp); renderEditor(apps); toast('New app row added. Fill fields and click "Save Apps".'); };

          // Save Apps
          $('#saveApps').onclick = async ()=>{
            const edited = apps.map(a=>({ ...a }));
            document.querySelectorAll('#appsEditor [data-k]').forEach(el=>{
              const k=el.getAttribute('data-k'); const key=el.getAttribute('data-key'); const item=edited.find(x=>x.key===key); if(!item) return; if(k==='hidden') item.hidden=el.checked; else item[k]=el.value.trim();
            });
            for(const a of edited){ if(!a.name || !a.url){ toast('Each app needs at least a Name and URL','err'); return; } }
            await api('/api/apps',{ method:'PUT', body: JSON.stringify({ apps: edited }) }); toast('Apps saved'); await loadApps(); renderTiles();
          };
        }

        // SAB settings
        try{
          const sabCfg=await api('/api/sab');
          $('#sabBaseUrl').value=sabCfg.sab.baseUrl||'';
          $('#sabApiKey').value=sabCfg.sab.apiKey||'';
          const saveSabBtn=$('#saveSab');
          if(saveSabBtn){
            saveSabBtn.onclick=async ()=>{
              await api('/api/sab',{ method:'PUT', body: JSON.stringify({ baseUrl: $('#sabBaseUrl').value.trim(), apiKey: $('#sabApiKey').value.trim() }) });
              toast('SAB settings saved');
              $('#testSab')?.click();
            };
          }
          const testSabBtn=$('#testSab');
          if(testSabBtn){
            testSabBtn.onclick=async ()=>{
              try{ const r=await api('/api/sab/test'); if(r.ok) toast('SAB connection successful'); else toast(`SAB test failed (status ${r.status})`,'err'); }
              catch(e){ toast(e.error||'SAB test failed','err'); }
            };
          }
        }catch{}

        // Plex settings
        try{
          const plexCfg = await api('/api/plex');
          if (plexCfg && plexCfg.plex){ const tokInput=$('#plexToken'); const urlInput=$('#plexBaseUrl'); if(tokInput) tokInput.value = plexCfg.plex.token || ''; if(urlInput) urlInput.value = plexCfg.plex.baseUrl || ''; }
          const savePlexBtn=$('#savePlex');
          if (savePlexBtn){
            savePlexBtn.onclick = async ()=>{
              const token=($('#plexToken')?.value||'').trim();
              let baseUrl=($('#plexBaseUrl')?.value||'').trim();
              await api('/api/plex', { method:'PUT', body: JSON.stringify({ baseUrl, token }) });
              toast('Plex settings saved');
              $('#testPlex')?.click();
            };
          }
          const testBtn=$('#testPlex');
          if (testBtn){
            testBtn.onclick = async ()=>{
              try{ const result=await api('/api/plex/test'); if(result.ok) toast('Plex connection successful'); else toast(`Plex test failed (status ${result.status})`,'err'); }
              catch(e){ toast(e.error||'Plex test failed','err'); }
            };
          }
        }catch{}

        // SMTP settings
        try{
          const smtpCfg = await api('/api/smtp');
          $('#smtpHost').value = smtpCfg.smtp.host || '';
          $('#smtpPort').value = smtpCfg.smtp.port || '';
          $('#smtpUser').value = smtpCfg.smtp.user || '';
          $('#smtpFrom').value = smtpCfg.smtp.from || '';
          $('#smtpSecure').checked = smtpCfg.smtp.secure || false;
          const saveBtn = $('#saveSmtp');
          if(saveBtn){ saveBtn.onclick = async ()=>{
            await api('/api/smtp',{ method:'PUT', body: JSON.stringify({ host: $('#smtpHost').value.trim(), port: Number($('#smtpPort').value.trim()||'587'), user: $('#smtpUser').value.trim(), pass: $('#smtpPass').value, from: $('#smtpFrom').value.trim(), secure: $('#smtpSecure').checked }) });
            toast('SMTP settings saved');
          }; }
          const testBtn = $('#testSmtp');
          if(testBtn){ testBtn.onclick = async ()=>{ try{ const r=await api('/api/smtp/test'); if(r.ok) toast('Test email sent'); else toast('SMTP test failed','err'); }catch(e){ toast(e.error||'SMTP test failed','err'); } }; }
        }catch{}

        await renderUsers();
        await renderInvites();
      }
    }

    function randKey(){ return Math.random().toString(16).slice(2,10); }

    async function renderUsers(){
      const ul = $('#usersList'); if (!ul) return;
      const usersRes = await api('/api/users');
      const adminCount = usersRes.users.filter(u=>u.role==='admin').length;

      ul.innerHTML='';
      for(const u of usersRes.users){
        const row=document.createElement('div'); row.className='bg-white/5 border border-white/10 rounded p-3';
        const initials = ((u.firstName||'')[0]||'') + ((u.lastName||'')[0]||'');
        const avatarHTML = u.profileImage
          ? `<img src="${u.profileImage}" class="h-8 w-8 rounded-full object-cover mr-2" alt="avatar" />`
          : `<span class="mr-2 inline-flex items-center justify-center h-8 w-8 rounded-full text-sm font-semibold" style="background:linear-gradient(135deg, rgba(253,81,58,.9), rgba(44,83,216,.85));">${(initials||u.username||'?').slice(0,2).toUpperCase()}</span>`;

        const displayName = [u.firstName,u.lastName].filter(Boolean).join(' ') || u.username;
        row.innerHTML = `
          <div class="flex items-center justify-between">
            <div class="text-sm flex items-center">
              ${avatarHTML}
              <span class="font-semibold truncate max-w-[40vw]">${displayName}</span>
              <span class="text-neutral-300 ml-2">(${u.role})</span>
            </div>
            <div class="flex gap-2">
              <button type="button" data-act="promote" class="px-2 py-1 bg-white/10 rounded">Toggle Admin</button>
              <button type="button" data-act="delete" class="px-2 py-1 bg-red-700/80 rounded">Delete</button>
            </div>
          </div>`;

        const promoteBtn = row.querySelector('[data-act="promote"]');
        promoteBtn.disabled = adminCount <= 1 && u.role === 'admin';
        promoteBtn.classList.toggle('opacity-50', promoteBtn.disabled);
        promoteBtn.onclick = async ()=>{ const newRole = u.role==='admin'?'user':'admin'; try{ await api(`/api/users/${u.username}`, { method:'PATCH', body: JSON.stringify({ role:newRole })}); toast('Role updated'); await renderUsers(); }catch(e){ toast(e.error||'Update failed','err'); } };
        row.querySelector('[data-act="delete"]').onclick = async ()=>{ if(!confirm(`Delete user ${u.username}? This cannot be undone.`)) return; try{ await api(`/api/users/${encodeURIComponent(u.username)}`, { method:'DELETE' }); toast('User deleted'); await renderUsers(); }catch(e){ toast(e.error||'Delete failed','err'); } };

        ul.appendChild(row);
      }
    }

    async function renderInvites(){
      const box=$('#invList'); if(!box) return;
      const r=await api('/api/invites');
      const rows=r.invites.sort((a,b)=> (b.createdAt||'').localeCompare(a.createdAt||''))
        .map(i=>`<tr class="border-t border-white/10"><td class="py-2 pr-2 mono">${i.code}</td><td>${i.role}</td><td>${i.createdBy||''}</td><td>${i.createdAt||''}</td><td>${i.expiresAt||'never'}</td><td>${i.usedBy||''}</td><td>${i.usedAt||''}</td><td class="text-right"><button data-code="${i.code}" class="px-2 py-1 bg-white/10 rounded copy">Copy</button><button data-code="${i.code}" class="ml-2 px-2 py-1 bg-red-700/80 rounded del">Delete</button></td></tr>`).join('');
      box.innerHTML = `<table class="w-full text-sm"><thead class="text-neutral-300"><tr><th class="text-left py-2">Code</th><th class="text-left">Role</th><th class="text-left">Created by</th><th class="text-left">Created at</th><th class="text-left">Expires</th><th class="text-left">Used by</th><th class="text-left">Used at</th><th class="text-right">Actions</th></tr></thead><tbody>${rows || `<tr><td class="py-2 text-neutral-300" colspan="8">No invites</td></tr>`}</tbody></table>`;
      box.querySelectorAll('.copy').forEach(b=> b.onclick = ()=> copyToClipboard(b.dataset.code));
      box.querySelectorAll('.del').forEach(b=> b.onclick = async ()=>{ if(!confirm(`Delete invite ${b.dataset.code}?`)) return; await api(`/api/invites/${b.dataset.code}`, { method:'DELETE' }); toast('Invite deleted'); await renderInvites(); });
      $('#invCreate').onclick = async ()=>{
        const role=$('#invRole').value||'user';
        const expiresAt=(()=>{ const p=$('#invPreset').value; if(p==='never') return null; const d=new Date(); if(p==='1d') d.setDate(d.getDate()+1); if(p==='7d') d.setDate(d.getDate()+7); if(p==='1m') d.setMonth(d.getMonth()+1); if(p==='6m') d.setMonth(d.getMonth()+6); return d.toISOString(); })();
        const email=($('#invEmail')?.value||'').trim();
        const r=await api('/api/invites',{ method:'POST', body: JSON.stringify({ role, expiresAt, email: email||undefined })});
        toast(`Invite created: ${r.code}${r.emailSent ? ' (email sent)' : ''}`);
        if($('#invEmail')) $('#invEmail').value='';
        await renderInvites();
      };
      $('#eraseUsedInvites').onclick = async ()=>{ if(!confirm('Erase USED invites from history? This cannot be undone.')) return; await api('/api/invites/erase-history',{ method:'POST', body: JSON.stringify({ includeUnused:false }) }); toast('Used invite history cleared'); await renderInvites(); };
      $('#eraseAllInvites').onclick = async ()=>{ if(!confirm('Erase ALL invites? This cannot be undone.')) return; await api('/api/invites/erase-history',{ method:'POST', body: JSON.stringify({ includeUnused:true }) }); toast('All invites cleared'); await renderInvites(); };
    }

    // Tiles (drag & drop + persist)
    function renderTiles(){
      const grid=$('#tiles'); if(!grid) return; grid.innerHTML='';
      for(const a of S.apps){
        const card=document.createElement('a'); card.href=a.url; card.target='_blank'; card.className='tile glass rounded-2xl p-4 flex items-center gap-4 no-underline text-inherit'; card.setAttribute('draggable','true'); card.dataset.key=a.key;
        card.innerHTML = `<img src="${a.logo}" class="h-10 w-10 object-contain" alt="${a.name}"><div><div class="font-semibold">${a.name}</div><div class="text-xs text-neutral-300">${a.url}</div></div>`;
        card.addEventListener('dragstart',(e)=>{ e.dataTransfer.setData('text/app-key', a.key); e.dataTransfer.effectAllowed='move'; card.classList.add('ring-2','ring-white/30'); });
        card.addEventListener('dragend',()=>{ card.classList.remove('ring-2','ring-white/30'); });
        card.addEventListener('dragover',(e)=>{ e.preventDefault(); e.dataTransfer.dropEffect='move'; });
        card.addEventListener('drop', async (e)=>{ e.preventDefault(); const draggedKey=e.dataTransfer.getData('text/app-key'); const targetKey=card.dataset.key; if(!draggedKey||draggedKey===targetKey) return; const keys=S.apps.map(x=>x.key); const from=keys.indexOf(draggedKey); const to=keys.indexOf(targetKey); if(from<0||to<0) return; const moved=S.apps.splice(from,1)[0]; S.apps.splice(to,0,moved); renderTiles(); await saveAppOrder(S.apps.map(x=>x.key)); });
        grid.appendChild(card);
      }
      if(!localStorage.getItem('zm_dnd_hint')){ const hint=document.createElement('div'); hint.className='text-xs text-neutral-300 mt-2'; hint.textContent='Tip: Drag tiles to rearrange. Your layout is saved to your account.'; grid.parentElement.appendChild(hint); localStorage.setItem('zm_dnd_hint','1'); }
    }

    // SAB queue
    async function fetchSab(page){
      try{ const r=await api(`/api/sab/queue?page=${page}`); S.sabPage=r.page; S.sabPages=r.pages||1; const tbody=$('#sabRows'); const rows=(r.slots||[]).map(s=>{ const pct=Math.max(0,Math.min(100,Number(s.percentage||0))); return `<tr class="border-t border-white/10"><td class="py-2 pr-2">${s.filename}</td><td>${s.status}</td><td class="w-56"><div class="relative bar h-5"><span style="width:${pct}%; border-radius:9999px;"></span><div class="absolute inset-0 flex items-center justify-center text-[11px] font-semibold text-white drop-shadow">${pct}%</div></div></td><td class="text-right">${s.timeleft||''}</td></tr>`; }).join(''); tbody.innerHTML = rows || `<tr class="border-t border-white/10"><td class="py-2 pr-2 text-neutral-300">–</td><td class="text-neutral-300">–</td><td class="w-56"><div class="relative bar h-5"><span style="width:0%; border-radius:9999px;"></span><div class="absolute inset-0 flex items-center justify-center text-[11px] font-semibold text-white drop-shadow">0%</div></div></td><td class="text-right text-neutral-300">–</td></tr>`; const sp=r.speedText||(r.speed?((r.speed>=1024?(r.speed/1024).toFixed(2)+' MB/s':r.speed.toFixed(0)+' KB/s')):'0 KB/s'); $('#sabStatus').textContent=`Speed: ${sp}${r.paused?' (paused)':''}`; const pageText=$('#sabPage'); const prevBtn=$('#sabPrev'); const nextBtn=$('#sabNext'); if(S.sabPages>1){ pageText.textContent=`Page ${S.sabPage} / ${S.sabPages}`; prevBtn.disabled=S.sabPage<=1; nextBtn.disabled=S.sabPage>=S.sabPages; prevBtn.classList.toggle('opacity-50', prevBtn.disabled); nextBtn.classList.toggle('opacity-50', nextBtn.disabled); pageText.parentElement.classList.remove('hidden'); } else { pageText.parentElement.classList.add('hidden'); } }
      catch{ $('#sabRows').innerHTML = `<tr class="border-t border-white/10"><td class="py-2 pr-2 text-neutral-300">–</td><td class="text-neutral-300">–</td><td class="w-56"><div class="relative bar h-5"><span style="width:0%; border-radius:9999px;"></span><div class="absolute inset-0 flex items-center justify-center text-[11px] font-semibold text-white drop-shadow">0%</div></div></td><td class="text-right text-neutral-300">–</td></tr>`; $('#sabStatus').textContent=''; const pageWrap=$('#sabPage')?.parentElement; if(pageWrap) pageWrap.classList.add('hidden'); }
    }
    function startSabPolling(){ clearInterval(S.sabTimer); if(typeof S.sabPage!=='number'||S.sabPage<1) S.sabPage=1; fetchSab(S.sabPage); S.sabTimer=setInterval(()=>fetchSab(S.sabPage), 3000); $('#sabPrev').onclick=()=>{ if(S.sabPage>1){ S.sabPage--; fetchSab(S.sabPage);} }; $('#sabNext').onclick=()=>{ if(S.sabPages && S.sabPage<S.sabPages){ S.sabPage++; fetchSab(S.sabPage);} }; }

    // NOW PLAYING (Plex)
    function shouldShowNowPlaying(){ if(!S.me||S.me.role!=='admin') return false; const pref=S.me.preferences||{}; return (pref.showNowPlaying!==false); }
    async function fetchNowPlaying(){ try{ const r=await api('/api/now-playing'); const sessions=Array.isArray(r)?r:(r.sessions||[]); const wrap=$('#nowPlayingWrap'); const box=$('#nowPlaying'); const meta=$('#npMeta'); if(!shouldShowNowPlaying()){ wrap.classList.add('hidden'); return; } wrap.classList.remove('hidden'); window.__npSampledAt=Date.now(); meta.textContent = sessions.length ? `${sessions.length} active session${sessions.length>1?'s':''}` : ''; if(!sessions.length){ box.innerHTML = `<div class="text-sm text-neutral-300">No one is watching right now.</div>`; return; } box.innerHTML = sessions.map(s=>{ const viewOffsetMs=(typeof s.viewOffsetMs==='number')?s.viewOffsetMs:(typeof s.viewOffset==='number'?s.viewOffset:null); const durationMs=(typeof s.durationMs==='number')?s.durationMs:(typeof s.duration==='number'?s.duration:null); const posSec=viewOffsetMs!=null?viewOffsetMs/1000:null; const durSec=durationMs!=null?durationMs/1000:null; const pctFromTime=(posSec!=null && durSec>0)?Math.max(0,Math.min(100,(posSec/durSec)*100)):null; const pct=pctFromTime!=null?pctFromTime:Math.max(0,Math.min(100,Number(s.progress||0))); const u=s.user||'Unknown'; const t=s.title||''; const q=s.quality?` • ${s.quality}`:''; const state=s.state==='paused'?' (paused)':''; const timeText=(posSec!=null && durSec>0)?`${fmtTime(posSec)} / ${fmtTime(durSec)}`:`${pct.toFixed(0)}%`; return `<div class="flex items-center justify-between py-2 border-t border-white/10" data-npid="${(s.id||t+u).toString().replace(/"/g,'')}" data-duration="${durationMs||''}" data-offset="${viewOffsetMs||''}" data-state="${s.state||''}"><div class="min-w-0 pr-4"><div class="font-semibold truncate">${u}${state}</div><div class="text-xs text-neutral-300 truncate">${t}${q}${s.device?` • ${s.device}`:''}</div></div><div class="w-56"><div class="relative bar h-4"><span style="width:${pct}%"></span><div class="absolute inset-0 flex items-center justify-center text-[10px]" data-role="np-time">${timeText}</div></div></div></div>`; }).join(''); startNowPlayingClock(); }catch(e){ const wrap=$('#nowPlayingWrap'); if(shouldShowNowPlaying()){ wrap.classList.remove('hidden'); $('#nowPlaying').innerHTML = `<div class="text-sm text-red-300">Now Playing unavailable.</div>`; $('#npMeta').textContent=''; } else { wrap.classList.add('hidden'); } } }
    function startNowPlayingClock(){ try{ if(S.npClock){ clearInterval(S.npClock); } S.npClock=setInterval(()=>{ const sampledAt=window.__npSampledAt||Date.now(); const delta=Date.now()-sampledAt; document.querySelectorAll('#nowPlaying [data-duration]').forEach(row=>{ const duration=Number(row.getAttribute('data-duration')||0); let offset=Number(row.getAttribute('data-offset')||0); const state=(row.getAttribute('data-state')||'').toLowerCase(); if(!duration||duration<=0) return; if(state!=='paused') offset=offset+delta; const posSec=Math.max(0,Math.min(duration,offset))/1000; const durSec=duration/1000; const pct=Math.max(0,Math.min(100,(posSec/durSec)*100)); const bar=row.querySelector('.bar span'); if(bar) bar.style.width=pct+'%'; const lab=row.querySelector('[data-role="np-time"]'); if(lab) lab.textContent=`${fmtTime(posSec)} / ${fmtTime(durSec)}`; }); }, 1000); }catch{} }
    function startNowPlayingPolling(){ clearInterval(S.npTimer); if(!shouldShowNowPlaying()){ $('#nowPlayingWrap').classList.add('hidden'); return; } fetchNowPlaying(); S.npTimer=setInterval(fetchNowPlaying, 5000); }

    function hasMfaEnabled(){ return !!(S.me && S.me.totpSecret); }
    async function setupMfaUI(){
      const box=$('#mfaBox'); if(!box) return;
      const enabled=hasMfaEnabled();
      $('#mfaStatus').textContent = enabled ? 'Enabled' : 'Disabled';
      $('#mfaStart').classList.toggle('hidden', enabled);
      $('#mfaDisable').classList.toggle('hidden', !enabled);
      $('#mfaSetup').classList.add('hidden');
      $('#mfaStart').onclick = async ()=>{
        try{
          const r=await api('/api/me',{ method:'PUT', body: JSON.stringify({ mfaAction:'start' }) });
          if(r.otpauth){
            const sec = r.secret || (()=>{ try{ const u=new URL(r.otpauth); return new URLSearchParams(u.search).get('secret')||''; }catch{} return ''; })();
            $('#mfaSetup').classList.remove('hidden');
            $('#mfaOtpauth').textContent = r.otpauth;
            $('#mfaSecret').textContent = sec;
            $('#mfaCopyLink').onclick = ()=>copyToClipboard(r.otpauth);
            $('#mfaCopySecret').onclick = ()=>copyToClipboard(sec);
            try{ renderQRTo('#mfaQr', r.otpauth); }catch(err){ console.error(err); }
            S.me = r.user || S.me;
          }
        }catch(e){ toast(e.error||'Failed to start setup','err'); }
      };
      $('#mfaDisable').onclick = async ()=>{
        if(!confirm('Disable authenticator app for this account?')) return;
        try{
          const r=await api('/api/me',{ method:'PUT', body: JSON.stringify({ mfaAction:'disable' }) });
          S.me=r.user; toast('MFA disabled'); setupMfaUI();
        }catch(e){ toast(e.error||'Failed to disable','err'); }
      };
      $('#mfaVerify').onclick = async ()=>{
        const code=$('#mfaCode').value.trim();
        if(!/^[0-9]{6}$/.test(code)){
          toast('Enter the 6‑digit code from your app','err');
          return;
        }
        try{
          const r=await api('/api/me',{ method:'PUT', body: JSON.stringify({ mfaAction:'verify', code }) });
          S.me=r.user; toast('MFA enabled and saved'); setupMfaUI();
        }catch(e){ toast(e.error||'Invalid or expired MFA code','err'); }
      };
    }

    // Settings (profile + picture + prefs)
    function populateMeForm(){ const f=document.getElementById('meForm'); if(!f||!S.me) return; f.username.value=''; f.password.value=''; f.firstName.value = S.me.firstName || ''; f.lastName.value = S.me.lastName || ''; }
    document.getElementById('meForm').addEventListener('submit', async (e)=>{
      e.preventDefault(); const fd=new FormData(e.target);
      const body = { username: fd.get('username')||undefined, password: fd.get('password')||undefined, firstName: (fd.get('firstName')||'').trim(), lastName: (fd.get('lastName')||'').trim() };
      const cb=$('#prefShowNP'); if(cb && S.me && S.me.role==='admin'){ body.preferences = Object.assign({}, S.me.preferences||{}, { showNowPlaying: !!cb.checked }); }
      if($('#pfp') && $('#pfp').files[0]){ const file=$('#pfp').files[0]; body.profileImage = await new Promise((res,rej)=>{ const r=new FileReader(); r.onload=()=>res(r.result); r.onerror=rej; r.readAsDataURL(file); }); }
      try{ const r=await api('/api/me',{ method:'PUT', body: JSON.stringify(body) }); S.me=r.user; toast('Saved.'); const displayName=[S.me.firstName,S.me.lastName].filter(Boolean).join(' ')||S.me.username; $('#userName').textContent = displayName; const ua=$('#userAvatar'), ui=$('#userInitial'); if(S.me.profileImage){ ua.src=S.me.profileImage; ua.classList.remove('hidden'); ui.classList.add('hidden'); } else { ui.textContent = initialsFor(S.me); ui.classList.remove('hidden'); ua.classList.add('hidden'); } }
      catch(err){ toast(err.error||'Save failed','err'); }
    });
    $('#btn-admin-close').onclick = ()=> show('#view-apps');
    $('#btn-settings-close').onclick = ()=> show('#view-apps');

    // SAB controls
    function startSab(){ startSabPolling(); }

    // Init
    document.getElementById('year').textContent = new Date().getFullYear();
  