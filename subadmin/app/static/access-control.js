/* People & Access > Access Control. Hub page permissions, folded in from the standalone
   corpit.nrpi.local/access-admin.html (and the older /saas-admin.html) on 2026-10-12.

   This file only draws and submits. Every read and write goes to the hub's own RBAC API on
   this origin (/api/rbac/*, plus the AD re-check at /api/saas-admin/users/<email>/invalidate),
   which nginx exposes here through an exact, method-limited allow-list. The hub decides who may
   do what: every route used here is behind its requireSuperAdmin. The console only hides the tab
   from people who are not platform owners; it never grants anything itself.

   The resolution helpers mirror rbac-middleware.computeEffectiveLevel, exactly as the old page
   did, so a cell shows what the hub will actually enforce. */
(function(){
  'use strict';
  var root = document.querySelector('[data-access-control]');
  if(!root) return;
  var panel = root.closest('[data-tabpanel]');

  var API = '/api/rbac';
  var LEVELS = ['none', 'read', 'admin'];
  var RANK = { none: 0, read: 1, admin: 2 };
  var LOOKUP_ACTIONS = { view_as_lookup: 1, superadmin_access: 1, user_activity_lookup: 1 };
  var PORTAL_KEYS = { accessportal: 1, 'approver-portal': 1 };
  var PORTAL_LINK = '<a href="https://accessportal.nrpi.local/approver.html">Manage in Approval Access</a>';

  var $ = function(sel){ return root.querySelector(sel); };
  var has = function(o, k){ return Object.prototype.hasOwnProperty.call(o, k); };
  var esc = function(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };

  var S = {
    pages: [], roles: [], users: [],
    roleDirty: {},      // role_key -> { default_access?, grants: {page: level|null} }
    person: null,       // { email, display_name, roles[], override{}, effective{}, isSuperAdmin }
    personDirty: null,  // page -> level | null  (null === back to Default)
    role: null, editing: false, personQuery: '', personOnly: false, audit: [], personRequest: 0, view: 'roles', loaded: false, loading: false, fatal: false, saving: false,
  };

  /* ---------- plumbing ---------- */
  function api(method, path, body, base){
    return fetch((base || API) + path, {
      method: method,
      credentials: 'same-origin',
      headers: body ? { 'Content-Type': 'application/json', 'Accept': 'application/json' } : { 'Accept': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    }).then(function(r){
      var ct = r.headers.get('Content-Type') || '';
      if(ct.indexOf('application/json') < 0){
        // The gate answers an expired session with its HTML sign-in page, not JSON.
        var e = new Error(r.status === 403 ? 'The sign-in gate refused this request.'
          : 'Your console session has ended. Reload the page to sign in again.');
        e.status = r.status; e.fatal = true; throw e;
      }
      return r.json().then(function(j){
        if(!r.ok){
          var e = new Error((j && (j.error || j.code)) || ('HTTP ' + r.status));
          e.status = r.status;
          if(r.status === 401 || r.status === 403) e.fatal = true;
          throw e;
        }
        return j;
      });
    });
  }
  var msgT = null;
  function msg(text, kind){
    var m = $('[data-ac-msg]');
    m.textContent = text || '';
    m.className = 'ac-msg' + (kind ? ' is-' + kind : '');
    clearTimeout(msgT);
    if(text && kind === 'ok') msgT = setTimeout(function(){ m.textContent = ''; m.className = 'ac-msg'; }, 4000);
  }
  function deniedHtml(e){
    if(e && (e.status === 401 || e.status === 403) && !/session has ended|gate refused/.test(e.message)){
      return '<b>The hub refused this.</b>Hub page permissions are super-admin only in the hub itself ' +
             '(<span class="mono">SaaS-ITH-SA</span> or <span class="mono">RBAC_SUPERADMINS</span>). ' +
             'Being a platform owner here does not grant it. The hub said: ' + esc(e.message);
    }
    return '<b>Could not load hub access data.</b>' + esc(e ? e.message : 'unknown error');
  }

  /* ---------- resolution, mirroring rbac-middleware.computeEffectiveLevel ---------- */
  function roleGrant(role, pageKey){
    var d = S.roleDirty[role.role_key];
    if(d && d.grants && has(d.grants, pageKey)) return d.grants[pageKey];
    var g = role.grantMap[pageKey];
    return g === undefined ? null : g;                      // null === inherit the default
  }
  function roleDefault(role){
    var d = S.roleDirty[role.role_key];
    return (d && d.default_access !== undefined) ? d.default_access : role.default_access;
  }
  // What the cell would resolve to if set back to Default (NOT roleEffective, which honours
  // the explicit grant and would make a cell set to read announce "Default (read)").
  function roleFallback(role, page){
    if(page.hard_excluded) return 'none';
    var lvl = roleDefault(role);
    if(page.access_policy === 'authenticated' && RANK[lvl] < RANK.read) lvl = 'read';
    return lvl;
  }
  function roleEffective(role, page){
    if(page.hard_excluded) return 'none';
    var g = roleGrant(role, page.page_key);
    var lvl = g === null ? roleDefault(role) : g;
    if(page.access_policy === 'authenticated' && RANK[lvl] < RANK.read) lvl = 'read';
    return lvl;
  }
  function rolesEffective(roleKeys, page){                  // most-permissive merge across roles
    if(page.hard_excluded) return 'none';
    var lvl = 'none';
    roleKeys.forEach(function(rk){
      var role = S.roles.find(function(r){ return r.role_key === rk; });
      if(!role) return;
      var e = roleEffective(role, page);
      if(RANK[e] > RANK[lvl]) lvl = e;
    });
    if(page.access_policy === 'authenticated' && RANK[lvl] < RANK.read) lvl = 'read';
    return lvl;
  }
  var LVL_PILL = { admin: 'p-info', read: 'p-good', none: 'p-mut' };
  function tag(lvl){ return '<span class="pill ' + (LVL_PILL[lvl] || 'p-mut') + '">' + esc(levelName(lvl)) + '</span>'; }

  // rbac_user_roles also carries @local test accounts and rows with no user record, so the
  // extras are named rather than folded into the people count.
  function memberLine(r){
    var n = r.user_count, out = n + (n === 1 ? ' person' : ' people');
    var extras = Math.max(0, r.member_rows - n), why = [];
    if(r.test_accounts) why.push(r.test_accounts + ' @local test');
    if(r.orphan_rows) why.push(r.orphan_rows + ' with no user record');
    if(r.inactive_users) why.push(r.inactive_users + ' inactive');
    if(extras){
      out += ' <span class="ac-xtra" title="' + extras + ' more row' + (extras === 1 ? '' : 's') +
             ' in this role, not counted as people' +
             (why.length ? '. They are: ' + esc(why.join(', ')) + '. One row can fall into two of those.' : '') +
             '">+' + extras + '</span>';
    }
    if(r.bypasses_matrix){
      out += ' <span class="ac-xtra" title="Anyone listed in the RBAC_SUPERADMINS environment variable is also a ' +
             'super admin without holding this role, and does not appear in this count.">+env</span>';
    }
    return out;
  }

  /* ---------- matrix ---------- */
  function visiblePages(){
    var q = $('#ac-m-search').value.trim().toLowerCase();
    var inactive = $('#ac-m-inactive').checked, onlyset = $('#ac-m-onlyset').checked;
    return S.pages.filter(function(p){
      if(!inactive && p.status !== 'active') return false;
      if(q && !(p.page_key.toLowerCase().indexOf(q) >= 0 ||
                String(p.display_name || '').toLowerCase().indexOf(q) >= 0)) return false;
      if(onlyset && !S.roles.some(function(r){ return roleGrant(r, p.page_key) !== null; })) return false;
      return true;
    });
  }
  function levelSelect(cls, current, defaultLabel, attrs){
    var h = '<select class="' + cls + '" ' + attrs + '><option value="">' + esc(defaultLabel) + '</option>';
    LEVELS.forEach(function(l){
      h += '<option value="' + l + '"' + (current === l ? ' selected' : '') + '>' + levelName(l) + '</option>';
    });
    return h + '</select>';
  }
  function renderComparison(){
    var pages = visiblePages(), t = $('#ac-matrix');
    var h = '<colgroup><col class="ac-pagecol">' + S.roles.map(function(){ return '<col class="ac-rolecol">'; }).join('') + '</colgroup>';
    h += '<thead><tr><th class="ac-pin"><div>Page</div><small>' + pages.length + ' shown</small></th>';
    S.roles.forEach(function(r){
      var dd = roleDefault(r);
      var changed = S.roleDirty[r.role_key] && S.roleDirty[r.role_key].default_access !== undefined;
      h += '<th class="ac-rolehead"><div class="ac-rn">' + esc(r.display_name || r.role_key) + '</div>' +
           '<div class="ac-rm">' + memberLine(r) + '</div>' +
           (r.bypasses_matrix
             ? '<div class="ac-bypass" title="rbac-middleware resolves super admins before it reads these tables">always admin</div>'
             : '<select class="ac-lvl ac-def' + (changed ? ' is-dirty' : '') + '" data-roledef="' + esc(r.role_key) + '" ' +
               'aria-label="Default for ' + esc(r.display_name || r.role_key) + '" title="Applies to every page with no explicit setting below">' +
               LEVELS.map(function(l){ return '<option value="' + l + '"' + (dd === l ? ' selected' : '') + '>' + levelName(l) + '</option>'; }).join('') +
               '</select>') +
           '</th>';
    });
    h += '</tr></thead><tbody>';
    if(!pages.length) h += '<tr><td colspan="' + (S.roles.length + 1) + '"><div class="empty"><b>No pages match that filter.</b></div></td></tr>';
    pages.forEach(function(p){
      h += '<tr><td class="ac-pin"><div class="ac-pk">' + esc(p.display_name || p.page_key);
      if(p.status !== 'active') h += ' <span class="pill p-mut">' + esc(p.status) + '</span>';
      if(p.hard_excluded) h += ' <span class="pill p-info">locked</span>';
      if(p.access_policy === 'authenticated') h += ' <span class="pill p-mut">all signed in</span>';
      h += '<small>' + esc(p.page_key) + '</small></div></td>';
      if(PORTAL_KEYS[p.page_key]){
        h += '<td colspan="' + S.roles.length + '">' + PORTAL_LINK + '<div class="hint">Department policies, person exceptions and portal entry are managed inside the approval app. Public requester forms do not use this matrix.</div></td></tr>';
        return;
      }
      if(p.hard_excluded){
        h += '<td colspan="' + S.roles.length + '" class="ac-locked"><span class="pill p-info">super admins only</span> locked in code. No role grant or personal exception can open this page.</td></tr>';
        return;
      }
      S.roles.forEach(function(r){
        if(r.bypasses_matrix){ h += '<td class="ac-sa">' + (p.access_policy === 'authenticated' ? 'read' : 'admin') + '</td>'; return; }
        var g = roleGrant(r, p.page_key), eff = roleFallback(r, p), d = S.roleDirty[r.role_key];
        var isDirty = d && d.grants && has(d.grants, p.page_key);
        var cls = 'ac-lvl' + (g === 'none' ? ' is-deny' : g ? ' is-set' : '') + (isDirty ? ' is-dirty' : '');
        h += '<td>' + levelSelect(cls, g, 'Inherited · ' + levelName(eff),
               'data-role="' + esc(r.role_key) + '" data-page="' + esc(p.page_key) + '" aria-label="' +
               esc((p.display_name || p.page_key) + ' for ' + (r.display_name || r.role_key)) + '"') + '</td>';
      });
      h += '</tr>';
    });
    t.innerHTML = h + '</tbody>';
  }


  /* Role-first workspace. Resolution and all writes remain owned by the existing Hub API. */
  function levelName(l){ return {none:'No access', read:'Read', admin:'Admin'}[l] || l; }
  function roleName(k){ var r=S.roles.find(function(x){return x.role_key===k;});return r ? (r.display_name || k) : k; }
  var motion = window.matchMedia('(prefers-reduced-motion: reduce)'), runningMotion = null;
  function cancelMotion(){ if(runningMotion){runningMotion.cancel();runningMotion=null;} }
  function enter(el, pointer){
    cancelMotion();
    if(!pointer || motion.matches || !el || !el.animate || document.hidden) return;
    runningMotion=el.animate([{opacity:.4,transform:'translateY(4px)'},{opacity:1,transform:'translateY(0)'}],{duration:200,easing:'cubic-bezier(0.23,1,0.32,1)'});
  }
  if(motion.addEventListener)motion.addEventListener('change',cancelMotion);
  document.addEventListener('visibilitychange',function(){if(document.hidden)cancelMotion();});
  window.addEventListener('console-route',cancelMotion);
  root.addEventListener('pointerdown',function(){root.classList.add('ac-pointer');});
  root.addEventListener('keydown',function(){root.classList.remove('ac-pointer');cancelMotion();});
  function focusKey(el){
    if(!el || !root.contains(el))return null;
    var keys=['data-roledef','data-role','data-page','data-uspage','data-ac-role','data-email'];
    return {id:el.id,attrs:keys.filter(function(k){return el.hasAttribute(k);}).map(function(k){return [k,el.getAttribute(k)];}),start:el.selectionStart,end:el.selectionEnd};
  }
  function restoreFocus(k){
    if(!k)return;
    var el=k.id ? root.querySelector('#'+k.id) : Array.from(root.querySelectorAll('button,select,input')).find(function(e){return !e.closest('[hidden]') && k.attrs.length && k.attrs.every(function(a){return e.getAttribute(a[0])===a[1];});});
    if(el && !el.disabled){el.focus({preventScroll:true});if(k.start!==null && k.start!==undefined && el.setSelectionRange)try{el.setSelectionRange(k.start,k.end);}catch(e){}}
  }
  var rememberedDisabled=new Map();
  function syncControls(){
    root.querySelectorAll('[data-roledef],[data-role][data-page],[data-uspage]').forEach(function(el){el.disabled=!S.editing || S.saving;});
    $('[data-ac-edit]').disabled=!S.loaded || S.saving || S.fatal;
    $('[data-ac-edit]').textContent=S.editing?'Finish editing':'Edit permissions';
    root.classList.toggle('is-editing',S.editing);
    if(S.saving){
      root.querySelectorAll('button,input,select').forEach(function(el){if(!rememberedDisabled.has(el))rememberedDisabled.set(el,el.disabled);el.disabled=true;});
    } else {
      rememberedDisabled.forEach(function(disabled,el){if(el.isConnected)el.disabled=disabled;});rememberedDisabled.clear();
      root.querySelectorAll('[data-roledef],[data-role][data-page],[data-uspage]').forEach(function(el){el.disabled=!S.editing;});
      $('[data-ac-save]').disabled=!$('#ac-confirm').checked;
    }
    root.setAttribute('aria-busy',String(S.saving));
  }
  function invalidateReview(){
    $('[data-ac-review]').hidden=true;$('#ac-confirm').checked=false;$('[data-ac-save]').disabled=true;
  }
  function renderRoles(){
    if(!S.role || !S.roles.some(function(r){return r.role_key===S.role;}))S.role=S.roles.length?S.roles[0].role_key:null;
    var q=$('#ac-r-search').value.trim().toLowerCase();
    var shown=S.roles.filter(function(r){return (r.display_name+' '+r.role_key).toLowerCase().indexOf(q)>=0;});
    $('#ac-role-count').textContent=S.roles.length;
    $('#ac-role-list').innerHTML=shown.length?shown.map(function(r){
      var n=Object.keys(r.grantMap).length,d=S.roleDirty[r.role_key];
      return '<button type="button" class="ac-role-row'+(r.role_key===S.role?' is-sel':'')+'" data-ac-role="'+esc(r.role_key)+'" aria-pressed="'+(r.role_key===S.role)+'"><b>'+esc(r.display_name || r.role_key)+'</b><small>'+memberLine(r)+'</small><span>'+ (r.bypasses_matrix?'Protected super-admin role':n+' explicit permission'+(n===1?'':'s'))+'</span>'+(d?'<em>Draft</em>':'')+'</button>';
    }).join(''):'<div class="empty"><b>No roles match.</b>Try a different name.</div>';
    var r=S.roles.find(function(x){return x.role_key===S.role;});
    if(!r){$('#ac-role-summary').innerHTML='<div class="empty">No Hub roles available.</div>';$('#ac-role-pages').innerHTML='';return;}
    var count=S.pages.filter(function(pg){return pg.status==='active'&&!pg.hard_excluded&&!PORTAL_KEYS[pg.page_key]&&roleEffective(r,pg)!=='none';}).length;
    $('#ac-role-summary').innerHTML='<header class="ac-detail-head"><div><span class="ac-eyebrow">Role permissions</span><h3>'+esc(r.display_name || r.role_key)+'</h3><p>'+memberLine(r)+' · <span class="mono">'+esc(r.role_key)+'</span></p></div><span class="pill p-mut">'+(S.editing?'Editing draft':'Review mode')+'</span></header><div class="ac-default-card"><div><b>Default page access</b><p>Applies to pages without an explicit permission. Signed-in pages allow at least Read.</p></div>'+(r.bypasses_matrix?'<span class="pill p-info">Protected · Admin</span>':'<label><span class="sr-only">Default for '+esc(r.display_name || r.role_key)+'</span><select class="ac-lvl ac-def'+(S.roleDirty[r.role_key]&&S.roleDirty[r.role_key].default_access!==undefined?' is-dirty':'')+'" data-roledef="'+esc(r.role_key)+'">'+LEVELS.map(function(l){return '<option value="'+l+'"'+(roleDefault(r)===l?' selected':'')+'>'+levelName(l)+'</option>';}).join('')+'</select></label>')+'</div><p class="ac-scope-note">'+(r.bypasses_matrix?'Super-admin access is enforced by the Hub and cannot be reduced here.':count+' active Hub pages resolve to Read or Admin for this role. People with multiple roles receive the highest permission, unless a personal exception applies.')+'</p>';
    var query=$('#ac-rp-search').value.trim().toLowerCase(),explicit=$('#ac-rp-explicit').checked,retired=$('#ac-rp-retired').checked;
    var pages=S.pages.filter(function(pg){return (retired||pg.status==='active')&&(!query||(pg.display_name+' '+pg.page_key).toLowerCase().indexOf(query)>=0)&&(!explicit||roleGrant(r,pg.page_key)!==null);});
    $('#ac-rp-count').textContent=pages.length+' pages';
    $('#ac-role-pages').innerHTML='<thead><tr><th scope="col">Hub page</th><th scope="col">Permission setting</th><th scope="col">Effective access</th></tr></thead><tbody>'+pages.map(function(pg){
      var locked=pg.hard_excluded,portal=PORTAL_KEYS[pg.page_key],grant=roleGrant(r,pg.page_key),dirty=S.roleDirty[r.role_key]&&has(S.roleDirty[r.role_key].grants,pg.page_key);
      var setting=portal?PORTAL_LINK:locked?'<span class="pill p-mut">Super admins only</span>':r.bypasses_matrix?'<span class="hint">Protected role</span>':levelSelect('ac-lvl'+(dirty?' is-dirty':''),grant,'Inherited · '+levelName(roleFallback(r,pg)),'data-role="'+esc(r.role_key)+'" data-page="'+esc(pg.page_key)+'" aria-label="'+esc((pg.display_name || pg.page_key)+' for '+(r.display_name || r.role_key))+'"');
      var effective=portal?'<span class="hint">Managed in Approval Access</span>':locked?(r.bypasses_matrix?tag('admin'):tag('none')):r.bypasses_matrix?tag(pg.access_policy==='authenticated'?'read':'admin'):tag(roleEffective(r,pg));
      var why=portal?'Separate approval policy':locked?'Protected by Hub code':r.bypasses_matrix?'Super-admin enforcement':pg.access_policy==='authenticated'?'Signed-in minimum: Read':grant===null?'Inherited from role default':'Explicit page permission';
      return '<tr><td><div class="ac-pk">'+esc(pg.display_name || pg.page_key)+'<small>'+esc(pg.page_key)+'</small></div>'+(pg.status!=='active'?'<span class="pill p-mut">'+esc(pg.status)+'</span>':'')+'</td><td>'+setting+'</td><td>'+effective+'<small class="ac-access-source">'+why+'</small></td></tr>';
    }).join('')+(pages.length?'':'<tr><td colspan="3"><div class="empty"><b>No pages match.</b>Clear the search or permission filter.</div></td></tr>')+'</tbody>';
  }
  function renderMatrix(){var key=focusKey(document.activeElement);renderComparison();renderRoles();syncControls();restoreFocus(key);}

  /* ---------- people ---------- */
  function renderPeopleList(){
    var q = $('#ac-p-search').value.trim().toLowerCase();
    var list = S.users.filter(function(u){
      return (!$('#ac-p-exceptions').checked || u.grant_count>0) && (!q || u.email.toLowerCase().indexOf(q) >= 0 ||
        String(u.display_name || '').toLowerCase().indexOf(q) >= 0 ||
        (u.roles || []).some(function(r){ return (roleName(r)+' '+r).toLowerCase().indexOf(q) >= 0; }));
    });
    $('#ac-plist').innerHTML = list.length
      ? list.map(function(u){
          return '<button type="button" class="ac-prow' + (S.person && S.person.email === u.email ? ' is-sel' : '') +
            '" data-email="' + esc(u.email) + '"><b>' + esc(u.display_name || u.email) +
            (u.is_active ? '' : ' <span class="pill p-crit">inactive</span>') + '</b>' +
            '<small class="mono">' + esc(u.email) + '</small>' +
            '<small>' + esc((u.roles && u.roles.length) ? u.roles.map(roleName).join(', ') : 'no role') +
            (u.grant_count ? ' · ' + u.grant_count + ' exception' + (u.grant_count === 1 ? '' : 's') : '') + '</small></button>';
        }).join('')
      : '<div class="empty"><b>Nobody matches that.</b></div>';
  }
  function selectPerson(email, pointer, strict){
    var request=++S.personRequest;S.person=null;S.personDirty=null;invalidateReview();refreshSaveBar();
    $('#ac-pdet').innerHTML = '<div class="empty"><b>Loading…</b></div>';
    return Promise.all([
      api('GET', '/users/' + encodeURIComponent(email) + '/access'),
      api('GET', '/admin/view-as/' + encodeURIComponent(email)).catch(function(){ return null; }),
    ]).then(function(res){
      if(request!==S.personRequest)return;
      var acc = res[0], eff = res[1];
      var u = S.users.find(function(x){ return x.email === email; }) || {};
      var override = {};
      (acc.access || []).forEach(function(a){ override[a.page_key] = a.access_level; });
      S.person = {
        email: email,
        display_name: u.display_name || email,
        roles: acc.roles || (acc.role_key ? [acc.role_key] : []),
        override: override,
        effective: (eff && (eff.pages || eff.effective_pages)) || null,
        isSuperAdmin: !!(eff && (eff.isSuperAdmin || (eff.user && eff.user.isSuperAdmin))),
      };
      S.personDirty = {};
      renderPeopleList(); renderPerson();enter($('#ac-pdet'),pointer);
      var heading=$('#ac-pdet h4');if(heading){heading.tabIndex=-1;heading.focus({preventScroll:true});if(window.innerWidth<900)heading.scrollIntoView({block:'start',behavior:'instant'});}
    }).catch(function(e){
      if(request!==S.personRequest)return;
      $('#ac-pdet').innerHTML = '<div class="empty"><b>Could not load ' + esc(email) + '.</b>' + esc(e.message) + '</div>';if(strict)throw e;
    });
  }
  function personSetting(pageKey){
    if(S.personDirty && has(S.personDirty, pageKey)) return S.personDirty[pageKey];
    var o = S.person.override[pageKey];
    return o === undefined ? null : o;
  }
  function renderPerson(){
    var key=focusKey(document.activeElement),p=S.person;if(!p)return;
    var pages=S.pages.filter(function(x){return x.status==='active'&&(!S.personQuery||(x.display_name+' '+x.page_key).toLowerCase().indexOf(S.personQuery)>=0)&&(!S.personOnly||personSetting(x.page_key)!==null);});
    var h = '<div class="ac-phead"><div><h4>' + esc(p.display_name) + '</h4>' +
      '<div class="hint"><span class="mono">' + esc(p.email) + '</span> · roles: <b>' + esc(p.roles.map(roleName).join(', ') || 'none') + '</b>' +
      (p.isSuperAdmin ? ' · <span class="pill p-info">super admin</span>' : '') + '</div></div>' +
      '<button type="button" class="btn sm" data-ac-recheck title="Stamps roles_invalidated_at so the hub re-reads this person\'s AD groups on their next request">Re-check AD groups</button></div>' +
      '<p class="hint ac-recheck-why">Hub roles are cached from AD for up to 24 hours, and signing out and in again does not refresh them. Use this after adding someone to a <span class="mono">SaaS-ITH-*</span> group.</p>';
    if(p.isSuperAdmin){
      h += '<div class="note warn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>' +
           '<div>This account is a super admin, so it holds admin on every active page whatever is set below. Super admin comes from the ' +
           '<span class="mono">SaaS-ITH-SA</span> AD group or the <span class="mono">RBAC_SUPERADMINS</span> environment variable. Neither is editable here.</div></div>';
    }
    h += '<div class="ac-toolbar"><label class="sr-only" for="ac-person-pages">Find a person page</label><input id="ac-person-pages" type="search" placeholder="Find a page" value="'+esc(S.personQuery)+'"><label class="ac-chk"><input id="ac-person-only" type="checkbox"'+(S.personOnly?' checked':'')+'> Personal exceptions only</label></div>';
    h += '<div class="tblwrap ac-ptbl"><table class="grid"><colgroup><col style="width:44%"><col style="width:18%"><col style="width:20%"><col style="width:18%"></colgroup>' +
         '<thead><tr><th>Page</th><th>From their roles</th><th>Personal exception</th><th>Effective access</th></tr></thead><tbody>';
    pages.forEach(function(pg){
      if(PORTAL_KEYS[pg.page_key]){
        var entry = p.effective && p.effective[pg.page_key];
        h += '<tr><td><div class="ac-pk">' + esc(pg.display_name || pg.page_key) + '<small>' + esc(pg.page_key) + '</small></div></td><td colspan="3">' + PORTAL_LINK +
             '<div class="hint">' + (pg.page_key === 'accessportal' ? 'Public requester forms; approval records require separate access.'
               : 'Saved portal entry: ' + esc(entry || 'unavailable') + '. Check live account, directory and department scope in the app.') + '</div></td></tr>';
        return;
      }
      var fromRoles = p.isSuperAdmin ? (pg.access_policy === 'authenticated' ? 'read' : 'admin') : rolesEffective(p.roles, pg);
      var set = personSetting(pg.page_key);
      var result = set === null ? fromRoles : set;
      if(pg.access_policy === 'authenticated' && RANK[result] < RANK.read) result = 'read';
      if(pg.hard_excluded) result = 'none';
      if(p.isSuperAdmin) result = pg.access_policy === 'authenticated' ? 'read' : 'admin';
      var isDirty = S.personDirty && has(S.personDirty, pg.page_key);
      var cls = 'ac-lvl' + (set === 'none' ? ' is-deny' : set ? ' is-set' : '') + (isDirty ? ' is-dirty' : '');
      h += '<tr><td><div class="ac-pk">' + esc(pg.display_name || pg.page_key) +
           (pg.hard_excluded ? ' <span class="pill p-info">locked</span>' : '') + '<small>' + esc(pg.page_key) + '</small></div></td>' +
           '<td>' + tag(fromRoles) + '</td><td>' +
           (p.isSuperAdmin ? '<span class="hint">Protected super-admin access</span>' : pg.hard_excluded ? '<span class="hint">super admins only</span>'
             : levelSelect(cls, set, 'Inherited · '+levelName(fromRoles), 'data-uspage="' + esc(pg.page_key) + '" aria-label="' + esc((pg.display_name || pg.page_key) + ' for this person') + '"')) +
           '</td><td>' + tag(result) + '<small class="ac-access-source">'+(p.isSuperAdmin?'Super-admin enforcement':pg.hard_excluded?'Protected by Hub code':pg.access_policy==='authenticated'?'Signed-in minimum: Read':set===null?'Highest permission from their roles':'Personal exception')+'</small></td></tr>';
    });
    $('#ac-pdet').innerHTML = h + (pages.length?'':'<tr><td colspan="4"><div class="empty">No pages match this filter.</div></td></tr>')+'</tbody></table></div>';syncControls();restoreFocus(key);
  }
  function recheck(btn){
    var email = S.person && S.person.email;
    if(!email) return;
    btn.disabled = true; btn.textContent = 'Asking the hub…';
    api('POST', '/users/' + encodeURIComponent(email) + '/invalidate', {}, '/api/saas-admin').then(function(){
      msg('AD groups for ' + email + ' will be re-read on their next request to the hub.', 'ok');
    }).catch(function(e){
      msg('Re-check not recorded: ' + e.message, 'err');
    }).then(function(){ btn.disabled = false; btn.textContent = 'Re-check AD groups'; });
  }

  /* ---------- activity ---------- */

  var auditRequest=0;
  function renderAudit(){
    var q=$('#ac-a-search').value.trim().toLowerCase();
    var rows=S.audit.filter(function(a){return ($('#ac-a-lookups').checked||!LOOKUP_ACTIONS[a.action])&&(!q||[a.actor_email,a.action,a.target_email,a.target_page_key,JSON.stringify(a.details)].join(' ').toLowerCase().indexOf(q)>=0);});
    $('#ac-a-count').textContent=rows.length+' of '+S.audit.length+' loaded events';
    var labels={view_as_lookup:'Access checked',superadmin_access:'Super-admin access',user_activity_lookup:'User activity checked',authorization_denied:'Access denied',qa_token_minted:'QA token created',role_updated:'Role permissions updated',user_access_updated:'Personal permissions updated',roles_invalidated:'AD group refresh requested',page_registered:'Page registered'};
    $('#ac-audit').innerHTML='<thead><tr><th>When</th><th>Actor</th><th>Event & target</th><th>Details</th></tr></thead><tbody>'+rows.map(function(a){
      var d=a.details;if(typeof d==='string')try{d=JSON.parse(d);}catch(e){}
      var when=new Date(a.created_at),target=[a.target_email,a.target_page_key].filter(Boolean).join(' · '),label=labels[a.action]||String(a.action||'Event').replace(/_/g,' ').replace(/^./,function(c){return c.toUpperCase();});
      return '<tr><td class="ac-ts"><time datetime="'+esc(a.created_at)+'">'+esc(isNaN(when)?a.created_at:when.toLocaleString())+'</time></td><td>'+esc(a.actor_email)+'</td><td><b>'+esc(label)+'</b><small class="ac-access-source">'+esc(target||'Hub access')+'</small></td><td><details><summary>Technical details</summary><code>'+esc(a.action)+'</code><pre>'+esc(d&&typeof d==='object'?JSON.stringify(d,null,2):(d||'No additional details'))+'</pre></details></td></tr>';
    }).join('')+(rows.length?'':'<tr><td colspan="4"><div class="empty"><b>No matching events.</b>Try another search or include access lookups.</div></td></tr>')+'</tbody>';
  }
  function loadAudit(){
    var request=++auditRequest;$('#ac-audit').innerHTML='<tbody><tr><td>Loading audit events…</td></tr></tbody>';
    return api('GET','/audit?limit=120').then(function(j){if(request!==auditRequest)return;S.audit=j.entries||[];renderAudit();}).catch(function(e){if(request!==auditRequest)return;$('#ac-audit').innerHTML='<tbody><tr><td>'+deniedHtml(e)+'</td></tr></tbody>';$('#ac-a-count').textContent='Unavailable';});
  }

  /* ---------- register a page (regpagekit 2026-10-20) ----------
     POST /api/rbac/pages adds the rbac_pages row and one explicit grant per role in one
     hub transaction. Every role is sent, so no role silently follows its default. */
  var regFresh = true;
  function renderRegister(){
    var t = $('#ac-reg-roles'); if(!t) return;
    var keep = {};
    if(!regFresh) t.querySelectorAll('select[data-reg-role]').forEach(function(s){ keep[s.dataset.regRole] = s.value; });
    regFresh = false;
    var roles = S.roles.slice().sort(function(a, b){ return a.role_key.localeCompare(b.role_key); });
    t.innerHTML = '<thead><tr><th>Role</th><th>Role default</th><th>On this page</th></tr></thead><tbody>' + roles.map(function(r){
      var cur = keep[r.role_key] || 'none', id = 'ac-reg-' + r.role_key;
      return '<tr><td><b>' + esc(r.display_name || r.role_key) + '</b><small class="ac-access-source">' + esc(r.role_key) + '</small></td><td>' + tag(r.default_access) +
        '</td><td><label class="sr-only" for="' + esc(id) + '">Level for ' + esc(r.display_name || r.role_key) + '</label><select id="' + esc(id) + '" data-reg-role="' + esc(r.role_key) + '">' +
        LEVELS.map(function(l){ return '<option value="' + l + '"' + (l === cur ? ' selected' : '') + '>' + esc(levelName(l)) + '</option>'; }).join('') + '</select></td></tr>';
    }).join('') + (roles.length ? '' : '<tr><td colspan="3">No roles loaded.</td></tr>') + '</tbody>';
  }
  function regErr(text){ var p = $('[data-ac-reg-err]'); p.textContent = text || ''; p.hidden = !text; }
  function register(form){
    var f = form.elements, grants = {}, picked = [];
    regErr('');
    if(!form.reportValidity()) return;
    form.querySelectorAll('select[data-reg-role]').forEach(function(s){
      grants[s.dataset.regRole] = s.value;
      if(s.value !== 'none') picked.push(roleName(s.dataset.regRole) + ': ' + levelName(s.value));
    });
    var body = {
      page_key: f.page_key.value.trim().toLowerCase(), display_name: f.display_name.value.trim(), url_path: f.url_path.value.trim(),
      category: f.category.value, access_policy: f.access_policy.value, status: f.status.value,
      display_order: f.display_order.value === '' ? 100 : Number(f.display_order.value), description: f.description.value.trim(),
      has_admin_actions: f.has_admin_actions.checked, nav_visible: f.nav_visible.checked, grants: grants,
    };
    if(!Object.keys(grants).length){ regErr('Roles have not loaded. Refresh and try again.'); return; }
    if(S.pages.some(function(p){ return p.page_key === body.page_key; })){ regErr(body.page_key + ' is already registered.'); return; }
    if(!confirm('Register ' + body.page_key + ' (' + body.url_path + ')?\n\n' + (picked.length ? picked.join('\n') + '\n' : '') +
      'Every other role: No access.\n\nThe change is audited and takes effect immediately.')) return;
    var btn = $('[data-ac-reg-go]'); btn.disabled = true; btn.textContent = 'Registering…';
    api('POST', '/pages', body).then(function(j){
      form.reset(); regFresh = true;
      msg('Registered ' + j.page.page_key + '. It is in Roles & permissions now.', 'ok');
      return loadAll();
    }).catch(function(e){ regErr(e.message); }).then(function(){
      btn.disabled = false; btn.textContent = 'Register page'; renderRegister();
    });
  }

  /* ---------- dirty tracking + save ---------- */
  function describeChanges(){
    var out = [];
    Object.keys(S.roleDirty).forEach(function(rk){
      var d = S.roleDirty[rk], role = S.roles.find(function(r){ return r.role_key === rk; });
      if(!role) return;
      var name = role.display_name || rk;
      if(d.default_access !== undefined){
        out.push('<b>' + esc(name) + '</b> default <span class="mono">' + esc(role.default_access) + ' → ' + esc(d.default_access) + '</span> · applies to ' + S.pages.filter(function(pg){return pg.status==='active'&&!pg.hard_excluded&&!PORTAL_KEYS[pg.page_key]&&roleGrant(role,pg.page_key)===null;}).length + ' active pages without explicit permissions');
      }
      Object.keys(d.grants || {}).forEach(function(pk){
        var lvl = d.grants[pk], was = role.grantMap[pk] === undefined ? 'default' : role.grantMap[pk];
        out.push('<b>' + esc(name) + '</b> <span class="mono">' + esc(pk) + ': ' + esc(was) + ' → ' + esc(lvl === null ? 'default' : lvl) + '</span>');
      });
    });
    if(S.person && S.personDirty){
      Object.keys(S.personDirty).forEach(function(pk){
        var lvl = S.personDirty[pk], was = S.person.override[pk] === undefined ? 'default' : S.person.override[pk];
        out.push('<b>' + esc(S.person.display_name) + '</b> <span class="mono">' + esc(pk) + ': ' + esc(was) + ' → ' + esc(lvl === null ? 'default' : lvl) + '</span>');
      });
    }
    return out;
  }
  function refreshSaveBar(){
    var c = describeChanges(), bar = $('[data-ac-savebar]');
    bar.hidden = c.length === 0;
    $('[data-ac-changes]').innerHTML = c.length
      ? '<b>' + c.length + ' permission change' + (c.length === 1 ? '' : 's') + ' pending</b><span>Review every draft before saving.</span>' : '';
    syncControls();
  }
  function openReview(pointer){
    var changes=describeChanges();if(!changes.length)return;
    $('#ac-confirm').checked=false;$('[data-ac-review-list]').innerHTML=changes.map(function(c){return '<li>'+c+'</li>';}).join('');
    var review=$('[data-ac-review]');review.hidden=false;review.focus({preventScroll:true});review.scrollIntoView({block:'nearest',behavior:'instant'});syncControls();enter(review,pointer);
  }
  function markRole(rk){ if(!S.roleDirty[rk]) S.roleDirty[rk] = { grants: {} }; return S.roleDirty[rk]; }

  function save(){
    if(S.saving || $('[data-ac-review]').hidden || !$('#ac-confirm').checked || !describeChanges().length)return;
    var btn = $('[data-ac-save]'), failures = [], jobs = [];invalidateReview();
    S.saving = true;syncControls();btn.textContent = 'Saving…';msg('Saving reviewed permission changes…');
    Object.keys(S.roleDirty).forEach(function(rk){
      var d = S.roleDirty[rk], role = S.roles.find(function(r){ return r.role_key === rk; });
      if(!role) return;
      // PUT replaces the WHOLE grant set, so send the merged result, and only when a grant
      // actually moved, so a default-only edit does not rewrite every row and bury the audit trail.
      var body = {};
      if(Object.keys(d.grants || {}).length){
        var merged = Object.assign({}, role.grantMap);
        Object.keys(d.grants).forEach(function(pk){ if(d.grants[pk] === null) delete merged[pk]; else merged[pk] = d.grants[pk]; });
        body.grants = merged;
      }
      if(d.default_access !== undefined) body.default_access = d.default_access;
      if(!Object.keys(body).length) return;
      jobs.push(function(){ return api('PUT', '/roles/' + encodeURIComponent(rk), body).then(function(){if(body.grants)role.grantMap=body.grants;if(body.default_access!==undefined)role.default_access=body.default_access;delete S.roleDirty[rk];}).catch(function(e){ failures.push(rk + ': ' + e.message); }); });
    });
    if(S.person && S.personDirty && Object.keys(S.personDirty).length){
      var merged = Object.assign({}, S.person.override), email = S.person.email;
      Object.keys(S.personDirty).forEach(function(pk){ if(S.personDirty[pk] === null) delete merged[pk]; else merged[pk] = S.personDirty[pk]; });
      jobs.push(function(){ return api('PUT', '/users/' + encodeURIComponent(email) + '/access', { access: merged }).then(function(){S.person.override=merged;S.personDirty={};}).catch(function(e){ failures.push(email + ': ' + e.message); }); });
    }
    // Keep every editing control frozen until readback completes.
    var committed=false;
    function finish(){S.saving=false;syncControls();btn.textContent='Save reviewed changes';renderMatrix();if(S.person)renderPerson();refreshSaveBar();}
    jobs.reduce(function(p, job){return p.then(job);},Promise.resolve()).then(function(){
      if(failures.length){finish();msg('Some changes were not saved: '+failures.join('; ')+'. Successful changes are removed from the draft. Review the remaining changes before retrying.','err');return;}
      committed=true;var who=S.person&&S.person.email;S.editing=false;invalidateReview();S.roleDirty={};S.personDirty=null;
      return loadAll().then(function(){if(who)return selectPerson(who,false,true);}).then(function(){if(S.view==='activity')return loadAudit();}).then(function(){finish();msg('Saved and refreshed from the Hub. People already signed in may retain access until their session refreshes.','ok');});
    }).catch(function(e){finish();msg((committed?'The Hub accepted the changes, but refreshing the page data failed. Refresh before making another change. ':'Save could not complete. ')+e.message,'err');});
  }

  /* ---------- load ---------- */
  function loadAll(){
    return Promise.all([
      api('GET', '/pages'),
      api('GET', '/roles'),
      api('GET', '/users' + ($('#ac-p-inactive').checked ? '?include_inactive=1' : '')),
    ]).then(function(res){
      S.pages = (res[0].pages || []).slice().sort(function(a, b){
        return String(a.display_name || a.page_key).localeCompare(String(b.display_name || b.page_key)); });
      S.roles = (res[1].roles || []).map(function(r){
        var gm = {}; (r.grants || []).forEach(function(g){ gm[g.page_key] = g.access_level; });
        return Object.assign({}, r, { grantMap: gm });
      }).sort(function(a, b){ return (b.user_count - a.user_count) || a.role_key.localeCompare(b.role_key); });
      S.users = res[2].users || [];
      S.loaded = true;
      root.classList.remove('is-loading');
      $('[data-ac-body]').hidden = false;
      $('[data-ac-blocked]').hidden = true;
      $('[data-ac-reload]').disabled = false;
      renderMatrix(); renderPeopleList(); refreshSaveBar();syncControls();
    });
  }
  function firstLoad(){
    if(S.loaded || S.loading || S.fatal) return;
    S.loading = true;
    loadAll().catch(function(e){
      root.classList.remove('is-loading');
      var b = $('[data-ac-blocked]');
      b.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg><div>' + deniedHtml(e) + '</div>';
      b.hidden = false;
      $('[data-ac-body]').hidden = true;
      if(e.fatal) S.fatal = true;
      $('[data-ac-reload]').disabled = !!e.fatal;
    }).then(function(){ S.loading = false; });
  }
  function setView(v){
    cancelMotion();
    S.view = v;
    root.querySelectorAll('[data-ac-view]').forEach(function(b){ b.setAttribute('aria-pressed', String(b.dataset.acView === v)); });
    root.querySelectorAll('[data-ac-pane]').forEach(function(p){ p.hidden = p.dataset.acPane !== v; });
    if(v === 'activity') loadAudit();
    if(v === 'register') renderRegister();
  }

  /* ---------- events (scoped to this panel) ---------- */
  root.addEventListener('change', function(e){
    var t = e.target, d, rk, pk, want, orig, role;
    if(S.saving)return;
    if(t.id==='ac-confirm'){syncControls();return;}
    if(t.id==='ac-person-only'){S.personOnly=t.checked;renderPerson();return;}
    if(t.id==='ac-p-exceptions'){renderPeopleList();return;}
    if(t.id==='ac-rp-explicit'||t.id==='ac-rp-retired'){renderMatrix();return;}
    if((t.dataset.roledef!==undefined||t.dataset.role!==undefined||t.dataset.uspage!==undefined)&&!S.editing)return;
    if(t.dataset.roledef !== undefined){
      rk = t.dataset.roledef; role = S.roles.find(function(r){ return r.role_key === rk; });
      d = markRole(rk);
      if(t.value === role.default_access) delete d.default_access; else d.default_access = t.value;
      if(d.default_access === undefined && !Object.keys(d.grants).length) delete S.roleDirty[rk];
      invalidateReview();renderMatrix();if(S.person)renderPerson();refreshSaveBar();return;
    }
    if(t.dataset.role !== undefined && t.dataset.page !== undefined){
      rk = t.dataset.role; pk = t.dataset.page; role = S.roles.find(function(r){ return r.role_key === rk; });
      d = markRole(rk);
      want = t.value === '' ? null : t.value;
      orig = role.grantMap[pk] === undefined ? null : role.grantMap[pk];
      if(want === orig) delete d.grants[pk]; else d.grants[pk] = want;
      if(d.default_access === undefined && !Object.keys(d.grants).length) delete S.roleDirty[rk];
      invalidateReview();renderMatrix();if(S.person)renderPerson();refreshSaveBar();return;
    }
    if(t.dataset.uspage !== undefined){
      pk = t.dataset.uspage;
      want = t.value === '' ? null : t.value;
      orig = S.person.override[pk] === undefined ? null : S.person.override[pk];
      if(want === orig) delete S.personDirty[pk]; else S.personDirty[pk] = want;
      invalidateReview();renderPerson();refreshSaveBar();return;
    }
    if(t.id === 'ac-m-inactive' || t.id === 'ac-m-onlyset'){ renderMatrix(); return; }
    if(t.id === 'ac-a-lookups'){renderAudit();return;}
    if(t.id === 'ac-p-inactive'){ loadAll().catch(function(err){ msg(err.message, 'err'); }); }
  });
  root.addEventListener('input', function(e){
    if(e.target.id === 'ac-m-search') renderMatrix();
    if(e.target.id === 'ac-p-search') renderPeopleList();
    if(e.target.id==='ac-r-search'||e.target.id==='ac-rp-search')renderMatrix();
    if(e.target.id==='ac-a-search')renderAudit();
    if(e.target.id==='ac-person-pages'){S.personQuery=e.target.value.toLowerCase();renderPerson();}
  });
  root.addEventListener('click', function(e){
    if(S.saving)return;
    var roleRow=e.target.closest('[data-ac-role]');
    if(roleRow){S.role=roleRow.dataset.acRole;renderMatrix();return;}
    if(e.target.closest('[data-ac-check]')){setView('people');$('#ac-p-search').focus();return;}
    if(e.target.closest('[data-ac-edit]')){if(S.editing&&describeChanges().length){openReview(e.detail>0);return;}S.editing=!S.editing;syncControls();renderMatrix();return;}
    if(e.target.closest('[data-ac-review-open]')){openReview(e.detail>0);return;}
    if(e.target.closest('[data-ac-back-edit]')){invalidateReview();$('[data-ac-review-open]').focus();return;}
    var v = e.target.closest('[data-ac-view]');
    if(v){ setView(v.dataset.acView); return; }
    var row = e.target.closest('.ac-prow');
    if(row){
      if(S.person && S.person.email===row.dataset.email)return;
      if(S.personDirty && Object.keys(S.personDirty).length &&
         !confirm('Discard the unsaved changes for ' + S.person.display_name + '?')) return;
      selectPerson(row.dataset.email,e.detail>0);
      return;
    }
    if(e.target.closest('[data-ac-recheck]')){ recheck(e.target.closest('[data-ac-recheck]')); return; }
    if(e.target.closest('[data-ac-save]')){ save(); return; }
    if(e.target.closest('[data-ac-discard]')){
      invalidateReview();S.roleDirty = {}; if(S.personDirty) S.personDirty = {};
      renderMatrix();if(S.person)renderPerson();refreshSaveBar();return;
    }
    if(e.target.closest('[data-ac-reload]')){
      if(describeChanges().length && !confirm('Reloading discards your unsaved changes. Continue?')) return;
      invalidateReview();S.roleDirty = {}; S.personDirty = S.person ? {} : null;
      loadAll().then(function(){ if(S.person) return selectPerson(S.person.email); })
        .then(function(){ msg('Reloaded from the hub.', 'ok'); })
        .catch(function(err){ msg(err.message, 'err'); });
    }
  });
  root.addEventListener('submit', function(e){
    var form = e.target.closest('[data-ac-reg]');
    if(!form) return;
    e.preventDefault();
    if(S.saving) return;
    register(form);
  });
  window.addEventListener('beforeunload', function(e){
    if(S.loaded && describeChanges().length){ e.preventDefault(); e.returnValue = ''; }
  });

  // Load only when the tab is actually opened: the hub audits some reads, and nobody who
  // never opens this tab should cause hub traffic on every console load.
  // console-hybrid.js and console-saas.js title the iam tabs they know about; this one is ours.
  // console-hybrid.js rebuilds the breadcrumb workspace switcher on every route from a fixed list;
  // add this tab to it (owners only: the panel exists only for them) and select it when it is open.
  function syncSwitcher(){
    var sel = document.getElementById('hybrid-workspace');
    if(!sel || !/^#?(iam|directory)\//.test(location.hash || '')) return;
    var opt = Array.prototype.find.call(sel.options, function(o){ return o.value === 'iam/access'; });
    if(!opt){
      if(!Array.prototype.some.call(sel.options, function(o){ return o.value.indexOf('iam/') === 0; })) return;
      opt = new Option('Hub page access', 'iam/access');
      var after = Array.prototype.find.call(sel.options, function(o){ return o.value === 'iam/roles'; });
      sel.add(opt, after ? after.nextSibling : null);
    }
    if(/^#iam\/access(\/|$)/.test(location.hash)) sel.value = 'iam/access';
  }
  function maybeLoad(){
    syncSwitcher();
    var iam=root.closest('[data-view=iam]');if(iam)iam.classList.toggle('is-hub-access',!!panel&&!panel.hidden);
    if(!panel || panel.hidden) return;
    var t = document.getElementById('access-page-title'), d = document.getElementById('access-page-description');
    if(t) t.textContent = 'Hub page access';
    if(d) d.textContent = 'Set which Hub pages each role can open, and exceptions for one person.';
    firstLoad();
  }
  window.addEventListener('console-route', maybeLoad);
  window.addEventListener('hashchange', maybeLoad);
  if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded', maybeLoad); else maybeLoad();
})();
