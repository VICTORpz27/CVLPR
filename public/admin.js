'use strict';
const $ = id => document.getElementById(id);
const categories = ['Cantine','Enseignement','Vie lycéenne','Sport','Événements','Environnement','Locaux','Autres','À vérifier'];
const statusOptions = [['approved','Retenue'],['review','À vérifier'],['spam','Spam'],['duplicate','Doublon']];
const roleLabels = {superadmin:'Super Admin',admin:'Admin',member:'Membre CVL',reader:'Lecteur'};
let me = null, allSuggestions = [], counts = {}, selectedStatus = 'approved', selectedCategory = '', activeView = 'suggestions', deleteTarget = null;

async function api(path, method='GET', body) {
  const res = await fetch(path, {method,credentials:'same-origin',headers:body!==undefined?{'content-type':'application/json'}:{},body:body!==undefined?JSON.stringify(body):undefined});
  let data;
  try { data = await res.json(); } catch { throw new Error('Réponse du serveur invalide.'); }
  if (!res.ok) throw new Error(data.error || 'Erreur serveur');
  return data;
}
function el(tag, text, cls) { const e=document.createElement(tag); if(text!==undefined)e.textContent=text; if(cls)e.className=cls; return e; }
function optionSelect(values,current) { const s=el('select'); values.forEach(([v,label])=>{const o=el('option',label);o.value=v;s.append(o)});s.value=current;return s; }
function field(label, input) { const d=el('div',undefined,'control-field'); const l=el('label',label); l.htmlFor=input.id || ''; d.append(l,input); return d; }
function canEdit() { return ['superadmin','admin','member'].includes(me?.role); }
function canDelete() { return ['superadmin','admin'].includes(me?.role); }
function canManageUsers() { return canDelete(); }
function showMessage(id,message) { $(id).textContent=message; }
function dateValue(s) { const d=new Date(String(s||'').replace(' ','T')+'Z');return Number.isNaN(d.getTime())?0:d.getTime(); }
function formatDate(s) { const d=new Date(dateValue(s));return Number.isNaN(d.getTime())?'Date inconnue':new Intl.DateTimeFormat('fr-FR',{dateStyle:'medium',timeStyle:'short'}).format(d); }
function normalize(s) {return String(s||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();}
function countForStatus(status) { return Number(counts[status]||0); }
function statusLabel(s) { return statusOptions.find(x=>x[0]===s)?.[1] || (s==='pending'?'En attente':s); }
function setView(view) {
  activeView=view;
  $('suggestions-view').hidden=view!=='suggestions';$('personnel-view').hidden=view!=='personnel';
  for(const [name,id] of [['suggestions','tab-suggestions'],['personnel','tab-personnel']]) {$(id).classList.toggle('active',name===view);$(id).setAttribute('aria-selected',String(name===view));}
  if(view==='personnel'&&canManageUsers()) loadUsers().catch(e=>showMessage('users-message',e.message));
}
async function init() {
  const config=await api('/api/config');
  const session=await api('/api/session');me=session.user;
  $('setup').hidden=!config.setupRequired;
  if(!me) { $('dashboard').hidden=true;$('logout').hidden=true;$('auth').hidden=config.setupRequired;return; }
  $('auth').hidden=true;$('setup').hidden=true;$('dashboard').hidden=false;$('logout').hidden=false;
  $('welcome').textContent=`Connecté : ${me.username} · ${roleLabels[me.role]||me.role}`;
  $('tab-personnel').hidden=!canManageUsers();
  if(!canManageUsers()&&activeView==='personnel')setView('suggestions');
  await refresh();
}
async function refresh() {
  showMessage('suggestions-message','');
  const [stats,list]=await Promise.all([api('/api/admin/stats'),api('/api/admin/suggestions')]);
  counts=Object.fromEntries((stats.counts||[]).map(x=>[x.moderation,Number(x.n)]));
  allSuggestions=list.suggestions||[];
  renderStats();renderCategories();renderSuggestions();
}
function renderStats() {
  const container=$('stats');container.replaceChildren();
  for(const [key,label] of [['approved','Retenues'],['review','À vérifier'],['spam','Spam'],['duplicate','Doublons']]) {
    const b=el('button',undefined,'stat'+(selectedStatus===key?' active':''));b.type='button';b.setAttribute('aria-pressed',String(selectedStatus===key));
    b.append(el('span',label,'stat-label'),el('strong',String(countForStatus(key)),'stat-number'));
    b.onclick=()=>{selectedStatus=key;selectedCategory='';renderStats();renderCategories();renderSuggestions();};container.append(b);
  }
}
function filteredByStatus() { return allSuggestions.filter(x=>x.moderation===selectedStatus); }
function renderCategories() {
  const items=filteredByStatus(),container=$('category-filters');container.replaceChildren();
  for(const name of ['',...categories]) {
    const count=name?items.filter(x=>x.category===name).length:items.length;
    const b=el('button',undefined,'category-pill'+(selectedCategory===name?' active':''));b.type='button';b.setAttribute('aria-pressed',String(selectedCategory===name));
    b.append(document.createTextNode(name||'Toutes'),el('span',String(count),'pill-count'));
    b.onclick=()=>{selectedCategory=name;renderCategories();renderSuggestions();};container.append(b);
  }
}
function renderSuggestions() {
  const query=normalize($('search').value.trim());const sort=$('sort').value;
  const items=filteredByStatus().filter(x=>(!selectedCategory||x.category===selectedCategory)&&(!query||normalize([x.body,x.category,x.firstname,x.lastname,x.class_name].join(' ')).includes(query)));
  items.sort((a,b)=>sort==='oldest'?dateValue(a.created_at)-dateValue(b.created_at):sort==='category'?String(a.category).localeCompare(String(b.category),'fr'):sort==='popular'?(Number(b.occurrences||b.duplicate_count||1)-Number(a.occurrences||a.duplicate_count||1))||dateValue(b.created_at)-dateValue(a.created_at):dateValue(b.created_at)-dateValue(a.created_at));
  $('results-count').textContent=`${items.length} suggestion${items.length>1?'s':''} affichée${items.length>1?'s':''}`;
  const loaded=allSuggestions.length,total=Object.values(counts).reduce((a,b)=>a+Number(b),0);
  $('results-note').textContent=total>loaded?`Affichage limité aux ${loaded} dernières suggestions par le serveur (sur ${total}).`:'Recherche dans les suggestions chargées.';
  const container=$('suggestions');container.replaceChildren();
  if(!items.length){container.append(el('div','Aucune suggestion pour ces filtres.','empty'));return;}
  for(const item of items) container.append(suggestionCard(item));
}
function suggestionCard(item) {
  const card=el('article',undefined,'suggestion');
  const top=el('div',undefined,'suggestion-top');top.append(el('span',item.category,'tag'),el('span',statusLabel(item.moderation),'tag-status'));card.append(top);
  card.append(el('p',item.body,'suggestion-body'));
  const name=[item.firstname,item.lastname].filter(Boolean).join(' ')||'Anonyme';
  card.append(el('p',`${name} · ${item.class_name||'Classe non renseignée'} · ${formatDate(item.created_at)}`,'meta'));
  const bottom=el('div',undefined,'suggestion-bottom'),controls=el('div',undefined,'controls');
  const status=optionSelect(statusOptions,item.moderation==='pending'?'review':item.moderation);
  const category=optionSelect(categories.map(x=>[x,x]),item.category);
  status.disabled=!canEdit();category.disabled=!canEdit();
  controls.append(field('Statut',status),field('Catégorie',category));
  if(canEdit()) {
    const save=el('button','Enregistrer','btn btn-dark');save.type='button';
    save.onclick=async()=>{save.disabled=true;try{await api('/api/admin/suggestions/'+encodeURIComponent(item.id),'PATCH',{moderation:status.value,category:category.value});await refresh();}catch(e){showMessage('suggestions-message',e.message);save.disabled=false;}};
    controls.append(save);
  }
  bottom.append(controls);
  if(canDelete()) {
    const remove=el('button','Supprimer','btn btn-danger');remove.type='button';remove.setAttribute('aria-label','Supprimer définitivement cette suggestion');remove.onclick=()=>openDelete(item);bottom.append(remove);
  }
  card.append(bottom);return card;
}
function openDelete(item) {
  deleteTarget=item;$('delete-preview').textContent=item.body;$('delete-error').textContent='';$('confirm-delete').disabled=false;
  $('delete-dialog').showModal();
}
async function confirmDelete() {
  if(!deleteTarget)return;
  const id=deleteTarget.id;$('confirm-delete').disabled=true;$('delete-error').textContent='';
  try {
    await api('/api/admin/suggestions/'+encodeURIComponent(id),'DELETE');
    $('delete-dialog').close();deleteTarget=null;await refresh();showMessage('suggestions-message','Suggestion supprimée définitivement.');
  }catch(e){$('delete-error').textContent=e.message;$('confirm-delete').disabled=false;}
}
async function loadUsers() {
  if(!canManageUsers())return;
  const data=await api('/api/admin/users'),container=$('users');container.replaceChildren();
  for(const u of data.users||[]) {
    const row=el('div',undefined,'user-row'),info=el('div');info.append(el('div',u.username,'user-name'),el('div',`${roleLabels[u.role]||u.role} · ${u.active?'Actif':'Désactivé'}`,'user-sub'));row.append(info);
    const controls=el('div',undefined,'controls');const roles=[['reader','Lecteur'],['member','Membre CVL'],['admin','Admin']];if(me.role==='superadmin')roles.push(['superadmin','Super Admin']);
    if(!roles.some(([v])=>v===u.role))roles.push([u.role,roleLabels[u.role]||u.role]);
    const role=optionSelect(roles,u.role),active=optionSelect([['1','Actif'],['0','Désactivé']],String(u.active)),save=el('button','Enregistrer','btn btn-dark');save.type='button';
    if(u.id===me.id||(u.role==='superadmin'&&me.role!=='superadmin')){role.disabled=true;active.disabled=true;save.disabled=true;}
    save.onclick=async()=>{save.disabled=true;try{await api('/api/admin/users/'+encodeURIComponent(u.id),'PATCH',{role:role.value,active:Number(active.value)});await loadUsers();showMessage('users-message','Compte mis à jour.');}catch(e){showMessage('users-message',e.message);save.disabled=false;}};
    controls.append(field('Rôle',role),field('Accès',active),save);row.append(controls);container.append(row);
  }
}
$('login-form').addEventListener('submit',async e=>{e.preventDefault();showMessage('login-message','');try{await api('/api/login','POST',{username:$('username').value,password:$('password').value});$('password').value='';await init();}catch(err){showMessage('login-message',err.message);}});
$('setup-form').addEventListener('submit',async e=>{e.preventDefault();try{await api('/api/setup','POST',{setupSecret:$('secret').value,username:$('setup-user').value,password:$('setup-password').value});$('setup').hidden=true;$('auth').hidden=false;showMessage('login-message','Compte créé. Connectez-vous.');}catch(err){showMessage('setup-message',err.message);}});
$('logout').onclick=async()=>{try{await api('/api/logout','POST');location.reload();}catch(e){alert(e.message);}};
$('tab-suggestions').onclick=()=>setView('suggestions');$('tab-personnel').onclick=()=>{if(canManageUsers())setView('personnel');};
$('reload-suggestions').onclick=()=>refresh().catch(e=>showMessage('suggestions-message',e.message));
$('reload-users').onclick=()=>loadUsers().catch(e=>showMessage('users-message',e.message));
$('search').addEventListener('input',renderSuggestions);$('sort').addEventListener('change',renderSuggestions);
$('clear-filters').onclick=()=>{selectedStatus='approved';selectedCategory='';$('search').value='';$('sort').value='recent';renderStats();renderCategories();renderSuggestions();};
$('cancel-delete').onclick=()=>$('delete-dialog').close();$('confirm-delete').onclick=confirmDelete;
$('delete-dialog').addEventListener('close',()=>{deleteTarget=null;});
$('new-user').addEventListener('submit',async e=>{e.preventDefault();try{await api('/api/admin/users','POST',{username:$('new-username').value,password:$('new-password').value,role:$('new-role').value});$('new-user').reset();await loadUsers();showMessage('users-message','Compte créé.');}catch(err){showMessage('users-message',err.message);}});
init().catch(e=>showMessage('login-message','Erreur de connexion : '+e.message));
