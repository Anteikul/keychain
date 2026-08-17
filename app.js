const root=document.documentElement;
const saved=localStorage.getItem('kc-theme');
root.dataset.theme=saved||((matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light');
document.querySelectorAll('[data-theme-toggle]').forEach(b=>b.onclick=()=>{root.dataset.theme=root.dataset.theme==='dark'?'light':'dark';localStorage.setItem('kc-theme',root.dataset.theme)});

const dlg=document.querySelector('#add'),form=dlg?.querySelector('form');
function openItem(data=null){
  if(!dlg)return;
  form.reset(); form.action='/item'; form.elements.id.value='';
  dlg.querySelector('[data-dialog-title]').textContent=data?'Edit credential':'Add credential';
  if(data){for(const k of ['id','title','folder','tags','login','secret','totp','url','notes','icon_id']){const name=k==='totp'?'totp_secret':k;if(form.elements[name])form.elements[name].value=data[k]??''}form.elements.shared.checked=!!data.shared}
  form.elements.icon_data.value='';const preview=document.querySelector('[data-upload-preview]');if(preview){preview.hidden=true;preview.classList.remove('selected');preview.querySelector('img').removeAttribute('src')}document.querySelectorAll('[data-icon-id]').forEach(b=>b.classList.toggle('selected',b.dataset.iconId===String(data?.icon_id||'')));
  dlg.showModal();
}
document.querySelector('[data-open]')?.addEventListener('click',()=>openItem());
document.querySelector('[data-close]')?.addEventListener('click',()=>dlg.close());
document.querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>openItem(JSON.parse(b.dataset.edit)));
document.querySelectorAll('[data-icon-id]').forEach(b=>b.onclick=()=>{form.elements.icon_id.value=b.dataset.iconId;form.elements.icon_data.value='';document.querySelector('[data-upload-preview]')?.classList.remove('selected');document.querySelectorAll('[data-icon-id]').forEach(x=>x.classList.toggle('selected',x===b))});
document.querySelector('[data-icon-file]')?.addEventListener('change',e=>{const file=e.target.files[0];if(!file)return;if(file.size>256*1024){alert('The icon must not exceed 256 kB.');e.target.value='';return}const reader=new FileReader();reader.onload=()=>{form.elements.icon_data.value=String(reader.result).split(',')[1]||'';form.elements.icon_id.value='';document.querySelectorAll('[data-icon-id]').forEach(x=>x.classList.remove('selected'));const preview=document.querySelector('[data-upload-preview]');preview.hidden=false;preview.querySelector('img').src=reader.result;preview.classList.add('selected')};reader.readAsDataURL(file)});
document.querySelector('[data-upload-preview]')?.addEventListener('click',e=>{if(!form.elements.icon_data.value)return;document.querySelectorAll('[data-icon-id]').forEach(x=>x.classList.remove('selected'));e.currentTarget.classList.add('selected');form.elements.icon_id.value=''});
function randomFrom(chars){const limit=256-256%chars.length;while(true){const n=crypto.getRandomValues(new Uint8Array(1))[0];if(n<limit)return chars[n%chars.length]}}
document.querySelector('[data-generate-password]')?.addEventListener('click',()=>{const length=Math.max(12,Math.min(64,Number(document.querySelector('[data-password-length]').value)||20)),symbols=document.querySelector('[data-password-symbols]').checked,chars='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'+(symbols?'!@#$%^&*()-_=+[]{}:,.?':''),required=['A','a','7'].concat(symbols?['!']:[]),out=required.concat(Array.from({length:length-required.length},()=>randomFrom(chars)));for(let i=out.length-1;i>0;i--){const j=crypto.getRandomValues(new Uint32Array(1))[0]%(i+1);[out[i],out[j]]=[out[j],out[i]]}form.elements.secret.value=out.join('');form.elements.secret.type='text';form.elements.secret.focus()});
const deleteDlg=document.querySelector('#delete-confirm'),deleteForm=deleteDlg?.querySelector('form'),deleteInput=deleteDlg?.querySelector('[data-delete-input]'),deleteSubmit=deleteDlg?.querySelector('[data-delete-submit]');let deleteTitle='';
document.querySelectorAll('[data-delete-id]').forEach(b=>b.onclick=()=>{deleteTitle=b.dataset.deleteTitle;deleteForm.reset();deleteForm.elements.id.value=b.dataset.deleteId;deleteDlg.querySelector('[data-delete-name]').textContent=deleteTitle;deleteSubmit.disabled=true;deleteDlg.showModal();deleteInput.focus()});
document.querySelectorAll('[data-delete-close]').forEach(b=>b.onclick=()=>deleteDlg.close());
deleteInput?.addEventListener('input',()=>deleteSubmit.disabled=deleteInput.value!==deleteTitle);
document.querySelectorAll('[data-reveal]').forEach(b=>b.onclick=()=>{const c=b.parentNode.querySelector('code');const shown=b.textContent==='Hide';c.textContent=shown?'••••••••••':c.dataset.secret;b.textContent=shown?'Show':'Hide'});
async function copyText(value){
  if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(value);return}
  const area=document.createElement('textarea');area.value=value;area.setAttribute('readonly','');area.style.cssText='position:fixed;opacity:0;pointer-events:none';document.body.appendChild(area);area.select();area.setSelectionRange(0,area.value.length);const ok=document.execCommand('copy');area.remove();if(!ok)throw new Error('Copy failed')
}
async function copyButton(b,value){const old=b.textContent;try{await copyText(value);b.textContent='Copied'}catch{b.textContent='Select manually'}setTimeout(()=>b.textContent=old,1600)}
document.querySelectorAll('[data-copy-value]').forEach(b=>b.onclick=()=>copyButton(b,b.dataset.copyValue));
document.querySelectorAll('[data-copy-totp]').forEach(b=>b.onclick=()=>copyButton(b,b.closest('[data-totp-id]').querySelector('[data-totp-code]').textContent));
const sessionOut=document.querySelector('[data-session-timer]');let idleDeadline=Number(document.body.dataset.sessionExpires||0)*1000,lastBeat=0;
async function activity(){if(!sessionOut)return;idleDeadline=Date.now()+15*60*1000;if(Date.now()-lastBeat<45000)return;lastBeat=Date.now();try{const r=await fetch('/heartbeat',{credentials:'same-origin'});if(!r.ok){location.href='/';return}const data=await r.json();if(data.csrf)document.querySelectorAll('input[name=csrf]').forEach(x=>x.value=data.csrf)}catch{}}
for(const event of ['pointerdown','keydown','mousemove','touchstart','scroll'])addEventListener(event,activity,{passive:true});
function sessionTick(){if(!idleDeadline||!sessionOut)return;const left=Math.max(0,Math.ceil((idleDeadline-Date.now())/1000)),m=Math.floor(left/60),s=left%60;sessionOut.textContent=`${m}:${String(s).padStart(2,'0')}`;if(!left)location.href='/'}
sessionTick();setInterval(sessionTick,1000);
document.querySelectorAll('[data-totp-id]').forEach(box=>{
  let left=Number(box.dataset.left),loading=false;const number=box.querySelector('[data-totp-left]'),ring=box.querySelector('.totp-ring'),code=box.querySelector('[data-totp-code]');
  function animate(){ring.style.animation='none';ring.offsetWidth;ring.style.setProperty('--progress',`${left/30*360}deg`);ring.style.setProperty('--duration',`${left}s`);ring.style.animation='totpDrain var(--duration) linear forwards'}animate();
  async function tick(){left--;if(left<=0&&!loading){loading=true;try{const r=await fetch(`/totp?id=${encodeURIComponent(box.dataset.totpId)}`,{credentials:'same-origin'});if(r.status===401||r.redirected){location.href='/';return}const data=await r.json();if(r.ok){code.textContent=data.code;left=data.left;animate()}}finally{loading=false}}number.textContent=Math.max(0,left)}
  setInterval(tick,1000);
});
const cards=[...document.querySelectorAll('.card')],search=document.querySelector('#search'),folderFilter=document.querySelector('#folder-filter'),userKey=document.body.dataset.userKey||'guest';let scope='all';
const vault=document.querySelector('[data-vault]');function setView(view){if(!vault)return;vault.dataset.view=view;localStorage.setItem(`kc-view-${userKey}`,view);document.querySelectorAll('[data-view]').forEach(b=>b.classList.toggle('active',b.dataset.view===view))}setView(localStorage.getItem(`kc-view-${userKey}`)||'grid');document.querySelectorAll('[data-view]').forEach(b=>b.onclick=()=>setView(b.dataset.view));
function filter(){const q=(search?.value||'').toLowerCase(),folder=(folderFilter?.value||'').toLowerCase();cards.forEach(c=>c.hidden=(scope!=='all'&&c.dataset.scope!==scope)||(folder&&c.dataset.folder!==folder)||!c.dataset.search.includes(q))}
function setFilter(value){scope=['all','mine','shared'].includes(value)?value:'all';document.querySelectorAll('[data-filter]').forEach(x=>x.classList.toggle('active',x.dataset.filter===scope));localStorage.setItem(`kc-filter-${userKey}`,scope);filter()}setFilter(localStorage.getItem(`kc-filter-${userKey}`)||'all');document.querySelectorAll('[data-filter]').forEach(b=>b.onclick=()=>setFilter(b.dataset.filter));search?.addEventListener('input',filter);
folderFilter?.addEventListener('change',filter);
