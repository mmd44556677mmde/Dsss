'use strict';
const $ = id => document.getElementById(id);
let csrf = '';
async function api(url, options = {}) {
  const response = await fetch(url, { ...options, headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(csrf ? { 'X-CSRF-Token': csrf } : {}), ...options.headers } });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) { const error = new Error(data.error || 'خطایی رخ داد.'); error.status = response.status; throw error; }
  return data;
}
let toastTimer;
function notify(message) { $('toast').textContent = message; $('toast').classList.remove('hidden'); clearTimeout(toastTimer); toastTimer = setTimeout(() => $('toast').classList.add('hidden'), 3500); }
function view(authenticated) { $('login').classList.toggle('hidden', authenticated); $('dashboard').classList.toggle('hidden', !authenticated); $('logout').classList.toggle('hidden', !authenticated); }
function button(text, className, action) { const b = document.createElement('button'); b.className = className; b.textContent = text; b.onclick = action; return b; }
async function refresh() {
  const data = await api('/api/clients');
  $('count').textContent = data.clients.length.toLocaleString('fa-IR'); $('count-pill').textContent = data.clients.length.toLocaleString('fa-IR');
  $('core').textContent = data.core ? 'فعال' : 'غیرفعال';
  $('empty').classList.toggle('hidden', data.clients.length > 0); $('list').replaceChildren();
  for (const c of data.clients.slice().reverse()) {
    const item = document.createElement('div'); item.className = 'item card';
    const icon = document.createElement('div'); icon.className = 'item-icon'; icon.textContent = '⌁';
    const info = document.createElement('div'); info.className = 'item-info';
    const title = document.createElement('div'); title.className = 'item-title'; title.textContent = c.name;
    const date = document.createElement('div'); date.className = 'item-date'; date.textContent = `ساخته شده در ${new Date(c.createdAt).toLocaleDateString('fa-IR')} · بدون محدودیت حجم و زمان`;
    info.append(title, date);
    const actions = document.createElement('div'); actions.className = 'item-buttons';
    const copy = button('کپی لینک', 'outline', async () => { try { await navigator.clipboard.writeText(c.link); notify('لینک کانفیگ کپی شد.'); } catch { window.prompt('لینک را کپی کنید:', c.link); } });
    const remove = button('حذف', 'outline danger', async () => { if (!confirm(`کانفیگ «${c.name}» حذف شود؟ اتصال‌های فعال قطع می‌شوند.`)) return; remove.disabled = true; try { await api(`/api/clients/${encodeURIComponent(c.id)}`, { method: 'DELETE' }); await refresh(); notify('کانفیگ حذف شد.'); } catch (e) { notify(e.message); remove.disabled = false; } });
    actions.append(copy, remove); item.append(icon, info, actions); $('list').append(item);
  }
}
$('login-form').addEventListener('submit', async event => { event.preventDefault(); const submit = event.submitter; submit.disabled = true; try { const data = await api('/api/login', { method: 'POST', body: JSON.stringify({ password: $('password').value }) }); csrf = data.csrf; $('password').value = ''; await refresh(); view(true); } catch (e) { notify(e.message); } finally { submit.disabled = false; } });
$('logout').onclick = async () => { try { await api('/api/logout', { method: 'POST' }); csrf = ''; view(false); } catch (e) { notify(e.message); } };
function showAdd() { $('add-form').classList.remove('hidden'); $('name').focus(); }
$('show-add').onclick = showAdd; $('empty-add').onclick = showAdd;
$('cancel-add').onclick = () => { $('add-form').classList.add('hidden'); $('name').value = ''; };
$('add-form').addEventListener('submit', async event => { event.preventDefault(); const submit = event.submitter; submit.disabled = true; try { await api('/api/clients', { method: 'POST', body: JSON.stringify({ name: $('name').value }) }); $('name').value = ''; $('add-form').classList.add('hidden'); await refresh(); notify('کانفیگ ساخته شد.'); } catch (e) { notify(e.message); } finally { submit.disabled = false; } });
(async () => { try { csrf = (await api('/api/session')).csrf; await refresh(); view(true); } catch { view(false); } })();
