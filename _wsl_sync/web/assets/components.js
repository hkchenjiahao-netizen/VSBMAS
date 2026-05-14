import { $ } from './common.js';

/** Simple toast: toast('message', 'ok'|'warn'|'danger', 3000) */
export function toast(msg, level = 'ok', timeout = 3000) {
  let host = document.getElementById('toast-host');
  if (!host) {
    host = document.createElement('div');
    host.id = 'toast-host';
    host.className = 'fixed top-4 right-4 z-50 flex flex-col gap-2 pointer-events-none';
    document.body.appendChild(host);
  }
  const color = level === 'danger' ? 'bg-red-600' : level === 'warn' ? 'bg-amber-500' : 'bg-emerald-600';
  const el = document.createElement('div');
  el.className = `${color} text-white px-4 py-2 rounded shadow-lg pointer-events-auto transition-opacity`;
  el.textContent = msg;
  host.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, timeout);
}

export function hexCard({ title, hex, sizeBytes, meta }) {
  const preview = hex.length > 96 ? hex.slice(0, 96) + '…' : hex;
  const el = document.createElement('div');
  el.className = 'border rounded-lg p-3 bg-slate-50';
  el.innerHTML = `
    <div class="flex justify-between items-start mb-1">
      <div class="font-semibold">${title}</div>
      <div class="text-xs text-slate-500">${sizeBytes ?? '-'} bytes</div>
    </div>
    <div class="hex-monospace text-xs text-slate-700">${preview}</div>
    ${meta ? `<div class="text-xs text-slate-500 mt-1">${meta}</div>` : ''}
    <button class="mt-2 text-xs text-indigo-600 hover:underline">copy full</button>
  `;
  el.querySelector('button').onclick = async () => {
    await navigator.clipboard.writeText(hex);
    toast('copied to clipboard', 'ok', 1500);
  };
  return el;
}

export function phaseBadge(phase) {
  const map = {
    BidCollection:   ['Bid collection', 'bg-blue-100   text-blue-700'],
    BidSelfOpening:  ['Self-open',      'bg-amber-100  text-amber-700'],
    BidForceOpening: ['Force-open',     'bg-rose-100   text-rose-700'],
    Complete:        ['Complete',       'bg-emerald-100 text-emerald-700'],
  };
  const [txt, cls] = map[phase] || [phase, 'bg-slate-100 text-slate-700'];
  const el = document.createElement('span');
  el.className = `inline-block px-2 py-0.5 text-xs rounded ${cls}`;
  el.textContent = txt;
  return el;
}
