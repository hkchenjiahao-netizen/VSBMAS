// Shared fetch / WebSocket helpers
const API = '/api';

export async function api(method, path, body) {
  const res = await fetch(API + path, {
    method,
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!res.ok) {
    const msg = data.error != null
      ? (typeof data.error === 'string' ? data.error : JSON.stringify(data))
      : (data.raw || text);
    throw Object.assign(new Error(msg), { status: res.status, data });
  }
  return data;
}

export class EventStream extends EventTarget {
  constructor() {
    super();
    this.seq = 0;
    this.connect();
  }
  connect() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${location.host}/ws`);
    this.ws = ws;
    ws.onopen    = () => this.dispatchEvent(new Event('open'));
    ws.onclose   = () => {
      this.dispatchEvent(new Event('close'));
      setTimeout(() => this.connect(), 2000);
    };
    ws.onerror   = (e) => this.dispatchEvent(new Event('error'));
    ws.onmessage = (m) => {
      try {
        const ev = JSON.parse(m.data);
        if (typeof ev.seq === 'number') this.seq = Math.max(this.seq, ev.seq);
        this.dispatchEvent(new CustomEvent('event', { detail: ev }));
      } catch {}
    };
  }
  send(obj) {
    if (this.ws.readyState === 1) this.ws.send(JSON.stringify(obj));
  }
}

export function $(sel, root = document) { return root.querySelector(sel); }
export function $$(sel, root = document) { return [...root.querySelectorAll(sel)]; }

export function debounce(fn, ms = 200) {
  let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}
