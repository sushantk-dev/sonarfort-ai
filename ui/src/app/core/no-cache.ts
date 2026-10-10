// src/app/core/no-cache.ts
//
// App-wide "always fetch the latest" layer. Two halves, because this app
// talks to its backends two different ways:
//
//   1. noCacheInterceptor — every HttpClient request (ApiService, the
//      Fortify status polls in PipelineStateService, etc.).
//   2. installNoCacheFetch — every raw window.fetch() call (Fortify run
//      start, escalations, summary report, build estimate, cancel/delete…).
//
// Both add a unique `_ts` query param to GETs so no browser, proxy or CDN
// cache can ever answer with an old response. Deliberately does NOT add
// Cache-Control/Pragma *request* headers: those are non-simple headers and
// would trigger a CORS preflight on every call to the Sonar/Fortify servers
// (and fail outright if their CORS config doesn't allow them).
import { HttpInterceptorFn } from '@angular/common/http';

const TS_PARAM = '_ts';

function stamp(): string {
  return `${Date.now()}${Math.floor(Math.random() * 1000)}`;
}

/** HttpClient: cache-bust every GET/HEAD. */
export const noCacheInterceptor: HttpInterceptorFn = (req, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next(req);
  return next(req.clone({ setParams: { [TS_PARAM]: stamp() } }));
};

function withTs(url: string): string {
  try {
    const u = new URL(url, window.location.href);
    u.searchParams.set(TS_PARAM, stamp());
    // Keep relative URLs relative so same-origin calls stay untouched otherwise.
    return /^[a-z][a-z0-9+.-]*:/i.test(url) ? u.href : `${u.pathname}${u.search}${u.hash}`;
  } catch {
    return url;
  }
}

/**
 * Patch window.fetch once so every call bypasses the HTTP cache
 * (`cache: 'no-store'`) and every GET gets a unique `_ts` param.
 * Also wipes any Cache Storage entries left by an old service worker.
 */
export function installNoCacheFetch(): void {
  if (typeof window === 'undefined' || (window as any).__sfNoCacheFetch) return;
  (window as any).__sfNoCacheFetch = true;

  const original = window.fetch.bind(window);

  window.fetch = (input: RequestInfo | URL, init: RequestInit = {}) => {
    const isRequestObj = typeof Request !== 'undefined' && input instanceof Request;
    const rawUrl = typeof input === 'string' ? input
                 : input instanceof URL      ? input.href
                 : (input as Request).url;

    // Object URLs / data URLs — nothing to cache-bust.
    if (/^(blob|data):/i.test(rawUrl)) return original(input, init);

    const method = (init.method ?? (isRequestObj ? (input as Request).method : 'GET')).toUpperCase();
    const target: RequestInfo | URL =
      method === 'GET' && !isRequestObj ? withTs(rawUrl) : input;

    return original(target, { ...init, cache: 'no-store' });
  };

  try {
    if ('caches' in window) {
      caches.keys().then(keys => keys.forEach(k => caches.delete(k))).catch(() => {});
    }
  } catch { /* Cache Storage unavailable — nothing to clear */ }
}
