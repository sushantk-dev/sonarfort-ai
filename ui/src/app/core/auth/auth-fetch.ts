// src/app/core/auth/auth-fetch.ts
// Some components call the backend with window.fetch() instead of HttpClient,
// so the auth interceptor never sees those requests. This patch adds the same
// "Authorization: Bearer <token>" header to them.
//
// The token is only sent to this app's own backend: same-origin URLs (through
// nginx: /api/..., /fortify/...) or localhost (local dev without the proxy).
// It is never attached to the SSO endpoints or any other host.

const TOKEN_KEY = 'access_token'; // same key AuthService writes
const PUBLIC_PATHS = ['/auth/config', '/auth/token', '/auth/refresh', '/health'];

export function installAuthFetch(): void {
  const original = window.fetch.bind(window);

  window.fetch = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const rawUrl =
      typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

    let url: URL;
    try {
      url = new URL(rawUrl, window.location.href);
    } catch {
      return original(input, init);
    }

    const ownBackend =
      url.origin === window.location.origin ||
      url.hostname === 'localhost' ||
      url.hostname === '127.0.0.1';
    const isPublic = PUBLIC_PATHS.some(p => url.pathname.endsWith(p));

    let token: string | null = null;
    try {
      token = localStorage.getItem(TOKEN_KEY);
    } catch {
      /* storage unavailable */
    }

    if (!token || !ownBackend || isPublic) return original(input, init);

    const headers = new Headers(
      init?.headers ?? (input instanceof Request ? input.headers : undefined),
    );
    if (!headers.has('Authorization')) headers.set('Authorization', `Bearer ${token}`);
    return original(input, { ...init, headers });
  };
}
