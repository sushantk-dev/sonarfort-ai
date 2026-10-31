// src/app/core/auth/auth.service.ts
// Scramble ID SSO — centralized auth service (signals-based, Angular 17+)
// Covers: config loading, PKCE login, callback, token storage, auto refresh, logout.

import { Injectable, computed, inject, signal } from '@angular/core';
import { HttpClient, HttpContext, HttpContextToken, HttpErrorResponse } from '@angular/common/http';
import { Router } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { ApiConfigService } from '../api-config.service';

/** Marks requests the interceptor must not try to refresh-and-retry (avoids loops). */
export const SKIP_REFRESH = new HttpContextToken<boolean>(() => false);

interface SsoConfig {
  authorization_url: string;
  logout_url: string;
  client_id: string;
  redirect_uri: string;
  issuer: string;
}

interface TokenResponse {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  expires_in: number;
}

export interface AppUser {
  id: string;
  email?: string;
  first_name?: string;
  last_name?: string;
  groups: string[];
  roles: string[];
}

// localStorage keys (per the integration page)
const K = {
  token: 'access_token',            // the id_token — used for API auth
  oauthToken: 'oauth_access_token', // OAuth access token (optional)
  refresh: 'refresh_token',
  expiresAt: 'token_expires_at',
  returnUrl: 'returnUrl',
} as const;
// One-time PKCE values live in sessionStorage
const S = { verifier: 'pkce_verifier', state: 'oauth_state' } as const;

const MAX_REFRESH_ATTEMPTS = 10;

@Injectable({ providedIn: 'root' })
export class AuthService {
  private http = inject(HttpClient);
  private router = inject(Router);
  private apiCfg = inject(ApiConfigService);

  /** FortifyAI backend hosting /auth/*, /me and /logout. Same base URL the
   *  rest of the app uses: http://localhost:8001 under ng serve, and
   *  <host>/fortify when deployed (nginx strips the prefix). */
  private get api(): string {
    return this.apiCfg.fortifyBaseUrl();
  }

  private config: SsoConfig | null = null;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private refreshAttempts = 0;
  private refreshInFlight: Promise<boolean> | null = null;

  readonly token = signal<string | null>(localStorage.getItem(K.token));
  private readonly expiresAt = signal<number>(Number(localStorage.getItem(K.expiresAt) ?? 0));
  readonly user = signal<AppUser | null>(null);

  readonly isLoggedIn = computed(() => !!this.token() && this.expiresAt() > Date.now());
  readonly roles = computed(() => this.user()?.roles ?? []);

  // ── Startup: restore session after page reload (call from APP_INITIALIZER) ──
  async init(): Promise<void> {
    if (this.isLoggedIn()) {
      this.scheduleRefresh((this.expiresAt() - Date.now()) / 1000);
      await this.loadUser().catch(() => this.refresh());
    } else if (localStorage.getItem(K.refresh)) {
      await this.refresh();
    }
  }

  // ── Configuration loading ───────────────────────────────────────────────────
  async loadConfig(): Promise<SsoConfig> {
    if (!this.config) {
      this.config = await firstValueFrom(this.http.get<SsoConfig>(`${this.api}/auth/config`));
    }
    return this.config;
  }

  // ── Login flow (PKCE) ───────────────────────────────────────────────────────
  async login(): Promise<void> {
    const cfg = await this.loadConfig();
    const verifier = randomString(64);
    const state = randomString(32);
    sessionStorage.setItem(S.verifier, verifier);
    sessionStorage.setItem(S.state, state);

    const params = new URLSearchParams({
      client_id: cfg.client_id,
      redirect_uri: cfg.redirect_uri,
      scope: 'openid groups',
      response_type: 'code',
      code_challenge: await pkceChallenge(verifier),
      code_challenge_method: 'S256',
      state,
    });
    window.location.href = `${cfg.authorization_url}?${params}`;
  }

  // ── Callback handling ───────────────────────────────────────────────────────
  async handleCallback(): Promise<void> {
    const q = new URLSearchParams(window.location.search);
    if (q.get('error')) throw new Error(q.get('error_description') ?? q.get('error')!);

    const code = q.get('code');
    if (!code) throw new Error('No authorization code in callback URL');
    if (q.get('state') !== sessionStorage.getItem(S.state)) throw new Error('Invalid state');

    const verifier = sessionStorage.getItem(S.verifier) ?? undefined;
    sessionStorage.removeItem(S.verifier);
    sessionStorage.removeItem(S.state);

    const tokens = await firstValueFrom(
      this.http.post<TokenResponse>(`${this.api}/auth/token`, { code, code_verifier: verifier }),
    );
    this.storeTokens(tokens);
    await this.loadUser();

    const returnUrl = localStorage.getItem(K.returnUrl) || '/';
    localStorage.removeItem(K.returnUrl);
    await this.router.navigateByUrl(returnUrl, { replaceUrl: true });
  }

  async loadUser(): Promise<AppUser> {
    const u = await firstValueFrom(
      this.http.get<AppUser>(`${this.api}/me`, { context: new HttpContext().set(SKIP_REFRESH, true) }),
    );
    this.user.set(u);
    return u;
  }

  /** For guards: make sure the user (roles) is loaded. */
  async ensureUser(): Promise<AppUser | null> {
    if (this.user()) return this.user();
    if (!this.isLoggedIn()) return null;
    return this.loadUser().catch(() => null);
  }

  // ── Token storage ───────────────────────────────────────────────────────────
  private storeTokens(t: TokenResponse): void {
    // id_token is the primary token. The page warns SSO may omit it on refresh —
    // if that happens, ask the SSO team; we fall back to the access token meanwhile.
    const primary = t.id_token ?? t.access_token;
    if (!t.id_token) console.warn('[auth] SSO did not return id_token; using access_token');

    const expiresAt = Date.now() + t.expires_in * 1000;
    localStorage.setItem(K.token, primary);
    localStorage.setItem(K.oauthToken, t.access_token);
    if (t.refresh_token) localStorage.setItem(K.refresh, t.refresh_token);
    localStorage.setItem(K.expiresAt, String(expiresAt));

    this.token.set(primary);
    this.expiresAt.set(expiresAt);
    this.scheduleRefresh(t.expires_in);
  }

  // ── Automatic token refresh ─────────────────────────────────────────────────
  private scheduleRefresh(expiresInSec: number): void {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    const delayMs = Math.max(expiresInSec * 0.75 * 1000, 5_000); // 75% of lifetime
    this.refreshTimer = setTimeout(() => this.refresh(), delayMs);
  }

  /** Refreshes tokens. Concurrent callers share one in-flight refresh. */
  refresh(): Promise<boolean> {
    this.refreshInFlight ??= this.doRefresh().finally(() => (this.refreshInFlight = null));
    return this.refreshInFlight;
  }

  private async doRefresh(): Promise<boolean> {
    const refreshToken = localStorage.getItem(K.refresh);
    if (!refreshToken) {
      // Never signed in (or storage cleared): nothing to end at the SSO side,
      // so just drop any stale tokens and go to the login page.
      this.clearSession();
      if (!this.router.url.startsWith('/login') && !this.router.url.startsWith('/callback')) {
        await this.router.navigate(['/login']);
      }
      return false;
    }

    while (this.refreshAttempts < MAX_REFRESH_ATTEMPTS) {
      this.refreshAttempts++;
      try {
        const tokens = await firstValueFrom(
          this.http.post<TokenResponse>(`${this.api}/auth/refresh`, { refresh_token: refreshToken }),
        );
        this.storeTokens(tokens);
        await this.loadUser();          // verify new token works
        this.refreshAttempts = 0;       // reset on success
        return true;
      } catch (e) {
        const networkError = e instanceof HttpErrorResponse && (e.status === 0 || e.status >= 500);
        if (!networkError) break;       // refresh token rejected → no point retrying
        await sleep(Math.min(1000 * 2 ** (this.refreshAttempts - 1), 30_000)); // exponential backoff
      }
    }
    this.refreshAttempts = 0;
    await this.logout();
    return false;
  }

  /** Removes tokens (keeps returnUrl) and resets in-memory auth state. */
  private clearSession(): void {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    [K.token, K.oauthToken, K.refresh, K.expiresAt].forEach((k) => localStorage.removeItem(k));
    this.token.set(null);
    this.expiresAt.set(0);
    this.user.set(null);
  }

  // ── Logout ──────────────────────────────────────────────────────────────────
  async logout(): Promise<void> {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);

    const current = this.router.url;
    if (current && !current.startsWith('/login') && !current.startsWith('/callback')) {
      localStorage.setItem(K.returnUrl, current);
    }

    // Call backend /logout while the token is still available (best effort)
    if (this.token()) {
      await firstValueFrom(
        this.http.post(`${this.api}/logout`, {}, { context: new HttpContext().set(SKIP_REFRESH, true) }),
      ).catch(() => undefined);
    }

    this.clearSession();

    const cfg = await this.loadConfig().catch(() => null);
    if (cfg?.logout_url) {
      // SSO redirects back to the app login page (redirect target is configured with the SSO team)
      window.location.href = cfg.logout_url;
    } else {
      await this.router.navigate(['/login']);
    }
  }
}

// ── PKCE helpers ──────────────────────────────────────────────────────────────
function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomString(len: number): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(len))).slice(0, len);
}

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64Url(new Uint8Array(digest));
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
