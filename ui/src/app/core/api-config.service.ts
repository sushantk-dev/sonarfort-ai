// src/app/core/api-config.service.ts
//
// Single source of truth for backend base URLs.
//
// In deployed environments, Sonar and Fortify share one fixed host with no
// port: Sonar calls go straight to the host; Fortify calls go to the same
// host under the /fortify path.
//
// In local development (ng serve, no injected host, nothing saved yet),
// the two backends run as separate local processes, so we split them:
//   Sonar   -> http://localhost:8000
//   Fortify -> http://localhost:8001
//
import { Injectable, signal, computed, effect, isDevMode } from '@angular/core';

const STORAGE_KEY   = 'sonarfort_api';
// DEFAULT_HOST resolved at runtime so the same Angular build works in every
// environment without a rebuild. Precedence:
//   1. window.__FORTIFYAI_API_HOST__  — injected by nginx entrypoint in GKE
//   2. localStorage                   — saved from a prior Settings change
//   3. Dev-mode local default         — split localhost:8000 / :8001
//   4. Hardcoded fallback             — non-dev build with nothing configured
const _w = (typeof window !== 'undefined' ? window : {}) as any;

const DEV_SONAR_HOST    = 'http://localhost:8000';
const DEV_FORTIFY_HOST  = 'http://localhost:8001';

const PROD_FALLBACK_HOST = 'https://sonarfort-ai.use1.npe.usis.gcp.efx';

// Only fall back to the dev split when nothing has been explicitly
// configured — an injected host or a saved Settings value always wins.
const _hasInjectedHost = !!_w.__FORTIFYAI_API_HOST__;
const _isDevDefault = isDevMode() && !_hasInjectedHost;
const DEFAULT_HOST = _w.__FORTIFYAI_API_HOST__
  ?? (_isDevDefault ? DEV_SONAR_HOST : PROD_FALLBACK_HOST);

// Fortify's path suffix — empty in the dev split (separate localhost:8001
// host needs no path), '/fortify' otherwise (shared host, deployed envs).
const FORTIFY_PATH = _isDevDefault
  ? ''
  : ((_w.__FORTIFYAI_FORTIFY_PATH__ ?? '/fortify') as string);

@Injectable({ providedIn: 'root' })
export class ApiConfigService {

  // ── Shared host — no port required in deployed environments ───────────────
  apiHost = signal<string>(this._load('host') ?? DEFAULT_HOST);

  // ── Dev-mode split override for Fortify. Only used when nothing has been
  //    explicitly configured (no injected host, no saved localStorage host,
  //    and no Settings-page apiHost edit has occurred). ─────────────────────
  private _devSplitActive = isDevMode() && !_hasInjectedHost && this._load('host') === null;
  private _devFortifyHost = signal<string>(this._load('fortifyHost') ?? DEV_FORTIFY_HOST);

  // ── Legacy port signals — kept only so existing callers (e.g.
  //    SettingsStateService) that still read/pass apiPort / fortifyPort
  //    keep compiling. They no longer affect URL construction. ─────────────
  apiPort = signal<number>(0);
  fortifyPort = signal<number | null>(null);

  // ── Derived URLs ──────────────────────────────────────────────────────────
  /** Base URL for Sonar + shared API calls */
  sonarBaseUrl = computed(() => this._normalize(this.apiHost()));

  /** Base URL for Fortify API calls — separate localhost:8001 host (no
   *  path) in local dev; shared host + /fortify path in deployed envs.
   *  FORTIFY_PATH is already '' whenever the dev split applies, so
   *  /fortify is never appended in development mode either way. */
  fortifyBaseUrl = computed(() => this._devSplitActive
    ? this._normalize(this._devFortifyHost())
    : `${this._normalize(this.apiHost())}${FORTIFY_PATH}`);

  /** Convenience alias — same as sonarBaseUrl, used by ApiService */
  baseUrl = this.sonarBaseUrl;

  /** True only in the local-dev split (separate Sonar/Fortify hosts) */
  isSplit = computed(() => this._devSplitActive);

  constructor() {
    effect(() => this._save('host', this.apiHost()));
    effect(() => { if (this._devSplitActive) this._save('fortifyHost', this._devFortifyHost()); });
  }

  /**
   * Called by SettingsStateService.save(). Port args are accepted for
   * backward compatibility but ignored — no port is needed. Saving a host
   * here (even the same dev value) opts the browser out of the automatic
   * dev split; it now points explicitly at whatever host was entered, for
   * both Sonar and Fortify.
   */
  apply(host: string, _port?: number, _fortifyPort?: number | null) {
    this._devSplitActive = false;
    this.apiHost.set(host?.trim() || DEFAULT_HOST);
  }

  private _normalize(host: string): string {
    // Strip trailing slash(es) so paths can be appended safely
    return host.replace(/\/+$/, '');
  }

  private _load(key: string): string | null {
    try { return localStorage.getItem(`${STORAGE_KEY}_${key}`); } catch { return null; }
  }

  private _save(key: string, value: string): void {
    try { localStorage.setItem(`${STORAGE_KEY}_${key}`, value); } catch {}
  }
}