// src/app/core/api-config.service.ts
//
// Single source of truth for backend base URLs.
//
// Sonar and Fortify now share one fixed host with no port. Sonar calls
// go straight to the host; Fortify calls go to the same host under the
// /fortify path.
//
import { Injectable, signal, computed, effect } from '@angular/core';

const STORAGE_KEY   = 'sonarfort_api';
// DEFAULT_HOST resolved at runtime so the same Angular build works in every
// environment without a rebuild. Precedence:
//   1. window.__FORTIFYAI_API_HOST__  — injected by nginx entrypoint in GKE
//   2. localStorage                   — saved from a prior Settings change
//   3. Hardcoded fallback             — for local dev
const _w = (typeof window !== 'undefined' ? window : {}) as any;
const DEFAULT_HOST  = _w.__FORTIFYAI_API_HOST__ ?? 'https://sonarfort-ai.use1.npe.usis.gcp.efx';
const FORTIFY_PATH  = (_w.__FORTIFYAI_FORTIFY_PATH__ ?? '/fortify') as string;

@Injectable({ providedIn: 'root' })
export class ApiConfigService {

  // ── Shared host — no port required ────────────────────────────────────────
  apiHost = signal<string>(this._load('host') ?? DEFAULT_HOST);

  // ── Legacy port signals — kept only so existing callers (e.g.
  //    SettingsStateService) that still read/pass apiPort / fortifyPort
  //    keep compiling. They no longer affect URL construction. ─────────────
  apiPort = signal<number>(0);
  fortifyPort = signal<number | null>(null);

  // ── Derived URLs ──────────────────────────────────────────────────────────
  /** Base URL for Sonar + shared API calls */
  sonarBaseUrl = computed(() => this._normalize(this.apiHost()));

  /** Base URL for Fortify API calls — same host, under /fortify, no port */
  fortifyBaseUrl = computed(() => `${this._normalize(this.apiHost())}${FORTIFY_PATH}`);

  /** Convenience alias — same as sonarBaseUrl, used by ApiService */
  baseUrl = this.sonarBaseUrl;

  /** Always false now — Sonar and Fortify always share the same host */
  isSplit = computed(() => false);

  constructor() {
    effect(() => this._save('host', this.apiHost()));
  }

  /**
   * Called by SettingsStateService.save(). Port args are accepted for
   * backward compatibility but ignored — no port is needed.
   */
  apply(host: string, _port?: number, _fortifyPort?: number | null) {
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