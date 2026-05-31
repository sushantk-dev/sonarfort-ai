// src/app/core/api-config.service.ts
//
// Single source of truth for backend base URLs.
//
// Both Sonar and Fortify share one server (port 8000) by default.
// If they are split into separate processes, set fortifyPort to the
// Fortify server's port — all Fortify API calls will route there
// automatically while Sonar calls continue using sonarBaseUrl.
//
import { Injectable, signal, computed, effect } from '@angular/core';

const STORAGE_KEY    = 'sonarfort_api';
const DEFAULT_HOST   = 'localhost';
const DEFAULT_PORT   = 8000;  // shared / Sonar port
const DEFAULT_F_PORT = 8001;  // Fortify port — same by default

@Injectable({ providedIn: 'root' })
export class ApiConfigService {

  // ── Shared / Sonar server ─────────────────────────────────────────────────
  apiHost = signal<string>(this._load('host') ?? DEFAULT_HOST);
  apiPort = signal<number>(Number(this._load('port') ?? DEFAULT_PORT));

  // ── Fortify server — optional separate port ───────────────────────────────
  /** When null/undefined, Fortify falls back to the shared apiPort */
  fortifyPort = signal<number | null>(this._loadFortifyPort());

  // ── Derived URLs ──────────────────────────────────────────────────────────
  /** Base URL for Sonar + shared API calls */
  sonarBaseUrl = computed(() =>
    `http://${this.apiHost()}:${this.apiPort()}`
  );

  /** Base URL for Fortify API calls — uses fortifyPort when set */
  fortifyBaseUrl = computed(() => {
    const fp = this.fortifyPort();
    const port = (fp !== null && fp > 0) ? fp : this.apiPort();
    return `http://${this.apiHost()}:${port}`;
  });

  /** Convenience alias — same as sonarBaseUrl, used by ApiService */
  baseUrl = this.sonarBaseUrl;

  /** True when Fortify is running on a different port from Sonar */
  isSplit = computed(() => {
    const fp = this.fortifyPort();
    return fp !== null && fp > 0 && fp !== this.apiPort();
  });

  constructor() {
    effect(() => this._save('host',         this.apiHost()));
    effect(() => this._save('port',         String(this.apiPort())));
    effect(() => this._save('fortify_port', this.fortifyPort() !== null ? String(this.fortifyPort()) : ''));
  }

  /** Called by SettingsStateService.save() */
  apply(host: string, port: number, fortifyPort: number | null) {
    this.apiHost.set(host?.trim() || DEFAULT_HOST);
    this.apiPort.set(port > 0 ? port : DEFAULT_PORT);
    // null means "use shared port" — store as null so fortifyBaseUrl falls back
    this.fortifyPort.set(
      fortifyPort !== null && fortifyPort > 0 && fortifyPort !== port
        ? fortifyPort
        : null
    );
  }

  private _loadFortifyPort(): number | null {
    try {
      const raw = localStorage.getItem(`${STORAGE_KEY}_fortify_port`);
      if (!raw) return null;
      const n = Number(raw);
      return n > 0 ? n : null;
    } catch { return null; }
  }

  private _load(key: string): string | null {
    try { return localStorage.getItem(`${STORAGE_KEY}_${key}`); } catch { return null; }
  }

  private _save(key: string, value: string): void {
    try { localStorage.setItem(`${STORAGE_KEY}_${key}`, value); } catch {}
  }
}