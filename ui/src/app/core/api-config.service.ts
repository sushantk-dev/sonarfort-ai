// src/app/core/api-config.service.ts
//
// Single source of truth for the backend base URL.
// All services read baseUrl() — changing host/port in Settings
// propagates everywhere instantly without a page reload.
//
import { Injectable, signal, computed, effect } from '@angular/core';

const STORAGE_KEY  = 'sonarfort_api';
const DEFAULT_HOST = 'localhost';
const DEFAULT_PORT = 8000;

@Injectable({ providedIn: 'root' })
export class ApiConfigService {

  /** Editable host — persisted to localStorage */
  apiHost = signal<string>(this._load('host') ?? DEFAULT_HOST);

  /** Editable port — persisted to localStorage */
  apiPort = signal<number>(Number(this._load('port') ?? DEFAULT_PORT));

  /** Derived base URL consumed by every service and component */
  baseUrl = computed(() => `http://${this.apiHost()}:${this.apiPort()}`);

  constructor() {
    // Keep localStorage in sync so the value survives page reload
    // even before the user saves to the backend
    effect(() => this._save('host', this.apiHost()));
    effect(() => this._save('port', String(this.apiPort())));
  }

  /** Called by SettingsStateService.save() to apply host + port together */
  apply(host: string, port: number) {
    this.apiHost.set(host?.trim() || DEFAULT_HOST);
    this.apiPort.set(port > 0 ? port : DEFAULT_PORT);
  }

  private _load(key: string): string | null {
    try { return localStorage.getItem(`${STORAGE_KEY}_${key}`); } catch { return null; }
  }

  private _save(key: string, value: string): void {
    try { localStorage.setItem(`${STORAGE_KEY}_${key}`, value); } catch {}
  }
}