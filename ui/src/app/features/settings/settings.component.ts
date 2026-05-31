// src/app/features/settings/settings.component.ts
import { Component, inject, signal, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiConfigService } from '../../core/api-config.service';
import {
  SettingsStateService,
  VERTEX_MODELS,
  EMBEDDING_MODELS,
} from '../../core/settings-state.service';

interface Tab { id: string; label: string; icon: string; }

// Shape returned by POST /auth/token
interface OAuthTokenResult {
  access_token: string;
  token_type:   string;
  expires_in:   number;
  scope?:       string;
}

@Component({
  selector: 'app-settings',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './settings.component.html',
  styleUrl:    './settings.component.scss',
})
export class SettingsComponent implements OnInit {
  st     = inject(SettingsStateService);
  private apiCfg = inject(ApiConfigService);
  active = signal('pipeline');

  readonly vertexModels    = VERTEX_MODELS;
  readonly embeddingModels = EMBEDDING_MODELS;

  tabs: Tab[] = [
    { id: 'pipeline',     label: 'Pipeline',     icon: 'M3 6h18M3 12h18M3 18h18' },
    { id: 'integrations', label: 'Integrations', icon: 'M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71' },
    { id: 'agents',       label: 'Agents',       icon: 'M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z' },
  ];

  ngOnInit() { this.st.load(); }

  get cfg()         { return this.st.cfg(); }
  get tokenStatus() { return this.st.tokenStatus(); }
  get saving()      { return this.st.saving(); }
  get saved()       { return this.st.saved(); }
  get saveErr()     { return this.st.saveErr(); }
  get loadErr()     { return this.st.loadErr(); }

  patch(field: string, value: any) { this.st.patch({ [field]: value } as any); }
  save() { this.st.save(); }

  isEditing(field: string)     { return this.st.isEditing(field); }
  startEditing(field: string)  { this.st.startEditing(field); }
  cancelEditing(field: string) { this.st.cancelEditing(field); }

  // ── Fortify OAuth refresh ─────────────────────────────────────────────────
  showOAuthForm  = signal(false);
  oauthUsername  = signal('');
  oauthPassword  = signal('');
  oauthScope     = signal('api-tenant');
  oauthWriteToEnv = signal(true);
  oauthLoading   = signal(false);
  oauthResult    = signal<OAuthTokenResult | null>(null);
  oauthError     = signal('');

  /**
   * POST /auth/token → fetch a fresh Fortify Bearer token.
   * On success: updates the in-memory fortifyToken config field and
   * shows the token expiry. On failure: surfaces the API error message.
   */
  async refreshFortifyToken(): Promise<void> {
    this.oauthLoading.set(true);
    this.oauthError.set('');
    this.oauthResult.set(null);

    const body: Record<string, unknown> = {
      username:     this.oauthUsername()   || null,
      password:     this.oauthPassword()   || null,
      scope:        this.oauthScope()      || null,
      write_to_env: this.oauthWriteToEnv(),
    };

    try {
      const resp = await fetch(`${this.apiCfg.fortifyBaseUrl()}/auth/token`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
      });

      const data = await resp.json();

      if (!resp.ok) {
        // FastAPI error shape: { detail: string }
        throw new Error(data?.detail ?? `HTTP ${resp.status}`);
      }

      const result: OAuthTokenResult = {
        access_token: data.access_token,
        token_type:   data.token_type   ?? 'Bearer',
        expires_in:   data.expires_in   ?? 0,
        scope:        data.scope,
      };

      this.oauthResult.set(result);

      // Mirror the new token into the settings config so the UI reflects it
      // immediately without requiring a page reload
      this.patch('fortifyToken', result.access_token);
      this.st.tokenStatus.update(s => ({ ...s, fortifyToken: true }));

    } catch (err: any) {
      this.oauthError.set(err?.message ?? 'Token refresh failed');
    } finally {
      this.oauthLoading.set(false);
    }
  }
}