// src/app/core/settings-state.service.ts
import { Injectable, inject, signal, computed } from '@angular/core';
import { forkJoin, of } from 'rxjs';
import { switchMap, catchError } from 'rxjs/operators';
import { ApiService } from './api.service';
import { ApiConfigService } from './api-config.service';

export interface AppConfig {
  apiHost:        string;  // fixed base host — no port, Fortify shares it under /fortify
  gcpProject:     string;
  gcpLocation:    string;
  model:          string;
  maxIssues:      number;
  maxTokens:      number;
  highThresh:     number;
  medThresh:      number;
  githubToken:    string;
  sonarToken:     string;
  sonarOrg:       string;
  fortifyApiToken:   string;
  fortifyHostUrl: string;
  plannerTemp:    number;
  generatorTemp:  number;
  maxRetries:     number;
  chromaPath:     string;
  embeddingModel: string;
  ragTopK:        number;
  adrOutputDir:   string;
}

export const VERTEX_MODELS = [
  { value: 'gemini-2.5-flash',     label: 'Gemini 2.5 Flash  (default)' },
  { value: 'gemini-2.5-pro',       label: 'Gemini 2.5 Pro' },
  { value: 'gemini-2.0-flash',     label: 'Gemini 2.0 Flash' },
  { value: 'gemini-1.5-pro-002',   label: 'Gemini 1.5 Pro 002' },
  { value: 'gemini-1.5-flash-002', label: 'Gemini 1.5 Flash 002' },
  { value: 'gemini-1.5-pro',       label: 'Gemini 1.5 Pro' },
  { value: 'gemini-1.5-flash',     label: 'Gemini 1.5 Flash' },
];

export const EMBEDDING_MODELS = [
  { value: 'text-embedding-005',  label: 'text-embedding-005  (default)' },
  { value: 'text-embedding-004',  label: 'text-embedding-004' },
  { value: 'textembedding-gecko', label: 'textembedding-gecko' },
  { value: 'all-MiniLM-L6-v2',   label: 'all-MiniLM-L6-v2 (local)' },
];

// Which tokens are set on the backend (masked '***') vs empty
export interface TokenStatus {
  githubToken:  boolean;   // true = set in .env
  sonarToken:   boolean;
  fortifyApiToken: boolean;
}

@Injectable({ providedIn: 'root' })
export class SettingsStateService {
  private apiSvc  = inject(ApiService);
  private apiCfg  = inject(ApiConfigService);

  cfg = signal<AppConfig>({
    apiHost:        'https://sonarfort-ai.use1.npe.usis.gcp.efx',
    gcpProject:     '',
    gcpLocation:    'us-central1',
    model:          'gemini-2.5-flash',
    maxIssues:      1,
    maxTokens:      8192,
    highThresh:     0.80,
    medThresh:      0.50,
    githubToken:    '',
    sonarToken:     '',
    sonarOrg:       'https://sonarcloud.io',
    fortifyApiToken:   '',
    fortifyHostUrl: 'https://api.ams.fortify.com',
    plannerTemp:    0.1,
    generatorTemp:  0.3,
    maxRetries:     1,
    chromaPath:     './chroma_db',
    embeddingModel: 'text-embedding-005',
    ragTopK:        3,
    adrOutputDir:   '/tmp/fortifyai',
  });

  // Which tokens are already set on the backend
  tokenStatus = signal<TokenStatus>({
    githubToken:  false,
    sonarToken:   false,
    fortifyApiToken: false,
  });

  // Track which token fields the user is actively editing
  // (so we show the input instead of the masked placeholder)
  editingTokens = signal<Set<string>>(new Set());

  loaded  = signal(false);
  saving  = signal(false);
  saved   = signal(false);
  saveErr = signal('');
  loadErr = signal('');

  patch(partial: Partial<AppConfig>) {
    this.cfg.update(c => ({ ...c, ...partial }));
  }

  // ── Token edit helpers ────────────────────────────────────────────────────

  isEditing(field: string): boolean {
    return this.editingTokens().has(field);
  }

  startEditing(field: string) {
    this.editingTokens.update(s => new Set([...s, field]));
    // Clear the field so user types a fresh value
    this.patch({ [field]: '' } as any);
  }

  cancelEditing(field: string) {
    this.editingTokens.update(s => { const n = new Set(s); n.delete(field); return n; });
    // Restore blank (the masked value stays on backend)
    this.patch({ [field]: '' } as any);
  }

  // ── Load from backend ─────────────────────────────────────────────────────

  load() {
    if (this.loaded()) return;

    // Sequential fetch: Sonar/general config first, then Fortify.
    // Fortify's response is merged in only after the Sonar call resolves,
    // so Fortify-specific fields (fortify_api_token / fortify_host_url)
    // never get clobbered by a general-config response that arrived later.
    this.apiSvc.getConfig().pipe(
      switchMap((remote) => {
        // Apply the Sonar/general response immediately.
        this.tokenStatus.update(ts => ({
          ...ts,
          githubToken: remote.github_token === '***',
          sonarToken:  remote.sonar_token  === '***',
        }));

        this.cfg.update(c => ({
          ...c,
          gcpProject:     remote.gcp_project                 || c.gcpProject,
          model:          remote.vertex_model                || c.model,
          maxIssues:      remote.max_issues                  ?? c.maxIssues,
          maxTokens:      remote.max_tokens                  ?? c.maxTokens,
          highThresh:     remote.confidence_high_threshold   ?? c.highThresh,
          medThresh:      remote.confidence_medium_threshold ?? c.medThresh,
          plannerTemp:    remote.planner_temperature         ?? c.plannerTemp,
          generatorTemp:  remote.generator_temperature       ?? c.generatorTemp,
          sonarOrg:       remote.sonar_host_url              || c.sonarOrg,
          maxRetries:     remote.max_critic_retries          ?? c.maxRetries,
          chromaPath:     remote.chroma_persist_dir          || c.chromaPath,
          embeddingModel: remote.embedding_model             || c.embeddingModel,
          ragTopK:        remote.rag_top_k                   ?? c.ragTopK,
          adrOutputDir:   remote.adr_output_dir              || c.adrOutputDir,
          // Tokens: keep empty — we show the masked placeholder UI instead
          githubToken:    '',
          sonarToken:     '',
        }));

        // Now chase it with the Fortify config fetch.
        return this.apiSvc.getFortifyConfig().pipe(
          catchError(() => {
            // Fortify side unreachable — Sonar/general values already
            // applied above, so just fall back to Fortify defaults.
            this.loadErr.set('Fortify backend offline — showing defaults for Fortify fields.');
            return of(null);
          }),
        );
      }),
    ).subscribe({
      next: (fortifyRemote) => {
        if (fortifyRemote) {
          this.tokenStatus.update(ts => ({
            ...ts,
            fortifyApiToken: fortifyRemote.fortify_api_token === '***',
          }));

          this.cfg.update(c => ({
            ...c,
            fortifyHostUrl: fortifyRemote.fortify_host_url || c.fortifyHostUrl,
            fortifyApiToken: '',
          }));
        }

        // Sync UI fields from live apiCfg (may differ if loaded from localStorage)
        this.cfg.update(cc => ({
          ...cc,
          apiHost: this.apiCfg.apiHost(),
        }));
        this.loaded.set(true);
        if (fortifyRemote) this.loadErr.set('');
      },
      error: () => {
        this.loadErr.set('Backend offline — showing defaults. Changes will not persist until API is reachable.');
        this.loaded.set(true);
      },
    });
  }

  // ── Save to backend ───────────────────────────────────────────────────────

  save() {
    if (this.saving()) return;
    this.saving.set(true);
    this.saveErr.set('');
    this.saved.set(false);

    const c = this.cfg();

    // General payload — everything except Fortify token/host URL.
    // Sent to the shared root /api/config.
    const payload: any = {
      gcp_project:                 c.gcpProject     || undefined,
      vertex_model:                c.model,
      max_issues:                  c.maxIssues,
      max_tokens:                  c.maxTokens,
      confidence_high_threshold:   c.highThresh,
      confidence_medium_threshold: c.medThresh,
      planner_temp:                c.plannerTemp,
      generator_temp:              c.generatorTemp,
      max_critic_retries:          c.maxRetries,
      chroma_persist_dir:          c.chromaPath,
      embedding_model:             c.embeddingModel,
      rag_top_k:                   c.ragTopK,
    };

    // Include token fields if:
    //   - user was actively editing (Change button flow), OR
    //   - token field has a value typed directly (first-time entry, editingTokens not set)
    const editing = this.editingTokens();

    const sendGithubToken = editing.has('githubToken') || (!this.tokenStatus().githubToken && c.githubToken);
    if (sendGithubToken) {
      payload['github_token'] = c.githubToken;
    }
    if (editing.has('sonarToken') || (!this.tokenStatus().sonarToken && c.sonarToken)) {
      payload['sonar_token'] = c.sonarToken;
    }

    // Always send sonar_host_url when it has a value
    if (c.sonarOrg) {
      payload['sonar_host_url'] = c.sonarOrg;
    }

    // Fortify payload — fortify_api_token + fortify_host_url, sent
    // separately to /fortify/api/config so writes for Fortify go through
    // the dedicated Fortify path, same as the OAuth refresh-token call.
    // github_token, gcp_project, vertex_model, and max_tokens are mirrored
    // here too, since the Fortify side may be a separate backend instance
    // and needs these same values available locally (GitHub access for
    // writeback flows, and the GCP/Vertex settings used for its own LLM calls).
    const fortifyPayload: any = {
      gcp_project:  c.gcpProject || undefined,
      vertex_model: c.model,
      max_tokens:   c.maxTokens,
    };

    if (sendGithubToken) {
      fortifyPayload['github_token'] = c.githubToken;
    }
    if (editing.has('fortifyApiToken') || (!this.tokenStatus().fortifyApiToken && c.fortifyApiToken)) {
      fortifyPayload['fortify_api_token'] = c.fortifyApiToken;
    }
    if (c.fortifyHostUrl) {
      fortifyPayload['fortify_host_url'] = c.fortifyHostUrl;
    }

    // Apply host to ApiConfigService immediately — no backend round-trip needed
    this.apiCfg.apply(c.apiHost);

    const saveGeneral$ = this.apiSvc.saveConfig(payload);
    const saveFortify$ = Object.keys(fortifyPayload).length
      ? this.apiSvc.saveFortifyConfig(fortifyPayload)
      : of(null);

    forkJoin([saveGeneral$, saveFortify$]).subscribe({
      next: () => {
        // Update tokenStatus based on what was saved
        this.tokenStatus.update(ts => ({
          ...ts,
          ...(payload['github_token']  !== undefined ? { githubToken:  !!c.githubToken  } : {}),
          ...(payload['sonar_token']   !== undefined ? { sonarToken:   !!c.sonarToken   } : {}),
          ...(fortifyPayload['fortify_api_token'] !== undefined ? { fortifyApiToken: !!c.fortifyApiToken } : {}),
        }));

        // Clear editing state and token values after save
        this.editingTokens.set(new Set());
        this.cfg.update(cc => ({ ...cc, githubToken: '', sonarToken: '', fortifyApiToken: '' }));

        this.saving.set(false);
        this.saved.set(true);

        // Reload the page so every view re-fetches fresh config from the
        // backend on init. A brief delay lets the "Saved" confirmation
        // flash before the reload happens.
        //
        // Note: this only refreshes what the *browser* shows. It does NOT
        // reach into the backend process — if you rotated the Fortify
        // token/password without changing the host URL or username, the
        // backend's in-memory token cache can still serve the old token
        // until it naturally expires. POST /api/reload on the backend is
        // the only thing that forces that specific case to take effect
        // immediately.
        setTimeout(() => window.location.reload(), 800);
      },
      error: (err: Error) => {
        this.saving.set(false);
        this.saveErr.set(err.message || 'Failed to save — is the backend running?');
      },
    });
  }

}