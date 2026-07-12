// src/app/core/api.service.ts
import { Injectable, inject } from '@angular/core';
import { ApiConfigService } from './api-config.service';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import {
  Observable, interval, switchMap, takeWhile,
  catchError, throwError, tap, share
} from 'rxjs';

export interface RunRequest {
  repo_url:   string;
  commit_sha: string;
  max_issues: number;
  parallel:   boolean;
  rescan:     boolean;
  no_rag:     boolean;
  dry_run:    boolean;
  severities: string;   // ← NEW: comma-separated e.g. "BLOCKER,CRITICAL"
}

export interface PipelineStep {
  label:  string;
  status: 'pending' | 'running' | 'done' | 'error' | 'cancelled';
  detail: string;
  ms:     number;
}

export interface IssueResult {
  issue_key:       string;
  rule_key:        string;
  severity:        string;
  file_path:       string;
  line:            number;
  outcome:         string;
  pr_url:          string | null;
  escalation_path: string | null;
  confidence:      number;
  sonar_rescan_ok: boolean | null;
  error:           string | null;
}

export interface RunStatus {
  id:          string;
  status:      'queued' | 'running' | 'done' | 'error' | 'cancelled';
  steps:       PipelineStep[];
  results:     IssueResult[];
  error:       string | null;
  elapsed_ms?: number;
}

export interface ApiIssue {
  key:         string;
  rule_key:    string;
  severity:    string;
  component:   string;
  project?:    string;
  line:        number;
  message:     string;
  status:      string;
  effort:      string;
  hash?:       string;
  text_range?: {
    start_line:   number;
    end_line:     number;
    start_offset: number;
    end_offset:   number;
  };
  tags?: string[];
  type?: string;
}

export interface SonarFetchRequest {
  component_keys: string;
  severities?:    string;
  resolved?:      boolean;
  ps?:            number;
}

export interface SonarFetchResponse {
  message:      string;
  issue_count:  number;
  total:        number;
  effort_total: number;
  component:    string;
}

export interface SonarReport {
  generated_at: string;
  total:        number;
  by_severity:  Record<string, { count: number; issues: ApiIssue[] }>;
  by_rule:      Record<string, { rule_key: string; severity: string; count: number; files: string[] }>;
  issues:       ApiIssue[];
}

export interface BackendConfig {
  gcp_project:                 string;
  vertex_model:                string;
  max_issues:                  number;
  max_tokens:                  number;
  confidence_high_threshold:   number;
  confidence_medium_threshold: number;
  github_token:                string;
  github_repo:                 string;
  sonar_token:                 string;
  sonar_host_url:              string;
  fortify_api_token:               string;
  fortify_host_url:            string;
  planner_temperature:         number;
  generator_temperature:       number;
  max_critic_retries:          number;
  chroma_persist_dir:          string;
  embedding_model:             string;
  rag_top_k:                   number;
  enable_rag:                  boolean;
  langsmith_project:           string;
  langsmith_api_key:           string;
  langchain_tracing:           boolean;
  parallel_issues:             boolean;
  enable_sonar_rescan:         boolean;
  adr_output_dir:              string;
}

/**
 * Shape returned by GET on the Fortify config endpoint. Same as
 * BackendConfig except the token field comes back as `fortify_token`
 * (the POST/save side still uses `fortify_api_token` — see
 * saveFortifyConfig below, which is unchanged).
 */
export type FortifyConfigResponse = Omit<BackendConfig, 'fortify_api_token'> & {
  fortify_token: string;
};

@Injectable({ providedIn: 'root' })
export class ApiService {
  private http   = inject(HttpClient);
  private apiCfg = inject(ApiConfigService);

  /** Always reflects the current host from Settings */
  get base() { return this.apiCfg.baseUrl(); }

  /** Fortify-specific base — same host, under /fortify */
  get fortifyBase() { return this.apiCfg.fortifyBaseUrl(); }

  // ── Health ────────────────────────────────────────────────────────────────

  health(): Observable<{ status: string }> {
    return this.http.get<{ status: string }>(`${this.base}/api/health`);
  }

  // ── Report ────────────────────────────────────────────────────────────────

  uploadReport(file: File): Observable<{ message: string; issue_count: number; path: string }> {
    const form = new FormData();
    form.append('file', file, file.name);
    return this.http.post<any>(`${this.base}/api/report/upload`, form);
  }

  getIssues(): Observable<{ issues: ApiIssue[]; total: number }> {
    return this.http.get<any>(`${this.base}/api/issues`);
  }

  deleteIssue(key: string): Observable<{ message: string; remaining: number }> {
    return this.http.delete<any>(`${this.base}/api/issues/${key}`);
  }

  // ── Live SonarQube fetch ──────────────────────────────────────────────────

  fetchSonarIssues(req: SonarFetchRequest): Observable<SonarFetchResponse> {
    return this.http.post<SonarFetchResponse>(`${this.base}/api/sonar/fetch`, req);
  }

  getSonarReport(): Observable<SonarReport> {
    return this.http.get<SonarReport>(`${this.base}/api/sonar/report`);
  }

  // ── Pipeline ──────────────────────────────────────────────────────────────

  startRun(req: RunRequest): Observable<{ run_id: string; status: string }> {
    return this.http.post<any>(`${this.base}/api/pipeline/run`, req);
  }

  getRunStatus(runId: string): Observable<RunStatus> {
    return this.http.get<RunStatus>(`${this.base}/api/pipeline/status/${runId}`);
  }

  /**
   * Poll a run every 30 s until status is 'done' or 'error'.
   * Emits each intermediate RunStatus so the UI can show live steps.
   */
  pollRun(runId: string): Observable<RunStatus> {
    return interval(30000).pipe(
      switchMap(() => this.getRunStatus(runId)),
      takeWhile(s => s.status !== 'done' && s.status !== 'error', true),
      share(),
    );
  }

  cancelRun(runId: string): Observable<{ message: string }> {
    return this.http.post<any>(`${this.base}/api/pipeline/cancel/${runId}`, {});
  }

  deleteRun(runId: string): Observable<{ message: string }> {
    return this.http.delete<any>(`${this.base}/api/pipeline/runs/${runId}`);
  }

  listRuns(): Observable<{ runs: any[] }> {
    return this.http.get<any>(`${this.base}/api/pipeline/runs`);
  }

  // ── Escalations ──────────────────────────────────────────────────────────

  listEscalations(): Observable<{ escalations: any[]; total: number }> {
    return this.http.get<any>(`${this.base}/api/escalations`);
  }

  getEscalation(filename: string): Observable<{ filename: string; content: string; modified_at: number }> {
    return this.http.get<any>(`${this.base}/api/escalations/${filename}`);
  }

  deleteEscalation(filename: string): Observable<{ message: string }> {
    return this.http.delete<any>(`${this.base}/api/escalations/${filename}`);
  }

  // ── Config ────────────────────────────────────────────────────────────────

  getConfig(): Observable<BackendConfig> {
    return this.http.get<BackendConfig>(`${this.base}/api/config`);
  }

  /**
   * Same /api/config endpoint, but routed through fortifyBase (/fortify).
   * Used to read back Fortify-specific fields (fortify_api_token,
   * fortify_host_url) from the Fortify side, matching how
   * saveFortifyConfig() writes them.
   */
  getFortifyConfig(): Observable<FortifyConfigResponse> {
    return this.http.get<FortifyConfigResponse>(`${this.fortifyBase}/api/config`);
  }

  saveConfig(cfg: Partial<BackendConfig>): Observable<{ message: string }> {
    return this.http.post<any>(`${this.base}/api/config`, cfg);
  }

  /**
   * Same /api/config endpoint, but routed through fortifyBase (/fortify).
   * Used for Fortify-specific fields (fortify_api_token, fortify_host_url)
   * so they travel through the Fortify path, matching the OAuth refresh call.
   */
  saveFortifyConfig(cfg: Partial<BackendConfig>): Observable<{ message: string }> {
    return this.http.post<any>(`${this.fortifyBase}/api/config`, cfg);
  }

  reloadConfig(): Observable<{ message: string; sonar_token_set: boolean; sonar_host_url: string }> {
    return this.http.post<any>(`${this.base}/api/reload`, {});
  }

  // ── Error helper ──────────────────────────────────────────────────────────

  handleError(err: HttpErrorResponse): Observable<never> {
    const msg = err.error?.detail ?? err.message ?? 'Unknown API error';
    return throwError(() => new Error(msg));
  }
}