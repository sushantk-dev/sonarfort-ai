// src/app/core/pipeline-state.service.ts
import { Injectable, inject, signal } from '@angular/core';
import { Subscription, timer } from 'rxjs';
import { switchMap, takeWhile, tap } from 'rxjs/operators';
import { HttpClient } from '@angular/common/http';
import { ApiService, RunStatus, PipelineStep } from './api.service';
import { ApiConfigService } from './api-config.service';
import { DataService } from './data.service';

export type ConfLabel = 'HIGH' | 'MEDIUM' | 'LOW' | null;
export type FortifyMode = 'live' | 'offline' | 'app-name' | 'dry-run';

// ── Fortify pipeline stages in execution order ────────────────────────────────
// Must match ALL_STAGE_NAMES in api_server.py exactly
const FORTIFY_STAGE_LABELS: Record<string, string> = {
  'triage':             'Triage',
  'version-resolver':   'Version Resolver',
  'context':            'Context',
  'api-diff':           'API Diff',
  'ai-reasoning':       'AI Reasoning',
  'adr-fix':            'ADR Fix',
  'pr-agent':           'PR Agent',
  'fortify-writeback':  'Fortify Writeback',
};

const FORTIFY_STAGE_ORDER = Object.keys(FORTIFY_STAGE_LABELS);

const POLL_MS        = 2000;   // poll interval while running
const QUEUED_POLL_MS = 600;    // faster poll while job is still queued

// ── localStorage key for Fortify runs that survived a page reload ─────────────
const FORTIFY_ACTIVE_KEY = 'sonarfort_fortify_active_runs';

// ── localStorage key for full run history (both Sonar and Fortify) ───────────
const ALL_RUNS_KEY = 'sonarfort_all_runs';

export interface RunRequest {
  repo_url:   string;
  commit_sha: string;
  max_issues: number;
  parallel:   boolean;
  rescan:     boolean;
  no_rag:     boolean;
  dry_run:    boolean;
  severities: string;
}

export interface FortifyRunRequest {
  mode:        FortifyMode;
  endpoint:    string;
  body:        Record<string, unknown>;
  pipeline_id: string;
}

// Shape persisted to localStorage so a reload can rehydrate
interface PersistedFortifyRun {
  pipeline_id: string;
  mode:        FortifyMode;
  body:        Record<string, unknown>;
  started_at:  number;  // epoch ms — used to discard stale entries
}

export interface UiRun {
  id:            string;
  ruleKey:       string;
  severity:      string;
  component:     string;
  steps:         PipelineStep[];
  outcome?:      string;
  confidence?:   ConfLabel;
  prUrl?:        string;
  ragHits?:      number;
  retries?:      number;
  live:          boolean;
  status?:       'queued' | 'running' | 'done' | 'error' | 'cancelled' | 'empty';
  request?:      RunRequest;
  fortifyRequest?: FortifyRunRequest;
  source?:       'sonar' | 'fortify';
  startedAt?:    number;   // epoch ms — for elapsed timer and history ordering
}

@Injectable({ providedIn: 'root' })
export class PipelineStateService {
  private api    = inject(ApiService);
  private data   = inject(DataService);
  private http   = inject(HttpClient);
  private apiCfg = inject(ApiConfigService);

  /** Always reflects the current host:port from Settings */
  /** Routes to Fortify server — separate port if configured, else shared */
  private get fortifyBase() { return this.apiCfg.fortifyBaseUrl(); }

  runs     = signal<UiRun[]>([]);
  selected = signal<UiRun | null>(null);
  running  = signal(false);
  error    = signal<string | null>(null);

  private _activeRunId: string | null = null;
  private _poll?: Subscription;

  // FIX 1: map of pipelineId → Subscription so multiple Fortify polls
  // can coexist, and we can attach to one independently of the Sonar poll.
  private _fortifyPolls = new Map<string, Subscription>();

  // FIX 2: queue of Fortify runs waiting for the current run to finish
  private _fortifyQueue: Array<{ pipelineId: string; mode: FortifyMode; body: Record<string, unknown> }> = [];

  get allRuns()  { return this.runs(); }
  get canCancel(){ return this.running() && !!this._activeRunId; }

  constructor() {
    this._rehydrate();
  }

  // ══════════════════════════════════════════════════════════════════════════
  // STARTUP — rehydrate both Sonar and Fortify in-progress runs
  // ══════════════════════════════════════════════════════════════════════════
  private _rehydrate() {
    // ── Step 1: Load saved history immediately (no network needed) ────────────
    const history = this._loadRunHistory();
    if (history.length > 0) {
      this.runs.set(history);
      this.selected.set(history[0]);
    }

    // ── Step 2: Fetch live Sonar runs from backend and merge ──────────────────
    this.api.listRuns().subscribe({
      next: ({ runs }) => {
        const fromBackend: UiRun[] = (runs ?? []).map((r: any) => this._backendRunToUiRun(r));

        // Merge: backend runs take precedence over history for same IDs.
        // History-only runs (not in backend) are kept as-is.
        const backendIds = new Set(fromBackend.map(r => r.id));
        const historyOnly = history.filter(r => !backendIds.has(r.id));
        const merged = [...fromBackend, ...historyOnly]
          .sort((a, b) => (b.startedAt ?? 0) - (a.startedAt ?? 0));

        this.runs.set(merged);
        this.selected.set(merged[0] ?? null);

        // Re-attach Sonar polling for any run still in progress
        const inProgress = fromBackend.find(
          r => r.source !== 'fortify' && (r.status === 'running' || r.status === 'queued')
        );
        if (inProgress) {
          this.running.set(true);
          this._activeRunId = inProgress.id;
          this._poll = this.api.pollRun(inProgress.id).subscribe({
            next:  (s: RunStatus) => this._applyStatus(inProgress.id, s),
            error: (err: Error) => {
              this.error.set(err.message);
              this.running.set(false);
              this._activeRunId = null;
            },
          });
        }

        // After Sonar hydration, rehydrate any persisted Fortify active runs
        this._rehydrateFortify();
      },
      error: () => {
        // Backend unreachable — history is already loaded, just rehydrate Fortify
        if (history.length === 0) {
          const seeded = this._seedRuns();
          this.runs.set(seeded);
          this.selected.set(seeded[0] ?? null);
        }
        this._rehydrateFortify();
      },
    });
  }

  // ── FIX 2: Reload Fortify runs from localStorage on page refresh ──────────
  private _rehydrateFortify() {
    const raw = localStorage.getItem(FORTIFY_ACTIVE_KEY);
    if (!raw) return;

    let persisted: PersistedFortifyRun[] = [];
    try { persisted = JSON.parse(raw); } catch { return; }

    // Discard entries older than 12 hours (pipeline can't still be running)
    const cutoff = Date.now() - 12 * 60 * 60 * 1000;
    const alive  = persisted.filter(p => p.started_at > cutoff);

    if (alive.length === 0) {
      localStorage.removeItem(FORTIFY_ACTIVE_KEY);
      return;
    }

    // For each persisted run, check its current status on the backend.
    // Retry up to 3 times with 1s delay before giving up — handles the case
    // where the backend isn't ready in the first few ms after page load.
    alive.forEach(p => this._rehydrateOne(p, 3));
  }

  private _rehydrateOne(p: PersistedFortifyRun, retriesLeft: number) {
    fetch(`${this.fortifyBase}/pipeline/status/${p.pipeline_id}`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(resp => {
        // Unwrap { ok, data } envelope from backend
        const job = resp?.data ?? resp;
        const isTerminal = job.status === 'completed' || job.status === 'failed';

        if (isTerminal) {
          // Render final state immediately without polling
          this._injectFortifyCard(p.pipeline_id, p.mode, p.body, 'done');
          this._applyFortifyStatus(p.pipeline_id, resp);
          this._removePersisted(p.pipeline_id);
        } else {
          // Still running — inject card, apply current stage states, resume polling
          const uiStatus = job.status === 'running' ? 'running' : 'queued';
          this._injectFortifyCard(p.pipeline_id, p.mode, p.body, uiStatus);
          this._applyFortifyStatus(p.pipeline_id, resp);
          this._startFortifyPoll(p.pipeline_id);
          // Restore the global running flag
          if (!this.running()) {
            this.running.set(true);
            this._activeRunId = p.pipeline_id;
          }
        }
      })
      .catch(() => {
        if (retriesLeft > 0) {
          // Transient error (backend not ready yet) — retry after 1s, keep in localStorage
          setTimeout(() => this._rehydrateOne(p, retriesLeft - 1), 1000);
        } else {
          // Backend genuinely unreachable after all retries — show card as queued
          // but DO NOT remove from localStorage so the next reload can try again
          this._injectFortifyCard(p.pipeline_id, p.mode, p.body, 'queued');
        }
      });
  }

  // ── Persist a Fortify run to localStorage ─────────────────────────────────
  private _persistFortifyRun(pipelineId: string, mode: FortifyMode, body: Record<string, unknown>) {
    let existing: PersistedFortifyRun[] = [];
    try {
      const raw = localStorage.getItem(FORTIFY_ACTIVE_KEY);
      if (raw) existing = JSON.parse(raw);
    } catch {}

    const entry: PersistedFortifyRun = { pipeline_id: pipelineId, mode, body, started_at: Date.now() };
    const updated = [...existing.filter(p => p.pipeline_id !== pipelineId), entry];
    localStorage.setItem(FORTIFY_ACTIVE_KEY, JSON.stringify(updated));
  }

  private _removePersisted(pipelineId: string) {
    try {
      const raw = localStorage.getItem(FORTIFY_ACTIVE_KEY);
      if (!raw) return;
      const existing: PersistedFortifyRun[] = JSON.parse(raw);
      const updated = existing.filter(p => p.pipeline_id !== pipelineId);
      if (updated.length === 0) localStorage.removeItem(FORTIFY_ACTIVE_KEY);
      else localStorage.setItem(FORTIFY_ACTIVE_KEY, JSON.stringify(updated));
    } catch {}
  }

  // ── Full run history — persists all runs until user clicks X ─────────────

  private _saveRunToHistory(run: UiRun) {
    try {
      const history = this._loadRunHistory();
      // Upsert: update existing entry or prepend new one
      const without = history.filter(r => r.id !== run.id);
      const updated = [run, ...without].slice(0, 200); // cap at 200 runs
      localStorage.setItem(ALL_RUNS_KEY, JSON.stringify(updated));
    } catch {}
  }

  private _loadRunHistory(): UiRun[] {
    try {
      const raw = localStorage.getItem(ALL_RUNS_KEY);
      if (!raw) return [];
      return JSON.parse(raw) as UiRun[];
    } catch { return []; }
  }

  private _removeFromHistory(id: string) {
    try {
      const history = this._loadRunHistory().filter(r => r.id !== id);
      if (history.length === 0) localStorage.removeItem(ALL_RUNS_KEY);
      else localStorage.setItem(ALL_RUNS_KEY, JSON.stringify(history));
    } catch {}
  }

  // ══════════════════════════════════════════════════════════════════════════
  // FORTIFY — public entry point (called from component after POST succeeds)
  // FIX 1: no longer blocks if a Sonar run is active — queues instead
  // ══════════════════════════════════════════════════════════════════════════
  trackFortifyRun(pipelineId: string, mode: FortifyMode, body: Record<string, unknown>) {
    // Only queue behind a SONAR run — Fortify runs can coexist with each other.
    // A Sonar run is active when _activeRunId is set but NOT in _fortifyPolls.
    const sonarRunActive = !!this._activeRunId && !this._fortifyPolls.has(this._activeRunId);
    if (sonarRunActive) {
      this._fortifyQueue.push({ pipelineId, mode, body });
      this._injectFortifyCard(pipelineId, mode, body, 'queued');
      this._persistFortifyRun(pipelineId, mode, body);
      return;
    }

    this._persistFortifyRun(pipelineId, mode, body);
    this._injectFortifyCard(pipelineId, mode, body, 'running');
    this._startFortifyPoll(pipelineId);
    this.running.set(true);
    this._activeRunId = pipelineId;
  }

  // ── Inject a Fortify run card into the runs list (idempotent) ────────────
  private _injectFortifyCard(
    pipelineId: string,
    mode: FortifyMode,
    body: Record<string, unknown>,
    status: UiRun['status']
  ) {
    // Don't duplicate if already present (reload path)
    if (this.runs().find(r => r.id === pipelineId)) return;

    const fortifyReq: FortifyRunRequest = {
      mode,
      endpoint: `/pipeline/${mode}`,
      body,
      pipeline_id: pipelineId,
    };

    const card: UiRun = {
      id:             pipelineId,
      ruleKey:        this._fortifyRunLabel(mode, body),
      severity:       'FORTIFY',
      component:      this._fortifyComponentLabel(mode, body),
      steps:          FORTIFY_STAGE_ORDER.map(key => ({
        label:  FORTIFY_STAGE_LABELS[key],
        status: 'pending' as const,
        detail: '',
        ms:     0,
      })),
      live:           true,
      status,
      fortifyRequest: fortifyReq,
      source:         'fortify',
      startedAt:      Date.now(),
    };

    this.runs.update(rs => [card, ...rs]);
    // Auto-select: on first inject (new run from component), always select.
    // On rehydration the selected signal may already be set to a Sonar run —
    // only override if currently nothing is selected or the selected run is done.
    const cur = this.selected();
    if (!cur || cur.status === 'done' || cur.status === 'error' || cur.status === 'cancelled') {
      this.selected.set(card);
    }
  }

  // ── Start (or resume) polling for one Fortify pipeline_id ─────────────────
  private _startFortifyPoll(pipelineId: string) {
    if (this._fortifyPolls.has(pipelineId)) return;   // already polling

    // Pre-register with a placeholder so _cleanupFortifyPoll works even if
    // tap() fires before the real sub is assigned (RxJS cold observable quirk)
    this._fortifyPolls.set(pipelineId, null as any);

    const sub = timer(0, QUEUED_POLL_MS)
      .pipe(
        switchMap(() =>
          this.http.get<any>(`${this.fortifyBase}/pipeline/status/${pipelineId}`)
        ),
        tap(resp => this._applyFortifyStatus(pipelineId, resp)),
        takeWhile(
          resp => (resp?.data ?? resp).status !== 'completed' && (resp?.data ?? resp).status !== 'failed',
          true  // inclusive — emit terminal event before completing
        )
      )
      .subscribe({
        error: (err: any) => {
          this.error.set(`Fortify polling error: ${err?.message ?? err}`);
          this._cleanupFortifyPoll(pipelineId);
          this.running.set(false);
        },
        // complete fires after takeWhile closes the stream on terminal state
        complete: () => {
          this._cleanupFortifyPoll(pipelineId);
          this.running.set(false);
        },
      });

    // Update the placeholder with the real subscription
    this._fortifyPolls.set(pipelineId, sub);
  }

  // ── Clean up a finished Fortify poll and drain the queue ──────────────────
  private _cleanupFortifyPoll(pipelineId: string) {
    this._fortifyPolls.get(pipelineId)?.unsubscribe();
    this._fortifyPolls.delete(pipelineId);
    this._removePersisted(pipelineId);

    // Clear _activeRunId so the next trackFortifyRun doesn't misidentify it
    // as a still-running Sonar run and push to the queue instead of starting.
    if (this._activeRunId === pipelineId) {
      this._activeRunId = null;
    }

    // Drain the queue — start any Fortify runs that were waiting
    if (this._fortifyQueue.length > 0) {
      const next = this._fortifyQueue.shift()!;
      this.runs.update(rs => rs.map(r =>
        r.id === next.pipelineId ? { ...r, status: 'running' } : r
      ));
      this._activeRunId = next.pipelineId;
      this._persistFortifyRun(next.pipelineId, next.mode, next.body);
      this._startFortifyPoll(next.pipelineId);
      return; // still running — don't clear running flag
    }

    // Only clear the global running flag if no Sonar run is active either
    if (!this._activeRunId && this._fortifyPolls.size === 0) {
      this.running.set(false);
    }
  }

  // ── Map GET /pipeline/status response → UiRun update ─────────────────────
  private _applyFortifyStatus(pipelineId: string, raw: any) {
    // Backend wraps all responses: { ok: true, data: { ... } }
    const resp = raw?.data ?? raw;

    const backendStatus = resp.status;
    const fromBackend =
      backendStatus === 'completed' ? 'done'
      : backendStatus === 'failed'  ? 'error'
      : backendStatus === 'running' ? 'running'
      : 'queued';

    // STATUS ORDER — never allow status to go backwards.
    // Backend occasionally returns 'queued' for a run that the UI already
    // knows is 'running' (race between worker pick-up and poll interval).
    const STATUS_RANK: Record<string, number> = {
      queued: 0, running: 1, done: 2, error: 2,
    };
    const currentRun = this.runs().find(r => r.id === pipelineId);
    const currentStatus = currentRun?.status ?? 'queued';
    const terminalStatus =
      (STATUS_RANK[fromBackend] ?? 0) >= (STATUS_RANK[currentStatus as string] ?? 0)
        ? fromBackend
        : currentStatus as typeof fromBackend;

    const stages: Record<string, any> = resp.stages ?? {};
    const steps: PipelineStep[] = FORTIFY_STAGE_ORDER.map(key => {
      const s = stages[key] ?? {};
      const apiStatus: string = s.status ?? 'pending';
      const uiStatus =
        apiStatus === 'completed' ? 'done'
        : apiStatus === 'failed'  ? 'error'
        : apiStatus === 'running' ? 'running'
        : apiStatus === 'skipped' ? 'done'
        : 'pending';

      const ms = s.elapsed_seconds != null ? Math.round(s.elapsed_seconds * 1000) : 0;

      const summary = s.output_summary;
      let detail = s.error ?? '';
      if (!detail && summary) detail = this._summariseStageOutput(key, summary);

      return { label: FORTIFY_STAGE_LABELS[key], status: uiStatus as any, detail, ms };
    });

    const result = resp.result ?? {};
    let outcome: string | undefined;
    let prUrl: string | undefined;
    let confidence: ConfLabel | undefined;

    if (terminalStatus === 'done') {
      const prResults: any[] = result.pr_results ?? [];
      const fixed     = prResults.filter((p: any) => p?.pr_url).length;
      const escalated = result.total_escalated ?? 0;
      outcome = fixed > 0 ? 'pr_opened' : escalated > 0 ? 'escalated' : 'empty';
      prUrl   = prResults[0]?.pr_url ?? undefined;
    } else if (terminalStatus === 'error') {
      outcome = 'error';
    }

    if (result.groups?.length) {
      const avgConf = result.groups.reduce(
        (sum: number, g: any) => sum + (g.ai_reasoning?.confidence_score ?? 0), 0
      ) / result.groups.length;
      confidence = this.confLabel(avgConf);
    }

    this.runs.update(rs => rs.map(r => {
      if (r.id !== pipelineId) return r;
      const updated: UiRun = {
        ...r, steps,
        status:     terminalStatus as any,
        outcome:    outcome     ?? r.outcome,
        prUrl:      prUrl       ?? r.prUrl,
        confidence: confidence  ?? r.confidence,
        startedAt:  r.startedAt ?? Date.now(),
      };
      if (this.selected()?.id === pipelineId) this.selected.set(updated);
      // Persist to history on terminal state so it survives reload
      if (terminalStatus === 'done' || terminalStatus === 'error') {
        this._saveRunToHistory(updated);
      }
      return updated;
    }));

    if (terminalStatus === 'error' && resp.error) {
      this.error.set(`Fortify: ${resp.error}`);
    }
    // Note: cleanup and running.set(false) are handled by the subscribe
    // complete/error callbacks — NOT here — because this method runs via tap()
    // before the subscription object is stored in _fortifyPolls.
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  private _summariseStageOutput(stage: string, summary: any): string {
    if (!summary) return '';
    switch (stage) {
      case 'triage':          return `${summary.total_groups ?? 0} groups, ${summary.total_skipped ?? 0} skipped`;
      case 'version-resolver': return summary.candidates?.length
        ? `Candidates: ${summary.candidates.slice(0, 3).join(', ')}`
        : summary.next_safe ? `Next safe: ${summary.next_safe}` : '';
      case 'context':         return summary.pom_file ? `pom: ${summary.pom_file}` : '';
      case 'api-diff':        return summary.has_breaking_changes
        ? `⚠ ${summary.breaking_count} breaking change(s)`
        : '✓ No breaking changes';
      case 'ai-reasoning':    return summary.confidence
        ? `${summary.safe ? '✓ Safe' : '⚠ Unsafe'} · confidence: ${summary.confidence}` : '';
      case 'adr-fix':         return summary.branch_name ? `Branch: ${summary.branch_name}` : summary.error_reason ?? '';
      case 'pr-agent':        return summary.pr_url ? `PR: ${summary.pr_url}` : '';
      case 'fortify-writeback': return summary.total_fixed != null
        ? `Fixed: ${summary.total_fixed}, Escalated: ${summary.total_escalated ?? 0}` : '';
      default:                return '';
    }
  }

  private _fortifyRunLabel(mode: FortifyMode, body: Record<string, unknown>): string {
    switch (mode) {
      case 'live':     return `Release ${body['release_id'] ?? '—'}`;
      case 'offline':  return `Offline · ${(body['report_path'] as string)?.split('/').pop() ?? 'report.json'}`;
      case 'app-name': return `${body['app_name'] ?? '—'}`;
      case 'dry-run':  return `Dry Run · Release ${body['release_id'] ?? '—'}`;
    }
  }

  private _fortifyComponentLabel(mode: FortifyMode, body: Record<string, unknown>): string {
    const cfg: any = body['config'] ?? {};
    return cfg.github_repo ?? (body['app_name'] as string) ?? '';
  }

  // ══════════════════════════════════════════════════════════════════════════
  // SONAR — start / poll
  // ══════════════════════════════════════════════════════════════════════════
  startRun(req: RunRequest) {
    if (this.running()) return;
    this.running.set(true);
    this.error.set(null);

    this.api.startRun(req).subscribe({
      next: ({ run_id }) => this._pollRun(run_id, req),
      error: (err: any) => {
        const detail = err?.error?.detail ?? err?.message ?? 'Pipeline start failed';
        this.error.set(detail);
        this.running.set(false);
      },
    });
  }

  private _pollRun(runId: string, req: RunRequest) {
    this._activeRunId = runId;

    const liveRun: UiRun = {
      id:        runId,
      ruleKey:   '—',
      severity:  'INFO',
      component: '',
      steps: ['Ingest','Load Repo','RAG Fetch','Fetch Rule','Planner','Generator','Critic','Validate','Deliver']
        .map(label => ({ label, status: 'pending' as const, detail: '', ms: 0 })),
      live:      true,
      status:    'running',
      request:   req,
      source:    'sonar',
      startedAt: Date.now(),
    };

    this.runs.update(rs => [liveRun, ...rs]);
    this.selected.set(liveRun);

    this._poll = this.api.pollRun(runId).subscribe({
      next:  (s: RunStatus) => this._applyStatus(runId, s),
      error: (err: Error) => {
        this.error.set(err.message);
        this.running.set(false);
        this._activeRunId = null;
        this._drainFortifyQueue();
      },
    });
  }

  // FIX 1: after Sonar completes, drain queued Fortify runs
  private _drainFortifyQueue() {
    if (this._fortifyQueue.length === 0) return;
    const next = this._fortifyQueue.shift()!;
    this.runs.update(rs => rs.map(r =>
      r.id === next.pipelineId ? { ...r, status: 'running' } : r
    ));
    this._startFortifyPoll(next.pipelineId);
    // Start remaining ones immediately too (Fortify runs can run in parallel)
    while (this._fortifyQueue.length > 0) {
      const n = this._fortifyQueue.shift()!;
      this.runs.update(rs => rs.map(r =>
        r.id === n.pipelineId ? { ...r, status: 'running' } : r
      ));
      this._startFortifyPoll(n.pipelineId);
    }
  }

  private _applyStatus(runId: string, status: RunStatus) {
    this.runs.update(rs => rs.map(r => {
      if (r.id !== runId) return r;

      const first     = status.results?.[0];
      const noResults = status.status === 'done' && (!status.results || status.results.length === 0);

      let mergedSteps = r.steps;
      if (status.steps?.length) {
        const hasProgress = status.steps.some((s: any) => s.status !== 'pending');
        if (hasProgress) {
          mergedSteps = status.steps.map((bs: any) => {
            const local = r.steps.find(ls => ls.label === bs.label);
            return { ...bs, detail: bs.detail || local?.detail || '', ms: bs.ms || local?.ms || 0 };
          });
        }
      }

      const updated: UiRun = {
        ...r,
        steps:      mergedSteps,
        outcome:    noResults ? 'empty' : (first?.outcome ?? r.outcome),
        confidence: first ? this.confLabel(first.confidence) : r.confidence,
        prUrl:      first?.pr_url ?? r.prUrl,
        status:     noResults ? 'empty' as any : status.status,
        ruleKey:    first?.rule_key  ? first.rule_key  : r.ruleKey,
        severity:   first?.severity  ? first.severity  : r.severity,
        component:  first?.file_path ? first.file_path : r.component,
        startedAt:  r.startedAt ?? Date.now(),
      };

      if (this.selected()?.id === runId) this.selected.set(updated);

      // Save to persistent history when done or error
      if (status.status === 'done' || status.status === 'error' || noResults) {
        this._saveRunToHistory(updated);
      }

      return updated;
    }));

    if (status.status === 'done' || status.status === 'error') {
      this.running.set(false);
      this._activeRunId = null;

      if (status.status === 'error' && status.error) this.error.set(status.error);

      const noResults = !status.results || status.results.length === 0;
      if (noResults && status.status === 'done') {
        this.error.set('No issues found for the selected severity — run is kept in history.');
        this._drainFortifyQueue();
        return;
      }

      if ((status.results?.length ?? 0) > 1) this._explodeResults(runId, status);

      this._drainFortifyQueue();
    }
  }

  private _explodeResults(runId: string, status: RunStatus) {
    const parentReq = this.runs().find(r => r.id === runId)?.request;
    const newCards: UiRun[] = status.results.map((r, i) => ({
      id:         `${runId}-${i}`,
      ruleKey:    r.rule_key,
      severity:   r.severity,
      component:  r.file_path,
      outcome:    r.outcome,
      confidence: this.confLabel(r.confidence),
      prUrl:      r.pr_url ?? undefined,
      steps:      status.steps ?? [],
      live:       true,
      status:     'done' as const,
      request:    parentReq,
      source:     'sonar' as const,
    }));
    this.runs.update(rs => [...newCards, ...rs.filter(r => r.id !== runId)]);
    if (newCards[0]) this.selected.set(newCards[0]);
  }

  // ── Backend run hydration ─────────────────────────────────────────────────
  private _backendRunToUiRun(r: any): UiRun {
    const first = Array.isArray(r.results) ? r.results[0] : undefined;
    const confLabel: ConfLabel = first?.confidence != null ? this.confLabel(first.confidence) : null;
    const steps: PipelineStep[] = Array.isArray(r.steps)
      ? r.steps.map((s: any) => ({ label: s.label ?? '', status: s.status ?? 'done', detail: s.detail ?? '', ms: s.ms ?? 0 }))
      : [];
    return {
      id:         r.id ?? r.run_id,
      ruleKey:    first?.rule_key  ?? '—',
      severity:   first?.severity  ?? 'INFO',
      component:  first?.file_path ?? '',
      outcome:    first?.outcome   ?? (r.status === 'error' ? 'error' : undefined),
      confidence: confLabel,
      prUrl:      first?.pr_url    ?? undefined,
      steps,
      live:       false,
      status:     r.status ?? 'done',
      request:    r.request,
      source:     r.source ?? 'sonar',
      startedAt:  r.started_at ? new Date(r.started_at).getTime() : undefined,
    };
  }

  private _seedRuns(): UiRun[] {
    return this.data.runs.map(r => ({
      id:         r.id,
      ruleKey:    r.ruleKey,
      severity:   r.severity,
      component:  r.component,
      steps:      r.steps.map(s => ({ label: s.label, status: s.status as any, detail: s.detail ?? '', ms: s.ms ?? 0 })),
      outcome:    r.outcome,
      confidence: r.confidence as ConfLabel,
      prUrl:      r.prUrl,
      ragHits:    r.ragHits,
      retries:    r.retries,
      live:       false,
      status:     'done',
      request:    undefined,
      source:     'sonar',
    }));
  }

  // ── Shared helpers ────────────────────────────────────────────────────────
  select(run: UiRun)   { this.selected.set(run); }
  doneCnt(run: UiRun)  { return run.steps.filter(s => s.status === 'done').length; }
  confClass(c: ConfLabel | string | undefined) { return (c ?? '').toLowerCase(); }

  outcomeIcon(o?: string) {
    return { pr_opened:'✓', draft_pr:'~', escalated:'!', error:'✕', cancelled:'◼', empty:'—' }[o ?? ''] ?? '?';
  }

  outcomeTitle(o?: string) {
    return {
      pr_opened: 'Pull request opened',
      draft_pr:  'Draft PR — review required',
      escalated: 'Escalated — manual fix needed',
      error:     'Pipeline error',
      cancelled: 'Run cancelled',
      empty:     'No issues found in report',
    }[o ?? ''] ?? o ?? '';
  }

  confLabel(score: number): ConfLabel {
    if (score >= 0.8) return 'HIGH';
    if (score >= 0.5) return 'MEDIUM';
    return 'LOW';
  }

  // ── Delete ────────────────────────────────────────────────────────────────
  deleteRun(id: string) {
    if (id === this._activeRunId) return;
    // Remove from UI
    this.runs.update(rs => rs.filter(r => r.id !== id));
    if (this.selected()?.id === id) this.selected.set(this.runs()[0] ?? null);
    // Remove from persistent history
    this._removeFromHistory(id);
    // Remove from active Fortify tracking (if it was a Fortify run)
    this._removePersisted(id);
    // Best-effort delete from Sonar backend (no-op for Fortify runs)
    this.api.deleteRun(id).subscribe({ error: () => {} });
  }

  // ── Cancel ────────────────────────────────────────────────────────────────
  cancelRun() {
    const runId = this._activeRunId;
    if (!runId) return;

    this._poll?.unsubscribe();
    this._poll = undefined;

    // Cancel all active Fortify polls too
    this._fortifyPolls.forEach(sub => sub.unsubscribe());
    this._fortifyPolls.clear();
    this._fortifyQueue.length = 0;

    this.api.cancelRun(runId).subscribe({ error: () => {} });

    this.runs.update(rs => rs.map(r => {
      if (r.id !== runId && !this._fortifyPolls.has(r.id)) return r;
      return {
        ...r,
        status:  'cancelled',
        outcome: 'cancelled',
        steps: r.steps.map(s =>
          s.status === 'running' || s.status === 'pending'
            ? { ...s, status: 'cancelled' as const, detail: s.status === 'running' ? 'Cancelled by user' : '' }
            : s
        ),
      };
    }));

    const updated = this.runs().find(r => r.id === runId);
    if (updated && this.selected()?.id === runId) this.selected.set(updated);

    this.running.set(false);
    this._activeRunId = null;

    // Clear persisted Fortify runs so they don't rehydrate on next reload
    localStorage.removeItem(FORTIFY_ACTIVE_KEY);
  }
}