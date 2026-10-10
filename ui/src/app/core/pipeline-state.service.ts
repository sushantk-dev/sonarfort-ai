// src/app/core/pipeline-state.service.ts
import { Injectable, inject, signal } from '@angular/core';
import { Subscription, timer, firstValueFrom } from 'rxjs';
import { switchMap, takeWhile, tap } from 'rxjs/operators';
import { HttpClient } from '@angular/common/http';
import { ApiService, RunStatus, PipelineStep } from './api.service';
import { ApiConfigService } from './api-config.service';

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
  'adr-fix':            'Dependency Fix',
  'build-validation':   'Build Validation',
  'ai-code-fix':        'AI Code Fix',
  'pr-agent':           'PR Agent',
  'fortify-writeback':  'Fortify Writeback',
};

const FORTIFY_STAGE_ORDER = Object.keys(FORTIFY_STAGE_LABELS);

const POLL_MS        = 30000;  // poll interval while running
const QUEUED_POLL_MS = 30000;  // poll interval — same cadence whether queued or running

// Poll interval for the shared "all users" Fortify runs list (GET /pipeline/runs).
// Independent of QUEUED_POLL_MS above, which only tracks pipelines *this*
// browser started — this one is what surfaces teammates' runs.
const ALL_RUNS_POLL_MS = 20000;

// ── localStorage key for Fortify runs that survived a page reload ─────────────
// Not a data cache: it only remembers *which* pipeline_ids this browser
// started so polling can re-attach after a reload. Every entry is re-checked
// against GET /pipeline/status before anything is shown.
const FORTIFY_ACTIVE_KEY = 'sonarfort_fortify_active_runs';

// ── Legacy localStorage key for full run history (both Sonar and Fortify) ────
// NO LONGER USED as a source of runs — the job lists are always taken from
// the servers so the UI never shows stale/deleted pipeline jobs. The key is
// only referenced to purge whatever an older build left behind.
const LEGACY_ALL_RUNS_KEY = 'sonarfort_all_runs';

export interface RunRequest {
  repo_url:   string;
  commit_sha: string;
  max_issues: number;
  parallel:   boolean;
  rescan:     boolean;
  no_rag:     boolean;
  dry_run:    boolean;
  severities: string;
  /** Maven `mvn compile` + `mvn test` in the Validator step. Off by default — opt-in per run. */
  run_build:  boolean;
  /** Per-run credential overrides — optional, blank falls back to server config.
   *  Sent to the backend on the initial POST only; stripped before the request
   *  is kept in client-side state, see PipelineStateService.startRun(). */
  github_token?: string;
  sonar_token?:  string;
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
  id:                 string;
  ruleKey:            string;
  severity:           string;
  component:          string;
  steps:              PipelineStep[];
  outcome?:           string;
  confidence?:        ConfLabel;
  confidencePercent?: string;   // e.g. "65%" — derived from avg confidence_score
  prUrl?:             string;     // first PR — kept for Sonar backwards compat
  prUrls?:            string[];   // all PRs — Fortify can fix multiple deps per run
  escalationFiles?:   string[];   // escalation report filenames written by this run (Fortify only)
  ragHits?:           number;
  retries?:           number;
  tokens?:            { input: number; output: number };   // LLM token consumption (in/out)
  live:               boolean;
  status?:            'queued' | 'running' | 'done' | 'error' | 'cancelled' | 'empty';
  request?:           RunRequest;
  fortifyRequest?:    FortifyRunRequest;
  source?:            'sonar' | 'fortify';
  startedAt?:         number;   // epoch ms — for elapsed timer and history ordering
  /** Next stage a resume would start at (mirrors the backend job doc's
   *  resume_stage — see job_store._blank_job). undefined = not loaded yet or
   *  no checkpoint at all. Used by canResume() to enforce that resume is only
   *  offered up to the Dependency Fix (adr-fix) stage. */
  resumeStage?:       string | null;
}

@Injectable({ providedIn: 'root' })
export class PipelineStateService {
  private api    = inject(ApiService);
  private http   = inject(HttpClient);
  private apiCfg = inject(ApiConfigService);

  /** Always reflects the current host:port from Settings */
  /** Routes to Fortify server — separate port if configured, else shared */
  private get fortifyBase() { return this.apiCfg.fortifyBaseUrl(); }

  runs     = signal<UiRun[]>([]);
  /**
   * True while the initial `GET /pipeline/runs` fetch (or an explicit,
   * non-silent refresh) is in flight. Drives loading UI in the Activity and
   * Pipeline run lists so they don't flash an empty state before the real
   * list arrives.
   */
  loadingRuns = signal(true);
  selected = signal<UiRun | null>(null);
  running  = signal(false);
  error    = signal<string | null>(null);

  /**
   * Which action (if any) currently has a request in flight to a backend.
   * Drives a full-screen loader in the UI — 'start' while waiting on the
   * initial POST for a Sonar or Fortify run, 'stop' while waiting on the
   * cancel request(s) to be acknowledged, 'resume' while waiting on a
   * resumed run's POST *and* the follow-up status fetch that confirms the
   * backend has actually picked it back up (see resumeFortifyRun). null the
   * rest of the time.
   */
  submitting = signal<'start' | 'stop' | 'resume' | null>(null);

  /**
   * Actual backend reachability, independent of `error` (which only reflects
   * whether an *interactive* operation — start/cancel/resume/etc — failed).
   * `null` = not checked yet (initial load in flight). Driven by the
   * recurring "all users" Fortify poll below, which runs continuously
   * regardless of whether any run is active, so it doubles as a heartbeat.
   */
  apiOnline = signal<boolean | null>(null);

  /**
   * Set to the pipeline_id of the most recently completed (or errored) Fortify
   * run. PipelineComponent watches this with effect() and navigates to the
   * summary report. Reset by calling clearLastCompleted() after navigation.
   */
  lastCompletedFortifyId = signal<string | null>(null);

  /** Call after navigating so the effect doesn't re-trigger on revisit. */
  clearLastCompleted() { this.lastCompletedFortifyId.set(null); }

  // Map of pipelineId → Subscription — lets multiple Sonar runs poll
  // concurrently (mirrors the Fortify map below).
  private _sonarPolls = new Map<string, Subscription>();

  // map of pipelineId → Subscription so multiple Fortify polls
  // can coexist, and we can attach to one independently of any Sonar poll.
  private _fortifyPolls = new Map<string, Subscription>();

  // queue of Fortify runs waiting for the current run to finish
  private _fortifyQueue: Array<{ pipelineId: string; mode: FortifyMode; body: Record<string, unknown> }> = [];

  // Polls GET /pipeline/runs on the Fortify server — the shared, GCS-backed
  // job list that includes runs started by *any* user, not just this browser.
  private _allRunsPoll?: Subscription;

  // Guards refreshRuns() against stacking when navigation fires it repeatedly.
  private _refreshInFlight = false;

  // Two independent fetches feed the combined `runs` list on startup (Sonar's
  // api.listRuns() and the Fortify all-users poll's first tick). loadingRuns
  // only clears once BOTH have reported back at least once.
  private _sonarListLoaded   = false;
  private _fortifyListLoaded = false;

  // Runs that were already in `error` when this page loaded — hidden from the
  // list for the rest of the session. In-memory only, so it's rebuilt on every
  // reload. Hidden, NOT deleted: Fortify runs live in the shared all-users job
  // store, and deleteRun() would remove them for every teammate (and kill Resume).
  private _hiddenErroredIds = new Set<string>();
  private _erroredPurgedThisLoad = false;

  /** Still errored AND was errored at load time — once a run leaves `error`
   *  (e.g. a teammate resumes it) it shows up again. */
  private _isHiddenError(r: UiRun): boolean {
    return r.status === 'error' && this._hiddenErroredIds.has(r.id);
  }

  private _maybeFinishInitialLoad() {
    if (this._sonarListLoaded && this._fortifyListLoaded) {
      this._purgeErroredOnLoad();
      this.loadingRuns.set(false);
    }
  }

  /** Runs once per page load, after both run lists have arrived. */
  private _purgeErroredOnLoad() {
    if (this._erroredPurgedThisLoad) return;
    this._erroredPurgedThisLoad = true;

    const current = this.runs();
    current.filter(r => r.status === 'error').forEach(r => {
      this._hiddenErroredIds.add(r.id);
      this._removePersisted(r.id);   // nothing left to re-attach to after reload
    });
    if (this._hiddenErroredIds.size === 0) return;

    const visible = current.filter(r => !this._isHiddenError(r));
    this.runs.set(visible);
    this.selected.set(this._reselect(visible));
  }

  get allRuns()  { return this.runs(); }

  /** Drives the per-card Stop button on a Fortify run — true for any Fortify
   *  run still in flight, whether this browser started it or it's a
   *  teammate's run merged in from the shared all-users list. */
  canCancelRun(run: UiRun): boolean {
    return run.source === 'fortify' && (run.status === 'running' || run.status === 'queued');
  }

  /** Drives the per-card Stop button in the run LIST. Any Fortify run still
   *  in flight (canCancelRun), or any Sonar run this browser is actively
   *  polling. */
  canStopRun(run: UiRun): boolean {
    if (this.canCancelRun(run)) return true;
    return run.source !== 'fortify' && this._sonarPolls.has(run.id);
  }

  constructor() {
    this._purgeLegacyHistory();
    this._rehydrate();
  }

  // ══════════════════════════════════════════════════════════════════════════
  // STARTUP — load runs from the servers (never from a browser-side cache)
  // ══════════════════════════════════════════════════════════════════════════
  private _rehydrate() {
    // ── Step 1: Start polling the shared "all users" Fortify runs list.
    this._startAllFortifyRunsPolling();

    // ── Step 2: Fetch Sonar runs from backend and merge ───────────────────────
    this.api.listRuns().subscribe({
      next: ({ runs }) => {
        const fromBackend: UiRun[] = (runs ?? []).map((r: any) => this._backendRunToUiRun(r));

        // Keep any Fortify runs the all-users poll may already have merged in.
        const backendIds = new Set(fromBackend.map(r => r.id));
        const fortify = this.runs().filter(r => r.source === 'fortify' && !backendIds.has(r.id));
        const merged = [...fromBackend, ...fortify]
          .sort((a, b) => (b.startedAt ?? 0) - (a.startedAt ?? 0));

        this.runs.set(merged);
        this.selected.set(this._reselect(merged));
        this._sonarListLoaded = true;
        this.apiOnline.set(true);
        this._maybeFinishInitialLoad();

        // Re-attach Sonar polling for every run still in progress.
        const inProgress = fromBackend.filter(
          r => r.source !== 'fortify' && (r.status === 'running' || r.status === 'queued')
        );
        inProgress.forEach(r => this._startSonarPoll(r.id));

        this._rehydrateFortify();
      },
      error: () => {
        // Sonar backend unreachable — show nothing rather than stale/mock data.
        // Deliberately NOT setting apiOnline(false): the recurring Fortify
        // heartbeat poll is the source of truth for that.
        this._sonarListLoaded = true;
        this._maybeFinishInitialLoad();
        this._rehydrateFortify();
      },
    });
  }

  /**
   * Re-fetch BOTH run lists from the servers and REPLACE the client-side list
   * with what they return — runs deleted server-side disappear, status/stage
   * changes show up immediately. Only runs this browser is actively driving
   * (polling or queued locally) are kept if the server lists don't include
   * them yet.
   *
   * `silent: true` (used on route navigation) skips the full-list loader and
   * the error banner, so moving between pages doesn't flicker or nag.
   */
  refreshRuns(opts: { silent?: boolean } = {}) {
    if (this._refreshInFlight) return;
    this._refreshInFlight = true;
    const silent = !!opts.silent;
    if (!silent) this.loadingRuns.set(true);

    let sonar:   UiRun[] | null = null;   // null = request failed → keep what we had
    let fortify: any[]   | null = null;
    let pending = 2;

    const finish = () => {
      if (--pending > 0) return;
      this._applyRefresh(sonar, fortify);
      this._refreshInFlight = false;
      if (!silent) this.loadingRuns.set(false);
    };

    this.api.listRuns().subscribe({
      next: ({ runs }) => {
        sonar = (runs ?? []).map((r: any) => this._backendRunToUiRun(r));
        finish();
      },
      error: (err: Error) => {
        if (!silent) this.error.set(err.message);
        finish();
      },
    });

    this.api.listFortifyRuns().subscribe({
      next: resp => {
        fortify = (resp as any)?.data?.jobs ?? (resp as any)?.jobs ?? [];
        this.apiOnline.set(true);
        finish();
      },
      error: () => {
        this.apiOnline.set(false);
        finish();
      },
    });
  }

  private _applyRefresh(sonar: UiRun[] | null, fortifyJobs: any[] | null) {
    const current = this.runs();
    const byId = new Map(current.map(r => [r.id, r] as const));
    const isLocallyActive = (id: string) =>
      this._sonarPolls.has(id) || this._fortifyPolls.has(id) ||
      this._fortifyQueue.some(q => q.pipelineId === id);

    // ── Sonar side ───────────────────────────────────────────────────────────
    let sonarRuns: UiRun[];
    if (sonar) {
      const ids = new Set(sonar.map(r => r.id));
      // Exploded per-issue cards ("<runId>-<n>") are built client-side from a
      // finished run; keep them only if their parent run still exists.
      const exploded = current.filter(r =>
        r.source !== 'fortify' && !ids.has(r.id) &&
        (isLocallyActive(r.id) || ids.has(r.id.replace(/-\d+$/, '')))
      );
      sonarRuns = [
        ...sonar.map(r => this._sonarPolls.has(r.id) ? (byId.get(r.id) ?? r) : r)
                .filter(r => !exploded.some(e => e.id.startsWith(`${r.id}-`))),
        ...exploded,
      ];
    } else {
      sonarRuns = current.filter(r => r.source !== 'fortify');
    }

    // ── Fortify side ─────────────────────────────────────────────────────────
    let fortifyRuns: UiRun[];
    if (fortifyJobs) {
      const fromServer = fortifyJobs
        .filter(j => j?.pipeline_id)
        .map(j => {
          const id = j.pipeline_id as string;
          const existing = byId.get(id);
          // A run this browser is polling has fresher, richer local state.
          if (existing && this._fortifyPolls.has(id)) return existing;
          const mapped = this._backendFortifyJobToUiRun(j);
          // The list endpoint omits result details (PR urls, escalation files,
          // confidence). Carry those over ONLY when the job is unchanged and
          // terminal — a finished job's result can't change, anything else
          // must come fresh from the server.
          const sameTerminal = existing && existing.status === mapped.status &&
            (mapped.status === 'done' || mapped.status === 'error');
          return sameTerminal ? {
            ...mapped,
            outcome:           existing!.outcome           ?? mapped.outcome,
            prUrl:             existing!.prUrl,
            prUrls:            existing!.prUrls,
            escalationFiles:   existing!.escalationFiles,
            confidence:        existing!.confidence,
            confidencePercent: existing!.confidencePercent,
            fortifyRequest:    existing!.fortifyRequest,
          } : { ...mapped, fortifyRequest: existing?.fortifyRequest };
        });
      const serverIds = new Set(fromServer.map(r => r.id));
      const localOnly = current.filter(r =>
        r.source === 'fortify' && !serverIds.has(r.id) && isLocallyActive(r.id)
      );
      fortifyRuns = [...fromServer, ...localOnly];
    } else {
      fortifyRuns = current.filter(r => r.source === 'fortify');
    }

    // Runs that were already errored at page load stay hidden across every
    // refresh/poll — otherwise the next 20s all-users tick would bring them back.
    const merged = [...sonarRuns, ...fortifyRuns]
      .filter(r => !this._isHiddenError(r))
      .sort((a, b) => (b.startedAt ?? 0) - (a.startedAt ?? 0));
    this.runs.set(merged);
    this.selected.set(this._reselect(merged));
  }

  /** Keep the current selection if it still exists (with its fresh data), else pick the newest. */
  private _reselect(list: UiRun[]): UiRun | null {
    const cur = this.selected();
    return (cur && list.find(r => r.id === cur.id)) ?? list[0] ?? null;
  }

  // ── Reload in-flight Fortify runs this browser started (after page refresh) ─
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

    alive.forEach(p => this._rehydrateOne(p, 3));
  }

  private _rehydrateOne(p: PersistedFortifyRun, retriesLeft: number) {
    fetch(`${this.fortifyBase}/pipeline/status/${p.pipeline_id}`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(resp => {
        const job = resp?.data ?? resp;
        const isTerminal = job.status === 'completed' || job.status === 'failed';

        // Already hidden as errored-at-load — don't re-inject it into the list.
        if (job.status === 'failed' && this._hiddenErroredIds.has(p.pipeline_id)) {
          this._removePersisted(p.pipeline_id);
          return;
        }

        if (isTerminal) {
          this._injectFortifyCard(p.pipeline_id, p.mode, p.body, 'done');
          this._applyFortifyStatus(p.pipeline_id, resp);
          this._removePersisted(p.pipeline_id);
        } else {
          const uiStatus = job.status === 'running' ? 'running' : 'queued';
          this._injectFortifyCard(p.pipeline_id, p.mode, p.body, uiStatus);
          this._applyFortifyStatus(p.pipeline_id, resp);
          this._startFortifyPoll(p.pipeline_id);
        }
      })
      .catch(() => {
        if (retriesLeft > 0) {
          setTimeout(() => this._rehydrateOne(p, retriesLeft - 1), 1000);
        } else {
          this._injectFortifyCard(p.pipeline_id, p.mode, p.body, 'queued');
        }
      });
  }

  // ── Persist a Fortify run id to localStorage (re-attach after reload) ─────
  private _persistFortifyRun(pipelineId: string, mode: FortifyMode, body: Record<string, unknown>) {
    let existing: PersistedFortifyRun[] = [];
    try {
      const raw = localStorage.getItem(FORTIFY_ACTIVE_KEY);
      if (raw) existing = JSON.parse(raw);
    } catch {}

    const entry: PersistedFortifyRun = { pipeline_id: pipelineId, mode, body, started_at: Date.now() };
    const updated = [...existing.filter(p => p.pipeline_id !== pipelineId), entry];
    try { localStorage.setItem(FORTIFY_ACTIVE_KEY, JSON.stringify(updated)); } catch {}
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

  /** Remove the run-history cache older builds wrote — it's what kept
   *  resurrecting stale/deleted pipeline jobs. */
  private _purgeLegacyHistory() {
    try { localStorage.removeItem(LEGACY_ALL_RUNS_KEY); } catch {}
  }

  // ══════════════════════════════════════════════════════════════════════════
  // FORTIFY — public entry point (called from component after POST succeeds)
  // ══════════════════════════════════════════════════════════════════════════
  trackFortifyRun(pipelineId: string, mode: FortifyMode, body: Record<string, unknown>) {
    // Only queue behind a SONAR run — Fortify runs can coexist with each other.
    const sonarRunActive = this._sonarPolls.size > 0;
    if (sonarRunActive) {
      this._fortifyQueue.push({ pipelineId, mode, body });
      this._injectFortifyCard(pipelineId, mode, body, 'queued');
      this._persistFortifyRun(pipelineId, mode, body);
      return;
    }

    this._persistFortifyRun(pipelineId, mode, body);
    this._injectFortifyCard(pipelineId, mode, body, 'running');
    this._startFortifyPoll(pipelineId);
  }

  // ── Inject a Fortify run card into the runs list (idempotent) ────────────
  private _injectFortifyCard(
    pipelineId: string,
    mode: FortifyMode,
    body: Record<string, unknown>,
    status: UiRun['status']
  ) {
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
    const cur = this.selected();
    if (!cur || cur.status === 'done' || cur.status === 'error' || cur.status === 'cancelled') {
      this.selected.set(card);
    }
  }

  // ── Start (or resume) polling for one Fortify pipeline_id ─────────────────
  private _startFortifyPoll(pipelineId: string) {
    if (this._fortifyPolls.has(pipelineId)) return;   // already polling

    this._fortifyPolls.set(pipelineId, null as any);
    this._recomputeRunning();

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
        },
        complete: () => {
          this._cleanupFortifyPoll(pipelineId);
        },
      });

    this._fortifyPolls.set(pipelineId, sub);
  }

  // ── Clean up a finished Fortify poll and drain the queue ──────────────────
  private _cleanupFortifyPoll(pipelineId: string) {
    this._fortifyPolls.get(pipelineId)?.unsubscribe();
    this._fortifyPolls.delete(pipelineId);
    this._removePersisted(pipelineId);

    if (this._fortifyQueue.length > 0) {
      const next = this._fortifyQueue.shift()!;
      this.runs.update(rs => rs.map(r =>
        r.id === next.pipelineId ? { ...r, status: 'running' } : r
      ));
      this._persistFortifyRun(next.pipelineId, next.mode, next.body);
      this._startFortifyPoll(next.pipelineId);
      return;
    }

    this._recomputeRunning();
  }

  // ── Map GET /pipeline/status response → UiRun update ─────────────────────
  private _applyFortifyStatus(pipelineId: string, raw: any) {
    const resp = raw?.data ?? raw;

    const backendStatus = resp.status;
    const fromBackend =
      backendStatus === 'completed' ? 'done'
      : backendStatus === 'failed'  ? 'error'
      : backendStatus === 'running' ? 'running'
      : 'queued';

    // STATUS ORDER — never allow status to go backwards.
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
    let outcome:           string    | undefined;
    let prUrl:             string    | undefined;
    let prUrls:            string[]  | undefined;
    let escalationFiles:   string[]  | undefined;
    let confidence:        ConfLabel | undefined;
    let confidencePercent: string    | undefined;

    if (terminalStatus === 'done') {
      const prResults: any[] = result.pr_results ?? [];
      const allUrls = prResults.map((p: any) => p?.pr_url).filter(Boolean) as string[];
      const fixed     = allUrls.length;
      const escalated = result.total_escalated ?? 0;
      outcome = fixed > 0 ? 'pr_opened' : escalated > 0 ? 'escalated' : 'empty';
      prUrl   = allUrls[0];
      prUrls  = allUrls.length > 0 ? allUrls : undefined;

      const rawFiles: string[] = result.summary?.escalation_files ?? result.escalation_files ?? [];
      const names = rawFiles.map((p: string) => p.split('/').pop()).filter(Boolean) as string[];
      escalationFiles = names.length > 0 ? names : undefined;
    } else if (terminalStatus === 'error') {
      outcome = 'error';
    }

    if (result.groups?.length) {
      const scored = (result.groups as any[]).filter(
        (g: any) => g.ai_reasoning?.confidence_score != null
      );
      if (scored.length > 0) {
        const avgConf = scored.reduce(
          (sum: number, g: any) => sum + (g.ai_reasoning.confidence_score as number), 0
        ) / scored.length;
        confidence        = this.confLabel(avgConf);
        confidencePercent = this.confPercent(avgConf);
      }
    }

    this.runs.update(rs => rs.map(r => {
      if (r.id !== pipelineId) return r;
      const updated: UiRun = {
        ...r, steps,
        status:            terminalStatus as any,
        outcome:           outcome           ?? r.outcome,
        prUrl:             prUrl             ?? r.prUrl,
        prUrls:            prUrls            ?? r.prUrls,
        escalationFiles:   escalationFiles   ?? r.escalationFiles,
        confidence:        confidence        ?? r.confidence,
        confidencePercent: confidencePercent ?? r.confidencePercent,
        startedAt:         r.startedAt ?? Date.now(),
        resumeStage:       resp.resume_stage ?? r.resumeStage,
      };
      if (this.selected()?.id === pipelineId) this.selected.set(updated);
      // Only signal completion when this poll actually observed the transition
      // (avoids re-navigating to the summary when hydrating an old finished run).
      if ((terminalStatus === 'done' || terminalStatus === 'error') &&
          r.status !== 'done' && r.status !== 'error' && this._fortifyPolls.has(pipelineId)) {
        this.lastCompletedFortifyId.set(pipelineId);
      }
      return updated;
    }));

    if (terminalStatus === 'error' && resp.error && this._fortifyPolls.has(pipelineId)) {
      this.error.set(`Fortify: ${resp.error}`);
    }
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
      case 'adr-fix':         return summary.committed != null
        ? `Committed: ${summary.committed}/${summary.total}`
        : (summary.branch_name ? `Branch: ${summary.branch_name}` : summary.error_reason ?? '');
      case 'build-validation': return summary.pushed != null
        ? `Pushed: ${summary.pushed}/${summary.total}`
        : (summary.branch_name ? `Branch: ${summary.branch_name}` : summary.error_reason ?? '');
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
    this.submitting.set('start');
    this.error.set(null);

    this.api.startRun(req).subscribe({
      next: ({ run_id }) => {
        this.submitting.set(null);
        this._pollRun(run_id, this._sanitizeRunRequest(req));
      },
      error: (err: any) => {
        this.submitting.set(null);
        const detail = err?.error?.detail ?? err?.message ?? 'Pipeline start failed';
        this.error.set(detail);
      },
    });
  }

  /** Strips per-run credentials — never kept in component state. */
  private _sanitizeRunRequest(req: RunRequest): RunRequest {
    const { github_token, sonar_token, ...rest } = req;
    return rest as RunRequest;
  }

  private _pollRun(runId: string, req: RunRequest) {
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

    this._startSonarPoll(runId);
  }

  private _startSonarPoll(runId: string) {
    if (this._sonarPolls.has(runId)) return;   // already polling

    this._sonarPolls.set(runId, null as any);
    this._recomputeRunning();

    const sub = this.api.pollRun(runId).subscribe({
      next:  (s: RunStatus) => this._applyStatus(runId, s),
      error: (err: Error) => {
        this.error.set(err.message);
        this._sonarPolls.delete(runId);
        this._recomputeRunning();
        this._drainFortifyQueue();
      },
    });

    this._sonarPolls.set(runId, sub);
  }

  private _recomputeRunning() {
    this.running.set(this._sonarPolls.size > 0 || this._fortifyPolls.size > 0);
  }

  private _drainFortifyQueue() {
    if (this._sonarPolls.size > 0) return;
    if (this._fortifyQueue.length === 0) return;
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
        steps:             mergedSteps,
        outcome:           noResults ? 'empty' : (first?.outcome ?? r.outcome),
        confidence:        first ? this.confLabel(first.confidence) : r.confidence,
        confidencePercent: first?.confidence != null
                             ? this.confPercent(first.confidence)
                             : r.confidencePercent,
        prUrl:             first?.pr_url ?? r.prUrl,
        status:            noResults ? 'empty' as any : status.status,
        ruleKey:           first?.rule_key  ? first.rule_key  : r.ruleKey,
        severity:          first?.severity  ? first.severity  : r.severity,
        component:         first?.file_path ? first.file_path : r.component,
        tokens:            this._mapTokens(status.token_usage ?? first?.token_usage) ?? r.tokens,
        startedAt:         r.startedAt ?? Date.now(),
      };

      if (this.selected()?.id === runId) this.selected.set(updated);
      return updated;
    }));

    if (status.status === 'done' || status.status === 'error') {
      this._sonarPolls.delete(runId);
      this._recomputeRunning();

      if (status.status === 'error' && status.error) this.error.set(status.error);

      const noResults = !status.results || status.results.length === 0;
      if (noResults && status.status === 'done') {
        this.error.set('No issues found for the selected severity.');
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
      id:                `${runId}-${i}`,
      ruleKey:           r.rule_key,
      severity:          r.severity,
      component:         r.file_path,
      outcome:           r.outcome,
      confidence:        this.confLabel(r.confidence),
      confidencePercent: this.confPercent(r.confidence),
      tokens:            this._mapTokens(r.token_usage),
      prUrl:             r.pr_url ?? undefined,
      steps:             status.steps ?? [],
      live:              true,
      status:            'done' as const,
      request:           parentReq,
      source:            'sonar' as const,
    }));
    this.runs.update(rs => [...newCards, ...rs.filter(r => r.id !== runId)]);
    if (newCards[0]) this.selected.set(newCards[0]);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // ALL-USERS FORTIFY RUNS — GET /pipeline/runs (shared job store)
  // ══════════════════════════════════════════════════════════════════════════

  /** Start (or restart) periodic polling of the shared Fortify runs list. */
  private _startAllFortifyRunsPolling() {
    this._allRunsPoll?.unsubscribe();
    this._allRunsPoll = timer(0, ALL_RUNS_POLL_MS)
      .pipe(switchMap(() => this.api.listFortifyRuns()))
      .subscribe({
        next: resp => {
          const jobs: any[] = (resp as any)?.data?.jobs ?? (resp as any)?.jobs ?? [];
          // Same authoritative replace as a manual refresh, Fortify side only —
          // jobs deleted server-side drop out on the next tick.
          this._applyRefresh(null, jobs);
          this._fortifyListLoaded = true;
          this.apiOnline.set(true);   // heartbeat succeeded — backend is reachable
          this._maybeFinishInitialLoad();
        },
        error: () => {
          this._fortifyListLoaded = true;
          this.apiOnline.set(false);  // heartbeat failed — backend unreachable
          this._maybeFinishInitialLoad();
        },
      });
  }

  /** Map a job doc from GET /pipeline/runs (or /pipeline/status) → UiRun. */
  private _backendFortifyJobToUiRun(job: any): UiRun {
    const backendStatus = job.status;
    const status: UiRun['status'] =
      backendStatus === 'completed'   ? 'done'
      : backendStatus === 'failed'      ? 'error'
      : backendStatus === 'interrupted' ? 'error'
      : backendStatus === 'cancelled'   ? 'cancelled'
      : backendStatus === 'running'     ? 'running'
      : 'queued';

    const stages: Record<string, any> = job.stages ?? {};
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

    const meta = job.resume_meta ?? {};
    const ruleKey =
      meta.app_name    ? String(meta.app_name)
      : meta.release_id  ? `Release ${meta.release_id}`
      : meta.report_path ? `Offline · ${String(meta.report_path).split('/').pop()}`
      : 'Fortify pipeline';
    const component = meta.repo ?? '';

    const outcome = status === 'error' ? 'error' : status === 'cancelled' ? 'cancelled' : undefined;

    return {
      id:         job.pipeline_id,
      ruleKey,
      severity:   'FORTIFY',
      component,
      steps,
      live:       true,
      status,
      outcome,
      source:     'fortify',
      startedAt:  job.started_at ? new Date(job.started_at).getTime() : undefined,
      resumeStage: job.resume_stage ?? null,
    };
  }

  /**
   * Fetch the full detail (PR urls, escalation files, confidence, outcome)
   * for one pipeline_id and merge it into `runs`/`selected`.
   */
  hydrateRunDetail(pipelineId: string): void {
    this.http.get<any>(`${this.fortifyBase}/pipeline/status/${pipelineId}`).subscribe({
      next: resp => this._applyFortifyStatus(pipelineId, resp),
      error: () => {},
    });
  }

  // ── Backend run hydration ─────────────────────────────────────────────────
  private _backendRunToUiRun(r: any): UiRun {
    const first = Array.isArray(r.results) ? r.results[0] : undefined;
    const confScore: number | null = first?.confidence ?? null;
    const confLabel: ConfLabel = confScore != null ? this.confLabel(confScore) : null;
    const confPercent: string | undefined = confScore != null ? this.confPercent(confScore) : undefined;
    const steps: PipelineStep[] = Array.isArray(r.steps)
      ? r.steps.map((s: any) => ({ label: s.label ?? '', status: s.status ?? 'done', detail: s.detail ?? '', ms: s.ms ?? 0 }))
      : [];
    return {
      id:                r.id ?? r.run_id,
      ruleKey:           first?.rule_key  ?? '—',
      severity:          first?.severity  ?? 'INFO',
      component:         first?.file_path ?? '',
      outcome:           first?.outcome   ?? (r.status === 'error' ? 'error' : undefined),
      confidence:        confLabel,
      confidencePercent: confPercent,
      prUrl:             first?.pr_url    ?? undefined,
      tokens:            this._mapTokens(r.token_usage ?? first?.token_usage),
      steps,
      live:              false,
      status:            r.status ?? 'done',
      request:           r.request,
      source:            r.source ?? 'sonar',
      startedAt:         r.started_at ? new Date(r.started_at).getTime() : undefined,
    };
  }

  // ── Escalation report download ────────────────────────────────────────────
  async downloadEscalation(filename: string): Promise<void> {
    try {
      const resp = await fetch(`${this.fortifyBase}/escalations/${encodeURIComponent(filename)}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      const blob = new Blob([data.content ?? ''], { type: 'text/plain' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      this.error.set(`Could not download escalation report: ${err.message}`);
    }
  }

  // ── Shared helpers ────────────────────────────────────────────────────────
  select(run: UiRun)   { this.selected.set(run); }
  doneCnt(run: UiRun)  { return run.steps.filter(s => s.status === 'done').length; }
  confClass(c: ConfLabel | string | undefined) { return (c ?? '').toLowerCase(); }

  private _mapTokens(tu: any): { input: number; output: number } | undefined {
    if (!tu) return undefined;
    const input  = Number(tu.input_tokens  ?? 0);
    const output = Number(tu.output_tokens ?? 0);
    if (!input && !output) return undefined;
    return { input, output };
  }

  /** 1234 → "1.2k", 987 → "987", undefined → "—". */
  fmtTokens(n?: number): string {
    if (n == null) return '—';
    return n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(n);
  }

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

  confPercent(score: number): string {
    return `${Math.round(score * 100)}%`;
  }

  // ── Delete ────────────────────────────────────────────────────────────────
  deleteRun(id: string) {
    if (this._sonarPolls.has(id) || this._fortifyPolls.has(id) || this._fortifyQueue.some(q => q.pipelineId === id)) return;
    const run = this.runs().find(r => r.id === id);
    this.runs.update(rs => rs.filter(r => r.id !== id));
    if (this.selected()?.id === id) this.selected.set(this.runs()[0] ?? null);
    this._removePersisted(id);

    if (run?.source === 'fortify') {
      fetch(`${this.fortifyBase}/pipeline/runs/${id}`, { method: 'DELETE' }).catch(() => {});
    } else {
      this.api.deleteRun(id).subscribe({ error: () => {} });
    }
  }

  // ── Resume ────────────────────────────────────────────────────────────────
  /** Last stage index resume is still offered for — keep in sync with
   *  _RESUME_MAX_STAGE in api_server.py::_resume_precheck. */
  private readonly RESUME_MAX_STAGE_INDEX = FORTIFY_STAGE_ORDER.indexOf('ai-reasoning');

  canResume(run: UiRun): boolean {
    if (run.source !== 'fortify' || (run.status !== 'error' && run.status !== 'cancelled')) {
      return false;
    }
    if (!run.resumeStage) return true;
    const idx = FORTIFY_STAGE_ORDER.indexOf(run.resumeStage);
    return idx === -1 || idx <= this.RESUME_MAX_STAGE_INDEX;
  }

  resumeFortifyRun(pipelineId: string) {
    const run = this.runs().find(r => r.id === pipelineId);
    if (!run || !this.canResume(run)) return;

    const mode: FortifyMode = run.fortifyRequest?.mode ?? 'live';
    const body: Record<string, unknown> = run.fortifyRequest?.body ?? {};

    this.error.set(null);
    this.submitting.set('resume');

    this.api.resumeFortifyRun(pipelineId).subscribe({
      next: () => {
        this.http.get<any>(`${this.fortifyBase}/pipeline/status/${pipelineId}`).subscribe({
          next: resp => {
            this._applyFortifyStatus(pipelineId, resp);
            this._clearStaleTerminalState(pipelineId);
            this._finishResume(pipelineId, mode, body);
          },
          error: () => {
            this.runs.update(rs => rs.map(r => r.id === pipelineId
              ? { ...r, status: 'running' as const, outcome: undefined }
              : r
            ));
            this._clearStaleTerminalState(pipelineId);
            this._finishResume(pipelineId, mode, body);
          },
        });
      },
      error: (err: any) => {
        const detail = err?.error?.detail ?? err?.message ?? 'Resume failed';
        this.error.set(`Resume: ${detail}`);
        this.submitting.set(null);
      },
    });
  }

  /** Reset leftover terminal state (outcome, cancelled steps) from the
   *  previous attempt once a resumed run is confirmed running again. */
  private _clearStaleTerminalState(pipelineId: string) {
    this.runs.update(rs => rs.map(r => r.id === pipelineId
      ? {
          ...r,
          outcome: undefined,
          steps: r.steps.map(s =>
            s.status === 'cancelled' ? { ...s, status: 'pending' as const, detail: '' } : s
          ),
        }
      : r
    ));
  }

  private _finishResume(pipelineId: string, mode: FortifyMode, body: Record<string, unknown>) {
    if (this.selected()?.id === pipelineId) {
      this.selected.set(this.runs().find(r => r.id === pipelineId) ?? null);
    }

    const sonarRunActive = this._sonarPolls.size > 0;
    if (sonarRunActive) {
      this.runs.update(rs => rs.map(r => r.id === pipelineId ? { ...r, status: 'queued' as const } : r));
      this._fortifyQueue.push({ pipelineId, mode, body });
      this.submitting.set(null);
      return;
    }

    this._persistFortifyRun(pipelineId, mode, body);
    this._startFortifyPoll(pipelineId);
    this.submitting.set(null);
  }

  // ── Cancel ────────────────────────────────────────────────────────────────
  /** Cancel exactly one run (Sonar or Fortify); every other run is untouched. */
  async cancelRun(pipelineId?: string) {
    const targetId = pipelineId;
    if (!targetId) return;

    this.submitting.set('stop');

    const isSonarActive   = this._sonarPolls.has(targetId);
    const isFortifyActive = !isSonarActive && this._fortifyPolls.has(targetId);
    const isFortifyQueued = !isSonarActive && !isFortifyActive && this._fortifyQueue.some(q => q.pipelineId === targetId);

    try {
      if (isFortifyQueued) {
        this._fortifyQueue = this._fortifyQueue.filter(q => q.pipelineId !== targetId);
        this._removePersisted(targetId);
      } else if (isSonarActive) {
        this._sonarPolls.get(targetId)?.unsubscribe();
        await firstValueFrom(this.api.cancelRun(targetId)).catch(() => {});
        this._sonarPolls.delete(targetId);
        this._recomputeRunning();
        this._drainFortifyQueue();
      } else {
        await fetch(`${this.fortifyBase}/pipeline/cancel/${targetId}`, { method: 'POST' }).catch(() => {});
        if (isFortifyActive) {
          this._cleanupFortifyPoll(targetId);
        }
      }
    } finally {
      this.submitting.set(null);
    }

    this.runs.update(rs => rs.map(r => {
      if (r.id !== targetId) return r;
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

    const updated = this.runs().find(r => r.id === targetId);
    if (updated && this.selected()?.id === targetId) this.selected.set(updated);
  }
}