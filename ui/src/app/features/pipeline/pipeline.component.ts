// src/app/features/pipeline/pipeline.component.ts
import { Component, inject, signal, computed, effect } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { PipelineStateService, UiRun, RunRequest } from '../../core/pipeline-state.service';
import { ApiConfigService } from '../../core/api-config.service';
import { SevClassPipe }    from '../../shared/sev-class.pipe';
import { OutcomeClassPipe } from '../../shared/outcome-class.pipe';
import { OutcomeLabelPipe } from '../../shared/outcome-label.pipe';
import { ActiveStepPipe }  from '../../shared/active-step.pipe';

// ── Fortify pipeline mode → API endpoint mapping ──────────────────────────────
export type FortifyMode = 'live' | 'offline' | 'app-name';

const ENDPOINT_MAP: Record<FortifyMode, string> = {
  'live':     '/pipeline/live',
  'offline':  '/pipeline/offline',
  'app-name': '/pipeline/app-name',
};

@Component({
  selector: 'app-pipeline',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink, SevClassPipe, OutcomeClassPipe, OutcomeLabelPipe, ActiveStepPipe],
  templateUrl: './pipeline.component.html',
  styleUrl:    './pipeline.component.scss',
})
export class PipelineComponent {
  state    = inject(PipelineStateService);
  private apiCfg = inject(ApiConfigService);
  private router  = inject(Router);

  constructor() {
    // When a Fortify pipeline run completes (or errors), automatically navigate
    // to the summary report page so the user sees results immediately.
    effect(() => {
      const completedId = this.state.lastCompletedFortifyId();
      if (completedId) {
        this.state.clearLastCompleted();
        this.router.navigate(['/pipeline/summary', completedId]);
      }
    });
  }

  // ── Source tab: 'sonar' | 'fortify' | 'both' ─────────────────────────────
  activeSource = signal<'sonar' | 'fortify'>('fortify');

  // ── Pipeline step labels ──────────────────────────────────────────────────
  readonly FORTIFY_STEPS = [
    'Triage', 'Version Resolver', 'Context', 'API Diff',
    'AI Reasoning', 'Dependency Fix', 'Build Validation', 'AI Code Fix',
    'PR Agent', 'Fortify Writeback',
  ];

  readonly SONAR_STEPS = [
    'Ingest', 'Load Repo', 'RAG Fetch', 'Fetch Rule',
    'Planner', 'Generator', 'Critic', 'Validate', 'Deliver',
  ];

  // ── Fortify pipeline mode options ─────────────────────────────────────────
  readonly FORTIFY_MODES: { label: string; value: FortifyMode }[] = [
    { label: 'Live',      value: 'live'     },
    { label: 'Offline',   value: 'offline'  },
    { label: 'App Name',  value: 'app-name' },
  ];

  // ── Active Fortify mode ───────────────────────────────────────────────────
  fortifyMode = signal<FortifyMode>('live');

  // ── Derived endpoint label ────────────────────────────────────────────────
  fortifyEndpoint = computed(() => ENDPOINT_MAP[this.fortifyMode()]);

  // ── Severity options (in priority order) ─────────────────────────────────
  readonly SEV_OPTIONS = ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO'] as const;

  // ── Sonar run form signals ────────────────────────────────────────────────
  repoUrl      = signal('https://github.com/org/repo.git');
  commitSha    = signal('HEAD');
  maxIssues    = signal(1);
  parallel     = signal(false);
  rescan       = signal(false);
  noRag        = signal(false);
  dryRun       = signal(false);
  showForm     = signal(false);

  // ── Fortify run form signals ──────────────────────────────────────────────
  fortifyReleaseId   = signal('');
  fortifyAppName     = signal('');
  fortifyGithubRepo  = signal('');       // owner/repo — clones repo so no local PROJECT_PATH needed
  fortifyReportPath  = signal('');       // offline mode: path to JSON report
  fortifyMaxUpgrades = signal(1);        // min is always 1 — there is no "0 = all" anymore;
                                          // every run commits to an explicit, bounded batch.
  showFortifyForm    = signal(false);

  // ── Fortify form validation ─────────────────────────────────────────────────
  // Every visible field is mandatory for its mode (GitHub Repo always; Release ID
  // for Live; Report Path for Offline; App Name for App Name). Errors only render
  // once the user has actually tried to submit — see fortifyFormSubmitted — so an
  // empty field isn't flagged red before they've had a chance to fill it in.
  fortifyFormSubmitted = signal(false);

  private fortifyReleaseIdMissing = computed(() =>
    this.fortifyFormSubmitted() && this.fortifyMode() === 'live' && !this.fortifyReleaseId().trim()
  );
  private fortifyReportPathMissing = computed(() =>
    this.fortifyFormSubmitted() && this.fortifyMode() === 'offline' && !this.fortifyReportPath().trim()
  );
  private fortifyAppNameMissing = computed(() =>
    this.fortifyFormSubmitted() && this.fortifyMode() === 'app-name' && !this.fortifyAppName().trim()
  );
  private fortifyGithubRepoMissing = computed(() =>
    this.fortifyFormSubmitted() && !this.fortifyGithubRepo().trim()
  );
  private fortifyGithubTokenMissing = computed(() =>
    this.fortifyFormSubmitted() && !this.fortifyGithubToken().trim()
  );
  private fortifyUsernameMissing = computed(() =>
    this.fortifyFormSubmitted() && !this.fortifyUsername().trim()
  );
  private fortifyPasswordMissing = computed(() =>
    this.fortifyFormSubmitted() && !this.fortifyPassword().trim()
  );

  /** Field-error getters for the template — true only after a submit attempt. */
  releaseIdError    = computed(() => this.fortifyReleaseIdMissing());
  reportPathError   = computed(() => this.fortifyReportPathMissing());
  appNameError      = computed(() => this.fortifyAppNameMissing());
  githubRepoError   = computed(() => this.fortifyGithubRepoMissing());
  githubTokenError  = computed(() => this.fortifyGithubTokenMissing());
  usernameError     = computed(() => this.fortifyUsernameMissing());
  passwordError      = computed(() => this.fortifyPasswordMissing());

  /** True once every mandatory field for the active mode is filled in. */
  fortifyFormValid = computed(() => {
    if (!this.fortifyGithubRepo().trim())    return false;
    if (!this.fortifyGithubToken().trim())   return false;
    if (!this.fortifyUsername().trim())      return false;
    if (!this.fortifyPassword().trim())      return false;
    switch (this.fortifyMode()) {
      case 'live':     return !!this.fortifyReleaseId().trim();
      case 'offline':  return !!this.fortifyReportPath().trim();
      case 'app-name': return !!this.fortifyAppName().trim();
      default:         return true;
    }
  });

  // ── Run Maven build validation (Stage 6b) ──────────────────────────────────
  // Off by default — build validation costs real CI time per dependency, so
  // it's opt-in. Once enabled, this bounds max_upgrades to a small, fixed
  // batch (1–5).
  fortifyRunBuild = signal(false);
  readonly MIN_MAX_UPGRADES_WHEN_BUILD = 1;   // hard floor once build is on — shown in the UI
  readonly MAX_MAX_UPGRADES_WHEN_BUILD = 5;   // hard ceiling once build is on — shown in the UI

  // General ceiling — applies regardless of Run Maven Build. Max Upgrades is
  // always at least 1 (there's no "0 = all" anymore — every run commits to an
  // explicit, bounded batch), capped at 20 when build is off; a single run
  // committing more than that is treated as a config mistake rather than an
  // intentional batch.
  readonly MAX_MAX_UPGRADES_GENERAL = 20;

  /** Smallest legal Max Upgrades value — always 1, build on or off. */
  maxUpgradesMin = computed(() => this.MIN_MAX_UPGRADES_WHEN_BUILD);

  /** Largest legal Max Upgrades value — 5 once build validation is on, else the general 20-upgrade ceiling. */
  maxUpgradesMax = computed(() =>
    this.fortifyRunBuild() ? this.MAX_MAX_UPGRADES_WHEN_BUILD : this.MAX_MAX_UPGRADES_GENERAL
  );

  /** True when the current Max Upgrades value violates whichever range currently applies — blocks submit. */
  maxUpgradesInvalid = computed(() => {
    const n = this.fortifyMaxUpgrades();
    if (n < this.MIN_MAX_UPGRADES_WHEN_BUILD) return true;
    return n > this.maxUpgradesMax();
  });

  // ── Per-run credentials — never persisted, cleared after each submit ──────
  // Each Fortify run can use a different GitHub PAT / Fortify account, so
  // these live on the form rather than in global Settings/config.
  fortifyGithubToken = signal('');       // GitHub PAT used for clone + PR for THIS run
  fortifyUsername    = signal('');       // Fortify OAuth username, WITHOUT the "equifax\" prefix
  fortifyPassword     = signal('');       // Fortify OAuth password for THIS run

  /** Toggle Run Maven Build. Enabling it snaps Max Upgrades into the 1–5 range,
   *  since builds are only meant to run against a small, bounded batch of deps. */
  toggleFortifyRunBuild(on: boolean) {
    this.fortifyRunBuild.set(on);
    if (on) {
      const current = this.fortifyMaxUpgrades();
      if (current < this.MIN_MAX_UPGRADES_WHEN_BUILD || current > this.MAX_MAX_UPGRADES_WHEN_BUILD) {
        this.fortifyMaxUpgrades.set(this.MAX_MAX_UPGRADES_WHEN_BUILD);
      }
    }
    this._scheduleBuildEstimate();
  }

  /** Max Upgrades input handler — always clamps to at least 1, and up to whichever
   *  ceiling currently applies: 5 while Run Maven Build is on, else the general 20 cap. */
  onFortifyMaxUpgradesInput(raw: string) {
    let n = Math.trunc(+raw) || 0;
    n = Math.max(this.MIN_MAX_UPGRADES_WHEN_BUILD, Math.min(this.maxUpgradesMax(), n));
    this.fortifyMaxUpgrades.set(n);
    this._scheduleBuildEstimate();
  }

  /** GitHub Repo input handler — updates the field and, when build is on, re-estimates
   *  build time against the newly-typed repo (debounced so we don't clone on every keystroke). */
  onFortifyGithubRepoInput(raw: string) {
    this.fortifyGithubRepo.set(raw);
    this._scheduleBuildEstimate();
  }

  // ── Estimated run time ──────────────────────────────────────────────────────
  // Two layers: a local fixed heuristic that renders instantly (no round-trip),
  // and a project-size-aware estimate fetched from the backend
  // (POST /pipeline/estimate-build-time), which counts actual Maven modules
  // in the target repo instead of guessing. The server estimate — once it
  // arrives for the CURRENT form state — takes over the display; the local
  // heuristic is only shown while that request is in flight or unavailable
  // (e.g. no repo entered yet, or the call failed).
  private readonly EST_BASE_OVERHEAD_SEC   = 45;   // clone + auth + warm-up, once per run
  private readonly EST_PER_DEP_SEC         = 20;   // triage..writeback per dependency (no build)
  private readonly EST_BUILD_PER_DEP_SEC   = 150;  // extra mvn clean install per dependency (build on, local fallback only)

  /** Local fallback point estimate in seconds — always computable now that Max Upgrades is never 0. */
  private fallbackRuntimeSeconds = computed<number | null>(() => {
    const deps    = Math.max(this.fortifyMaxUpgrades(), this.MIN_MAX_UPGRADES_WHEN_BUILD);
    const perDep  = this.EST_PER_DEP_SEC + (this.fortifyRunBuild() ? this.EST_BUILD_PER_DEP_SEC : 0);
    return this.EST_BASE_OVERHEAD_SEC + deps * perDep;
  });

  /** Server-measured estimate for Run Maven Build, keyed to the inputs it was computed from. */
  private buildEstimateResult = signal<{
    repo: string; maxUpgrades: number; moduleCount: number; lowSec: number; highSec: number;
  } | null>(null);
  buildEstimateLoading = signal(false);
  private buildEstimateDebounce: ReturnType<typeof setTimeout> | null = null;

  /** True once a server estimate has been fetched for exactly the current repo + max upgrades. */
  private buildEstimateFresh = computed(() => {
    const r = this.buildEstimateResult();
    return !!r && r.repo === this.fortifyGithubRepo().trim() && r.maxUpgrades === this.fortifyMaxUpgrades();
  });

  /** Human-readable "~X–Y min" estimate — server-measured when fresh, else the local fallback. */
  estimatedRuntimeLabel = computed<string | null>(() => {
    if (this.fortifyRunBuild() && this.buildEstimateFresh()) {
      const r = this.buildEstimateResult()!;
      const lo = this._fmtMinutes(r.lowSec);
      const hi = this._fmtMinutes(r.highSec);
      return lo === hi ? `~${lo} min` : `~${lo}–${hi} min`;
    }
    const secs = this.fallbackRuntimeSeconds();
    if (secs == null) return null;
    const lo = this._fmtMinutes(secs * 0.75);
    const hi = this._fmtMinutes(secs * 1.3);
    return lo === hi ? `~${lo} min` : `~${lo}–${hi} min`;
  });

  /** Module count from the last server estimate, shown as "(N modules)" — only while fresh. */
  estimatedModuleCount = computed<number | null>(() =>
    this.fortifyRunBuild() && this.buildEstimateFresh() ? this.buildEstimateResult()!.moduleCount : null
  );

  private _fmtMinutes(seconds: number): number {
    return Math.max(1, Math.round(seconds / 60));
  }

  /** Debounced trigger for the server-side estimate — called whenever an input it depends on changes. */
  private _scheduleBuildEstimate() {
    if (this.buildEstimateDebounce) clearTimeout(this.buildEstimateDebounce);
    if (!this.fortifyRunBuild()) return;   // only relevant once build is on

    const repo = this.fortifyGithubRepo().trim();
    const maxUpgrades = this.fortifyMaxUpgrades();
    this.buildEstimateDebounce = setTimeout(() => this._fetchBuildEstimate(repo, maxUpgrades), 500);
  }

  private _fetchBuildEstimate(repo: string, maxUpgrades: number) {
    const baseUrl = this.apiCfg.fortifyBaseUrl();
    const config: Record<string, unknown> = {
      ...(this.fortifyGithubToken().trim() ? { github_token: this.fortifyGithubToken().trim() } : {}),
    };
    this.buildEstimateLoading.set(true);
    fetch(`${baseUrl}/pipeline/estimate-build-time`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        ...(repo ? { repo } : {}),
        max_upgrades: Math.max(1, maxUpgrades),
        config,
      }),
    })
    .then(r => r.json())
    .then(resp => {
      // Stale response guard — only apply if the inputs haven't changed since this call started.
      if (repo !== this.fortifyGithubRepo().trim() || maxUpgrades !== this.fortifyMaxUpgrades()) return;
      const data = resp?.data ?? resp;
      if (resp?.ok !== false && data?.module_count != null) {
        this.buildEstimateResult.set({
          repo, maxUpgrades,
          moduleCount: data.module_count,
          lowSec:      data.estimated_seconds_low,
          highSec:     data.estimated_seconds_high,
        });
      }
      // On failure, leave buildEstimateResult as-is — estimatedRuntimeLabel() falls back
      // to the local heuristic automatically since buildEstimateFresh() won't match.
    })
    .catch(() => { /* silent — local fallback estimate covers this */ })
    .finally(() => this.buildEstimateLoading.set(false));
  }



  private readonly FORTIFY_DOMAIN_PREFIX = 'equifax\\';

  /** Prepend the "equifax\" domain prefix expected by Fortify OAuth, once. */
  private _domainQualify(username: string): string {
    const trimmed = username.trim();
    if (!trimmed) return '';
    return trimmed.toLowerCase().startsWith(this.FORTIFY_DOMAIN_PREFIX.toLowerCase())
      ? trimmed
      : `${this.FORTIFY_DOMAIN_PREFIX}${trimmed}`;
  }

  // ── Severity multi-select — all enabled by default ────────────────────────
  selectedSevs = signal<Set<string>>(
    new Set(['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO'])
  );

  // ── Input viewer ──────────────────────────────────────────────────────────
  showInput = signal(false);

  // ── Delegate to service ───────────────────────────────────────────────────
  running()  { return this.state.running(); }
  error()    { return this.state.error(); }
  selected() { return this.state.selected(); }

  get allRuns()  { return this.state.allRuns; }
  get canCancel(){ return this.state.canCancel; }
  get loadingRuns() { return this.state.loadingRuns(); }

  /** Runs filtered to the active source tab — Sonar or Fortify */
  filteredRuns(): UiRun[] {
    return this._runsFor(this.activeSource());
  }

  private _runsFor(src: 'sonar' | 'fortify'): UiRun[] {
    return this.state.allRuns.filter(r =>
      src === 'sonar'
        ? (r.source === 'sonar' || !r.source)   // legacy runs without source field = Sonar
        : r.source === 'fortify'
    );
  }

  /**
   * Switch the active source tab and re-sync the detail panel selection.
   * `state.selected()` is shared across both tabs, so without this a run
   * selected under one tab (e.g. the last Fortify run) stays shown in the
   * detail panel after switching to the other tab, even though the run
   * list below no longer includes it.
   */
  switchSource(src: 'sonar' | 'fortify') {
    this.activeSource.set(src);
    this.showForm.set(false);
    this.showFortifyForm.set(false);
    this.showInput.set(false);

    const current = this.state.selected();
    const stillVisible = !!current && this._runsFor(src).some(r => r.id === current.id);
    if (!stillVisible) {
      this.state.selected.set(this._runsFor(src)[0] ?? null);
    }
  }

  select(run: UiRun) {
    this.state.select(run);
    this.showInput.set(false);
  }

  doneCnt(run: UiRun)      { return this.state.doneCnt(run); }
  confClass(c: any)        { return this.state.confClass(c); }
  fmtTokens(n?: number)    { return this.state.fmtTokens(n); }
  outcomeIcon(o?: string)  { return this.state.outcomeIcon(o); }
  outcomeTitle(o?: string) { return this.state.outcomeTitle(o); }

  // ── Severity toggle ───────────────────────────────────────────────────────
  toggleSev(s: string) {
    this.selectedSevs.update(set => {
      const next = new Set(set);
      if (next.has(s)) {
        if (next.size > 1) next.delete(s);
      } else {
        next.add(s);
      }
      return next;
    });
  }

  isSevSelected(s: string): boolean {
    return this.selectedSevs().has(s);
  }

  private _severitiesString(): string {
    return this.SEV_OPTIONS
      .filter(s => this.selectedSevs().has(s))
      .join(',');
  }

  // ── Sonar start ───────────────────────────────────────────────────────────
  startRun() {
    this.showForm.set(false);
    this.state.startRun({
      repo_url:   this.repoUrl(),
      commit_sha: this.commitSha(),
      max_issues: this.maxIssues(),
      parallel:   this.parallel(),
      rescan:     this.rescan(),
      no_rag:     this.noRag(),
      dry_run:    this.dryRun(),
      severities: this._severitiesString(),
    });
  }

  // ── Fortify start — builds request body per mode and calls correct endpoint ─
  startFortifyRun() {
    this.fortifyFormSubmitted.set(true);

    if (!this.fortifyFormValid()) {
      this.state.error.set('Please fill in all required fields before starting a run.');
      return;
    }

    // Guard: don't submit a run with Max Upgrades outside whichever range
    // currently applies — surface it as an error instead of silently
    // clamping, since a silent rewrite here could kick off a different
    // batch size than the one the user typed.
    if (this.maxUpgradesInvalid()) {
      this.state.error.set(
        `Max Upgrades must be between ${this.MIN_MAX_UPGRADES_WHEN_BUILD} and ${this.maxUpgradesMax()}` +
        (this.fortifyRunBuild() ? ' when Run Maven Build is enabled.' : '.')
      );
      return;
    }

    this.showFortifyForm.set(false);

    const mode     = this.fortifyMode();
    const endpoint = this.fortifyEndpoint();
    // Uses fortifyBaseUrl — routes to separate Fortify port if configured
    const baseUrl  = this.apiCfg.fortifyBaseUrl();

    // Per-run credential overrides — now mandatory (validated above), so these
    // are always present by the time we get here; no more falling back to
    // server-configured defaults for a blank field.
    const credConfig: Record<string, unknown> = {
      github_token:     this.fortifyGithubToken().trim(),
      fortify_username: this._domainQualify(this.fortifyUsername()),
      fortify_password: this.fortifyPassword(),
    };

    // The guard above already ensured Max Upgrades is within whichever range
    // currently applies — 1–5 with build on, or 1–20 with it off.
    const runBuild = this.fortifyRunBuild();
    const maxUpgrades = Math.max(
      this.MIN_MAX_UPGRADES_WHEN_BUILD,
      Math.min(this.maxUpgradesMax(), this.fortifyMaxUpgrades()),
    );

    let body: Record<string, unknown> = {
      max_upgrades: maxUpgrades,
      run_build:    runBuild,
      repo:         this.fortifyGithubRepo().trim(),
      config:       credConfig,
    };

    // Don't linger with plaintext credentials in memory / the DOM any longer
    // than needed — the values are already captured in credConfig above.
    this.fortifyPassword.set('');

    switch (mode) {
      case 'live':
        body = {
          ...body,
          release_id: Number(this.fortifyReleaseId()),
        };
        break;
      case 'offline':
        body = {
          ...body,
          report_path: this.fortifyReportPath(),
          release_id:  Number(this.fortifyReleaseId()) || 0,
        };
        break;
      case 'app-name':
        body = {
          ...body,
          app_name: this.fortifyAppName(),
        };
        break;
    }

    // Fire-and-forget: POST to Fortify API server, then poll /pipeline/status/{id}
    this.state.submitting.set('start');
    fetch(`${baseUrl}${endpoint}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    })
    .then(r => r.json())
    .then(resp => {
      this.state.submitting.set(null);
      // Backend wraps responses: { ok: true, data: { pipeline_id, status } }
      const pipeline_id = resp?.data?.pipeline_id ?? resp?.pipeline_id;
      if (pipeline_id) {
        this.state.trackFortifyRun(pipeline_id, mode, body);
        this._resetFortifyForm();
      } else {
        this.state.error.set(`Fortify API: no pipeline_id in response — ${JSON.stringify(resp)}`);
      }
    })
    .catch(err => {
      this.state.submitting.set(null);
      this.state.error.set(`Fortify API error: ${err.message}`);
    });
  }

  /** Clears every Fortify run-form field back to its default after a run starts
   *  successfully — the next run starts from a clean slate rather than reusing
   *  stale values. Only called on success; a failed submit keeps what was typed
   *  so the user can fix and resubmit without retyping everything. */
  private _resetFortifyForm() {
    this.fortifyReleaseId.set('');
    this.fortifyAppName.set('');
    this.fortifyGithubRepo.set('');
    this.fortifyReportPath.set('');
    this.fortifyMaxUpgrades.set(1);   // matches the field's own default — see its declaration
    this.fortifyRunBuild.set(false);
    this.fortifyGithubToken.set('');
    this.fortifyUsername.set('');
    this.fortifyPassword.set('');       // already cleared above, but reset again for clarity
    this.fortifyFormSubmitted.set(false);
    this.buildEstimateResult.set(null);
    this.buildEstimateLoading.set(false);
    if (this.buildEstimateDebounce) {
      clearTimeout(this.buildEstimateDebounce);
      this.buildEstimateDebounce = null;
    }
  }

  cancelRun() { this.state.cancelRun(); }
  deleteRun(id: string) { this.state.deleteRun(id); }

  // ── Escalation report download ────────────────────────────────────────────
  downloadEscalation(filename: string, event: Event) {
    event.stopPropagation();
    event.preventDefault();
    this.state.downloadEscalation(filename);
  }

  // ── Restart ───────────────────────────────────────────────────────────────
  restartRun(req: RunRequest) {
    this.repoUrl.set(req.repo_url);
    this.commitSha.set(req.commit_sha);
    this.maxIssues.set(req.max_issues);
    this.parallel.set(req.parallel);
    this.rescan.set(req.rescan);
    this.noRag.set(req.no_rag);
    this.dryRun.set(req.dry_run);
    if (req.severities) {
      const saved = new Set(req.severities.split(',').map(s => s.trim().toUpperCase()));
      this.selectedSevs.set(saved);
    }
    this.state.startRun(req);
  }

  allPending(run: UiRun): boolean {
    return run.steps.every(s => s.status === 'pending');
  }

  queuedSeconds(run: UiRun): number {
    if (!run.fortifyRequest?.pipeline_id) return 0;
    // Use started_at from the run if available, else approximate from now
    const started = (run as any).startedAt ?? (run as any).started_at;
    if (!started) return 0;
    return Math.floor((Date.now() - new Date(started).getTime()) / 1000);
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  flagsOf(req: RunRequest): { label: string; on: boolean }[] {
    return [
      { label: 'Parallel', on: req.parallel },
      { label: 'Rescan',   on: req.rescan   },
      { label: 'No RAG',   on: req.no_rag   },
      { label: 'Dry Run',  on: req.dry_run  },
    ];
  }

  sevLabel(req: RunRequest): string {
    if (!req.severities) return 'ALL';
    const parts = req.severities.split(',').map(s => s.trim()).filter(Boolean);
    return parts.length === 5 ? 'ALL' : parts.join(', ');
  }
}