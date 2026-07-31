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
    'AI Reasoning', 'Dependency Fix', 'AI Code Fix', 'PR Agent', 'Fortify Writeback',
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
  fortifyMaxUpgrades = signal(0);        // 0 = no limit
  showFortifyForm    = signal(false);

  // ── Per-run credentials — never persisted, cleared after each submit ──────
  // Each Fortify run can use a different GitHub PAT / Fortify account, so
  // these live on the form rather than in global Settings/config.
  fortifyGithubToken = signal('');       // GitHub PAT used for clone + PR for THIS run
  fortifyUsername    = signal('');       // Fortify OAuth username, WITHOUT the "equifax\" prefix
  fortifyPassword     = signal('');       // Fortify OAuth password for THIS run

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
    this.showFortifyForm.set(false);

    const mode     = this.fortifyMode();
    const endpoint = this.fortifyEndpoint();
    // Uses fortifyBaseUrl — routes to separate Fortify port if configured
    const baseUrl  = this.apiCfg.fortifyBaseUrl();

    // Per-run credential overrides — only sent when the user actually filled
    // them in, so an empty field falls back to the server's env-configured
    // defaults instead of clobbering them with an empty string.
    const credConfig: Record<string, unknown> = {
      ...(this.fortifyGithubToken().trim() ? { github_token: this.fortifyGithubToken().trim() } : {}),
      ...(this.fortifyUsername().trim()    ? { fortify_username: this._domainQualify(this.fortifyUsername()) } : {}),
      ...(this.fortifyPassword().trim()    ? { fortify_password: this.fortifyPassword() } : {}),
    };

    let body: Record<string, unknown> = {
      max_upgrades: this.fortifyMaxUpgrades() || 0,
      ...(this.fortifyGithubRepo() ? { repo: this.fortifyGithubRepo() } : {}),
      config: credConfig,
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
      } else {
        this.state.error.set(`Fortify API: no pipeline_id in response — ${JSON.stringify(resp)}`);
      }
    })
    .catch(err => {
      this.state.submitting.set(null);
      this.state.error.set(`Fortify API error: ${err.message}`);
    });
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