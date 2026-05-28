// src/app/features/pipeline/pipeline.component.ts
import { Component, inject, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { PipelineStateService, UiRun, RunRequest } from '../../core/pipeline-state.service';
import { ApiConfigService } from '../../core/api-config.service';
import { SevClassPipe }    from '../../shared/sev-class.pipe';
import { OutcomeClassPipe } from '../../shared/outcome-class.pipe';
import { OutcomeLabelPipe } from '../../shared/outcome-label.pipe';
import { ActiveStepPipe }  from '../../shared/active-step.pipe';

// ── Fortify pipeline mode → API endpoint mapping ──────────────────────────────
export type FortifyMode = 'live' | 'offline' | 'app-name' | 'dry-run';

const ENDPOINT_MAP: Record<FortifyMode, string> = {
  'live':     '/pipeline/live',
  'offline':  '/pipeline/offline',
  'app-name': '/pipeline/app-name',
  'dry-run':  '/pipeline/dry-run',
};

@Component({
  selector: 'app-pipeline',
  standalone: true,
  imports: [CommonModule, FormsModule, SevClassPipe, OutcomeClassPipe, OutcomeLabelPipe, ActiveStepPipe],
  templateUrl: './pipeline.component.html',
  styleUrl:    './pipeline.component.scss',
})
export class PipelineComponent {
  state    = inject(PipelineStateService);
  private apiCfg = inject(ApiConfigService);

  // ── Source tab: 'sonar' | 'fortify' | 'both' ─────────────────────────────
  activeSource = signal<'sonar' | 'fortify'>('sonar');

  // ── Pipeline step labels ──────────────────────────────────────────────────
  readonly FORTIFY_STEPS = [
    'Triage', 'Version Resolver', 'Context', 'API Diff',
    'AI Reasoning', 'ADR Fix', 'AI Code Fix', 'PR Agent', 'Fortify Writeback',
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
    { label: 'Dry Run',   value: 'dry-run'  },
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
  fortifyGithubRepo  = signal('');       // owner/repo override
  fortifyReportPath  = signal('');       // offline mode: path to JSON report
  fortifyMaxUpgrades = signal(0);        // 0 = no limit
  showFortifyForm    = signal(false);

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

  select(run: UiRun) {
    this.state.select(run);
    this.showInput.set(false);
  }

  doneCnt(run: UiRun)      { return this.state.doneCnt(run); }
  confClass(c: any)        { return this.state.confClass(c); }
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
    const baseUrl  = this.apiCfg.baseUrl();

    let body: Record<string, unknown> = {
      max_upgrades: this.fortifyMaxUpgrades() || 0,
      config: {
        ...(this.fortifyGithubRepo() ? { github_repo: this.fortifyGithubRepo() } : {}),
      },
    };

    switch (mode) {
      case 'live':
        body = { ...body, release_id: Number(this.fortifyReleaseId()) };
        break;
      case 'offline':
        body = {
          ...body,
          report_path: this.fortifyReportPath(),
          release_id:  Number(this.fortifyReleaseId()) || 0,
        };
        break;
      case 'app-name':
        body = { ...body, app_name: this.fortifyAppName() };
        break;
      case 'dry-run':
        body = {
          ...body,
          release_id:  Number(this.fortifyReleaseId()) || 0,
          report_path: this.fortifyReportPath() || null,
          app_name:    null,
        };
        break;
    }

    // Fire-and-forget: POST to Fortify API server, then poll /pipeline/status/{id}
    fetch(`${baseUrl}${endpoint}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    })
    .then(r => r.json())
    .then(({ pipeline_id }) => {
      if (pipeline_id) {
        // Hand off to state service for live polling (same UX as Sonar runs)
        this.state.trackFortifyRun(pipeline_id, mode, body);
      }
    })
    .catch(err => {
      this.state.error.set(`Fortify API error: ${err.message}`);
    });
  }

  cancelRun() { this.state.cancelRun(); }
  deleteRun(id: string) { this.state.deleteRun(id); }

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