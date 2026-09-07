// src/app/features/fortify-scan/fortify-scan.component.ts
import { Component, inject, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiConfigService } from '../../core/api-config.service';

// ── Job shape returned by GET /fortify/scan/status/{scan_id} ─────────────────
// Same envelope as GET /pipeline/status/{pipeline_id} — this endpoint just
// scopes it to a /fortify/scan job (stages: resolve/clone/package/session/
// submit/poll instead of the full remediation pipeline's stage list).
export interface FortifyScanStage {
  status: 'pending' | 'running' | 'completed' | 'skipped' | 'failed';
  started_at: string | null;
  finished_at: string | null;
  elapsed_seconds: number | null;
  error: string | null;
  output_summary: Record<string, unknown> | null;
}

export interface FortifyScanResult {
  app_name: string;
  repo_name: string;
  branch_name: string;
  release_id: number;
  fod_scan_id: string;
  scan_status: string;
  vulnerability_count: number | null;
}

export interface FortifyScanJob {
  pipeline_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'interrupted';
  started_at: string;
  finished_at: string | null;
  error: string | null;
  result: FortifyScanResult | null;
  stages: Record<string, FortifyScanStage>;
}

// ── Session-local record of a triggered scan — just enough to render the
//    run list without re-fetching until the user selects it ─────────────────
interface ScanRun {
  id: string;
  appName: string;
  repoName: string;
  branchName: string;
  startedAt: number;
}

const STAGE_ORDER = ['resolve', 'clone', 'package', 'session', 'setup', 'submit', 'poll'] as const;
type StageKey = typeof STAGE_ORDER[number];

const STAGE_LABELS: Record<StageKey, string> = {
  resolve: 'Resolve Release',
  clone:   'Clone Repository',
  package: 'ScanCentral Package',
  session: 'FoD Session',
  setup:   'Configure Scan Setup',
  submit:  'Submit Scan',
  poll:    'Poll to Completion',
};

const POLL_INTERVAL_MS = 4000;
const FORTIFY_DOMAIN_PREFIX = 'equifax\\';

@Component({
  selector: 'app-fortify-scan',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './fortify-scan.component.html',
  styleUrl:    './fortify-scan.component.scss',
})
export class FortifyScanComponent {
  private apiCfg = inject(ApiConfigService);

  // ── Form fields ────────────────────────────────────────────────────────────
  appName        = signal('');
  repoName       = signal('');       // owner/repo
  branchName     = signal('');       // optional — default branch if empty
  releaseId      = signal('');       // optional — string so the input can be blank
  githubToken    = signal('');
  fortifyUsername = signal('');      // domain prefix ("equifax\") added automatically
                                      // on submit — needed for the SSC-style release
                                      // resolve step; the backend strips it back off
                                      // again specifically for the FoD fcli login,
                                      // which wants the bare form (see fortify_scan.py's
                                      // _strip_domain_prefix).
  fortifyPassword  = signal('');

  showForm    = signal(true);        // form starts open — nothing to hide behind yet
  submitting  = signal(false);
  submitError = signal('');

  // ── Session run history + per-run job cache ───────────────────────────────
  runs   = signal<ScanRun[]>([]);
  jobs   = signal<Record<string, FortifyScanJob>>({});
  selectedId = signal<string | null>(null);

  private _pollTimers = new Map<string, ReturnType<typeof setTimeout>>();

  readonly stageOrder = STAGE_ORDER;
  readonly stageLabels = STAGE_LABELS;

  selectedRun = computed(() => this.runs().find(r => r.id === this.selectedId()) ?? null);
  selectedJob = computed<FortifyScanJob | null>(() => {
    const id = this.selectedId();
    return id ? (this.jobs()[id] ?? null) : null;
  });

  /** Prepend the "equifax\" domain prefix Fortify SSC OAuth expects, once. */
  private _domainQualify(username: string): string {
    const trimmed = username.trim();
    if (!trimmed) return '';
    return trimmed.toLowerCase().startsWith(FORTIFY_DOMAIN_PREFIX.toLowerCase())
      ? trimmed
      : `${FORTIFY_DOMAIN_PREFIX}${trimmed}`;
  }

  canSubmit(): boolean {
    return !!(
      this.appName().trim() &&
      this.repoName().trim() &&
      this.githubToken().trim() &&
      this.fortifyUsername().trim() &&
      this.fortifyPassword().trim()
    ) && !this.submitting();
  }

  // ── Submit — POST /fortify/scan, then start polling the returned scan_id ──
  startScan() {
    if (!this.canSubmit()) return;

    this.submitting.set(true);
    this.submitError.set('');

    const body: Record<string, unknown> = {
      app_name:  this.appName().trim(),
      repo_name: this.repoName().trim(),
      ...(this.branchName().trim() ? { branch_name: this.branchName().trim() } : {}),
      ...(this.releaseId().trim()  ? { release_id: Number(this.releaseId().trim()) } : {}),
      github_token:      this.githubToken().trim(),
      fortify_username:  this._domainQualify(this.fortifyUsername()),
      fortify_password:  this.fortifyPassword(),
    };

    const baseUrl = this.apiCfg.fortifyBaseUrl();

    fetch(`${baseUrl}/fortify/scan`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    })
      .then(async r => {
        const resp = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(resp?.error ?? resp?.detail ?? `HTTP ${r.status}`);
        return resp;
      })
      .then(resp => {
        const scanId: string | undefined = resp?.data?.scan_id ?? resp?.scan_id;
        if (!scanId) {
          this.submitError.set(`No scan_id in response — ${JSON.stringify(resp)}`);
          return;
        }
        const run: ScanRun = {
          id: scanId,
          appName:  this.appName().trim(),
          repoName: this.repoName().trim(),
          branchName: this.branchName().trim() || '(default)',
          startedAt: Date.now(),
        };
        this.runs.update(rs => [run, ...rs]);
        this.selectedId.set(scanId);
        this.showForm.set(false);
        this._poll(scanId);
      })
      .catch(err => this.submitError.set(err?.message ?? 'Failed to start scan'))
      .finally(() => {
        this.submitting.set(false);
        // Don't linger with plaintext credentials any longer than needed.
        this.fortifyPassword.set('');
      });
  }

  // ── Poll GET /fortify/scan/status/{scan_id} until terminal ────────────────
  private _poll(scanId: string) {
    const baseUrl = this.apiCfg.fortifyBaseUrl();
    const tick = () => {
      fetch(`${baseUrl}/fortify/scan/status/${encodeURIComponent(scanId)}`)
        .then(r => r.json())
        .then(resp => {
          const job: FortifyScanJob | undefined = resp?.data ?? resp;
          if (!job) return;
          this.jobs.update(j => ({ ...j, [scanId]: job }));
          if (job.status === 'queued' || job.status === 'running') {
            this._pollTimers.set(scanId, setTimeout(tick, POLL_INTERVAL_MS));
          } else {
            this._pollTimers.delete(scanId);
          }
        })
        .catch(() => {
          // Transient fetch failure — keep trying on the same cadence
          // rather than giving up on the whole run.
          this._pollTimers.set(scanId, setTimeout(tick, POLL_INTERVAL_MS));
        });
    };
    tick();
  }

  select(run: ScanRun) {
    this.selectedId.set(run.id);
    this.showForm.set(false);
    // Fetch immediately if we don't have it yet (e.g. selecting an older
    // run whose polling already stopped) so the detail pane isn't empty.
    if (!this.jobs()[run.id]) this._poll(run.id);
  }

  newScan() {
    this.showForm.set(true);
    this.selectedId.set(null);
  }

  // ── Stage helpers for the template ────────────────────────────────────────
  stageList(job: FortifyScanJob): { key: StageKey; label: string; stage: FortifyScanStage }[] {
    return STAGE_ORDER.map(key => ({
      key,
      label: STAGE_LABELS[key],
      stage: job.stages[key] ?? {
        status: 'pending', started_at: null, finished_at: null,
        elapsed_seconds: null, error: null, output_summary: null,
      },
    }));
  }

  stageSummary(stage: FortifyScanStage): string {
    const s = stage.output_summary;
    if (!s) return '';
    return Object.entries(s)
      .filter(([, v]) => v !== null && v !== undefined && v !== '')
      .map(([k, v]) => `${k}: ${v}`)
      .join(' · ');
  }

  statusLabel(status: string): string {
    return {
      queued: 'Queued', running: 'Running', completed: 'Completed',
      failed: 'Failed', cancelled: 'Cancelled', interrupted: 'Interrupted',
    }[status] ?? status;
  }

  formatDate(iso: string | null): string {
    return iso ? new Date(iso).toLocaleString() : '—';
  }

  startedAgo(ts: number): string {
    const mins = Math.floor((Date.now() - ts) / 60000);
    if (mins < 1)  return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24)  return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  }
}