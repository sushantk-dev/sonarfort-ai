// src/app/core/pipeline-state.service.ts
import { Injectable, inject, signal } from '@angular/core';
import { Subscription } from 'rxjs';
import { ApiService, RunStatus, PipelineStep } from './api.service';
import { DataService } from './data.service';

export type ConfLabel = 'HIGH' | 'MEDIUM' | 'LOW' | null;

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

export interface UiRun {
  id:          string;
  ruleKey:     string;
  severity:    string;
  component:   string;
  steps:       PipelineStep[];
  outcome?:    string;
  confidence?: ConfLabel;
  prUrl?:      string;
  ragHits?:    number;
  retries?:    number;
  live:        boolean;
  status?:     'queued' | 'running' | 'done' | 'error' | 'cancelled' | 'empty';
  request?:    RunRequest;
}

@Injectable({ providedIn: 'root' })
export class PipelineStateService {
  private api  = inject(ApiService);
  private data = inject(DataService);

  runs     = signal<UiRun[]>([]);
  selected = signal<UiRun | null>(null);
  running  = signal(false);
  error    = signal<string | null>(null);

  private _activeRunId: string | null = null;
  private _poll?: Subscription;

  get allRuns() { return this.runs(); }

  constructor() {
    // Rehydrate run history from the backend on every page load.
    // Falls back to static seed data if the backend is unreachable.
    this.api.listRuns().subscribe({
      next: ({ runs }) => {
        const hydrated: UiRun[] = (runs ?? []).map((r: any) => this._backendRunToUiRun(r));
        this.runs.set(hydrated);
        this.selected.set(hydrated[0] ?? null);

        // Re-attach polling for any run still in progress when the page reloaded
        const inProgress = hydrated.find(
          r => r.status === 'running' || r.status === 'queued'
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
      },
      error: () => {
        // Backend offline — fall back to static seed so the UI isn't blank
        const seeded = this._seedRuns();
        this.runs.set(seeded);
        this.selected.set(seeded[0] ?? null);
      },
    });
  }

  /** Map a raw backend run object to a UiRun card. */
  private _backendRunToUiRun(r: any): UiRun {
    const first = Array.isArray(r.results) ? r.results[0] : undefined;
    const confLabel: ConfLabel = first?.confidence != null
      ? this.confLabel(first.confidence) : null;
    const steps: PipelineStep[] = Array.isArray(r.steps)
      ? r.steps.map((s: any) => ({
          label:  s.label  ?? '',
          status: s.status ?? 'done',
          detail: s.detail ?? '',
          ms:     s.ms     ?? 0,
        }))
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
    };
  }

  private _seedRuns(): UiRun[] {
    return this.data.runs.map(r => ({
      id:         r.id,
      ruleKey:    r.ruleKey,
      severity:   r.severity,
      component:  r.component,
      steps:      r.steps.map(s => ({
        label:  s.label,
        status: s.status as any,
        detail: s.detail ?? '',
        ms:     s.ms     ?? 0,
      })),
      outcome:    r.outcome,
      confidence: r.confidence as ConfLabel,
      prUrl:      r.prUrl,
      ragHits:    r.ragHits,
      retries:    r.retries,
      live:       false,
      status:     'done',
      request:    undefined,
    }));
  }

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

  // ── Start ─────────────────────────────────────────────────────────────────
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
      ruleKey:   '—',           // blank until first result comes in
      severity:  'INFO',
      component: '',
      steps: ['Ingest','Load Repo','RAG Fetch','Fetch Rule','Planner','Generator','Critic','Validate','Deliver']
        .map(label => ({ label, status: 'pending' as const, detail: '', ms: 0 })),
      live:    true,
      status:  'running',
      request: req,
    };

    this.runs.update(rs => [liveRun, ...rs]);
    this.selected.set(liveRun);

    this._poll = this.api.pollRun(runId).subscribe({
      next:  (s: RunStatus) => this._applyStatus(runId, s),
      error: (err: Error) => {
        this.error.set(err.message);
        this.running.set(false);
        this._activeRunId = null;
      },
    });
  }

  private _applyStatus(runId: string, status: RunStatus) {
    this.runs.update(rs => rs.map(r => {
      if (r.id !== runId) return r;

      const first = status.results?.[0];
      const noResults = (status.status === 'done') && (!status.results || status.results.length === 0);

      // Smart step merge: backend sends all 9 steps on every poll.
      // Only replace local steps when the backend shows real progress (any step != pending).
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
      };

      // Sync selected in same signal update tick for instant reactivity
      if (this.selected()?.id === runId) {
        this.selected.set(updated);
      }

      return updated;
    }));

    if (status.status === 'done' || status.status === 'error') {
      this.running.set(false);
      this._activeRunId = null;

      if (status.status === 'error' && status.error) {
        this.error.set(status.error);
      }

      // ── REMOVED: auto-delete on no results ───────────────────────────────
      // Previously this block deleted the run card after 4 s when no issues
      // were found. Now we keep it in history permanently with outcome='empty'
      // so users have a full record of every pipeline run.
      // The error banner still surfaces the message; the card stays in the list.
      const noResults = !status.results || status.results.length === 0;
      if (noResults && status.status === 'done') {
        this.error.set('No issues found for the selected severity — run is kept in history.');
        // ← no deleteRun() call; card persists with status='empty'
        return;
      }

      if ((status.results?.length ?? 0) > 1) {
        this._explodeResults(runId, status);
      }
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
    }));

    this.runs.update(rs => [...newCards, ...rs.filter(r => r.id !== runId)]);
    if (newCards[0]) this.selected.set(newCards[0]);
  }

  // ── Delete a finished run card (manual only) ──────────────────────────────
  deleteRun(id: string) {
    // Don't delete an actively running run
    if (id === this._activeRunId) return;

    // Remove from UI immediately for instant feedback
    this.runs.update(rs => rs.filter(r => r.id !== id));
    if (this.selected()?.id === id) {
      this.selected.set(this.runs()[0] ?? null);
    }

    // Also remove from the backend so it won't reappear after reload
    this.api.deleteRun(id).subscribe({ error: () => {} });
  }

  // ── Cancel ────────────────────────────────────────────────────────────────
  cancelRun() {
    const runId = this._activeRunId;
    if (!runId) return;

    this._poll?.unsubscribe();
    this._poll = undefined;

    this.api.cancelRun(runId).subscribe({ error: () => {} });

    this.runs.update(rs => rs.map(r => {
      if (r.id !== runId) return r;
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
  }

  get canCancel() { return this.running() && !!this._activeRunId; }
}