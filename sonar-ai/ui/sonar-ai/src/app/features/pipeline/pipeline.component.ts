// src/app/features/pipeline/pipeline.component.ts
import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { PipelineStateService, UiRun, RunRequest } from '../../core/pipeline-state.service';
import { SevClassPipe }    from '../../shared/sev-class.pipe';
import { OutcomeClassPipe } from '../../shared/outcome-class.pipe';
import { OutcomeLabelPipe } from '../../shared/outcome-label.pipe';
import { ActiveStepPipe }  from '../../shared/active-step.pipe';

@Component({
  selector: 'app-pipeline',
  standalone: true,
  imports: [CommonModule, FormsModule, SevClassPipe, OutcomeClassPipe, OutcomeLabelPipe, ActiveStepPipe],
  templateUrl: './pipeline.component.html',
  styleUrl:    './pipeline.component.scss',
})
export class PipelineComponent {
  state = inject(PipelineStateService);

  // ── Severity options (in priority order) ─────────────────────────────────
  readonly SEV_OPTIONS = ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO'] as const;

  // ── Run form signals ──────────────────────────────────────────────────────
  repoUrl      = signal('https://github.com/org/repo.git');
  commitSha    = signal('HEAD');
  maxIssues    = signal(1);
  parallel     = signal(false);
  rescan       = signal(false);
  noRag        = signal(false);
  dryRun       = signal(false);
  showForm     = signal(false);

  // ── Severity multi-select — all enabled by default ────────────────────────
  selectedSevs = signal<Set<string>>(
    new Set(['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO'])
  );

  // ── Input viewer ──────────────────────────────────────────────────────────
  showInput = signal(false);   // toggles the input panel in detail pane

  // ── Delegate to service ───────────────────────────────────────────────────
  running()  { return this.state.running(); }
  error()    { return this.state.error(); }
  selected() { return this.state.selected(); }

  get allRuns()  { return this.state.allRuns; }
  get canCancel(){ return this.state.canCancel; }

  select(run: UiRun) {
    this.state.select(run);
    this.showInput.set(false);  // reset input panel on card change
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
        // Prevent deselecting all — keep at least one active
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

  /** Comma-separated string of currently selected severities in priority order. */
  private _severitiesString(): string {
    return this.SEV_OPTIONS
      .filter(s => this.selectedSevs().has(s))
      .join(',');
  }

  // ── Start ─────────────────────────────────────────────────────────────────
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
      severities: this._severitiesString(),   // ← NEW
    });
  }

  cancelRun() { this.state.cancelRun(); }
  deleteRun(id: string) { this.state.deleteRun(id); }

  // ── Restart — re-run with the exact same inputs ───────────────────────────
  restartRun(req: RunRequest) {
    // Pre-fill the form with the previous run's inputs
    this.repoUrl.set(req.repo_url);
    this.commitSha.set(req.commit_sha);
    this.maxIssues.set(req.max_issues);
    this.parallel.set(req.parallel);
    this.rescan.set(req.rescan);
    this.noRag.set(req.no_rag);
    this.dryRun.set(req.dry_run);

    // ← NEW: restore severity selection from the saved request
    if (req.severities) {
      const saved = new Set(req.severities.split(',').map(s => s.trim().toUpperCase()));
      this.selectedSevs.set(saved);
    }

    // Start immediately with the same request
    this.state.startRun(req);
  }

  // ── Helpers for the input display ─────────────────────────────────────────
  flagsOf(req: RunRequest): { label: string; on: boolean }[] {
    return [
      { label: 'Parallel', on: req.parallel },
      { label: 'Rescan',   on: req.rescan   },
      { label: 'No RAG',   on: req.no_rag   },
      { label: 'Dry Run',  on: req.dry_run  },
    ];
  }

  /** Display label for saved severities — "ALL" when all 5 are selected. */
  sevLabel(req: RunRequest): string {
    if (!req.severities) return 'ALL';
    const parts = req.severities.split(',').map(s => s.trim()).filter(Boolean);
    return parts.length === 5 ? 'ALL' : parts.join(', ');
  }
}