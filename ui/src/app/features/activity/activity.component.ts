// src/app/features/activity/activity.component.ts
import { Component, computed, inject, signal, effect } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { PipelineStateService, UiRun } from '../../core/pipeline-state.service';
import { OutcomeClassPipe } from '../../shared/outcome-class.pipe';
import { OutcomeLabelPipe } from '../../shared/outcome-label.pipe';

type StatusFilter = 'all' | 'running' | 'done' | 'error' | 'cancelled';
type OutputItem = { type: 'pr'; url: string } | { type: 'escalation'; file: string };
type SourceKey = 'fortify' | 'sonar';

/** Max output chips (PRs + escalation reports combined) shown per row before collapsing behind "+N more". */
const MAX_VISIBLE_OUTPUTS = 3;

@Component({
  selector: 'app-activity',
  standalone: true,
  imports: [CommonModule, RouterLink, OutcomeClassPipe, OutcomeLabelPipe],
  templateUrl: './activity.component.html',
  styleUrl: './activity.component.scss',
})
export class ActivityComponent {
  state = inject(PipelineStateService);

  // ── Source tab (Fortify | Sonar) ────────────────────────────────────────
  // Everything below (filter/search/table) is unchanged Fortify behavior —
  // switching the tab just re-scopes which runs allRuns() draws from.
  // Defaults to 'fortify' so nothing about the existing view changes unless
  // the user explicitly switches tabs.
  activeSource = signal<SourceKey>('fortify');

  filter  = signal<StatusFilter>('all');
  search  = signal('');

  /** True while GET /pipeline/runs is in flight (initial load or a manual refresh). */
  loadingRuns = this.state.loadingRuns;

  // Track which pipeline_ids we've already asked the backend to hydrate
  // with full detail (PR urls / escalation files), so a re-render or the
  // next 20s list poll doesn't re-request the same job over and over.
  private _hydrated = new Set<string>();

  // Rows where the user has clicked "+N more" to reveal every PR / escalation
  // chip instead of the capped preview — keyed by run id.
  private _expandedOutputs = new Set<string>();

  // Runs for whichever source tab is active, from every user —
  // PipelineStateService.runs already merges GET /pipeline/runs (shared,
  // GCS-backed job store) on a 20s poll, on top of whatever this browser is
  // actively driving/has in history.
  allRuns = computed<UiRun[]>(() => {
    const src = this.activeSource();
    return this.state.runs()
      .filter(r => src === 'sonar'
        ? (r.source === 'sonar' || !r.source)   // legacy runs without `source` = Sonar
        : r.source === 'fortify')
      .sort((a, b) => (b.startedAt ?? 0) - (a.startedAt ?? 0));
  });

  /** Per-tab counts, independent of the active tab — drives the badge on each source-tab button. */
  sourceCounts = computed(() => {
    const rs = this.state.runs();
    return {
      fortify: rs.filter(r => r.source === 'fortify').length,
      sonar:   rs.filter(r => r.source === 'sonar' || !r.source).length,
    };
  });

  counts = computed(() => {
    const rs = this.allRuns();
    return {
      all:       rs.length,
      running:   rs.filter(r => r.status === 'running' || r.status === 'queued').length,
      done:      rs.filter(r => r.status === 'done').length,
      error:     rs.filter(r => r.status === 'error').length,
      cancelled: rs.filter(r => r.status === 'cancelled').length,
    };
  });

  filteredRuns = computed<UiRun[]>(() => {
    const f = this.filter();
    const q = this.search().trim().toLowerCase();

    return this.allRuns().filter(r => {
      const matchesFilter =
        f === 'all'                                                ? true
        : f === 'running' ? (r.status === 'running' || r.status === 'queued')
        : r.status === f;

      if (!matchesFilter) return false;
      if (!q) return true;

      return (
        r.id.toLowerCase().includes(q) ||
        (r.ruleKey ?? '').toLowerCase().includes(q) ||
        (r.component ?? '').toLowerCase().includes(q)
      );
    });
  });

  constructor() {
    // Whenever the visible (filtered) list changes, backfill full detail
    // (PR links, escalation files) for any completed/failed row that only
    // has the lightweight list-endpoint data so far — capped so opening
    // this page never fires an unbounded burst of requests.
    //
    // Fortify-only: hydrateRunDetail() calls the Fortify server's
    // /pipeline/status/{id}. Sonar's GET /api/pipeline/runs already returns
    // full result data per row (see PipelineStateService._backendRunToUiRun),
    // so there's nothing to backfill when the Sonar tab is active.
    effect(() => {
      if (this.activeSource() !== 'fortify') return;
      const rows = this.filteredRuns();
      let requested = 0;
      for (const r of rows) {
        if (requested >= 25) break;
        const needsDetail = (r.status === 'done' || r.status === 'error') && !r.outcome;
        if (needsDetail && !this._hydrated.has(r.id)) {
          this._hydrated.add(r.id);
          requested++;
          this.state.hydrateRunDetail(r.id);
        }
      }
    });
  }

  /** Switch the active source tab. Filter/search reset so a "Failed" filter
   *  from one tab doesn't silently carry over and hide everything on the other. */
  switchSource(src: SourceKey) {
    this.activeSource.set(src);
    this.filter.set('all');
    this.search.set('');
  }

  setFilter(f: StatusFilter) { this.filter.set(f); }

  refresh() {
    // Re-fetch the shared run list itself (covers both sources)...
    this.state.refreshRuns();

    // ...and re-hydrate everything currently visible, ignoring the
    // "already requested" cache — a manual refresh should always hit
    // the network for row detail too. Only meaningful on the Fortify tab —
    // see the hydrate effect above for why Sonar doesn't need this.
    if (this.activeSource() !== 'fortify') return;
    this._hydrated.clear();
    for (const r of this.filteredRuns()) {
      if (r.status === 'done' || r.status === 'error') this.state.hydrateRunDetail(r.id);
    }
  }

  statusLabel(r: UiRun): string {
    return {
      queued: 'Queued', running: 'Running', done: 'Completed',
      error: 'Failed', cancelled: 'Cancelled', empty: 'Completed',
    }[r.status ?? 'queued'] ?? r.status ?? '';
  }

  stagesDone(r: UiRun): number { return r.steps.filter(s => s.status === 'done').length; }
  stagesTotal(r: UiRun): number { return r.steps.length; }

  /** Live "Xm Ys" elapsed while running/queued; "started X ago" once terminal
   *  (UiRun doesn't carry a finishedAt, so we can't show a precise duration). */
  elapsedLabel(r: UiRun): string {
    if (!r.startedAt) return '—';
    if (r.status !== 'running' && r.status !== 'queued') return this.startedAgo(r);
    const secs = Math.max(0, Math.round((Date.now() - r.startedAt) / 1000));
    const m = Math.floor(secs / 60), s = secs % 60;
    return `${m}m ${s}s`;
  }

  startedAgo(r: UiRun): string {
    if (!r.startedAt) return '—';
    const diffMs = Date.now() - r.startedAt;
    const mins = Math.floor(diffMs / 60000);
    if (mins < 1)   return 'just now';
    if (mins < 60)  return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24)   return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  }

  canResume(r: UiRun): boolean { return this.state.canResume(r); }
  resume(r: UiRun)   { this.state.resumeFortifyRun(r.id); }

  downloadEscalation(filename: string, ev: Event) {
    ev.stopPropagation();
    this.state.downloadEscalation(filename);
  }

  /** PRs + escalation reports for a run, normalized into one ordered list. */
  outputItems(r: UiRun): OutputItem[] {
    const items: OutputItem[] = [];
    const urls = r.prUrls?.length ? r.prUrls : (r.prUrl ? [r.prUrl] : []);
    for (const url of urls) items.push({ type: 'pr', url });
    for (const file of (r.escalationFiles ?? [])) items.push({ type: 'escalation', file });
    return items;
  }

  /** Capped list to render — full list once the row has been expanded. */
  visibleOutputItems(r: UiRun): OutputItem[] {
    const items = this.outputItems(r);
    if (items.length <= MAX_VISIBLE_OUTPUTS || this._expandedOutputs.has(r.id)) return items;
    return items.slice(0, MAX_VISIBLE_OUTPUTS);
  }

  /** How many chips are hidden behind "+N more" (0 once expanded or under the cap). */
  hiddenOutputCount(r: UiRun): number {
    if (this._expandedOutputs.has(r.id)) return 0;
    return Math.max(0, this.outputItems(r).length - MAX_VISIBLE_OUTPUTS);
  }

  toggleOutputExpand(r: UiRun, ev: Event) {
    ev.stopPropagation();
    if (this._expandedOutputs.has(r.id)) this._expandedOutputs.delete(r.id);
    else this._expandedOutputs.add(r.id);
  }
}