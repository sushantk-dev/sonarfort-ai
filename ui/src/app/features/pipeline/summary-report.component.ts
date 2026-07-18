// src/app/features/pipeline/summary-report.component.ts
import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { ApiConfigService } from '../../core/api-config.service';

// ── Types ────────────────────────────────────────────────────────────────────

interface DepGroup {
  parsed?: {
    artifact_id?: string;
    group_id?:    string;
    current_version?: string;
    severity?:    string;
    cves?:        string[];
  };
  artifact_id?:     string;
  current_version?: string;
  severity?:        string;
  cves?:            string[];
  current_candidate?: string;
  version_candidates?: { candidates?: string[] };
  escalate_reason?: string;
  next_node?:       string;
  ai_reasoning?: {
    confidence_score?:    number;
    reasoning?:           string;
    recommended_version?: string;
  };
  _outcome?: 'fixed' | 'escalated' | 'failed';
}

interface AdrEntry {
  artifact_id: string;
  result?: {
    success?:       boolean;
    branch_name?:   string;
    error_reason?:  string;
  };
  // sometimes the result fields are inlined directly
  success?:      boolean;
  branch_name?:  string;
  error_reason?: string;
}

interface PrResult {
  pr_url?:    string;
  pr_number?: number;
}

interface StageInfo {
  status?:          string;
  elapsed_seconds?: number;
  error?:           string;
  output_summary?:  Record<string, any>;
}

interface TokenStageUsage {
  calls:         number;
  input_tokens:  number;
  output_tokens: number;
  total_tokens:  number;
}

interface TokenUsage extends TokenStageUsage {
  models?: Record<string, number>;
  stages?: Record<string, TokenStageUsage>;
}

interface PipelineResult {
  total_fixed?:     number;
  total_escalated?: number;
  total_failed?:    number;
  release_id?:      number;
  groups_count?:    number;
  groups?:          DepGroup[];
  adr_results?:     AdrEntry[];
  pr_results?:      PrResult[];
  token_usage?:     TokenUsage;
  summary?: {
    total_fixed?:     number;
    total_escalated?: number;
    total_failed?:    number;
  };
}

interface PipelineStatus {
  status:           'completed' | 'failed' | 'running' | 'queued';
  elapsed_seconds?: number;
  error?:           string;
  stages?:          Record<string, StageInfo>;
  result?:          PipelineResult;
}

// ── Stage metadata ────────────────────────────────────────────────────────────

const STAGE_LABELS: Record<string, string> = {
  'triage':            'Triage',
  'version-resolver':  'Version Resolver',
  'context':           'Context',
  'api-diff':          'API Diff',
  'ai-reasoning':      'AI Reasoning',
  'adr-fix':           'ADR Fix',
  'pr-agent':          'PR Agent',
  'fortify-writeback': 'Fortify Writeback',
};

// Labels for stages appearing in token_usage.stages — superset of the job
// stages because AI Code Fix records tokens but is not a job-store stage.
const TOKEN_STAGE_LABELS: Record<string, string> = {
  ...STAGE_LABELS,
  'ai-code-fix': 'AI Code Fix',
};

// ── Component ─────────────────────────────────────────────────────────────────

@Component({
  selector: 'app-summary-report',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <div class="summary">

      <!-- Back nav -->
      <div class="summary__nav">
        <a routerLink="/pipeline" class="back-btn">
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <path d="M9 11L5 7L9 3" stroke="currentColor" stroke-width="1.5"
                  stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          Back to pipeline
        </a>

        <div class="summary__nav-right" *ngIf="status()">
          <span class="release-label" *ngIf="pipelineResult()?.release_id">
            Release {{ pipelineResult()!.release_id }}
          </span>
          <span class="elapsed-label" *ngIf="status()!.elapsed_seconds">
            {{ formatSeconds(status()!.elapsed_seconds!) }}
          </span>
          <span class="status-pill"
                [class.status-pill--ok]="status()!.status === 'completed'"
                [class.status-pill--err]="status()!.status === 'failed'">
            {{ status()!.status === 'completed' ? 'Completed' : status()!.status }}
          </span>
        </div>
      </div>

      <!-- Loading -->
      <div class="summary__loading" *ngIf="loading()">
        <div class="spinner"></div>
        <span>Loading report…</span>
      </div>

      <!-- Error -->
      <div class="summary__error" *ngIf="fetchError()">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
          <circle cx="8" cy="8" r="6.5" stroke="currentColor" stroke-width="1.3"/>
          <path d="M8 5V8.5M8 10.5V11" stroke="currentColor" stroke-width="1.4"
                stroke-linecap="round"/>
        </svg>
        {{ fetchError() }}
      </div>

      <ng-container *ngIf="!loading() && !fetchError() && status()">

        <!-- ── Stat cards ───────────────────────────────────────────────── -->
        <div class="stat-grid">
          <div class="stat-card stat-card--fixed">
            <div class="stat-card__icon">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <circle cx="8" cy="8" r="6.5" stroke="currentColor" stroke-width="1.3"/>
                <path d="M5 8L7 10L11 6" stroke="currentColor" stroke-width="1.4"
                      stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
            </div>
            <div class="stat-card__body">
              <span class="stat-card__label">Fixed</span>
              <span class="stat-card__value">{{ totalFixed() }}</span>
            </div>
          </div>

          <div class="stat-card stat-card--escalated">
            <div class="stat-card__icon">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <path d="M8 2L14 13H2L8 2Z" stroke="currentColor" stroke-width="1.3"
                      stroke-linejoin="round"/>
                <path d="M8 6V9" stroke="currentColor" stroke-width="1.4"
                      stroke-linecap="round"/>
                <circle cx="8" cy="11" r=".6" fill="currentColor"/>
              </svg>
            </div>
            <div class="stat-card__body">
              <span class="stat-card__label">Escalated</span>
              <span class="stat-card__value">{{ totalEscalated() }}</span>
            </div>
          </div>

          <div class="stat-card stat-card--failed">
            <div class="stat-card__icon">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <circle cx="8" cy="8" r="6.5" stroke="currentColor" stroke-width="1.3"/>
                <path d="M5.5 5.5L10.5 10.5M10.5 5.5L5.5 10.5" stroke="currentColor"
                      stroke-width="1.4" stroke-linecap="round"/>
              </svg>
            </div>
            <div class="stat-card__body">
              <span class="stat-card__label">Failed</span>
              <span class="stat-card__value">{{ totalFailed() }}</span>
            </div>
          </div>

          <div class="stat-card stat-card--total">
            <div class="stat-card__icon">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <rect x="2" y="3" width="12" height="2" rx="1" fill="currentColor"/>
                <rect x="2" y="7" width="12" height="2" rx="1" fill="currentColor" opacity=".65"/>
                <rect x="2" y="11" width="8"  height="2" rx="1" fill="currentColor" opacity=".4"/>
              </svg>
            </div>
            <div class="stat-card__body">
              <span class="stat-card__label">Total deps</span>
              <span class="stat-card__value">{{ totalDeps() }}</span>
            </div>
          </div>

          <div class="stat-card stat-card--conf">
            <div class="stat-card__icon">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <circle cx="8" cy="8" r="6.5" stroke="currentColor" stroke-width="1.3"/>
                <path d="M5.5 8.5C5.5 8.5 6.5 10 8 10C9.5 10 10.5 8.5 10.5 8.5"
                      stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
                <circle cx="6" cy="6.5" r=".8" fill="currentColor"/>
                <circle cx="10" cy="6.5" r=".8" fill="currentColor"/>
              </svg>
            </div>
            <div class="stat-card__body">
              <span class="stat-card__label">Avg confidence</span>
              <span class="stat-card__value stat-card__value--conf"
                    [class]="confidenceClass(avgConfidence())">
                {{ avgConfidence() }}
                <span class="stat-card__value-sub" *ngIf="avgConfidence() !== '—'">
                  {{ avgConfidenceScore() }}
                </span>
              </span>
            </div>
          </div>

          <div class="stat-card stat-card--tokens" *ngIf="tokenUsage()">
            <div class="stat-card__icon">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <path d="M8 1.5L9.6 6.4L14.5 8L9.6 9.6L8 14.5L6.4 9.6L1.5 8L6.4 6.4L8 1.5Z"
                      stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
              </svg>
            </div>
            <div class="stat-card__body">
              <span class="stat-card__label">LLM tokens</span>
              <span class="stat-card__value">
                {{ formatTokens(tokenUsage()!.total_tokens) }}
                <span class="stat-card__value-sub">{{ tokenUsage()!.calls }} call{{ tokenUsage()!.calls === 1 ? '' : 's' }}</span>
              </span>
            </div>
          </div>
        </div>

        <!-- ── Progress bar ────────────────────────────────────────────── -->
        <div class="progress-block" *ngIf="totalDeps() > 0">
          <div class="progress-bar">
            <div class="progress-bar__seg progress-bar__seg--fixed"
                 [style.width.%]="(totalFixed() / totalDeps()) * 100"></div>
            <div class="progress-bar__seg progress-bar__seg--escalated"
                 [style.width.%]="(totalEscalated() / totalDeps()) * 100"></div>
            <div class="progress-bar__seg progress-bar__seg--failed"
                 [style.width.%]="(totalFailed() / totalDeps()) * 100"></div>
          </div>
          <div class="progress-legend">
            <span class="legend-item legend-item--fixed">Fixed</span>
            <span class="legend-item legend-item--escalated">Escalated</span>
            <span class="legend-item legend-item--failed">Failed</span>
            <span class="legend-pct">{{ pctFixed() }}% auto-fixed</span>
          </div>
        </div>

        <!-- ── Tabs ────────────────────────────────────────────────────── -->
        <div class="tabs">
          <button class="tab-btn" [class.tab-btn--active]="activeTab() === 'all'"
                  (click)="activeTab.set('all')">All deps</button>
          <button class="tab-btn" [class.tab-btn--active]="activeTab() === 'fixed'"
                  (click)="activeTab.set('fixed')">
            Fixed
            <span class="tab-count">{{ totalFixed() }}</span>
          </button>
          <button class="tab-btn" [class.tab-btn--active]="activeTab() === 'escalated'"
                  (click)="activeTab.set('escalated')">
            Escalated / Failed
            <span class="tab-count">{{ totalEscalated() + totalFailed() }}</span>
          </button>
          <button class="tab-btn" [class.tab-btn--active]="activeTab() === 'stages'"
                  (click)="activeTab.set('stages')">Stages</button>
        </div>

        <!-- ── Tab: All deps / Fixed ───────────────────────────────────── -->
        <ng-container *ngIf="activeTab() === 'all' || activeTab() === 'fixed'">
          <div class="dep-table">
            <div class="dep-table__head">
              <span></span>
              <span>Dependency</span>
              <span>Current</span>
              <span>Target</span>
              <span>CVEs</span>
              <span>Sev / Conf</span>
            </div>

            <ng-container *ngFor="let dep of displayedGroups()">
              <div class="dep-row">
                <!-- Status icon -->
                <span class="dep-row__icon dep-row__icon--{{ dep._outcome }}">
                  <svg *ngIf="dep._outcome === 'fixed'" width="13" height="13" viewBox="0 0 13 13" fill="none">
                    <circle cx="6.5" cy="6.5" r="5.5" stroke="currentColor" stroke-width="1.2"/>
                    <path d="M4 6.5L5.8 8.3L9 5" stroke="currentColor" stroke-width="1.3"
                          stroke-linecap="round" stroke-linejoin="round"/>
                  </svg>
                  <svg *ngIf="dep._outcome === 'escalated'" width="13" height="13" viewBox="0 0 13 13" fill="none">
                    <path d="M6.5 1.5L12 11H1L6.5 1.5Z" stroke="currentColor" stroke-width="1.2"
                          stroke-linejoin="round"/>
                    <path d="M6.5 5V7.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
                    <circle cx="6.5" cy="9.5" r=".5" fill="currentColor"/>
                  </svg>
                  <svg *ngIf="dep._outcome === 'failed'" width="13" height="13" viewBox="0 0 13 13" fill="none">
                    <circle cx="6.5" cy="6.5" r="5.5" stroke="currentColor" stroke-width="1.2"/>
                    <path d="M4.5 4.5L8.5 8.5M8.5 4.5L4.5 8.5" stroke="currentColor" stroke-width="1.3"
                          stroke-linecap="round"/>
                  </svg>
                </span>

                <!-- Name -->
                <div class="dep-row__name">
                  <span class="dep-row__artifact">{{ dep.parsed?.artifact_id || dep.artifact_id || '—' }}</span>
                  <span class="dep-row__group">{{ dep.parsed?.group_id || '' }}</span>
                </div>

                <!-- Versions -->
                <span class="dep-row__ver dep-row__ver--current">
                  {{ dep.parsed?.current_version || dep.current_version || '—' }}
                </span>
                <span class="dep-row__ver dep-row__ver--target"
                      [class.dep-row__ver--ok]="targetVersion(dep) !== '—'">
                  {{ targetVersion(dep) }}
                </span>

                <!-- CVEs -->
                <div class="dep-row__cves">
                  <span *ngFor="let cve of (dep.parsed?.cves || dep.cves || []).slice(0, 2)"
                        class="cve-chip">{{ cve }}</span>
                  <span *ngIf="((dep.parsed?.cves || dep.cves) || []).length > 2"
                        class="cve-more">+{{ ((dep.parsed?.cves || dep.cves) || []).length - 2 }}</span>
                </div>

                <!-- Severity + confidence + PR -->
                <div class="dep-row__meta">
                  <div class="dep-row__meta-badges">
                    <span class="sev-badge sev-badge--{{ (dep.parsed?.severity || dep.severity || 'INFO').toLowerCase() }}">
                      {{ dep.parsed?.severity || dep.severity || 'INFO' }}
                    </span>
                    <span *ngIf="dep._confidence != null"
                          class="conf-chip conf-chip--{{ confidenceClass(dep._confidence >= 0.75 ? 'HIGH' : dep._confidence >= 0.45 ? 'MEDIUM' : 'LOW') }}">
                      {{ (dep._confidence * 100).toFixed(0) }}%
                    </span>
                  </div>
                  <a *ngIf="dep._prUrl" [href]="dep._prUrl" target="_blank"
                     rel="noopener" class="pr-inline-link" title="Open PR">
                    <svg width="11" height="11" viewBox="0 0 13 13" fill="none">
                      <circle cx="3" cy="3" r="1.5" stroke="currentColor" stroke-width="1.2"/>
                      <circle cx="3" cy="10" r="1.5" stroke="currentColor" stroke-width="1.2"/>
                      <circle cx="10" cy="3" r="1.5" stroke="currentColor" stroke-width="1.2"/>
                      <path d="M3 4.5V8.5M10 4.5C10 7 7.5 8.5 4.5 8.5"
                            stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
                    </svg>
                    PR
                  </a>
                </div>
              </div>
            </ng-container>

            <div class="dep-table__empty" *ngIf="displayedGroups().length === 0">
              No dependency data available.
            </div>
          </div>

          <!-- PR links footer — fixed tab -->
          <div class="pr-links" *ngIf="activeTab() === 'fixed' && allPrResults().length > 0">
            <a *ngFor="let pr of allPrResults()"
               [href]="pr.pr_url" target="_blank" rel="noopener" class="pr-link">
              <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
                <circle cx="3" cy="3" r="1.5" stroke="currentColor" stroke-width="1.2"/>
                <circle cx="3" cy="10" r="1.5" stroke="currentColor" stroke-width="1.2"/>
                <circle cx="10" cy="3" r="1.5" stroke="currentColor" stroke-width="1.2"/>
                <path d="M3 4.5V8.5M10 4.5C10 7 7.5 8.5 4.5 8.5" stroke="currentColor"
                      stroke-width="1.2" stroke-linecap="round"/>
              </svg>
              <span *ngIf="pr.artifact_id" class="pr-link__artifact">{{ pr.artifact_id }}</span>
              <span *ngIf="pr.pr_number">· PR #{{ pr.pr_number }}</span>
              <span *ngIf="!pr.pr_number">· Open PR</span>
            </a>
          </div>
        </ng-container>

        <!-- ── Tab: Escalated / Failed ─────────────────────────────────── -->
        <ng-container *ngIf="activeTab() === 'escalated'">
          <p class="esc-section-label" *ngIf="escalatedGroups().length > 0">
            Manual action required
          </p>
          <div class="esc-card" *ngFor="let dep of escalatedGroups()"
               [class.esc-card--open]="expandedId() === dep.parsed?.artifact_id"
               (click)="toggleExpanded(dep.parsed?.artifact_id || '')">
            <div class="esc-card__header">
              <svg width="13" height="13" viewBox="0 0 13 13" fill="none" class="esc-icon">
                <path d="M6.5 1.5L12 11H1L6.5 1.5Z" stroke="currentColor" stroke-width="1.2"
                      stroke-linejoin="round"/>
                <path d="M6.5 5V7.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
                <circle cx="6.5" cy="9.5" r=".5" fill="currentColor"/>
              </svg>
              <span class="esc-card__name">{{ dep.parsed?.artifact_id || dep.artifact_id }}</span>
              <span class="esc-card__sev sev-badge sev-badge--{{ (dep.parsed?.severity || dep.severity || 'INFO').toLowerCase() }}">
                {{ dep.parsed?.severity || dep.severity || 'INFO' }}
              </span>
              <svg class="esc-card__chevron" width="12" height="12" viewBox="0 0 12 12" fill="none">
                <path d="M3 4.5L6 7.5L9 4.5" stroke="currentColor" stroke-width="1.3"
                      stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
            </div>
            <div class="esc-card__body"
                 *ngIf="expandedId() === dep.parsed?.artifact_id">
              {{ dep.escalate_reason || dep.ai_reasoning?.reasoning || 'No safe version found.' }}
            </div>
          </div>

          <p class="esc-section-label esc-section-label--failed" *ngIf="failedGroups().length > 0">
            Pipeline error
          </p>
          <div class="esc-card esc-card--failed" *ngFor="let dep of failedGroups()"
               [class.esc-card--open]="expandedId() === dep.parsed?.artifact_id"
               (click)="toggleExpanded(dep.parsed?.artifact_id || '')">
            <div class="esc-card__header">
              <svg width="13" height="13" viewBox="0 0 13 13" fill="none" class="esc-icon esc-icon--failed">
                <circle cx="6.5" cy="6.5" r="5.5" stroke="currentColor" stroke-width="1.2"/>
                <path d="M4.5 4.5L8.5 8.5M8.5 4.5L4.5 8.5" stroke="currentColor" stroke-width="1.3"
                      stroke-linecap="round"/>
              </svg>
              <span class="esc-card__name">{{ dep.parsed?.artifact_id || dep.artifact_id }}</span>
              <svg class="esc-card__chevron" width="12" height="12" viewBox="0 0 12 12" fill="none">
                <path d="M3 4.5L6 7.5L9 4.5" stroke="currentColor" stroke-width="1.3"
                      stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
            </div>
            <div class="esc-card__body"
                 *ngIf="expandedId() === dep.parsed?.artifact_id">
              {{ dep.escalate_reason || 'Dependency resolution failed.' }}
            </div>
          </div>

          <div class="dep-table__empty"
               *ngIf="escalatedGroups().length === 0 && failedGroups().length === 0">
            No escalations or failures — all dependencies were auto-fixed.
          </div>
        </ng-container>

        <!-- ── Tab: Stages ─────────────────────────────────────────────── -->
        <ng-container *ngIf="activeTab() === 'stages'">
          <div class="stage-grid">
            <div *ngFor="let stage of stageList()"
                 class="stage-pill stage-pill--{{ stage.uiStatus }}">
              <svg *ngIf="stage.uiStatus === 'done'" width="12" height="12" viewBox="0 0 12 12" fill="none">
                <path d="M2.5 6L4.8 8.5L9.5 3.5" stroke="currentColor" stroke-width="1.4"
                      stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
              <svg *ngIf="stage.uiStatus === 'error'" width="12" height="12" viewBox="0 0 12 12" fill="none">
                <path d="M3 3L9 9M9 3L3 9" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
              </svg>
              <svg *ngIf="stage.uiStatus === 'skipped' || stage.uiStatus === 'pending'" width="12" height="12" viewBox="0 0 12 12" fill="none">
                <path d="M3 6H9" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
              </svg>
              <span class="stage-pill__label">{{ stage.label }}</span>
              <span class="stage-pill__elapsed" *ngIf="stage.elapsed">{{ stage.elapsed }}s</span>
            </div>
          </div>

          <!-- ── LLM token usage breakdown ─────────────────────────────── -->
          <div class="token-panel" *ngIf="tokenUsage() && tokenStageRows().length > 0">
            <div class="token-panel__head">
              <span class="token-panel__title">LLM token usage</span>
              <span class="token-panel__models" *ngIf="tokenModelNames()">{{ tokenModelNames() }}</span>
            </div>
            <div class="token-table">
              <div class="token-table__head">
                <span>Stage</span>
                <span class="num">Calls</span>
                <span class="num">Input</span>
                <span class="num">Output</span>
                <span class="num">Total</span>
              </div>
              <div class="token-table__row" *ngFor="let r of tokenStageRows()">
                <span>{{ r.label }}</span>
                <span class="num">{{ r.calls }}</span>
                <span class="num">{{ formatTokens(r.input_tokens) }}</span>
                <span class="num">{{ formatTokens(r.output_tokens) }}</span>
                <span class="num token-table__total">{{ formatTokens(r.total_tokens) }}</span>
              </div>
              <div class="token-table__row token-table__row--sum">
                <span>Total</span>
                <span class="num">{{ tokenUsage()!.calls }}</span>
                <span class="num">{{ formatTokens(tokenUsage()!.input_tokens) }}</span>
                <span class="num">{{ formatTokens(tokenUsage()!.output_tokens) }}</span>
                <span class="num token-table__total">{{ formatTokens(tokenUsage()!.total_tokens) }}</span>
              </div>
            </div>
          </div>
        </ng-container>

      </ng-container>
    </div>
  `,
  styles: [`
    .summary {
      padding: 24px 28px;
      max-width: 960px;
    }

    /* Nav */
    .summary__nav {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 24px;
      flex-wrap: wrap;
      gap: 10px;
    }
    .summary__nav-right {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .back-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 13px;
      color: var(--text-muted);
      text-decoration: none;
      padding: 5px 10px;
      border-radius: 6px;
      border: 1px solid transparent;
      transition: background 0.15s, border-color 0.15s;
    }
    .back-btn:hover {
      background: var(--surface-2);
      border-color: var(--border);
    }
    .release-label, .elapsed-label {
      font-size: 12px;
      color: var(--text-muted);
    }
    .status-pill {
      font-size: 11px;
      font-weight: 500;
      padding: 3px 10px;
      border-radius: 999px;
      background: var(--surface-2);
      color: var(--text-muted);
      border: 1px solid var(--border);
    }
    .status-pill--ok  { background: #EAF3DE; color: #3B6D11; border-color: #97C459; }
    .status-pill--err { background: #FCEBEB; color: #A32D2D; border-color: #F09595; }

    /* Loading / error */
    .summary__loading {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 2rem;
      color: var(--text-muted);
      font-size: 13px;
    }
    .spinner {
      width: 16px; height: 16px;
      border: 2px solid var(--border);
      border-top-color: var(--brand);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .summary__error {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 12px 16px;
      border-radius: 8px;
      background: #FCEBEB;
      color: #A32D2D;
      font-size: 13px;
      border: 1px solid #F09595;
      margin-bottom: 1rem;
    }

    /* Stat grid */
    .stat-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(142px, 1fr));
      gap: 10px;
      margin-bottom: 20px;
    }
    .stat-card {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 14px 16px;
      border-radius: 8px;
      background: var(--surface-2);
      min-width: 0;
      overflow: hidden;
    }
    .stat-card__icon {
      width: 34px; height: 34px;
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      flex-shrink: 0;
    }
    .stat-card--fixed    .stat-card__icon { background: #EAF3DE22; color: #3B6D11; }
    .stat-card--escalated .stat-card__icon { background: #FAEEDA22; color: #854F0B; }
    .stat-card--failed   .stat-card__icon { background: #FCEBEB22; color: #A32D2D; }
    .stat-card--total    .stat-card__icon { background: #E6F1FB22; color: #185FA5; }
    .stat-card__body {
      min-width: 0; /* allow shrink inside flex — prevents clipped labels/values */
    }
    .stat-card__label {
      display: block;
      font-size: 12px;
      color: var(--text-muted);
      margin-bottom: 2px;
    }
    .stat-card__value {
      display: block;
      font-size: 22px;
      font-weight: 500;
      color: var(--text);
    }

    /* Progress bar */
    .progress-block { margin-bottom: 20px; }
    .progress-bar {
      height: 8px;
      border-radius: 999px;
      background: var(--surface-2);
      overflow: hidden;
      display: flex;
    }
    .progress-bar__seg { transition: width 0.6s ease; }
    .progress-bar__seg--fixed     { background: #639922; }
    .progress-bar__seg--escalated { background: #EF9F27; }
    .progress-bar__seg--failed    { background: #E24B4A; }
    .progress-legend {
      display: flex;
      gap: 14px;
      margin-top: 6px;
      font-size: 11px;
      color: var(--text-muted);
      align-items: center;
    }
    .legend-item { display: flex; align-items: center; gap: 4px; }
    .legend-item::before {
      content: '';
      width: 8px; height: 8px;
      border-radius: 2px;
      display: inline-block;
    }
    .legend-item--fixed::before     { background: #639922; }
    .legend-item--escalated::before { background: #EF9F27; }
    .legend-item--failed::before    { background: #E24B4A; }
    .legend-pct { margin-left: auto; }

    /* Tabs */
    .tabs {
      display: flex;
      gap: 2px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 16px;
    }
    .tab-btn {
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      padding: 7px 14px;
      font-size: 13px;
      color: var(--text-muted);
      cursor: pointer;
      margin-bottom: -1px;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .tab-btn--active {
      color: var(--text);
      font-weight: 500;
      border-bottom-color: var(--text);
    }
    .tab-count {
      font-size: 11px;
      padding: 1px 6px;
      border-radius: 10px;
      background: var(--surface-2);
      color: var(--text-muted);
    }

    /* Dep table */
    .dep-table {
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
    }
    .dep-table__head {
      display: grid;
      grid-template-columns: 26px minmax(0,2fr) 70px 80px minmax(0,1.2fr) 130px;
      gap: 10px;
      padding: 8px 14px;
      background: var(--surface-2);
      border-bottom: 1px solid var(--border);
      font-size: 11px;
      font-weight: 500;
      color: var(--text-muted);
    }
    .dep-row {
      display: grid;
      grid-template-columns: 26px minmax(0,2fr) 70px 80px minmax(0,1.2fr) 130px;
      gap: 10px;
      align-items: start;
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
      font-size: 13px;
    }
    .dep-row:last-child { border-bottom: none; }
    .dep-row__icon {
      display: flex;
      align-items: center;
      align-self: center;
    }
    .dep-row__icon--fixed     { color: #3B6D11; }
    .dep-row__icon--escalated { color: #854F0B; }
    .dep-row__icon--failed    { color: #A32D2D; }
    .dep-row__name {
      min-width: 0;
      align-self: center;
    }
    .dep-row__artifact {
      display: block;
      font-weight: 500;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: var(--text);
    }
    .dep-row__group {
      display: block;
      font-size: 11px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: var(--text-muted);
    }
    .dep-row__ver {
      color: var(--text-muted);
      align-self: center;
    }
    .dep-row__ver--ok { color: #0F6E56; }
    .dep-row__cves { display: flex; flex-wrap: wrap; gap: 3px; align-self: start; }
    .cve-chip {
      font-size: 10px;
      padding: 1px 5px;
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 3px;
      color: var(--text-muted);
    }
    .cve-more { font-size: 10px; color: var(--text-muted); }
    .dep-table__empty {
      padding: 2rem;
      text-align: center;
      font-size: 13px;
      color: var(--text-muted);
    }

    /* Last column meta: severity + confidence + PR */
    .dep-row__meta {
      display: flex;
      flex-direction: column;
      align-items: flex-start;
      gap: 4px;
    }
    .dep-row__meta-badges {
      display: flex;
      flex-direction: row;
      align-items: center;
      gap: 4px;
      flex-wrap: nowrap;
    }

    /* Confidence chip */
    .conf-chip {
      font-size: 10px;
      font-weight: 500;
      padding: 2px 6px;
      border-radius: 3px;
      white-space: nowrap;
      flex-shrink: 0;
    }
    .conf-chip--high   { background: #EAF3DE; color: #3B6D11; border: 1px solid #97C459; }
    .conf-chip--medium { background: #FAEEDA; color: #854F0B; border: 1px solid #EF9F27; }
    .conf-chip--low    { background: #FCEBEB; color: #A32D2D; border: 1px solid #F09595; }

    /* Inline PR link in dep row */
    .pr-inline-link {
      display: inline-flex;
      align-items: center;
      gap: 3px;
      font-size: 11px;
      font-weight: 500;
      color: var(--brand, #7c6af7);
      text-decoration: none;
      padding: 1px 5px;
      border: 1px solid currentColor;
      border-radius: 3px;
      opacity: 0.8;
    }
    .pr-inline-link:hover { opacity: 1; }

    /* Confidence stat card */
    .stat-card--conf .stat-card__icon { background: #E6F1FB22; color: #185FA5; }
    .stat-card__value--conf {
      display: flex;
      flex-direction: column;
      align-items: flex-start;
      gap: 1px;
      min-width: 0;
      font-size: 16px;      /* word value, not a number — 22px overflows the card */
      line-height: 1.25;
      padding-top: 2px;
      letter-spacing: 0.02em;
    }
    .stat-card__value-sub {
      font-size: 12px;
      font-weight: 400;
      color: var(--text-muted);
      white-space: nowrap;
    }
    .stat-card__value--conf.high   { color: #3B6D11; }
    .stat-card__value--conf.medium { color: #854F0B; }
    .stat-card__value--conf.low    { color: #A32D2D; }

    /* PR link footer artifact label */
    .pr-link__artifact { font-weight: 500; }

    /* Severity badges */
    .sev-badge {
      font-size: 11px;
      font-weight: 500;
      padding: 2px 7px;
      border-radius: 4px;
      white-space: nowrap;
    }
    .sev-badge--critical { background: #FCEBEB; color: #A32D2D; border: 1px solid #F09595; }
    .sev-badge--blocker  { background: #FCEBEB; color: #A32D2D; border: 1px solid #F09595; }
    .sev-badge--high     { background: #FAEEDA; color: #854F0B; border: 1px solid #EF9F27; }
    .sev-badge--medium   { background: #E6F1FB; color: #185FA5; border: 1px solid #85B7EB; }
    .sev-badge--major    { background: #E6F1FB; color: #185FA5; border: 1px solid #85B7EB; }
    .sev-badge--low      { background: #EAF3DE; color: #3B6D11; border: 1px solid #97C459; }
    .sev-badge--minor    { background: #EAF3DE; color: #3B6D11; border: 1px solid #97C459; }
    .sev-badge--info     { background: #F1EFE8; color: #5F5E5A; border: 1px solid #B4B2A9; }

    /* PR links */
    .pr-links {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      padding: 10px 14px;
      border: 1px solid var(--border);
      border-top: none;
      border-radius: 0 0 10px 10px;
      background: var(--surface-2);
    }
    .pr-link {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 12px;
      color: var(--brand);
      text-decoration: none;
    }
    .pr-link:hover { text-decoration: underline; }

    /* Escalation cards */
    .esc-section-label {
      font-size: 12px;
      font-weight: 500;
      color: var(--text-muted);
      margin-bottom: 8px;
    }
    .esc-section-label--failed { margin-top: 16px; }
    .esc-card {
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 8px;
      overflow: hidden;
      cursor: pointer;
    }
    .esc-card__header {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 14px;
    }
    .esc-icon     { color: #854F0B; flex-shrink: 0; }
    .esc-icon--failed { color: #A32D2D; }
    .esc-card__name {
      flex: 1;
      font-size: 13px;
      font-weight: 500;
      color: var(--text);
    }
    .esc-card__chevron {
      color: var(--text-muted);
      transition: transform 0.2s;
    }
    .esc-card--open .esc-card__chevron { transform: rotate(180deg); }
    .esc-card__body {
      padding: 8px 14px 12px 34px;
      font-size: 13px;
      color: var(--text-muted);
      border-top: 1px solid var(--border);
    }

    /* Stage pills */
    .stage-grid {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    .stage-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      font-size: 12px;
      background: var(--surface-2);
    }
    .stage-pill--done    { color: #3B6D11; }
    .stage-pill--error   { color: #A32D2D; }
    .stage-pill--skipped { color: var(--text-muted); }
    .stage-pill--pending { color: var(--text-muted); opacity: 0.6; }
    .stage-pill__label { font-weight: 500; }
    .stage-pill__elapsed { font-size: 11px; color: var(--text-muted); margin-left: 2px; }

    /* Token usage panel */
    .token-panel {
      margin-top: 18px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--surface-2);
      overflow: hidden;
    }
    .token-panel__head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
    }
    .token-panel__title {
      font-size: 12px;
      font-weight: 600;
    }
    .token-panel__models {
      font-size: 11px;
      color: var(--text-muted);
      font-family: monospace;
    }
    .token-table {
      font-size: 12px;
    }
    .token-table__head,
    .token-table__row {
      display: grid;
      grid-template-columns: 1fr 64px 84px 84px 84px;
      gap: 8px;
      padding: 7px 14px;
      align-items: center;
    }
    .token-table__head {
      color: var(--text-muted);
      font-size: 11px;
      border-bottom: 1px solid var(--border);
    }
    .token-table__row + .token-table__row {
      border-top: 1px solid var(--border);
    }
    .token-table__row--sum {
      font-weight: 600;
      background: var(--surface-1, transparent);
    }
    .token-table .num {
      text-align: right;
      font-variant-numeric: tabular-nums;
    }
    .token-table__total { font-weight: 500; }
  `]
})
export class SummaryReportComponent implements OnInit {
  private route   = inject(ActivatedRoute);
  private router  = inject(Router);
  private apiCfg  = inject(ApiConfigService);

  pipelineId = '';

  loading     = signal(true);
  fetchError  = signal<string | null>(null);
  status      = signal<PipelineStatus | null>(null);
  activeTab   = signal<'all' | 'fixed' | 'escalated' | 'stages'>('all');
  expandedId  = signal<string | null>(null);

  // ── Core derived: annotate each group with _outcome and _prUrl ────────────
  //
  // Backend result shape (full pipeline):
  //   result.groups[]        — all dependency groups (added to api_server.py return)
  //   result.adr_results[]   — [{ artifact_id, result: { success, branch_name, error_reason } }]
  //   result.pr_results[]    — [{ pr_url, pr_number }] — one per successful adr_result, in order
  //   result.total_fixed / total_escalated / total_failed  — writeback summary counts
  //
  // Fallback: if groups[] is absent (older backend), synthesise rows from adr_results.

  allGroups = (): (DepGroup & { _outcome: string; _prUrl?: string; _confidence?: number })[] => {
    const result  = this.status()?.result;
    if (!result) return [];

    const adrResults = result.adr_results ?? [];
    const prResults  = result.pr_results  ?? [];

    // Build artifact_id → adr result lookup
    const adrByArtifact = new Map<string, any>();
    for (const r of adrResults) {
      adrByArtifact.set(r.artifact_id, r.result ?? r);
    }

    // Walk pr_results in order — they match successful adr_results positionally
    let prIdx = 0;

    // Prefer the full groups array (present after api_server.py fix)
    const groups = result.groups ?? [];

    if (groups.length > 0) {
      return groups.map(g => {
        const artifactId = g.parsed?.artifact_id ?? g.artifact_id ?? '';
        const adr        = adrByArtifact.get(artifactId);
        const confidence = g.ai_reasoning?.confidence_score;

        if (adr?.success === true) {
          const pr = prResults[prIdx++];
          return { ...g, _outcome: 'fixed', _prUrl: pr?.pr_url, _confidence: confidence };
        }
        const hasReason = !!(g.escalate_reason || g.ai_reasoning?.reasoning || adr?.error_reason);
        return { ...g, _outcome: hasReason ? 'escalated' : 'failed', _confidence: confidence };
      });
    }

    // ── Fallback: no groups array — build synthetic rows from adr_results ────
    return adrResults.map((r: AdrEntry) => {
      const adr        = r.result ?? r;
      const artifactId = r.artifact_id ?? '';

      if (adr?.success === true) {
        const pr = prResults[prIdx++];
        const synthetic: DepGroup & { _outcome: string; _prUrl?: string } = {
          artifact_id:     artifactId,
          parsed:          { artifact_id: artifactId },
          _outcome:        'fixed',
          _prUrl:          pr?.pr_url,
        };
        return synthetic;
      }
      const reason = adr?.error_reason ?? '';
      const synthetic: DepGroup & { _outcome: string } = {
        artifact_id:     artifactId,
        parsed:          { artifact_id: artifactId },
        escalate_reason: reason,
        _outcome:        reason ? 'escalated' : 'failed',
      };
      return synthetic;
    });
  };

  fixedGroups     = () => this.allGroups().filter(g => g._outcome === 'fixed');
  escalatedGroups = () => this.allGroups().filter(g => g._outcome === 'escalated');
  failedGroups    = () => this.allGroups().filter(g => g._outcome === 'failed');

  displayedGroups = () =>
    this.activeTab() === 'fixed' ? this.fixedGroups() : this.allGroups();

  // All PRs with URLs, preserving per-group mapping
  allPrResults = (): { pr_url: string; pr_number?: number; artifact_id?: string }[] =>
    this.fixedGroups()
      .filter(g => g._prUrl)
      .map(g => ({
        pr_url:      g._prUrl!,
        pr_number:   (this.status()?.result?.pr_results ?? [])
                       .find(p => p.pr_url === g._prUrl)?.pr_number,
        artifact_id: g.parsed?.artifact_id ?? g.artifact_id,
      }));

  // Totals — prefer top-level summary counts, then result sub-fields, then group count
  totalFixed     = () => this.status()?.result?.total_fixed
                      ?? this.status()?.result?.summary?.total_fixed
                      ?? this.fixedGroups().length;
  totalEscalated = () => this.status()?.result?.total_escalated
                      ?? this.status()?.result?.summary?.total_escalated
                      ?? this.escalatedGroups().length;
  totalFailed    = () => this.status()?.result?.total_failed
                      ?? this.status()?.result?.summary?.total_failed
                      ?? this.failedGroups().length;
  totalDeps      = () => this.totalFixed() + this.totalEscalated() + this.totalFailed();

  pctFixed = () =>
    this.totalDeps() > 0 ? Math.round((this.totalFixed() / this.totalDeps()) * 100) : 0;

  // Average confidence across all groups that have a score
  avgConfidence = (): string => {
    const scores = this.allGroups()
      .map(g => g._confidence)
      .filter((s): s is number => s != null && !isNaN(s));
    if (!scores.length) return '—';
    const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
    if (avg >= 0.75) return 'HIGH';
    if (avg >= 0.45) return 'MEDIUM';
    return 'LOW';
  };

  avgConfidenceScore = (): string => {
    const scores = this.allGroups()
      .map(g => g._confidence)
      .filter((s): s is number => s != null && !isNaN(s));
    if (!scores.length) return '—';
    const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
    return (avg * 100).toFixed(0) + '%';
  };

  stageList = () =>
    Object.entries(STAGE_LABELS).map(([key, label]) => {
      const s = this.status()?.stages?.[key] ?? {};
      const apiStatus = s.status ?? 'pending';
      const uiStatus =
        apiStatus === 'completed' ? 'done'
        : apiStatus === 'failed'  ? 'error'
        : apiStatus === 'skipped' ? 'skipped'
        : 'pending';
      return {
        key, label, uiStatus,
        elapsed: s.elapsed_seconds != null ? s.elapsed_seconds.toFixed(1) : null,
        detail:  s.error ?? (s.output_summary ? this._summarise(key, s.output_summary) : null),
      };
    });

  private _summarise(stage: string, s: any): string {
    switch (stage) {
      case 'triage':             return `${s.total_groups ?? 0} groups, ${s.total_skipped ?? 0} skipped`;
      case 'version-resolver':   return s.next_safe ? `Next safe: ${s.next_safe}` : '';
      case 'api-diff':           return s.has_breaking_changes ? `⚠ ${s.breaking_count} breaking` : '✓ No breaking changes';
      case 'ai-reasoning':       return s.confidence ? `${s.safe ? '✓ Safe' : '⚠ Unsafe'} · ${s.confidence}` : '';
      case 'adr-fix':            return s.branch_name ?? s.error_reason ?? '';
      case 'pr-agent':           return s.pr_url ? `PR opened` : '';
      case 'fortify-writeback':  return s.total_fixed != null ? `Fixed: ${s.total_fixed}, Escalated: ${s.total_escalated ?? 0}` : '';
      default:                   return '';
    }
  }

  pipelineResult = () => this.status()?.result ?? null;

  targetVersion = (dep: DepGroup): string =>
    dep.current_candidate
    ?? dep.version_candidates?.candidates?.[0]
    ?? dep.ai_reasoning?.recommended_version
    ?? '—';

  // ── Token usage helpers ───────────────────────────────────────────────────

  tokenUsage = (): TokenUsage | null =>
    this.status()?.result?.token_usage ?? null;

  tokenStageRows = (): (TokenStageUsage & { label: string })[] => {
    const stages = this.tokenUsage()?.stages ?? {};
    return Object.entries(stages).map(([key, s]) => ({
      label: TOKEN_STAGE_LABELS[key] ?? key,
      ...s,
    }));
  };

  tokenModelNames = (): string =>
    Object.keys(this.tokenUsage()?.models ?? {}).join(', ');

  formatTokens = (n: number | undefined | null): string => {
    if (n == null) return '—';
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
    if (n >= 1_000)     return (n / 1_000).toFixed(1) + 'k';
    return `${n}`;
  };

  formatSeconds = (s: number): string => {
    if (s < 60) return `${Math.round(s)}s`;
    const m = Math.floor(s / 60);
    const r = Math.round(s % 60);
    return r > 0 ? `${m}m ${r}s` : `${m}m`;
  };

  confidenceClass = (label: string): string => label.toLowerCase();

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  ngOnInit(): void {
    this.pipelineId = this.route.snapshot.paramMap.get('pipelineId') ?? '';
    if (!this.pipelineId) {
      this.fetchError.set('No pipeline ID provided.');
      this.loading.set(false);
      return;
    }
    this._fetchStatus();
  }

  private _fetchStatus(): void {
    const base = this.apiCfg.fortifyBaseUrl();
    fetch(`${base}/pipeline/status/${this.pipelineId}`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(data => {
        const payload: PipelineStatus = data?.data ?? data;
        this.status.set(payload);
        this.loading.set(false);
      })
      .catch(err => {
        this.fetchError.set(`Could not load report: ${err.message}`);
        this.loading.set(false);
      });
  }

  // ── UI helpers ────────────────────────────────────────────────────────────

  toggleExpanded(id: string): void {
    this.expandedId.update(cur => cur === id ? null : id);
  }
}