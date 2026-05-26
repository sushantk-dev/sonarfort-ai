// src/app/features/issues/issues.component.ts
import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { IssuesStateService } from '../../core/issues-state.service';
import { DataService } from '../../core/data.service';
import { SonarIssue } from '../../core/models';
import { SevClassPipe }    from '../../shared/sev-class.pipe';
import { OutcomeLabelPipe } from '../../shared/outcome-label.pipe';
import { OutcomeClassPipe } from '../../shared/outcome-class.pipe';
import { ShortCompPipe }    from '../../shared/short-comp.pipe';

@Component({
  selector: 'app-issues',
  standalone: true,
  imports: [CommonModule, FormsModule, SevClassPipe, OutcomeLabelPipe, OutcomeClassPipe, ShortCompPipe],
  templateUrl: './issues.component.html',
  styleUrl:    './issues.component.scss',
})
export class IssuesComponent {
  // Singleton — state survives tab navigation
  st  = inject(IssuesStateService);
  svc = inject(DataService);
  
// Live SonarQube fetch
  sonarComponentKey = '';

  drawer: SonarIssue | null = null;
  get kb() { return this.drawer ? this.svc.getRuleKb(this.drawer.ruleKey) : null; }

  severities = ['ALL', 'BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO'];

  outcomeFilters = [
    { label: 'All',       value: 'ALL'       },
    { label: 'PR',        value: 'pr_opened' },
    { label: 'Draft PR',  value: 'draft_pr'  },
    { label: 'Escalated', value: 'escalated' },
    { label: 'Pending',   value: 'pending'   },
  ];

  openDrawer(issue: SonarIssue) {
    if (this.st.deleteConfirmKey()) { this.st.cancelDelete(); return; }
    this.drawer = this.drawer?.key === issue.key ? null : issue;
  }
  closeDrawer() { this.drawer = null; }

  // Row delete — stop propagation in template via $event
  requestDelete(event: Event, key: string) {
    event.stopPropagation();
    this.st.requestDelete(key);
  }

  confirmDelete(event: Event, key: string) {
    event.stopPropagation();
    if (this.drawer?.key === key) this.drawer = null;
    this.st.confirmDelete(key);
  }

  cancelDelete(event: Event) {
    event.stopPropagation();
    this.st.cancelDelete();
  }

  onImport(event: Event) {
    const input = event.target as HTMLInputElement;
    const file  = input.files?.[0];
    if (!file) return;
    this.st.onImport(file);
    input.value = '';
    this.sonarComponentKey = '';
  }

  fetchFromSonar() {
    this.st.fetchFromSonar(this.sonarComponentKey);
  }

  // Export structured report
  exportReport() {
    this.st.exportReport();
  }
}