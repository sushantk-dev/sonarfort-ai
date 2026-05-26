import { Pipe, PipeTransform } from '@angular/core';
@Pipe({ name: 'outcomeLabel', standalone: true })
export class OutcomeLabelPipe implements PipeTransform {
  transform(value: string | undefined): string {
    const map: Record<string, string> = {
      pr_opened: 'PR Opened',
      draft_pr:  'Draft PR',
      escalated: 'Escalated',
      error:     'Error',
      cancelled: 'Cancelled',
      empty:     'No Issues',
      pending:   'Pending',
    };
    return value ? (map[value] ?? value) : '—';
  }
}