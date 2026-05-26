// src/app/features/escalations/escalations.component.ts
import { Component, inject, signal, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService } from '../../core/api.service';

export interface EscalationItem {
  filename:    string;
  issue_key:   string;
  rule_key:    string;
  severity:    string;
  file_name:   string;
  size_bytes:  number;
  modified_at: number;
}

@Component({
  selector: 'app-escalations',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './escalations.component.html',
  styleUrl:    './escalations.component.scss',
})
export class EscalationsComponent implements OnInit {
  private api = inject(ApiService);

  items       = signal<EscalationItem[]>([]);
  selected    = signal<EscalationItem | null>(null);
  content     = signal<string>('');
  loading     = signal(true);
  loadingContent = signal(false);
  deleteKey   = signal<string | null>(null);
  error       = signal('');

  ngOnInit() { this.load(); }

  load() {
    this.loading.set(true);
    this.api.listEscalations().subscribe({
      next: (res) => {
        this.items.set(res.escalations);
        this.loading.set(false);
        // Re-select if current selected still exists
        const cur = this.selected();
        if (cur && !res.escalations.find((e: EscalationItem) => e.filename === cur.filename)) {
          this.selected.set(null);
          this.content.set('');
        }
      },
      error: () => {
        this.error.set('Could not load escalations — is the backend running?');
        this.loading.set(false);
      },
    });
  }

  select(item: EscalationItem) {
    this.selected.set(item);
    this.deleteKey.set(null);
    this.loadingContent.set(true);
    this.api.getEscalation(item.filename).subscribe({
      next: (res) => {
        this.content.set(res.content);
        this.loadingContent.set(false);
      },
      error: () => {
        this.content.set('Could not load file content.');
        this.loadingContent.set(false);
      },
    });
  }

  requestDelete(filename: string, event: Event) {
    event.stopPropagation();
    this.deleteKey.set(this.deleteKey() === filename ? null : filename);
  }

  confirmDelete(filename: string, event: Event) {
    event.stopPropagation();
    this.api.deleteEscalation(filename).subscribe({
      next: () => {
        if (this.selected()?.filename === filename) {
          this.selected.set(null);
          this.content.set('');
        }
        this.deleteKey.set(null);
        this.load();
      },
      error: () => {
        this.error.set(`Failed to delete ${filename}`);
        this.deleteKey.set(null);
      },
    });
  }

  cancelDelete(event: Event) {
    event.stopPropagation();
    this.deleteKey.set(null);
  }

  // Download escalation as .md file
  download(item: EscalationItem) {
    this.api.getEscalation(item.filename).subscribe({
      next: (res) => {
        const blob = new Blob([res.content], { type: 'text/markdown' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = item.filename;
        a.click();
        URL.revokeObjectURL(url);
      },
    });
  }

  sevClass(s: string) { return s.toLowerCase(); }

  formatDate(ts: number) {
    return new Date(ts * 1000).toLocaleString();
  }

  formatSize(bytes: number) {
    return bytes < 1024 ? `${bytes}B` : `${(bytes / 1024).toFixed(1)}KB`;
  }

  // Render markdown headings and code blocks as basic HTML for preview
  renderMarkdown(md: string): string {
    return md
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      // headings
      .replace(/^### (.+)$/gm, '<h3>$1</h3>')
      .replace(/^## (.+)$/gm,  '<h2>$1</h2>')
      .replace(/^# (.+)$/gm,   '<h1>$1</h1>')
      // bold
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      // inline code
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      // fenced code blocks
      .replace(/```(\w*)\n([\s\S]*?)```/gm, '<pre><code class="lang-$1">$2</code></pre>')
      // blockquote
      .replace(/^&gt; (.+)$/gm, '<blockquote>$1</blockquote>')
      // table rows  | a | b |
      .replace(/^\|(.+)\|$/gm, (_, row) => {
        const cells = row.split('|').map((c: string) => c.trim());
        if (cells.every((c: string) => /^[-:]+$/.test(c))) return ''; // separator row
        return '<tr>' + cells.map((c: string) => `<td>${c}</td>`).join('') + '</tr>';
      })
      // horizontal rule
      .replace(/^---$/gm, '<hr>')
      // line breaks
      .replace(/\n/g, '<br>');
  }
}
