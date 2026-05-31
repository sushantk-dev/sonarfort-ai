// src/app/features/escalations/escalations.component.ts
import { Component, inject, signal, OnInit, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService } from '../../core/api.service';
import { ApiConfigService } from '../../core/api-config.service';

// ── Shared escalation item shape ─────────────────────────────────────────────
export interface EscalationItem {
  filename:    string;
  issue_key:   string;
  rule_key:    string;
  severity:    string;
  file_name:   string;
  size_bytes:  number;
  modified_at: number;
  source?:     'sonar' | 'fortify';   // added for dual-source support
  // Fortify-specific fields (present when source === 'fortify')
  artifact_id?:  string;
  cves?:         string[];
  reason?:       string;
  tried?:        string[];
}

@Component({
  selector: 'app-escalations',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './escalations.component.html',
  styleUrl:    './escalations.component.scss',
})
export class EscalationsComponent implements OnInit {
  private api    = inject(ApiService);
  private apiCfg = inject(ApiConfigService);
  /** Routes to Fortify server — separate port if configured, else shared */
  /** Fortify pipeline API (port 8001) — now has /escalations endpoint */
  private get fortifyBase() { return this.apiCfg.fortifyBaseUrl(); }

  // ── Source tab ────────────────────────────────────────────────────────────
  activeSource = signal<'sonar' | 'fortify'>('sonar');

  // ── Sonar escalations ─────────────────────────────────────────────────────
  sonarItems   = signal<EscalationItem[]>([]);

  // ── Fortify escalations ───────────────────────────────────────────────────
  fortifyItems = signal<EscalationItem[]>([]);
  fortifyOutputDir = signal('/tmp/fortifyai');   // matches config.adr_output_dir default

  // ── Active list — derived from source tab ─────────────────────────────────
  items = computed(() =>
    this.activeSource() === 'sonar' ? this.sonarItems() : this.fortifyItems()
  );

  selected       = signal<EscalationItem | null>(null);
  content        = signal<string>('');
  loading        = signal(true);
  loadingContent = signal(false);
  deleteKey      = signal<string | null>(null);
  error          = signal('');

  // Fortify-specific loading state
  fortifyLoading = signal(false);
  fortifyLoaded  = signal(false);

  ngOnInit() { this.load(); }

  // ── Load — loads both sources ─────────────────────────────────────────────
  load() {
    this.loadSonar();
    if (this.fortifyLoaded()) this.loadFortify();   // refresh if already loaded
  }

  loadSonar() {
    this.loading.set(true);
    this.api.listEscalations().subscribe({
      next: (res) => {
        const items = (res.escalations as EscalationItem[]).map(e => ({ ...e, source: 'sonar' as const }));
        this.sonarItems.set(items);
        this.loading.set(false);
        this._resyncSelected(items);
      },
      error: () => {
        this.error.set('Could not load Sonar escalations — is the backend running?');
        this.loading.set(false);
      },
    });
  }

  // Load Fortify escalations from GET /escalations (Fortify API server)
  async loadFortify() {
    this.fortifyLoading.set(true);
    try {
      const resp = await fetch(`${this.fortifyBase}/escalations?output_dir=${encodeURIComponent(this.fortifyOutputDir())}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();

      const items: EscalationItem[] = (data.escalations ?? []).map((e: any) => ({
        filename:    e.filename,
        issue_key:   e.artifact_id ?? '',
        rule_key:    e.cves?.join(', ') ?? '—',
        severity:    e.severity ?? 'HIGH',
        file_name:   e.artifact_id ?? e.filename,
        size_bytes:  e.size_bytes ?? 0,
        modified_at: e.modified_at ?? 0,
        source:      'fortify' as const,
        artifact_id: e.artifact_id,
        cves:        e.cves ?? [],
        reason:      e.reason ?? '',
        tried:       e.tried ?? [],
      }));

      this.fortifyItems.set(items);
      this.fortifyLoaded.set(true);
      if (this.activeSource() === 'fortify') this._resyncSelected(items);
    } catch (err: any) {
      this.error.set(`Could not load Fortify escalations: ${err.message}`);
    } finally {
      this.fortifyLoading.set(false);
    }
  }

  // ── Tab switch ────────────────────────────────────────────────────────────
  switchSource(src: 'sonar' | 'fortify') {
    this.activeSource.set(src);
    this.selected.set(null);
    this.content.set('');
    this.deleteKey.set(null);
    // Lazy-load Fortify on first switch
    if (src === 'fortify' && !this.fortifyLoaded()) {
      this.loadFortify();
    }
  }

  // ── Select ────────────────────────────────────────────────────────────────
  select(item: EscalationItem) {
    this.selected.set(item);
    this.deleteKey.set(null);

    if (item.source === 'fortify') {
      this._loadFortifyContent(item);
    } else {
      this._loadSonarContent(item);
    }
  }

  private _loadSonarContent(item: EscalationItem) {
    this.loadingContent.set(true);
    this.api.getEscalation(item.filename).subscribe({
      next: (res) => { this.content.set(res.content); this.loadingContent.set(false); },
      error: () => { this.content.set('Could not load file content.'); this.loadingContent.set(false); },
    });
  }

  private async _loadFortifyContent(item: EscalationItem) {
    this.loadingContent.set(true);
    try {
      const resp = await fetch(
        `${this.fortifyBase}/escalations/${encodeURIComponent(item.filename)}?output_dir=${encodeURIComponent(this.fortifyOutputDir())}`
      );
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      this.content.set(data.content ?? '');
    } catch (err: any) {
      this.content.set(`Could not load escalation: ${err.message}`);
    } finally {
      this.loadingContent.set(false);
    }
  }

  // ── Delete ────────────────────────────────────────────────────────────────
  requestDelete(filename: string, event: Event) {
    event.stopPropagation();
    this.deleteKey.set(this.deleteKey() === filename ? null : filename);
  }

  confirmDelete(filename: string, event: Event) {
    event.stopPropagation();
    const item = this.items().find(i => i.filename === filename);

    if (item?.source === 'fortify') {
      this._deleteFortify(filename);
    } else {
      this._deleteSonar(filename);
    }
  }

  private _deleteSonar(filename: string) {
    this.api.deleteEscalation(filename).subscribe({
      next: () => {
        this._afterDelete(filename);
        this.loadSonar();
      },
      error: () => { this.error.set(`Failed to delete ${filename}`); this.deleteKey.set(null); },
    });
  }

  private async _deleteFortify(filename: string) {
    try {
      const resp = await fetch(
        `${this.fortifyBase}/escalations/${encodeURIComponent(filename)}?output_dir=${encodeURIComponent(this.fortifyOutputDir())}`,
        { method: 'DELETE' }
      );
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      this._afterDelete(filename);
      await this.loadFortify();
    } catch (err: any) {
      this.error.set(`Failed to delete ${filename}: ${err.message}`);
      this.deleteKey.set(null);
    }
  }

  private _afterDelete(filename: string) {
    if (this.selected()?.filename === filename) {
      this.selected.set(null);
      this.content.set('');
    }
    this.deleteKey.set(null);
  }

  cancelDelete(event: Event) {
    event.stopPropagation();
    this.deleteKey.set(null);
  }

  // ── Download ──────────────────────────────────────────────────────────────
  download(item: EscalationItem) {
    if (item.source === 'fortify') {
      this._downloadFortify(item);
    } else {
      this._downloadSonar(item);
    }
  }

  private _downloadSonar(item: EscalationItem) {
    this.api.getEscalation(item.filename).subscribe({
      next: (res) => this._triggerDownload(res.content, item.filename, 'text/markdown'),
    });
  }

  private async _downloadFortify(item: EscalationItem) {
    try {
      const resp = await fetch(
        `${this.fortifyBase}/escalations/${encodeURIComponent(item.filename)}?output_dir=${encodeURIComponent(this.fortifyOutputDir())}`
      );
      const data = await resp.json();
      this._triggerDownload(data.content ?? '', item.filename, 'text/plain');
    } catch {}
  }

  private _triggerDownload(content: string, filename: string, mime: string) {
    const blob = new Blob([content], { type: mime });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  private _resyncSelected(items: EscalationItem[]) {
    const cur = this.selected();
    if (cur && !items.find(e => e.filename === cur.filename)) {
      this.selected.set(null);
      this.content.set('');
    }
  }

  sevClass(s: string) { return s?.toLowerCase() ?? 'info'; }

  formatDate(ts: number) {
    return new Date(ts * 1000).toLocaleString();
  }

  formatSize(bytes: number) {
    return bytes < 1024 ? `${bytes}B` : `${(bytes / 1024).toFixed(1)}KB`;
  }

  // Renders both Sonar markdown and Fortify plain-text reports
  renderMarkdown(md: string): string {
    return md
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/^### (.+)$/gm, '<h3>$1</h3>')
      .replace(/^## (.+)$/gm,  '<h2>$1</h2>')
      .replace(/^# (.+)$/gm,   '<h1>$1</h1>')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/```(\w*)\n([\s\S]*?)```/gm, '<pre><code class="lang-$1">$2</code></pre>')
      .replace(/^&gt; (.+)$/gm, '<blockquote>$1</blockquote>')
      .replace(/^\|(.+)\|$/gm, (_, row) => {
        const cells = row.split('|').map((c: string) => c.trim());
        if (cells.every((c: string) => /^[-:]+$/.test(c))) return '';
        return '<tr>' + cells.map((c: string) => `<td>${c}</td>`).join('') + '</tr>';
      })
      .replace(/^(={60})$/gm,  '<hr class="report-divider">')
      .replace(/^(-{3,})$/gm,  '<hr>')
      // Fortify report key-value lines: "Key:   value"
      .replace(/^([A-Za-z ]+):\s{2,}(.+)$/gm, '<div class="kv-row"><span class="kv-key">$1</span><span class="kv-val">$2</span></div>')
      .replace(/\n/g, '<br>');
  }

  // Badge label for download button — .md for Sonar, .txt for Fortify
  downloadLabel(item: EscalationItem | null): string {
    return item?.source === 'fortify' ? 'Download .txt' : 'Download .md';
  }

  // Count helper for header badges
  get sonarCount()   { return this.sonarItems().length; }
  get fortifyCount() { return this.fortifyItems().length; }
}