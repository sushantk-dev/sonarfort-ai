// src/app/features/settings/settings.component.ts
import { Component, inject, signal, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  SettingsStateService,
  VERTEX_MODELS,
  EMBEDDING_MODELS,
} from '../../core/settings-state.service';

interface Tab { id: string; label: string; icon: string; }

@Component({
  selector: 'app-settings',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './settings.component.html',
  styleUrl:    './settings.component.scss',
})
export class SettingsComponent implements OnInit {
  st = inject(SettingsStateService);
  active = signal('pipeline');

  readonly vertexModels    = VERTEX_MODELS;
  readonly embeddingModels = EMBEDDING_MODELS;

  tabs: Tab[] = [
    { id: 'pipeline', label: 'Pipeline', icon: 'M3 6h18M3 12h18M3 18h18' },
    { id: 'integrations', label: 'Integrations', icon: 'M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71' },
    { id: 'agents',   label: 'Agents',   icon: 'M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z' },
  ];

  ngOnInit() { this.st.load(); }

  get cfg()         { return this.st.cfg(); }
  get tokenStatus() { return this.st.tokenStatus(); }
  get saving()      { return this.st.saving(); }
  get saved()       { return this.st.saved(); }
  get saveErr()     { return this.st.saveErr(); }
  get loadErr()     { return this.st.loadErr(); }

  patch(field: string, value: any) { this.st.patch({ [field]: value } as any); }
  save() { this.st.save(); }

  isEditing(field: string)     { return this.st.isEditing(field); }
  startEditing(field: string)  { this.st.startEditing(field); }
  cancelEditing(field: string) { this.st.cancelEditing(field); }
}