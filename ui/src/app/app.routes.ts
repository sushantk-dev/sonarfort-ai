// src/app/app.routes.ts
import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  {
    path: 'dashboard',
    loadComponent: () =>
      import('./features/dashboard/dashboard.component').then(m => m.DashboardComponent),
  },
  {
    path: 'pipeline',
    loadComponent: () =>
      import('./features/pipeline/pipeline.component').then(m => m.PipelineComponent),
  },
  {
    path: 'pipeline/summary/:pipelineId',
    loadComponent: () =>
      import('./features/pipeline/summary-report.component').then(m => m.SummaryReportComponent),
  },
  {
    path: 'issues',
    loadComponent: () =>
      import('./features/issues/issues.component').then(m => m.IssuesComponent),
  },
  {
    path: 'escalations',
    loadComponent: () =>
      import('./features/escalations/escalations.component').then(m => m.EscalationsComponent),
  },
  {
    path: 'settings',
    loadComponent: () =>
      import('./features/settings/settings.component').then(m => m.SettingsComponent),
  },
];