// src/app/app.routes.ts
import { Routes } from '@angular/router';
import { authGuard, roleGuard } from './core/auth/auth.guards';

export const routes: Routes = [
  // ── Public: SSO login + callback (no guard, shown without the sidebar) ───
  {
    path: 'login',
    loadComponent: () =>
      import('./features/auth/login.component').then(m => m.LoginComponent),
  },
  {
    path: 'callback',
    loadComponent: () =>
      import('./features/auth/callback.component').then(m => m.CallbackComponent),
  },

  // ── Protected: every page below needs a valid SSO session ────────────────
  {
    path: '',
    canActivateChild: [authGuard],
    children: [
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
        path: 'activity',
        loadComponent: () =>
          import('./features/activity/activity.component').then(m => m.ActivityComponent),
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
        canActivate: [roleGuard('admin')],
        loadComponent: () =>
          import('./features/settings/settings.component').then(m => m.SettingsComponent),
      },
      {
        path: 'fortify-scan',
        loadComponent: () =>
          import('./features/fortify-scan/fortify-scan.component').then(m => m.FortifyScanComponent),
      },
    ],
  },

  { path: '**', redirectTo: 'dashboard' },
];