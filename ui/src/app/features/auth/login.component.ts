// src/app/features/auth/login.component.ts
// Simple page — no username/password, just redirects to SSO.

import { Component, inject, signal } from '@angular/core';
import { AuthService } from '../../core/auth/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  template: `
    <div class="auth-page">
      <h1>SonarFort AI</h1>
      <p>Sign in with your company account to continue.</p>
      <button class="btn btn--primary" (click)="signIn()" [disabled]="busy()">
        {{ busy() ? 'Redirecting…' : 'Sign in with SSO' }}
      </button>
      @if (error()) { <p class="auth-page__error">{{ error() }}</p> }
    </div>
  `,
  styles: [`
    .auth-page { display:flex; flex-direction:column; align-items:center; gap:16px;
                 margin:15vh auto; max-width:360px; text-align:center; }
    .auth-page__error { color: var(--danger, #c0392b); }
  `],
})
export class LoginComponent {
  private auth = inject(AuthService);
  busy = signal(false);
  error = signal<string | null>(null);

  async signIn() {
    this.busy.set(true);
    try {
      await this.auth.login();
    } catch (e: any) {
      this.error.set(e?.message ?? 'Could not reach SSO');
      this.busy.set(false);
    }
  }
}
