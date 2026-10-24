// src/app/features/auth/callback.component.ts
// Handles the redirect from SSO, exchanges the code, then navigates on.

import { Component, OnInit, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';

@Component({
  selector: 'app-callback',
  standalone: true,
  imports: [RouterLink],
  template: `
    <div class="auth-page">
      @if (error()) {
        <p class="auth-page__error">Sign-in failed: {{ error() }}</p>
        <a routerLink="/login">Try again</a>
      } @else {
        <div class="spinner" aria-label="Signing in"></div>
        <p>Signing you in…</p>
      }
    </div>
  `,
  styles: [`
    .auth-page { display:flex; flex-direction:column; align-items:center; gap:16px; margin:20vh auto; }
    .auth-page__error { color: var(--danger, #c0392b); }
    .spinner { width:32px; height:32px; border:3px solid #ccc; border-top-color:#333;
               border-radius:50%; animation: spin 0.8s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
  `],
})
export class CallbackComponent implements OnInit {
  private auth = inject(AuthService);
  error = signal<string | null>(null);

  async ngOnInit() {
    try {
      await this.auth.handleCallback();
    } catch (e: any) {
      this.error.set(e?.message ?? 'Unknown error');
    }
  }
}
