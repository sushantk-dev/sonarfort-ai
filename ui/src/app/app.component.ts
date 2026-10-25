// src/app/app.component.ts
import { Component, Injector, computed, inject } from '@angular/core';
import { takeUntilDestroyed, toSignal } from '@angular/core/rxjs-interop';
import { filter, map } from 'rxjs/operators';
import { NavigationEnd, Router, RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';
import { PipelineStateService } from './core/pipeline-state.service';
import { AuthService } from './core/auth/auth.service';

/** Routes shown full-screen, without the sidebar. */
const BARE_ROUTES = ['/login', '/callback'];

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  templateUrl: './app.component.html',
  styles: [`
    .shell {
      display: flex;
      height: 100vh;
      overflow: hidden;
    }

    /* ── Sidebar ── */
    .sidebar {
      width: var(--sidebar-width);
      flex-shrink: 0;
      background: #1a1a2e;
      display: flex;
      flex-direction: column;
      padding: 0;
    }

    .sidebar__brand {
      display: flex;
      align-items: center;
      gap: 9px;
      padding: 18px 16px 16px;
      border-bottom: 1px solid rgba(255,255,255,0.06);
    }

    .brand-mark {
      width: 28px;
      height: 28px;
      background: var(--brand);
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .brand-name {
      font-size: 14px;
      font-weight: 600;
      color: #fff;
      letter-spacing: -0.2px;
    }

    .brand-ai {
      font-weight: 400;
      opacity: 0.6;
      font-size: 12px;
      letter-spacing: 0.04em;
    }

    /* ── Nav ── */
    .sidebar__nav {
      display: flex;
      flex-direction: column;
      gap: 2px;
      padding: 10px 8px;
      flex: 1;
    }

    .nav-link {
      display: flex;
      align-items: center;
      gap: 9px;
      padding: 8px 10px;
      border-radius: 7px;
      font-size: 13.5px;
      font-weight: 400;
      color: rgba(255,255,255,0.55);
      text-decoration: none;
      transition: background 0.15s, color 0.15s;

      &:hover {
        background: rgba(255,255,255,0.06);
        color: rgba(255,255,255,0.85);
      }

      &.is-active {
        background: rgba(91,95,199,0.22);
        color: #a5a8f5;
        font-weight: 500;
      }
    }

    /* ── Signed-in user ── */
    .sidebar__user {
      display: flex;
      align-items: center;
      gap: 9px;
      padding: 12px 12px 12px 16px;
      border-top: 1px solid rgba(255,255,255,0.06);
    }

    .user-avatar {
      width: 26px;
      height: 26px;
      border-radius: 50%;
      background: rgba(91,95,199,0.35);
      color: #d4d5fb;
      font-size: 11px;
      font-weight: 600;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .user-info {
      display: flex;
      flex-direction: column;
      min-width: 0;
      flex: 1;
    }

    .user-name {
      font-size: 12.5px;
      color: rgba(255,255,255,0.85);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .user-email {
      font-size: 11px;
      color: rgba(255,255,255,0.4);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .logout-btn {
      flex-shrink: 0;
      width: 28px;
      height: 28px;
      border: none;
      border-radius: 6px;
      background: transparent;
      color: rgba(255,255,255,0.45);
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: background 0.15s, color 0.15s;

      &:hover {
        background: rgba(255,255,255,0.08);
        color: #fff;
      }
    }

    /* ── Footer ── */
    .sidebar__footer {
      display: flex;
      align-items: center;
      gap: 7px;
      padding: 12px 16px;
      border-top: 1px solid rgba(255,255,255,0.06);
    }

    .idle-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: rgba(255,255,255,0.2);
    }

    .idle-label {
      font-size: 12px;
      color: rgba(255,255,255,0.3);
    }

    /* ── Main ── */
    .main {
      flex: 1;
      overflow: auto;
      background: var(--surface-1);
    }
  `],
})
export class AppComponent {
  private router   = inject(Router);
  private injector = inject(Injector);
  readonly auth    = inject(AuthService);

  /** Current path, without query string — drives the bare (no-sidebar) layout. */
  private readonly path = toSignal(
    this.router.events.pipe(
      filter((e): e is NavigationEnd => e instanceof NavigationEnd),
      map(e => e.urlAfterRedirects.split('?')[0]),
    ),
    { initialValue: window.location.pathname },
  );

  readonly bareLayout = computed(() => BARE_ROUTES.some(r => this.path().startsWith(r)));
  readonly isAdmin    = computed(() => this.auth.roles().includes('admin'));

  readonly displayName = computed(() => {
    const u = this.auth.user();
    if (!u) return '';
    const full = [u.first_name, u.last_name].filter(Boolean).join(' ');
    return full || u.email || u.id;
  });

  readonly initials = computed(() => {
    const name = this.displayName();
    const parts = name.split(/[\s@.]+/).filter(Boolean);
    return ((parts[0]?.[0] ?? '') + (parts[1]?.[0] ?? '')).toUpperCase() || '?';
  });

  constructor() {
    // PipelineStateService loads runs from the backend as soon as it is
    // created. Only create it once the user is signed in — on /login and
    // /callback there is no token yet, so those calls would just fail with 401.
    // After sign-in, the pages themselves inject it as before.
    if (this.auth.isLoggedIn()) {
      this.injector.get(PipelineStateService);
    }

    // Pipeline jobs live in a singleton service that outlives route changes,
    // so without this the Pipeline/Activity pages would show whatever was
    // fetched last. Re-pull the run list from the servers every time either
    // page is entered (or its nav link is clicked again). The very first
    // navigation is skipped — the service's own startup load covers it.
    let first = true;
    this.router.events
      .pipe(filter((e): e is NavigationEnd => e instanceof NavigationEnd), takeUntilDestroyed())
      .subscribe(e => {
        if (first) { first = false; return; }
        const path = e.urlAfterRedirects.split('?')[0];
        if (path === '/pipeline' || path === '/activity') {
          this.injector.get(PipelineStateService).refreshRuns({ silent: true });
        }
      });
  }

  logout(): void {
    if (confirm('Sign out of SonarFort AI?')) {
      this.auth.logout();
    }
  }
}