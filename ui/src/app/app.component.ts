// src/app/app.component.ts
import { Component, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { filter } from 'rxjs/operators';
import { NavigationEnd, Router, RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';
import { PipelineStateService } from './core/pipeline-state.service';

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
  private pipeline = inject(PipelineStateService);

  constructor() {
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
          this.pipeline.refreshRuns({ silent: true });
        }
      });
  }
}