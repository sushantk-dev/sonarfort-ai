// src/app/app.component.ts
import { Component } from '@angular/core';
import { RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <div class="shell">
      <!-- ── Sidebar ────────────────────────────────────────── -->
      <aside class="sidebar">
        <div class="sidebar__brand">
          <div class="brand-mark">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path d="M7 1L13 4V10L7 13L1 10V4L7 1Z"
                    fill="white" fill-opacity="0.25"
                    stroke="white" stroke-width="1.2" stroke-linejoin="round"/>
              <circle cx="7" cy="7" r="2" fill="white"/>
            </svg>
          </div>
          <span class="brand-name">SonarAI</span>
        </div>

        <nav class="sidebar__nav">
          <a routerLink="/dashboard" routerLinkActive="is-active" class="nav-link">
            <svg width="15" height="15" viewBox="0 0 15 15" fill="none">
              <rect x="1" y="1" width="5.5" height="5.5" rx="1.5" fill="currentColor" opacity=".85"/>
              <rect x="8.5" y="1" width="5.5" height="5.5" rx="1.5" fill="currentColor" opacity=".4"/>
              <rect x="1" y="8.5" width="5.5" height="5.5" rx="1.5" fill="currentColor" opacity=".4"/>
              <rect x="8.5" y="8.5" width="5.5" height="5.5" rx="1.5" fill="currentColor" opacity=".6"/>
            </svg>
            Dashboard
          </a>

          <a routerLink="/pipeline" routerLinkActive="is-active" class="nav-link">
            <svg width="15" height="15" viewBox="0 0 15 15" fill="none">
              <circle cx="7.5" cy="7.5" r="2" stroke="currentColor" stroke-width="1.4"/>
              <path d="M1.5 7.5H5.5M9.5 7.5H13.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
              <path d="M3.5 3.5H5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" opacity=".5"/>
              <path d="M3.5 11.5H5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" opacity=".5"/>
            </svg>
            Pipeline
          </a>

          <a routerLink="/issues" routerLinkActive="is-active" class="nav-link">
            <svg width="15" height="15" viewBox="0 0 15 15" fill="none">
              <rect x="1.5" y="3" width="12" height="1.4" rx=".7" fill="currentColor"/>
              <rect x="1.5" y="7" width="12" height="1.4" rx=".7" fill="currentColor" opacity=".65"/>
              <rect x="1.5" y="11" width="8"  height="1.4" rx=".7" fill="currentColor" opacity=".4"/>
            </svg>
            Issues
          </a>

          <a routerLink="/escalations" routerLinkActive="is-active" class="nav-link">
            <svg width="15" height="15" viewBox="0 0 15 15" fill="none">
              <path d="M7.5 1.5L13 12.5H2L7.5 1.5Z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/>
              <path d="M7.5 5.5V8.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
              <circle cx="7.5" cy="10.5" r=".7" fill="currentColor"/>
            </svg>
            Escalations
          </a>

          <a routerLink="/settings" routerLinkActive="is-active" class="nav-link">
            <svg width="15" height="15" viewBox="0 0 15 15" fill="none">
              <circle cx="7.5" cy="7.5" r="2.2" stroke="currentColor" stroke-width="1.3"/>
              <path d="M7.5 1.5V3M7.5 12V13.5M13.5 7.5H12M3 7.5H1.5M11.7 3.3L10.6 4.4M4.4 10.6L3.3 11.7M11.7 11.7L10.6 10.6M4.4 4.4L3.3 3.3"
                    stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
            </svg>
            Settings
          </a>
        </nav>

        <div class="sidebar__footer">
          <span class="idle-dot"></span>
          <span class="idle-label">Idle</span>
        </div>
      </aside>

      <!-- ── Main ──────────────────────────────────────────── -->
      <main class="main">
        <router-outlet/>
      </main>
    </div>
  `,
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
      font-size: 15px;
      font-weight: 600;
      color: #fff;
      letter-spacing: -0.2px;
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
export class AppComponent {}
