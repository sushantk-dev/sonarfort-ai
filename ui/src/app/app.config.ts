// src/app/app.config.ts
import { APP_INITIALIZER, ApplicationConfig, inject } from '@angular/core';
import { provideRouter, withRouterConfig } from '@angular/router';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { routes } from './app.routes';
import { installNoCacheFetch, noCacheInterceptor } from './core/no-cache';
import { installAuthFetch } from './core/auth/auth-fetch';
import { authInterceptor } from './core/auth/auth.interceptor';
import { AuthService } from './core/auth/auth.service';

// Patch window.fetch before anything (services, components) can call it.
installNoCacheFetch();
// Adds the SSO Bearer token to the components that call the backend with
// plain fetch() (settings, fortify-scan, summary-report) instead of HttpClient.
installAuthFetch();

export const appConfig: ApplicationConfig = {
  providers: [
    // 'reload' makes clicking the nav link for the page you're already on
    // fire a fresh NavigationEnd — AppComponent uses that to re-fetch runs.
    provideRouter(routes, withRouterConfig({ onSameUrlNavigation: 'reload' })),
    // noCache first, then auth: adds "Authorization: Bearer <token>" to every
    // HttpClient call; on 401 refreshes once and retries.
    provideHttpClient(withInterceptors([noCacheInterceptor, authInterceptor])),
    // On page load, restore the session from localStorage (or refresh it)
    // before the router runs the auth guard.
    {
      provide: APP_INITIALIZER,
      multi: true,
      useFactory: () => {
        const auth = inject(AuthService);
        return () => auth.init();
      },
    },
  ],
};