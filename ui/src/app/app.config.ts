// src/app/app.config.ts
import { ApplicationConfig } from '@angular/core';
import { provideRouter, withRouterConfig } from '@angular/router';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { routes } from './app.routes';
import { installNoCacheFetch, noCacheInterceptor } from './core/no-cache';

// Patch window.fetch before anything (services, components) can call it.
installNoCacheFetch();

export const appConfig: ApplicationConfig = {
  providers: [
    // 'reload' makes clicking the nav link for the page you're already on
    // fire a fresh NavigationEnd — AppComponent uses that to re-fetch runs.
    provideRouter(routes, withRouterConfig({ onSameUrlNavigation: 'reload' })),
    provideHttpClient(withInterceptors([noCacheInterceptor])),
  ],
};