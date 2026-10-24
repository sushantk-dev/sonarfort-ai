// src/app/core/auth/auth.guards.ts

import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './auth.service';

/** Auth guard: logged in → allow; otherwise remember the URL and go to /login. */
export const authGuard: CanActivateFn = (_route, state) => {
  const auth = inject(AuthService);
  if (auth.isLoggedIn()) return true;
  localStorage.setItem('returnUrl', state.url);
  return inject(Router).createUrlTree(['/login']);
};

/** Role guard (optional): e.g. canActivate: [authGuard, roleGuard('admin')] */
export const roleGuard =
  (...roles: string[]): CanActivateFn =>
  async () => {
    const auth = inject(AuthService);
    const router = inject(Router);
    const user = await auth.ensureUser();
    if (!user) return router.createUrlTree(['/login']);
    return roles.some((r) => user.roles.includes(r)) ? true : router.createUrlTree(['/forbidden']);
  };
