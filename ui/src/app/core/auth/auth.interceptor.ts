// src/app/core/auth/auth.interceptor.ts
// Adds Bearer token; on 401 refreshes once and retries; logs out if refresh fails.

import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, from, switchMap, throwError } from 'rxjs';
import { AuthService, SKIP_REFRESH } from './auth.service';

const PUBLIC_ENDPOINTS = ['/auth/config', '/auth/token', '/auth/refresh', '/health'];

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  if (PUBLIC_ENDPOINTS.some((p) => req.url.includes(p))) return next(req);

  const auth = inject(AuthService);
  const token = auth.token();
  const authReq = token ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }) : req;

  return next(authReq).pipe(
    catchError((err) => {
      const canRetry =
        err instanceof HttpErrorResponse && err.status === 401 && !req.context.get(SKIP_REFRESH);
      if (!canRetry) return throwError(() => err);

      // Refresh once, then retry the original request with the new token.
      // Retried request is marked SKIP_REFRESH so it can never loop.
      return from(auth.refresh()).pipe(
        switchMap((ok) => {
          if (!ok) return throwError(() => err); // refresh() already logged the user out
          return next(
            req.clone({
              setHeaders: { Authorization: `Bearer ${auth.token()}` },
              context: req.context.set(SKIP_REFRESH, true),
            }),
          );
        }),
      );
    }),
  );
};
