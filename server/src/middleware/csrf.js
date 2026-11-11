import { doubleCsrf } from 'csrf-csrf';

// Double-submit-cookie CSRF protection.
//
// GET /api/csrf-token hands the client a token in the response body and sets a
// matching httpOnly cookie. On every state-changing request the client must echo
// the token back in the `x-csrf-token` header. The browser attaches the cookie on
// its own, but a forged cross-site form cannot set custom headers, and CORS stops
// the attacker's page from reading the token out of /api/csrf-token. So a forged
// request never has a matching header and is rejected with 403.
const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  // Bind each token to the current session (the auth JWT), so a token issued for
  // one session is useless in another.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    path: '/'
  },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

// Login and register run before a session exists, so there is nothing to bind a
// token to yet. Safe methods (GET/HEAD/OPTIONS) are skipped by csrf-csrf itself.
const EXEMPT_PATHS = ['/api/auth/login', '/api/auth/register'];

export function csrfProtection(req, res, next) {
  if (EXEMPT_PATHS.includes(req.path)) return next();
  return doubleCsrfProtection(req, res, next);
}

// GET /api/csrf-token
export function csrfToken(req, res) {
  res.json({ csrfToken: generateCsrfToken(req, res) });
}
