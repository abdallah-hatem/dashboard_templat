import { NextResponse } from "next/server";

const VALID_LOCALES = ["en", "ar"];

export function setLangCookie(response: NextResponse, locale: string) {
  if (!VALID_LOCALES.includes(locale)) return response;

  response.cookies.set("lang", locale, {
    path: "/",
    maxAge: 60 * 60 * 24 * 365, // 1 year
  });

  return response;
}

/**
 * Redirects paths missing a locale to the default locale.
 */
export function redirectToDefaultLocale(request: any, defaultLocale = "ar") {
  const pathname = request.nextUrl.pathname;

  // If root or missing locale, redirect
  if (
    pathname === "/" ||
    !VALID_LOCALES.some((locale) => pathname.startsWith(`/${locale}`))
  ) {
    const url = new URL(request.url);
    url.pathname = `/${defaultLocale}${pathname === "/" ? "" : pathname}`;
    let response = NextResponse.redirect(url);
    response = setLangCookie(response, defaultLocale);

    return response;
  }
}

export function addCspHeaders(response: NextResponse) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const isDevelopment = process.env.NODE_ENV === "development";

  const cspHeader = [
    `default-src 'self'`,
    `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com`,
    `font-src 'self' data: https://fonts.googleapis.com https://fonts.gstatic.com`,
    isDevelopment
      ? `script-src 'self' 'unsafe-eval' 'unsafe-inline' 'nonce-${nonce}' `
      : `script-src 'self' 'unsafe-inline' 'nonce-${nonce}' `,
    `connect-src 'self' ${isDevelopment ? " ws: wss:" : ""}`,
    `img-src 'self' `,
    `frame-src 'self' `,
    `frame-ancestors 'none'`,
    `object-src 'none'`,
    `base-uri 'self'`,
    `form-action 'self' `,
    `navigate-to 'self' `,
    ...(isDevelopment ? [] : [`upgrade-insecure-requests`]),
  ].join("; ");

  response.headers.set("Content-Security-Policy", cspHeader);
  response.headers.set("x-nonce", nonce);

  // Additional security headers
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-XSS-Protection", "1; mode=block");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  response.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()",
  );

  return response;
}

/**
 * Checks if the user is authenticated and redirects to login if not.
 * Public routes (auth pages) are excluded from this check.
 */
export function checkAuthentication(request: any) {
  const pathname = request.nextUrl.pathname;

  // Extract locale from pathname (e.g., /en/dashboard -> en)
  const locale = pathname.split("/")[1];

  // Define public routes that don't require authentication
  const publicRoutes = [
    "/login",
    "/reset-password",
    "/verify-login",
    "/register",
  ];

  // Check if current path (without locale) is a public route
  const pathWithoutLocale = pathname.replace(/^\/(en|ar)/, "") || "/";
  const isPublicRoute = publicRoutes.some((route) =>
    pathWithoutLocale.startsWith(route),
  );

  // Check for authentication token in cookies
  const authToken = request.cookies.get(
    process.env.AUTH_TOKEN_KEY || "token",
  )?.value;

  // If user is authenticated and tries to access a public route, redirect to home
  if (authToken && isPublicRoute) {
    const url = new URL(request.url);
    url.pathname = `/${locale}/`; // Redirect to home/dashboard
    return NextResponse.redirect(url);
  }

  // If it's a public route and user is NOT authenticated, allow access
  if (isPublicRoute) {
    return null;
  }

  // If no token and trying to access a protected route, redirect to login
  if (!authToken) {
    const url = new URL(request.url);
    url.pathname = `/${locale}/login`;
    return NextResponse.redirect(url);
  }

  // User is authenticated and on a protected route, allow access
  return null;
}
