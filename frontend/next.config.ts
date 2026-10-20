import type { NextConfig } from "next";

// Backend address comes from the environment so no host is hardcoded.
// Defaults to the local backend from AGENTS.md.
// DOCKER BUILD ARG: BACKEND_URL is read HERE at BUILD time.
// Next.js resolves rewrites() once during `next build`, so the value must
// be passed as --build-arg BACKEND_URL=... when building the Docker image
// (default http://backend:8000, the future compose service name).
// Changing it at container RUN time alone will NOT change the rewrite.
const backendUrl = process.env.BACKEND_URL ?? "http://127.0.0.1:8000";
const isDev = process.env.NODE_ENV !== "production";

// Basic same-origin-only Content-Security-Policy.
// Things Next.js / React need beyond plain 'self', and why:
// - script-src 'unsafe-inline': App Router streams page data inside inline
//   <script> tags (self.__next_f), so scripts would break without it.
// - script-src 'unsafe-eval' (development only): React dev builds use eval()
//   to rebuild server error stacks in the browser. Production builds do not.
// - style-src 'unsafe-inline': React and Next inject small inline styles.
// - connect-src ws:/wss: (development only): Hot Module Replacement keeps a
//   websocket open to the dev server. Production only talks same-origin.
// - img-src data:: inline images/favicons. object-src 'none' blocks plugins.
const scriptSrc = isDev
  ? "'self' 'unsafe-inline' 'unsafe-eval'"
  : "'self' 'unsafe-inline'";
const connectSrc = isDev ? "'self' ws: wss:" : "'self'";
const csp = [
  "default-src 'self'",
  `script-src ${scriptSrc}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  `connect-src ${connectSrc}`,
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
].join("; ");

const nextConfig: NextConfig = {
  /* config options here */
  // Small production image: `next build` emits a self-contained
  // .next/standalone folder (server.js + minimal node_modules).
  output: "standalone",
  cacheComponents: true,
  partialPrefetching: true,
  async rewrites() {
    // Same-origin /api/* proxy: the browser never talks to the backend
    // directly, so the httpOnly login cookie works without CORS.
    return [
      {
        source: "/api/:path*",
        destination: `${backendUrl}/api/:path*`,
      },
    ];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Content-Security-Policy", value: csp },
        ],
      },
    ];
  },
};

export default nextConfig;
