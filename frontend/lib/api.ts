// Typed wrapper for the ScamShield backend. All calls go to the same
// origin (/api/* is rewritten to the backend), sending the login cookie.
// Server error text is never shown to users; only friendly messages.

export type ScanType = "url" | "message" | "upi";

// Matches backend ScanRequest (type + input, max 2048 chars).
export interface ScanRequest {
  type: ScanType;
  input: string;
}

// Matches backend FindingOut.
export interface Finding {
  rule_code: string;
  severity: number;
  explanation: string;
}

// Matches backend ScanResponse.
export interface ScanResponse {
  scan_id: string;
  type: string;
  risk_score: number;
  verdict: string;
  summary: string;
  findings: Finding[];
  redirect_chain: string[];
  notes: string[];
}

// Matches backend UserOut.
export interface AuthUser {
  id: string;
  email: string;
  role: string;
}

// Matches backend MessageOut.
export interface MessageOut {
  message: string;
}

// Matches backend ScanHistoryOut (created_at arrives as an ISO string).
export interface ScanHistoryItem {
  id: string;
  type: string;
  risk_score: number;
  verdict: string;
  created_at: string;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function friendlyError(status: number, retryAfter: string | null): ApiError {
  if (status === 401) {
    return new ApiError(status, "Please log in first, then try again.");
  }
  if (status === 404) {
    return new ApiError(
      status,
      "Scan not found. It may have been removed, or the link is wrong."
    );
  }
  if (status === 422) {
    return new ApiError(
      status,
      "Please check what you typed and try again."
    );
  }
  if (status === 429) {
    const seconds = retryAfter !== null ? Number.parseInt(retryAfter, 10) : NaN;
    const wait = Number.isFinite(seconds)
      ? ` Please wait ${seconds} seconds and try again.`
      : " Please wait a little while and try again.";
    return new ApiError(status, `Too many checks.${wait}`);
  }
  if (status >= 500) {
    return new ApiError(
      status,
      "Something went wrong on our side. Please try again later."
    );
  }
  return new ApiError(
    status,
    "Something went wrong. Please try again."
  );
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      ...init,
    });
  } catch {
    // Network down, server stopped, etc. No raw error text shown.
    throw new ApiError(
      0,
      "Could not reach the server. Check your connection and try again."
    );
  }
  if (res.ok) {
    return (await res.json()) as T;
  }
  // Never read the error body: it may contain server internals.
  throw friendlyError(res.status, res.headers.get("Retry-After"));
}

export function postScan(req: ScanRequest): Promise<ScanResponse> {
  return apiFetch<ScanResponse>("/api/scan", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export function getScan(id: string): Promise<ScanResponse> {
  return apiFetch<ScanResponse>(`/api/scan/${encodeURIComponent(id)}`);
}

export function getHistory(
  limit = 20,
  offset = 0
): Promise<ScanHistoryItem[]> {
  return apiFetch<ScanHistoryItem[]>(
    `/api/scans?limit=${limit}&offset=${offset}`
  );
}

function qrUploadError(status: number, retryAfter: string | null): ApiError {
  // Backend QR errors are friendly by design; mirror them by status code
  // without reading the response body.
  if (status === 400) {
    return new ApiError(
      status,
      "This file is not a valid image. Please choose a PNG, JPEG or WEBP photo of a QR code."
    );
  }
  if (status === 413) {
    return new ApiError(
      status,
      "The image is too large (max 5 MB). Please choose a smaller file."
    );
  }
  if (status === 422) {
    return new ApiError(
      status,
      "No QR code found in this image. Please try a clearer photo."
    );
  }
  return friendlyError(status, retryAfter);
}

export async function postScanQr(file: File): Promise<ScanResponse> {
  const form = new FormData();
  form.append("file", file);
  let res: Response;
  try {
    // No Content-Type header: the browser sets the multipart boundary.
    res = await fetch("/api/scan/qr", {
      method: "POST",
      credentials: "include",
      body: form,
    });
  } catch {
    throw new ApiError(
      0,
      "Could not reach the server. Check your connection and try again."
    );
  }
  if (res.ok) {
    return (await res.json()) as ScanResponse;
  }
  throw qrUploadError(res.status, res.headers.get("Retry-After"));
}

export interface RegisterRequest {
  email: string;
  password: string;
}

// Shows the backend's generic message exactly as returned.
export function register(req: RegisterRequest): Promise<MessageOut> {
  return apiFetch<MessageOut>("/api/auth/register", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export interface LoginRequest {
  email: string;
  password: string;
}

export function login(req: LoginRequest): Promise<AuthUser> {
  return apiFetch<AuthUser>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export function logout(): Promise<MessageOut> {
  return apiFetch<MessageOut>("/api/auth/logout", { method: "POST" });
}

export function getMe(): Promise<AuthUser> {
  return apiFetch<AuthUser>("/api/auth/me");
}

// --- Community reports ---

export type ScamType =
  | "phishing"
  | "upi_fraud"
  | "fake_kyc"
  | "lottery"
  | "digital_arrest"
  | "other";

export const SCAM_TYPES: { value: ScamType; label: string }[] = [
  { value: "phishing", label: "Fake link or website (phishing)" },
  { value: "upi_fraud", label: "UPI or payment fraud" },
  { value: "fake_kyc", label: "Fake KYC or bank call" },
  { value: "lottery", label: "Lottery or prize scam" },
  { value: "digital_arrest", label: "Digital arrest or police threat" },
  { value: "other", label: "Something else" },
];

// Matches backend ReportCreate (scam_type + content 10-2000 + optional target).
export interface ReportRequest {
  scam_type: ScamType;
  content: string;
  target?: string;
}

// Matches backend ReportCreatedOut.
export interface ReportCreatedOut {
  report_id: string;
  status: string;
  message: string;
}

// POST /api/reports with report-specific friendly errors. The server error
// body is never shown; only local friendly text by status code.
export async function submitReport(req: ReportRequest): Promise<ReportCreatedOut> {
  try {
    return await apiFetch<ReportCreatedOut>("/api/reports", {
      method: "POST",
      body: JSON.stringify(req),
    });
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.status === 422) {
        throw new ApiError(
          e.status,
          "This target cannot be reported. Please check the link, domain or UPI ID and try again."
        );
      }
      if (e.status === 409) {
        throw new ApiError(
          e.status,
          "You have already reported this target recently. Thanks — we will review your earlier report."
        );
      }
    }
    throw e;
  }
}

// --- Campaigns (trending + search) ---

// Matches backend CampaignOut (dates arrive as ISO strings).
export interface CampaignOut {
  title: string;
  scam_type: string;
  report_count: number;
  last_seen: string;
  sample_targets: string[];
}

export function getTrending(): Promise<CampaignOut[]> {
  return apiFetch<CampaignOut[]>("/api/campaigns/trending");
}

export function searchCampaigns(q: string): Promise<CampaignOut[]> {
  return apiFetch<CampaignOut[]>(
    `/api/campaigns/search?q=${encodeURIComponent(q)}`
  );
}

// --- Admin moderation ---

// Matches backend AdminReportOut.
export interface AdminReportOut {
  id: string;
  scam_type: string;
  content: string;
  reported_value_type: string | null;
  reported_value: string | null;
  status: string;
  created_at: string;
}

// Matches backend ReviewOut.
export interface ReviewOut {
  report_id: string;
  status: string;
}

export function listAdminReports(
  status = "pending",
  limit = 20,
  offset = 0
): Promise<AdminReportOut[]> {
  const params = new URLSearchParams({
    status,
    limit: String(limit),
    offset: String(offset),
  });
  return apiFetch<AdminReportOut[]>(`/api/admin/reports?${params.toString()}`);
}

async function reviewReport(
  reportId: string,
  action: "approve" | "reject"
): Promise<ReviewOut> {
  try {
    return await apiFetch<ReviewOut>(
      `/api/admin/reports/${encodeURIComponent(reportId)}/${action}`,
      { method: "POST" }
    );
  } catch (e) {
    if (e instanceof ApiError && e.status === 409) {
      throw new ApiError(
        e.status,
        "This report has already been reviewed by someone else."
      );
    }
    throw e;
  }
}

export function approveReport(reportId: string): Promise<ReviewOut> {
  return reviewReport(reportId, "approve");
}

export function rejectReport(reportId: string): Promise<ReviewOut> {
  return reviewReport(reportId, "reject");
}

// --- Developer API keys ---
//
// Expected backend contract (backend implementation may still be missing;
// every call sends the login cookie and maps errors to friendly text):
//   GET  /api/keys               -> ApiKeyOut[]
//   POST /api/keys {name}        -> ApiKeyCreatedOut (includes full_key once)
//   POST /api/keys/{id}/revoke   -> { message } or { status }
//   GET  /api/keys/{id}/usage    -> ApiKeyUsageOut

export interface ApiKeyOut {
  id: string;
  name: string;
  prefix: string;
  status: string;
  last_used: string | null;
  created_at?: string;
  daily_limit?: number | null;
  limits?: string | null;
}

export interface ApiKeyCreatedOut {
  id: string;
  name: string;
  prefix: string;
  full_key: string;
}

export interface ApiKeyUsageDay {
  date: string;
  count: number;
}

export interface ApiKeyUsageOut {
  days: ApiKeyUsageDay[];
  today_remaining: number | null;
  daily_limit: number | null;
}

export function listApiKeys(): Promise<ApiKeyOut[]> {
  return apiFetch<ApiKeyOut[]>("/api/keys");
}

export function createApiKey(name: string): Promise<ApiKeyCreatedOut> {
  return apiFetch<ApiKeyCreatedOut>("/api/keys", {
    method: "POST",
    body: JSON.stringify({ name }),
  });
}

export function revokeApiKey(id: string): Promise<void> {
  return apiFetch<void>(`/api/keys/${encodeURIComponent(id)}/revoke`, {
    method: "POST",
  });
}

export function getApiKeyUsage(id: string): Promise<ApiKeyUsageOut> {
  return apiFetch<ApiKeyUsageOut>(
    `/api/keys/${encodeURIComponent(id)}/usage`
  );
}
