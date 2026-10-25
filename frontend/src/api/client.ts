export const API = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string | null;
  readonly details: unknown;

  constructor(message: string, status: number, code: string | null = null, details: unknown = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function parseApiError(body: any, status: number): ApiError {
  const detail = body?.detail;
  if (detail && typeof detail === "object" && !Array.isArray(detail)) {
    const code = typeof detail.code === "string" ? detail.code : null;
    const message = typeof detail.message === "string" ? detail.message : `Request failed with HTTP ${status}.`;
    return new ApiError(message, status, code, detail);
  }
  if (typeof detail === "string") {
    return new ApiError(detail, status, null, detail);
  }
  return new ApiError(`Request failed with HTTP ${status}.`, status, null, body);
}

export async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
  token?: string,
): Promise<T> {
  const headers = new Headers(options.headers);

  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const sessionToken =
    token?.trim() ||
    localStorage.getItem("fttw_session_token")?.trim() ||
    sessionStorage.getItem("fttw_session_token")?.trim() ||
    "";

  if (sessionToken) headers.set("Authorization", `Bearer ${sessionToken}`);

  let response: Response;
  try {
    response = await fetch(`${API}${path}`, { ...options, headers });
  } catch (error) {
    throw new ApiError(
      "The application could not reach the server. Check your connection and try again.",
      0,
      "NETWORK_REQUEST_FAILED",
      error,
    );
  }

  let body: any = null;
  try { body = await response.json(); } catch { body = null; }

  if (!response.ok) {
    const error = parseApiError(body, response.status);
    if (typeof window !== "undefined") {
      if (error.status === 403 && error.code === "PERMISSION_DENIED") {
        window.dispatchEvent(new CustomEvent("fttw:permission-denied"));
      }
      if (error.status === 401 && sessionToken && path !== "/auth/login") {
        window.dispatchEvent(new CustomEvent("fttw:session-invalid", {
          detail:{ code:error.code, message:error.message },
        }));
      }
    }
    throw error;
  }
  return body as T;
}

export async function apiDownload(
  path: string,
  options: RequestInit = {},
  token?: string,
): Promise<{ blob: Blob; filename: string | null }> {
  const headers = new Headers(options.headers);
  if (options.body && typeof options.body === "string" && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const sessionToken = token?.trim() || localStorage.getItem("fttw_session_token")?.trim() || sessionStorage.getItem("fttw_session_token")?.trim() || "";
  if (sessionToken) headers.set("Authorization", `Bearer ${sessionToken}`);
  let response: Response;
  try { response = await fetch(`${API}${path}`, { ...options, headers }); }
  catch (error) { throw new ApiError("The application could not reach the server. Check your connection and try again.", 0, "NETWORK_REQUEST_FAILED", error); }
  if (!response.ok) {
    let body: any = null;
    try { body = await response.json(); } catch { body = null; }
    throw parseApiError(body, response.status);
  }
  const disposition = response.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="?([^";]+)"?/i);
  return { blob: await response.blob(), filename: match?.[1] || null };
}

export function saveDownloadedBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
