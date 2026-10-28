import axios, { AxiosError } from "axios";
import type { ApiErrorBody } from "../types/api";

const TOKEN_KEY = "ass.token";
let memoryToken: string | null = null;
let storageWarningShown = false;

function warnStorageUnavailable(error: unknown) {
  if (storageWarningShown) return;
  storageWarningShown = true;
  console.warn("Session storage is unavailable; using an in-memory token for this session.", error);
}

// sessionStorage keeps the token for the tab only; it is cleared when the tab is closed.
export const tokenStore = {
  get: (): string | null => {
    try {
      const token = window.sessionStorage.getItem(TOKEN_KEY);
      memoryToken = token?.trim() ? token : null;
      return memoryToken;
    } catch (error) {
      warnStorageUnavailable(error);
      return memoryToken;
    }
  },
  set: (token: string) => {
    memoryToken = token;
    try {
      window.sessionStorage.setItem(TOKEN_KEY, token);
    } catch (error) {
      warnStorageUnavailable(error);
    }
  },
  clear: () => {
    memoryToken = null;
    try {
      window.sessionStorage.removeItem(TOKEN_KEY);
    } catch (error) {
      warnStorageUnavailable(error);
    }
  },
};

let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(handler: (() => void) | null) {
  onUnauthorized = handler;
}

export const api = axios.create({ baseURL: "/api/v1", timeout: 30_000 });

api.interceptors.request.use((config) => {
  const token = tokenStore.get();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error: AxiosError<ApiErrorBody>) => {
    const url = error.config?.url ?? "";
    const isAuthForm = url.endsWith("/auth/login") || url.endsWith("/auth/register");
    if (error.response?.status === 401 && !isAuthForm && tokenStore.get()) {
      tokenStore.clear();
      onUnauthorized?.();
    }
    return Promise.reject(error);
  },
);

/** Turns any thrown value into a message that is safe and useful to show to the user. */
export function errorMessage(error: unknown): string {
  if (axios.isAxiosError<ApiErrorBody>(error)) {
    if (!error.response) return "Cannot reach the server. Check that the backend is running.";
    const body = error.response.data?.error;
    if (body?.details?.length) {
      return body.details.map((d) => (d.field ? `${d.field}: ${d.message}` : d.message)).join("; ");
    }
    if (body?.message) return body.message;
    return `Request failed (HTTP ${error.response.status}).`;
  }
  return error instanceof Error ? error.message : "Something went wrong.";
}
