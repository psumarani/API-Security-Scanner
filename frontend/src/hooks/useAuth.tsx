import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { setUnauthorizedHandler, tokenStore } from "../services/api";
import { authService } from "../services";
import type { User } from "../types/api";

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (identifier: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  sessionExpired: boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(() => tokenStore.get() !== null);
  const [sessionExpired, setSessionExpired] = useState(false);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUser(null);
      setSessionExpired(true);
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  useEffect(() => {
    if (!tokenStore.get()) return;
    let active = true;
    authService
      .me()
      .then((u) => active && setUser(u))
      .catch(() => tokenStore.clear())
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, []);

  const login = useCallback(async (identifier: string, password: string) => {
    const token = await authService.login({ identifier, password });
    tokenStore.set(token.access_token);
    setSessionExpired(false);
    setUser(await authService.me());
  }, []);

  const logout = useCallback(async () => {
    try {
      await authService.logout();
    } catch {
      /* the token may already be invalid; clearing locally is what matters */
    }
    tokenStore.clear();
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({ user, loading, login, logout, sessionExpired }),
    [user, loading, login, logout, sessionExpired],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
