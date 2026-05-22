import { createContext, useContext, useMemo, useState, type ReactNode } from "react";

type AuthTokens = {
  accessToken: string | null;
  refreshToken: string | null;
};

type AuthStore = AuthTokens & {
  isAuthenticated: boolean;
  setTokens: (accessToken?: string | null, refreshToken?: string | null) => void;
  clearTokens: () => void;
};

const AuthContext = createContext<AuthStore | null>(null);

function readToken(key: string) {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(key);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [accessToken, setAccessToken] = useState<string | null>(() => readToken("access_token"));
  const [refreshToken, setRefreshToken] = useState<string | null>(() => readToken("refresh_token"));

  const store = useMemo<AuthStore>(
    () => ({
      accessToken,
      refreshToken,
      isAuthenticated: Boolean(accessToken),
      setTokens(nextAccessToken, nextRefreshToken) {
        if (nextAccessToken) {
          window.localStorage.setItem("access_token", nextAccessToken);
          setAccessToken(nextAccessToken);
        }
        if (nextRefreshToken) {
          window.localStorage.setItem("refresh_token", nextRefreshToken);
          setRefreshToken(nextRefreshToken);
        }
      },
      clearTokens() {
        window.localStorage.removeItem("access_token");
        window.localStorage.removeItem("refresh_token");
        setAccessToken(null);
        setRefreshToken(null);
      },
    }),
    [accessToken, refreshToken],
  );

  return <AuthContext.Provider value={store}>{children}</AuthContext.Provider>;
}

export function useAuthStore() {
  const store = useContext(AuthContext);
  if (!store) {
    throw new Error("useAuthStore must be used inside AuthProvider");
  }
  return store;
}
