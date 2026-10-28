import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../../hooks/useAuth";
import { LoadingBlock } from "./States";

export function ProtectedRoute() {
  const { user, loading, sessionExpired } = useAuth();
  const location = useLocation();
  if (loading) return <LoadingBlock label="Checking your session" />;
  if (!user) {
    return <Navigate to={`/login${sessionExpired ? "?expired=1" : ""}`} replace state={{ from: location.pathname + location.search }} />;
  }
  return <Outlet />;
}
