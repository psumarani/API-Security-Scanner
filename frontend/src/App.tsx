import { lazy, Suspense } from "react";
import { Route, Routes } from "react-router-dom";
import { Layout } from "./components/common/Layout";
import { ProtectedRoute } from "./components/common/ProtectedRoute";
import { LoadingBlock } from "./components/common/States";

// Routes are code-split so the charting library is only downloaded when a chart page opens.
const page = <T extends Record<string, React.ComponentType>>(loader: () => Promise<T>, name: keyof T) =>
  lazy(async () => ({ default: (await loader())[name] }));

const LoginPage = page(() => import("./pages/AuthPages"), "LoginPage");
const RegisterPage = page(() => import("./pages/AuthPages"), "RegisterPage");
const DashboardPage = page(() => import("./pages/DashboardPage"), "DashboardPage");
const TargetsPage = page(() => import("./pages/TargetsPage"), "TargetsPage");
const TargetDetailPage = page(() => import("./pages/TargetDetailPage"), "TargetDetailPage");
const NewScanPage = page(() => import("./pages/NewScanPage"), "NewScanPage");
const ScanHistoryPage = page(() => import("./pages/ScanPages"), "ScanHistoryPage");
const ScanDetailsPage = page(() => import("./pages/ScanPages"), "ScanDetailsPage");
const ScanProgressPage = page(() => import("./pages/ScanPages"), "ScanProgressPage");
const FindingsPage = page(() => import("./pages/FindingPages"), "FindingsPage");
const FindingDetailPage = page(() => import("./pages/FindingPages"), "FindingDetailPage");
const ReportsPage = page(() => import("./pages/MiscPages"), "ReportsPage");
const CoveragePage = page(() => import("./pages/MiscPages"), "CoveragePage");
const SettingsPage = page(() => import("./pages/MiscPages"), "SettingsPage");
const NotFoundPage = page(() => import("./pages/MiscPages"), "NotFoundPage");

export default function App() {
  return (
    <Suspense fallback={<LoadingBlock />}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<Layout />}>
            <Route index element={<DashboardPage />} />
            <Route path="targets" element={<TargetsPage />} />
            <Route path="targets/:id" element={<TargetDetailPage />} />
            <Route path="scans" element={<ScanHistoryPage />} />
            <Route path="scans/new" element={<NewScanPage />} />
            <Route path="scans/:id" element={<ScanDetailsPage />} />
            <Route path="scans/:id/progress" element={<ScanProgressPage />} />
            <Route path="findings" element={<FindingsPage />} />
            <Route path="findings/:id" element={<FindingDetailPage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="coverage" element={<CoveragePage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Route>
      </Routes>
    </Suspense>
  );
}
