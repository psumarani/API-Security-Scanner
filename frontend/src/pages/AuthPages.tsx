import { useState } from "react";
import { useForm } from "react-hook-form";
import { Link, Navigate, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { z } from "zod";
import { Field, describedBy } from "../components/common/Field";
import { ErrorBanner } from "../components/common/States";
import { useAuth } from "../hooks/useAuth";
import { authService } from "../services";
import { errorMessage } from "../services/api";
import { btnPrimary, input, linkClass } from "../utils/ui";
import { zodResolver } from "../utils/zod";

function AuthShell({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-900 p-4">
      <div className="w-full max-w-md rounded-xl bg-white p-8 shadow-xl">
        <p className="text-xs font-semibold uppercase tracking-wider text-emerald-700">API Security Scanner</p>
        <h1 className="mt-1 mb-6 text-2xl font-semibold">{title}</h1>
        {children}
      </div>
    </div>
  );
}

const loginSchema = z.object({
  identifier: z.string().trim().min(1, "Enter your username or email"),
  password: z.string().min(1, "Enter your password"),
});
type LoginValues = z.infer<typeof loginSchema>;

export function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [params] = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<LoginValues>({ resolver: zodResolver(loginSchema) });
  const from = (location.state as { from?: string } | null)?.from ?? "/";

  if (user) return <Navigate to={from} replace />;

  const onSubmit = handleSubmit(async (values) => {
    setError(null);
    try {
      await login(values.identifier, values.password);
      navigate(from, { replace: true });
    } catch (e) {
      setError(errorMessage(e));
    }
  });

  return (
    <AuthShell title="Sign in">
      {params.get("expired") && <div role="status" className="mb-4 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">Your session has expired. Please sign in again.</div>}
      <form onSubmit={onSubmit} noValidate className="space-y-4">
        {error && <ErrorBanner message={error} />}
        <Field id="identifier" label="Username or email" error={errors.identifier?.message}>
          <input id="identifier" autoComplete="username" className={input} aria-invalid={!!errors.identifier} aria-describedby={describedBy("identifier", errors.identifier?.message)} {...register("identifier")} />
        </Field>
        <Field id="password" label="Password" error={errors.password?.message}>
          <input id="password" type="password" autoComplete="current-password" className={input} aria-invalid={!!errors.password} aria-describedby={describedBy("password", errors.password?.message)} {...register("password")} />
        </Field>
        <button className={`${btnPrimary} w-full`} disabled={isSubmitting}>{isSubmitting ? "Signing in…" : "Sign in"}</button>
      </form>
      <p className="mt-6 text-center text-sm text-slate-600">No account? <Link to="/register" className={linkClass}>Create one</Link></p>
    </AuthShell>
  );
}

const registerSchema = z.object({
  username: z.string().trim().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$/, "3–32 characters: letters, digits, '.', '_' or '-'"),
  email: z.string().trim().email("Enter a valid email address"),
  password: z.string()
    .min(12, "Use at least 12 characters")
    .refine((v) => new TextEncoder().encode(v).length <= 72, "Use at most 72 bytes"),
  confirm: z.string(),
}).refine((v) => v.password === v.confirm, { path: ["confirm"], message: "Passwords do not match" });
type RegisterValues = z.infer<typeof registerSchema>;

export function RegisterPage() {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<RegisterValues>({ resolver: zodResolver(registerSchema) });

  const onSubmit = handleSubmit(async ({ username, email, password }) => {
    setError(null);
    try {
      await authService.register({ username, email, password });
      navigate("/login", { replace: true });
    } catch (e) {
      setError(errorMessage(e));
    }
  });

  const field = (name: keyof RegisterValues, label: string, type = "text", auto?: string, hint?: string) => (
    <Field id={name} label={label} error={errors[name]?.message} hint={hint}>
      <input id={name} type={type} autoComplete={auto} className={input} aria-invalid={!!errors[name]} aria-describedby={describedBy(name, errors[name]?.message, hint)} {...register(name)} />
    </Field>
  );

  return (
    <AuthShell title="Create your account">
      <form onSubmit={onSubmit} noValidate className="space-y-4">
        {error && <ErrorBanner message={error} />}
        {field("username", "Username", "text", "username")}
        {field("email", "Email", "email", "email")}
        {field("password", "Password", "password", "new-password", "At least 12 characters.")}
        {field("confirm", "Confirm password", "password", "new-password")}
        <button className={`${btnPrimary} w-full`} disabled={isSubmitting}>{isSubmitting ? "Creating…" : "Create account"}</button>
      </form>
      <p className="mt-6 text-center text-sm text-slate-600">Already registered? <Link to="/login" className={linkClass}>Sign in</Link></p>
    </AuthShell>
  );
}
