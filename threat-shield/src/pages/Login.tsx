// src/pages/Login.tsx
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const HyperspeedBackground: React.FC = () => {
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden bg-slate-950">
      {/* Radial glow */}
      <div className="absolute inset-0 opacity-60">
        <div className="absolute left-1/2 top-1/2 h-[120vmax] w-[120vmax] -translate-x-1/2 -translate-y-1/2 rounded-full bg-[radial-gradient(circle_at_center,#22c55e_0,rgba(15,23,42,0)_60%)]" />
      </div>

      {/* Hyperspeed streaks */}
      <div className="absolute inset-0 opacity-60 mix-blend-screen">
        {[...Array(18)].map((_, i) => (
          <div
            key={i}
            className="absolute h-[160%] w-px bg-gradient-to-b from-emerald-400/0 via-emerald-400/70 to-emerald-400/0"
            style={{
              left: `${(i / 18) * 100}%`,
              animation: `hyperspeed-line ${3 + (i % 5)}s linear infinite`,
              animationDelay: `${(i % 7) * -0.7}s`,
            }}
          />
        ))}
      </div>

      {/* Soft noise overlay */}
      <div className="absolute inset-0 opacity-[0.15] mix-blend-soft-light bg-[radial-gradient(circle_at_top,_rgba(248,250,252,0.12)_0,_rgba(15,23,42,0)_55%),radial-gradient(circle_at_bottom,_rgba(248,250,252,0.15)_0,_rgba(15,23,42,0)_55%)]" />

      {/* Custom keyframes for hyperspeed lines */}
      <style>{`
        @keyframes hyperspeed-line {
          0% {
            transform: translate3d(0, -100%, 0) scaleY(0.3);
            opacity: 0;
          }
          10% {
            opacity: 1;
          }
          50% {
            transform: translate3d(0, 0%, 0) scaleY(1);
          }
          90% {
            opacity: 1;
          }
          100% {
            transform: translate3d(0, 120%, 0) scaleY(0.3);
            opacity: 0;
          }
        }
      `}</style>
    </div>
  );
};

const Login: React.FC = () => {
  const { login } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);

    try {
      await login(email, password);
      navigate("/home", { replace: true });
    } catch (err: any) {
      console.error("Login error:", err);
      setError(err?.message || "Failed to log in");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="relative min-h-screen flex items-center justify-center bg-slate-950 text-slate-50">
      {/* Hyperspeed background */}
      <HyperspeedBackground />

      {/* Foreground content */}
      <div className="relative z-10 w-full max-w-md">
        <div className="bg-slate-900/80 border border-emerald-500/30 backdrop-blur-xl rounded-2xl p-8 shadow-[0_0_60px_rgba(16,185,129,0.35)]">
          <div className="mb-6 text-center">
            <p className="text-xs uppercase tracking-[0.25em] text-emerald-300/80 mb-2">
              Secure Threat Modeling Console
            </p>
            <h1 className="text-2xl font-semibold">
              Sign in to <span className="text-emerald-400">ThreatShield</span>
            </h1>
          </div>

          {error && (
            <div className="mb-4 rounded-lg bg-red-900/40 border border-red-500/60 px-3 py-2 text-sm">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label
                className="block text-xs font-medium mb-1 text-slate-300"
                htmlFor="email"
              >
                Email
              </label>
              <input
                id="email"
                type="email"
                className="w-full rounded-md border border-slate-600/70 bg-slate-100 px-3 py-2 text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-emerald-400 focus:border-emerald-400/60 placeholder:text-slate-500"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                required
                placeholder="Email"
              />
            </div>

            <div>
              <label
                className="block text-xs font-medium mb-1 text-slate-300"
                htmlFor="password"
              >
                Password
              </label>
              <input
                id="password"
                type="password"
                className="w-full rounded-md border border-slate-600/70 bg-slate-100 px-3 py-2 text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-emerald-400 focus:border-emerald-400/60 placeholder:text-slate-500"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
                placeholder="••••••••"
              />
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="w-full mt-3 rounded-md bg-emerald-500 hover:bg-emerald-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 font-medium py-2.5 transition shadow-lg shadow-emerald-500/30"
            >
              {submitting ? "Signing in..." : "Sign In"}
            </button>
          </form>

          <p className="mt-4 text-[11px] text-slate-400 text-center">
            Access is restricted.
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;
