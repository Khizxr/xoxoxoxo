// src/components/LoginForm.jsx
import React, { useState } from "react";
import api from "../api/client";
import "./LoginForm.css";

function LoginForm({ onLoginSuccess }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");
    setSubmitting(true);

    try {
      const response = await api.post("/api/auth/login", {
        email,
        password,
      });

      const { access_token, user } = response.data || {};
      if (access_token && user) {
        try {
          window.localStorage.setItem("access_token", access_token);
        } catch (err) {
          console.warn("Could not store access_token in localStorage", err);
        }
        if (typeof onLoginSuccess === "function") {
          onLoginSuccess({ access_token, user });
        }
      } else {
        setError("Unexpected response from server.");
      }
    } catch (err) {
      console.error("Login failed", err);
      if (err.response && err.response.data && err.response.data.msg) {
        setError(err.response.data.msg);
      } else {
        setError("Login failed. Please check your credentials.");
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="login-shell">
      <div className="login-scanlines" />
      <div className="login-card">
        <h2 className="login-title">DISSOFINITO // ACCESS GATE</h2>
        <p className="login-subtitle">ENTER CREDENTIALS TO INITIATE SCAN PROTOCOL</p>

        <form className="login-form" onSubmit={handleSubmit}>
          <label className="login-label" htmlFor="email">
            USER IDENTIFIER
          </label>
          <input
            id="email"
            type="email"
            className="login-input"
            placeholder="admin@example.com"
            autoComplete="email"
            disabled={submitting}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />

          <label className="login-label" htmlFor="password">
            AUTHORIZATION KEY
          </label>
          <input
            id="password"
            type="password"
            className="login-input"
            placeholder="••••••••"
            autoComplete="current-password"
            disabled={submitting}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />

          {error && <div className="login-error">ERROR // {error}</div>}

          <button className="login-button" type="submit" disabled={submitting}>
            {submitting ? "INITIATING..." : "INITIATE PROTOCOL // LOGIN"}
          </button>
        </form>

        <div className="login-footer">
          <span>SYSTEM STATUS: ONLINE // ZAP LINK READY</span>
        </div>
      </div>
    </div>
  );
}

export default LoginForm;
