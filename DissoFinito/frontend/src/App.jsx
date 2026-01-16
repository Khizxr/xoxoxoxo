// src/App.jsx
import React, { useEffect, useState } from "react";
import api from "./api/client";
import LoginForm from "./components/LoginForm.jsx";
import Dashboard from "./components/Dashboard.jsx";

function App() {
  const [user, setUser] = useState(null); // { id, email, role } | null
  const [loading, setLoading] = useState(true);

  const handleLogout = () => {
    try {
      window.localStorage.removeItem("access_token");
    } catch (err) {
      console.warn("Could not clear access_token from localStorage", err);
    }
    setUser(null);
  };

  // On mount: check for existing token and validate with /api/auth/me
  useEffect(() => {
    const bootstrapAuth = async () => {
      setLoading(true);
      let token = null;
      try {
        token = window.localStorage.getItem("access_token");
      } catch (err) {
        console.warn("Could not read access_token from localStorage", err);
      }

      if (!token) {
        setUser(null);
        setLoading(false);
        return;
      }

      try {
        const res = await api.get("/api/auth/me");
        // backend returns { id, email, role }
        setUser(res.data);
      } catch (err) {
        console.warn("Failed to validate existing token", err);
        try {
          window.localStorage.removeItem("access_token");
        } catch (e) {
          console.warn("Could not clear invalid token", e);
        }
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    bootstrapAuth();
  }, []);

  const handleLoginSuccess = (payload) => {
    // Expect payload: { access_token, user: { id, email, role } }
    const { access_token, user: userInfo } = payload || {};
    if (access_token && userInfo) {
      try {
        window.localStorage.setItem("access_token", access_token);
      } catch (err) {
        console.warn("Could not store access_token in localStorage", err);
      }
      setUser(userInfo);
    }
  };

  if (loading) {
    return (
      <div style={{ padding: "2rem", fontFamily: "system-ui, sans-serif" }}>
        Loading…
      </div>
    );
  }

  if (!user) {
    return (
      <div style={{ padding: "2rem", fontFamily: "system-ui, sans-serif" }}>
        <h1>DissoFinito</h1>
        <LoginForm onLoginSuccess={handleLoginSuccess} />
      </div>
    );
  }

  return (
    <div style={{ padding: "2rem", fontFamily: "system-ui, sans-serif" }}>
      <header
        style={{
          display: "flex",
          justifyContent: "space-between",
          marginBottom: "1rem",
        }}
      >
        <h1>DissoFinito Dashboard</h1>
        <div>
          <span style={{ marginRight: "1rem" }}>
            {user.email} ({user.role})
          </span>
          <button type="button" onClick={handleLogout}>
            Logout
          </button>
        </div>
      </header>
      <Dashboard user={user} onLogout={handleLogout} />
    </div>
  );
}

export default App;
