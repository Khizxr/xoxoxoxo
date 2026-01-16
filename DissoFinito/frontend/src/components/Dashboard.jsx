// src/components/Dashboard.jsx
import React, { useEffect, useState } from "react";
import api from "../api/client";

function Dashboard({ currentUser, onLogout }) {
  const [scans, setScans] = useState([]);
  const [loadingScans, setLoadingScans] = useState(false);
  const [scanError, setScanError] = useState("");

  const [targetUrl, setTargetUrl] = useState("");
  const [creatingScan, setCreatingScan] = useState(false);

  const [selectedScanId, setSelectedScanId] = useState(null);
  const [findingsBySeverity, setFindingsBySeverity] = useState({
    critical: [],
    high: [],
    medium: [],
    low: [],
  });
  const [loadingFindings, setLoadingFindings] = useState(false);
  const [findingsError, setFindingsError] = useState("");

  const severityOrder = ["critical", "high", "medium", "low"];

  const loadScans = async () => {
    setLoadingScans(true);
    setScanError("");
    try {
      const res = await api.get("/api/scans");
      setScans(res.data || []);
    } catch (err) {
      console.error("Failed to load scans", err);
      setScanError("Failed to load scans.");
    } finally {
      setLoadingScans(false);
    }
  };

  useEffect(() => {
    loadScans();
  }, []);

  const handleStartScan = async (event) => {
    event.preventDefault();
    if (!targetUrl.trim()) {
      return;
    }
    setCreatingScan(true);
    setScanError("");
    try {
      await api.post("/api/scans", { target_url: targetUrl.trim() });
      setTargetUrl("");
      await loadScans();
    } catch (err) {
      console.error("Failed to start scan", err);
      setScanError("Failed to start scan. Check backend or target URL.");
    } finally {
      setCreatingScan(false);
    }
  };

  const loadFindings = async (scanId) => {
    setSelectedScanId(scanId);
    setFindingsError("");
    setLoadingFindings(true);

    try {
      const res = await api.get(`/api/scans/${scanId}/findings`);
      const findings = res.data || [];

      const grouped = {
        critical: [],
        high: [],
        medium: [],
        low: [],
      };

      findings.forEach((f) => {
        const sev = (f.severity || "").toLowerCase();
        if (grouped[sev]) {
          grouped[sev].push(f);
        } else {
          grouped.low.push(f);
        }
      });

      setFindingsBySeverity(grouped);
    } catch (err) {
      console.error("Failed to load findings", err);
      setFindingsError("Failed to load findings for this scan.");
      setFindingsBySeverity({
        critical: [],
        high: [],
        medium: [],
        low: [],
      });
    } finally {
      setLoadingFindings(false);
    }
  };

  const formatDateTime = (value) => {
    if (!value) return "-";
    try {
      const d = new Date(value);
      if (Number.isNaN(d.getTime())) return value;
      return d.toLocaleString();
    } catch {
      return value;
    }
  };

  return (
    <div style={{ fontFamily: "system-ui, -apple-system, BlinkMacSystemFont, sans-serif" }}>
      {/* Top bar */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          gap: "1rem",
          alignItems: "center",
          marginBottom: "1.5rem",
        }}
      >
        <div>
          <div style={{ fontSize: "1.5rem", fontWeight: 600 }}>DissoFinito</div>
          <div style={{ fontSize: "0.85rem", color: "#6b7280" }}>
            AI-Assisted Vulnerability Scanning Platform
          </div>
        </div>
        <div style={{ textAlign: "right", fontSize: "0.85rem" }}>
          <div>{currentUser?.email}</div>
          <div style={{ color: "#6b7280" }}>Role: {currentUser?.role}</div>
          <button
            type="button"
            onClick={onLogout}
            style={{
              marginTop: "0.4rem",
              padding: "0.35rem 0.75rem",
              fontSize: "0.8rem",
              borderRadius: "6px",
              border: "1px solid #ef4444",
              background: "#fee2e2",
              color: "#b91c1c",
              cursor: "pointer",
            }}
          >
            Logout
          </button>
        </div>
      </div>

      {/* Start scan section */}
      <section
        style={{
          marginBottom: "1.5rem",
          padding: "1rem",
          borderRadius: "8px",
          border: "1px solid #e5e7eb",
          background: "#f9fafb",
        }}
      >
        <h2 style={{ fontSize: "1rem", marginBottom: "0.75rem" }}>Start New Scan</h2>
        <form
          onSubmit={handleStartScan}
          style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}
        >
          <input
            type="url"
            placeholder="http://target-app.local"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            required
            style={{
              flex: 1,
              padding: "0.5rem 0.6rem",
              borderRadius: "6px",
              border: "1px solid #d1d5db",
              fontSize: "0.9rem",
            }}
            disabled={creatingScan}
          />
          <button
            type="submit"
            disabled={creatingScan}
            style={{
              padding: "0.5rem 0.9rem",
              borderRadius: "6px",
              border: "1px solid #0ea5e9",
              background: "#0ea5e9",
              color: "white",
              fontSize: "0.9rem",
              cursor: creatingScan ? "default" : "pointer",
            }}
          >
            {creatingScan ? "Starting…" : "Start Scan"}
          </button>
        </form>
        {scanError && (
          <div style={{ marginTop: "0.5rem", color: "#b91c1c", fontSize: "0.85rem" }}>
            {scanError}
          </div>
        )}
      </section>

      {/* Scans table */}
      <section
        style={{
          marginBottom: "1.5rem",
          padding: "1rem",
          borderRadius: "8px",
          border: "1px solid #e5e7eb",
          background: "white",
        }}
      >
        <div
          style={{
            marginBottom: "0.75rem",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <h2 style={{ fontSize: "1rem" }}>Your Scans</h2>
          {loadingScans && (
            <span style={{ fontSize: "0.8rem", color: "#6b7280" }}>Loading scans…</span>
          )}
        </div>

        {scans.length === 0 && !loadingScans ? (
          <div style={{ fontSize: "0.9rem", color: "#6b7280" }}>
            No scans yet. Start one above.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table
              style={{
                width: "100%",
                borderCollapse: "collapse",
                fontSize: "0.85rem",
              }}
            >
              <thead>
                <tr>
                  <th style={thStyle}>ID</th>
                  <th style={thStyle}>Target URL</th>
                  <th style={thStyle}>Status</th>
                  <th style={thStyle}>Risk Score</th>
                  <th style={thStyle}>Risk Band</th>
                  <th style={thStyle}>Started At</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr
                    key={scan.id}
                    onClick={() => loadFindings(scan.id)}
                    style={{
                      cursor: "pointer",
                      backgroundColor:
                        scan.id === selectedScanId ? "#eff6ff" : "transparent",
                    }}
                  >
                    <td style={tdStyle}>{scan.id}</td>
                    <td style={{ ...tdStyle, maxWidth: 280, wordBreak: "break-all" }}>
                      {scan.target_url}
                    </td>
                    <td style={tdStyle}>{scan.status}</td>
                    <td style={tdStyle}>
                      {typeof scan.risk_score === "number"
                        ? scan.risk_score.toFixed(1)
                        : "-"}
                    </td>
                    <td style={tdStyle}>{scan.risk_band || "-"}</td>
                    <td style={tdStyle}>{formatDateTime(scan.started_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Findings section */}
      <section
        style={{
          padding: "1rem",
          borderRadius: "8px",
          border: "1px solid #e5e7eb",
          background: "#f9fafb",
        }}
      >
        <div
          style={{
            marginBottom: "0.75rem",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <h2 style={{ fontSize: "1rem" }}>
            Findings {selectedScanId ? `for Scan #${selectedScanId}` : ""}
          </h2>
          {loadingFindings && (
            <span style={{ fontSize: "0.8rem", color: "#6b7280" }}>Loading findings…</span>
          )}
        </div>

        {findingsError && (
          <div style={{ marginBottom: "0.75rem", color: "#b91c1c", fontSize: "0.85rem" }}>
            {findingsError}
          </div>
        )}

        {!selectedScanId && (
          <div style={{ fontSize: "0.9rem", color: "#6b7280" }}>
            Select a scan above to view findings.
          </div>
        )}

        {selectedScanId && (
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
              gap: "1rem",
            }}
          >
            {severityOrder.map((sev) => {
              const items = findingsBySeverity[sev] || [];
              if (items.length === 0) {
                return (
                  <div
                    key={sev}
                    style={{
                      padding: "0.75rem",
                      borderRadius: "8px",
                      border: "1px dashed #d1d5db",
                      background: "white",
                      minHeight: "80px",
                    }}
                  >
                    <div style={{ fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.5rem" }}>
                      {sev.toUpperCase()} ({items.length})
                    </div>
                    <div style={{ fontSize: "0.8rem", color: "#9ca3af" }}>
                      No findings in this category.
                    </div>
                  </div>
                );
              }

              return (
                <div
                  key={sev}
                  style={{
                    padding: "0.75rem",
                    borderRadius: "8px",
                    border: "1px solid #d1d5db",
                    background: "white",
                    maxHeight: "260px",
                    overflowY: "auto",
                  }}
                >
                  <div style={{ fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.5rem" }}>
                    {sev.toUpperCase()} ({items.length})
                  </div>
                  {items.map((f) => (
                    <div
                      key={f.id}
                      style={{
                        marginBottom: "0.65rem",
                        paddingBottom: "0.5rem",
                        borderBottom: "1px solid #e5e7eb",
                      }}
                    >
                      <div style={{ fontSize: "0.8rem", fontWeight: 600 }}>
                        {f.title} <span style={{ color: "#9ca3af" }}>({f.tool})</span>
                      </div>
                      <div
                        style={{
                          fontSize: "0.8rem",
                          color: "#4b5563",
                          marginTop: "0.15rem",
                          whiteSpace: "pre-wrap",
                        }}
                      >
                        {f.description}
                      </div>
                      {f.url && (
                        <a
                          href={f.url}
                          target="_blank"
                          rel="noreferrer"
                          style={{
                            display: "inline-block",
                            marginTop: "0.2rem",
                            fontSize: "0.78rem",
                            color: "#2563eb",
                          }}
                        >
                          View URL
                        </a>
                      )}
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}

const thStyle = {
  textAlign: "left",
  padding: "0.5rem 0.4rem",
  borderBottom: "1px solid #e5e7eb",
  fontWeight: 600,
  fontSize: "0.8rem",
  color: "#6b7280",
};

const tdStyle = {
  padding: "0.45rem 0.4rem",
  borderBottom: "1px solid #f3f4f6",
  fontSize: "0.8rem",
  color: "#111827",
};

export default Dashboard;
