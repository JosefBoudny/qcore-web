import { useState, useEffect, useRef, useCallback } from "react";

// ═══════════════════════════════════════════════════════════════
// Q-CORE SYSTEMS — Command Center Dashboard
// Post-Quantum Cybersecurity Platform · 55 Modules
// ═══════════════════════════════════════════════════════════════

const API_BASE = "http://localhost:8002";
const WS_URL = "ws://localhost:8002/ws/live";

// ── Module Registry ──────────────────────────────────────────
const MODULE_CATEGORIES = [
  {
    name: "Core Cryptography",
    icon: "🔐",
    color: "#00f0ff",
    modules: ["Q-SHIELD","Q-VAULT","Q-GATE","Q-HSM","Q-CYCLE","Q-LICENSE","Q-CORE","Q-ENTROPY","Q-HARDEN"],
  },
  {
    name: "Scanning & Compliance",
    icon: "🔍",
    color: "#a855f7",
    modules: ["Q-SCANNER","Q-CRA","Q-POLICY","Q-TRACE","Q-VEX","Q-CBOM","Q-PHANTOM","Q-FORMAL"],
  },
  {
    name: "AI Security",
    icon: "🤖",
    color: "#f43f5e",
    modules: ["Q-GUARD","Q-PROX","Q-MEMEX","Q-WATERMARK","Q-INFERENCE","Q-DISTRIB","Q-NEURAL"],
  },
  {
    name: "Advanced Cryptography",
    icon: "🧬",
    color: "#22d3ee",
    modules: ["Q-ZKP","Q-FHE","Q-SMPC","Q-TUNNEL","Q-DRIVER"],
  },
  {
    name: "Network Defense",
    icon: "🛡️",
    color: "#facc15",
    modules: ["Q-SENTRY","Q-COVERT","Q-MESH","Q-DECEPTION"],
  },
  {
    name: "Forensic Analysis",
    icon: "🔬",
    color: "#fb923c",
    modules: ["Q-AUDIT","Q-SIGN","Q-FORENSICS","Q-CHAIN"],
  },
  {
    name: "Security Operations",
    icon: "⚙️",
    color: "#4ade80",
    modules: ["Q-AUTOPILOT","Q-HEAL","Q-TWIN","Q-THREAT","Q-SIEM","Q-IDENTITY","Q-DID"],
  },
  {
    name: "Governance & Privacy",
    icon: "📜",
    color: "#c084fc",
    modules: ["Q-OBLIVION","Q-CONFID","Q-SOVEREIGN","Q-INSIGHT","Q-MIGRATE","Q-RECOVER","Q-WORKSHOP"],
  },
  {
    name: "Extended",
    icon: "➕",
    color: "#94a3b8",
    modules: ["Q-SCANNER-v2.1","Q-AUDIT-SIGN","Q-ACADEMY-BRIDGE"],
  },
];

const AUTOPILOT_WORKFLOWS = [
  { id: "full_scan", name: "Full Scan", icon: "🔎", desc: "Complete platform security assessment" },
  { id: "incident_response", name: "Incident Response", icon: "🚨", desc: "Automated threat containment & analysis" },
  { id: "compliance_audit", name: "Compliance Audit", icon: "📋", desc: "CRA / NIS2 / ISO 27001 audit pipeline" },
  { id: "pqc_migration", name: "PQC Migration", icon: "🧬", desc: "Post-quantum cryptography transition" },
];

// ── Utility Hooks ────────────────────────────────────────────
function useApi() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const call = useCallback(async (endpoint, options = {}) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}${endpoint}`, {
        headers: { "Content-Type": "application/json" },
        ...options,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      return data;
    } catch (e) {
      setError(e.message);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  return { call, loading, error };
}

function useWebSocket(url) {
  const [messages, setMessages] = useState([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);
  const reconnectTimer = useRef(null);

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        reconnectTimer.current = setTimeout(connect, 3000);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          setMessages((prev) => [data, ...prev].slice(0, 200));
        } catch {
          setMessages((prev) => [{ type: "raw", text: e.data, ts: Date.now() }, ...prev].slice(0, 200));
        }
      };
    } catch {
      setConnected(false);
    }
  }, [url]);

  useEffect(() => {
    connect();
    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    };
  }, [connect]);

  return { messages, connected };
}

// ── Sub-components ───────────────────────────────────────────

function StatusDot({ active, color = "#4ade80" }) {
  return (
    <span
      style={{
        display: "inline-block",
        width: 8,
        height: 8,
        borderRadius: "50%",
        background: active ? color : "#475569",
        boxShadow: active ? `0 0 6px ${color}` : "none",
        marginRight: 6,
        transition: "all 0.3s",
      }}
    />
  );
}

function GlassCard({ children, style = {}, onClick, hoverable = false }) {
  const [hovered, setHovered] = useState(false);
  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: hovered && hoverable
          ? "rgba(255,255,255,0.07)"
          : "rgba(255,255,255,0.03)",
        border: "1px solid rgba(255,255,255,0.08)",
        borderRadius: 12,
        padding: 20,
        transition: "all 0.25s ease",
        cursor: onClick ? "pointer" : "default",
        transform: hovered && hoverable ? "translateY(-2px)" : "none",
        boxShadow: hovered && hoverable
          ? "0 8px 32px rgba(0,0,0,0.3)"
          : "0 2px 8px rgba(0,0,0,0.1)",
        ...style,
      }}
    >
      {children}
    </div>
  );
}

function ModuleChip({ name, color, onRun, onDemo, isRunning }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div style={{ position: "relative", display: "inline-block" }}>
      <button
        onClick={() => setExpanded(!expanded)}
        style={{
          background: isRunning
            ? `${color}22`
            : "rgba(255,255,255,0.04)",
          border: `1px solid ${isRunning ? color : "rgba(255,255,255,0.1)"}`,
          borderRadius: 8,
          padding: "6px 12px",
          color: isRunning ? color : "#cbd5e1",
          fontSize: 12,
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          cursor: "pointer",
          transition: "all 0.2s",
          whiteSpace: "nowrap",
        }}
      >
        {isRunning && (
          <span style={{ marginRight: 4, animation: "qcorePulse 1s infinite" }}>●</span>
        )}
        {name}
      </button>
      {expanded && (
        <div
          style={{
            position: "absolute",
            top: "100%",
            left: 0,
            marginTop: 4,
            background: "#1a1f2e",
            border: "1px solid rgba(255,255,255,0.12)",
            borderRadius: 8,
            padding: 6,
            zIndex: 100,
            display: "flex",
            gap: 4,
            boxShadow: "0 8px 24px rgba(0,0,0,0.5)",
          }}
        >
          <button
            onClick={(e) => { e.stopPropagation(); onRun(name); setExpanded(false); }}
            style={{
              background: `${color}22`,
              border: `1px solid ${color}`,
              borderRadius: 6,
              padding: "4px 10px",
              color: color,
              fontSize: 11,
              cursor: "pointer",
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            ▶ Run
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); onDemo(name); setExpanded(false); }}
            style={{
              background: "rgba(255,255,255,0.05)",
              border: "1px solid rgba(255,255,255,0.15)",
              borderRadius: 6,
              padding: "4px 10px",
              color: "#94a3b8",
              fontSize: 11,
              cursor: "pointer",
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            ◉ Demo
          </button>
        </div>
      )}
    </div>
  );
}

function LiveFeed({ messages, connected }) {
  const feedRef = useRef(null);

  const typeColors = {
    result: "#4ade80",
    error: "#f43f5e",
    warning: "#facc15",
    info: "#00f0ff",
    event: "#a855f7",
    raw: "#94a3b8",
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        marginBottom: 12,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 14 }}>📡</span>
          <span style={{ color: "#e2e8f0", fontSize: 13, fontWeight: 600 }}>Live Feed</span>
        </div>
        <div style={{
          display: "flex", alignItems: "center", gap: 6,
          background: connected ? "rgba(74,222,128,0.1)" : "rgba(244,63,94,0.1)",
          border: `1px solid ${connected ? "#4ade8844" : "#f43f5e44"}`,
          borderRadius: 20,
          padding: "3px 10px",
        }}>
          <StatusDot active={connected} color={connected ? "#4ade80" : "#f43f5e"} />
          <span style={{
            color: connected ? "#4ade80" : "#f43f5e",
            fontSize: 11,
            fontFamily: "'JetBrains Mono', monospace",
          }}>
            {connected ? "CONNECTED" : "RECONNECTING"}
          </span>
        </div>
      </div>
      <div
        ref={feedRef}
        style={{
          flex: 1,
          overflowY: "auto",
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontSize: 11,
          lineHeight: 1.6,
          padding: 12,
          background: "rgba(0,0,0,0.3)",
          borderRadius: 8,
          border: "1px solid rgba(255,255,255,0.05)",
        }}
      >
        {messages.length === 0 ? (
          <div style={{ color: "#475569", textAlign: "center", padding: 40 }}>
            Waiting for events...
          </div>
        ) : (
          messages.map((msg, i) => (
            <div key={i} style={{
              padding: "4px 0",
              borderBottom: "1px solid rgba(255,255,255,0.03)",
              animation: i === 0 ? "qcoreSlideIn 0.3s ease" : "none",
            }}>
              <span style={{ color: "#475569" }}>
                {new Date(msg.ts || msg.timestamp || Date.now()).toLocaleTimeString()}
              </span>
              {" "}
              <span style={{
                color: typeColors[msg.type] || "#94a3b8",
                fontWeight: 600,
              }}>
                [{(msg.type || "info").toUpperCase()}]
              </span>
              {" "}
              <span style={{ color: "#cbd5e1" }}>
                {msg.module && <span style={{ color: "#00f0ff" }}>{msg.module} → </span>}
                {msg.message || msg.text || JSON.stringify(msg)}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function QueuePanel({ api }) {
  const [queue, setQueue] = useState([]);
  const [queueInput, setQueueInput] = useState("");

  const refreshQueue = async () => {
    // In production this would call the queue status endpoint
    // For now we show a placeholder
  };

  const addToQueue = async () => {
    if (!queueInput.trim()) return;
    const moduleId = queueInput.trim().toLowerCase().replace("q-", "").replace(/ /g, "-");
    const result = await api.call("/queue/add", {
      method: "POST",
      body: JSON.stringify({ module_id: moduleId }),
    });
    if (result) {
      setQueue((prev) => [
        { id: result.task_id || Date.now(), module: queueInput, status: "queued" },
        ...prev,
      ]);
      setQueueInput("");
    }
  };

  const statusColors = {
    queued: "#facc15",
    running: "#00f0ff",
    done: "#4ade80",
    error: "#f43f5e",
  };

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <input
          value={queueInput}
          onChange={(e) => setQueueInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && addToQueue()}
          placeholder="Module name, e.g. Q-SCANNER"
          style={{
            flex: 1,
            background: "rgba(0,0,0,0.3)",
            border: "1px solid rgba(255,255,255,0.1)",
            borderRadius: 8,
            padding: "8px 12px",
            color: "#e2e8f0",
            fontSize: 12,
            fontFamily: "'JetBrains Mono', monospace",
            outline: "none",
          }}
        />
        <button
          onClick={addToQueue}
          disabled={api.loading}
          style={{
            background: "rgba(0,240,255,0.12)",
            border: "1px solid #00f0ff44",
            borderRadius: 8,
            padding: "8px 16px",
            color: "#00f0ff",
            fontSize: 12,
            fontFamily: "'JetBrains Mono', monospace",
            cursor: "pointer",
          }}
        >
          + Add
        </button>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {queue.length === 0 && (
          <div style={{ color: "#475569", fontSize: 12, textAlign: "center", padding: 20 }}>
            Queue is empty. Add modules to scan.
          </div>
        )}
        {queue.map((item) => (
          <div
            key={item.id}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              background: "rgba(0,0,0,0.2)",
              borderRadius: 8,
              padding: "8px 12px",
              border: `1px solid ${statusColors[item.status]}33`,
            }}
          >
            <span style={{
              color: "#e2e8f0",
              fontSize: 12,
              fontFamily: "'JetBrains Mono', monospace",
            }}>
              {item.module}
            </span>
            <span style={{
              color: statusColors[item.status],
              fontSize: 10,
              fontFamily: "'JetBrains Mono', monospace",
              textTransform: "uppercase",
              background: `${statusColors[item.status]}15`,
              padding: "2px 8px",
              borderRadius: 4,
            }}>
              {item.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function AutopilotPanel({ api, onEvent }) {
  const [running, setRunning] = useState(null);
  const [log, setLog] = useState([]);

  const runWorkflow = async (workflow) => {
    setRunning(workflow.id);
    setLog((prev) => [
      { ts: Date.now(), text: `Starting ${workflow.name}...`, type: "info" },
      ...prev,
    ]);

    const result = await api.call("/autopilot/run", {
      method: "POST",
      body: JSON.stringify({ workflow: workflow.id }),
    });

    if (result) {
      setLog((prev) => [
        { ts: Date.now(), text: `${workflow.name} completed`, type: "result" },
        ...prev,
      ]);
      if (onEvent) onEvent({ type: "autopilot_done", workflow: workflow.id, result });
    } else {
      setLog((prev) => [
        { ts: Date.now(), text: `${workflow.name} failed: ${api.error}`, type: "error" },
        ...prev,
      ]);
    }
    setRunning(null);
  };

  return (
    <div>
      <div style={{
        display: "grid",
        gridTemplateColumns: "1fr 1fr",
        gap: 10,
        marginBottom: 16,
      }}>
        {AUTOPILOT_WORKFLOWS.map((wf) => (
          <button
            key={wf.id}
            onClick={() => runWorkflow(wf)}
            disabled={running !== null}
            style={{
              background: running === wf.id
                ? "rgba(74,222,128,0.15)"
                : "rgba(255,255,255,0.03)",
              border: running === wf.id
                ? "1px solid #4ade8066"
                : "1px solid rgba(255,255,255,0.08)",
              borderRadius: 10,
              padding: 14,
              cursor: running ? "wait" : "pointer",
              textAlign: "left",
              transition: "all 0.2s",
            }}
          >
            <div style={{ fontSize: 20, marginBottom: 6 }}>{wf.icon}</div>
            <div style={{
              color: "#e2e8f0",
              fontSize: 13,
              fontWeight: 600,
              marginBottom: 4,
            }}>
              {wf.name}
            </div>
            <div style={{ color: "#64748b", fontSize: 11, lineHeight: 1.4 }}>
              {wf.desc}
            </div>
            {running === wf.id && (
              <div style={{
                marginTop: 8,
                color: "#4ade80",
                fontSize: 11,
                fontFamily: "'JetBrains Mono', monospace",
                animation: "qcorePulse 1s infinite",
              }}>
                ● RUNNING...
              </div>
            )}
          </button>
        ))}
      </div>
      {log.length > 0 && (
        <div style={{
          background: "rgba(0,0,0,0.3)",
          borderRadius: 8,
          padding: 12,
          maxHeight: 160,
          overflowY: "auto",
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11,
        }}>
          {log.map((entry, i) => (
            <div key={i} style={{
              color: entry.type === "error" ? "#f43f5e"
                : entry.type === "result" ? "#4ade80"
                : "#94a3b8",
              padding: "2px 0",
            }}>
              <span style={{ color: "#475569" }}>
                {new Date(entry.ts).toLocaleTimeString()}
              </span>
              {" "}{entry.text}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function CacheStats({ api }) {
  const [stats, setStats] = useState(null);

  const loadStats = async () => {
    const data = await api.call("/cache/stats");
    if (data) setStats(data);
  };

  const clearCache = async () => {
    await api.call("/cache/clear", { method: "POST" });
    loadStats();
  };

  useEffect(() => {
    loadStats();
    const interval = setInterval(loadStats, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div>
      {stats ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
            {[
              { label: "Cached", value: stats.cached_results ?? stats.keys ?? "—", color: "#00f0ff" },
              { label: "Hit Rate", value: stats.hit_rate ? `${(stats.hit_rate * 100).toFixed(0)}%` : "—", color: "#4ade80" },
              { label: "Memory", value: stats.memory_used ?? stats.memory ?? "—", color: "#a855f7" },
            ].map((s) => (
              <div key={s.label} style={{
                background: "rgba(0,0,0,0.2)",
                borderRadius: 8,
                padding: 12,
                textAlign: "center",
              }}>
                <div style={{
                  color: s.color,
                  fontSize: 22,
                  fontWeight: 700,
                  fontFamily: "'JetBrains Mono', monospace",
                }}>
                  {s.value}
                </div>
                <div style={{ color: "#64748b", fontSize: 10, marginTop: 4 }}>{s.label}</div>
              </div>
            ))}
          </div>
          <button
            onClick={clearCache}
            style={{
              background: "rgba(244,63,94,0.1)",
              border: "1px solid #f43f5e33",
              borderRadius: 8,
              padding: "8px 16px",
              color: "#f43f5e",
              fontSize: 11,
              fontFamily: "'JetBrains Mono', monospace",
              cursor: "pointer",
              alignSelf: "flex-start",
            }}
          >
            🗑 Clear Cache
          </button>
        </div>
      ) : (
        <div style={{ color: "#475569", fontSize: 12, textAlign: "center", padding: 20 }}>
          Loading cache stats...
        </div>
      )}
    </div>
  );
}

function HealthIndicator({ api }) {
  const [health, setHealth] = useState(null);

  useEffect(() => {
    const check = async () => {
      const data = await api.call("/health");
      setHealth(data);
    };
    check();
    const interval = setInterval(check, 10000);
    return () => clearInterval(interval);
  }, []);

  const isOk = health && (health.status === "ok" || health.status === "healthy" || health.api === "ok");

  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 8,
      background: isOk ? "rgba(74,222,128,0.08)" : "rgba(244,63,94,0.08)",
      border: `1px solid ${isOk ? "#4ade8033" : "#f43f5e33"}`,
      borderRadius: 20,
      padding: "6px 14px",
    }}>
      <StatusDot active={isOk} color={isOk ? "#4ade80" : "#f43f5e"} />
      <span style={{
        color: isOk ? "#4ade80" : "#f43f5e",
        fontSize: 11,
        fontFamily: "'JetBrains Mono', monospace",
        fontWeight: 600,
      }}>
        API {isOk ? "ONLINE" : health ? "DEGRADED" : "CHECKING"}
      </span>
      {health?.modules_count && (
        <span style={{ color: "#64748b", fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}>
          · {health.modules_count} modules
        </span>
      )}
      {health?.version && (
        <span style={{ color: "#64748b", fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}>
          · v{health.version}
        </span>
      )}
      {health?.redis === "ok" && (
        <span style={{ color: "#4ade80", fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}>
          · Redis OK
        </span>
      )}
    </div>
  );
}

// ── Result Modal ─────────────────────────────────────────────
function ResultModal({ result, onClose }) {
  if (!result) return null;
  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.7)",
        backdropFilter: "blur(8px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
        animation: "qcoreFadeIn 0.2s ease",
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: "#111827",
          border: "1px solid rgba(255,255,255,0.1)",
          borderRadius: 16,
          padding: 24,
          maxWidth: 700,
          width: "90%",
          maxHeight: "80vh",
          overflowY: "auto",
        }}
      >
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 16,
        }}>
          <h3 style={{
            margin: 0,
            color: "#00f0ff",
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 16,
          }}>
            {result.module || "Result"}
          </h3>
          <button
            onClick={onClose}
            style={{
              background: "rgba(255,255,255,0.05)",
              border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: 8,
              padding: "4px 12px",
              color: "#94a3b8",
              cursor: "pointer",
              fontSize: 14,
            }}
          >
            ✕
          </button>
        </div>
        <pre style={{
          background: "rgba(0,0,0,0.4)",
          borderRadius: 10,
          padding: 16,
          color: "#e2e8f0",
          fontSize: 12,
          fontFamily: "'JetBrains Mono', monospace",
          lineHeight: 1.6,
          overflowX: "auto",
          whiteSpace: "pre-wrap",
          margin: 0,
        }}>
          {typeof result.data === "string" ? result.data : JSON.stringify(result.data, null, 2)}
        </pre>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// MAIN DASHBOARD
// ═══════════════════════════════════════════════════════════════
export default function QCoreDashboard() {
  const api = useApi();
  const { messages: wsMessages, connected: wsConnected } = useWebSocket(WS_URL);

  const [activeTab, setActiveTab] = useState("modules");
  const [runningModules, setRunningModules] = useState(new Set());
  const [result, setResult] = useState(null);
  const [demoAllRunning, setDemoAllRunning] = useState(false);

  // ── Module actions ──
  const runModule = async (name) => {
    const moduleId = name.toLowerCase().replace("q-", "").replace(/ /g, "-");
    setRunningModules((prev) => new Set([...prev, name]));
    const data = await api.call(`/module/${moduleId}/run`, { method: "POST" });
    setRunningModules((prev) => {
      const next = new Set(prev);
      next.delete(name);
      return next;
    });
    if (data) setResult({ module: name, data });
  };

  const demoModule = async (name) => {
    const moduleId = name.toLowerCase().replace("q-", "").replace(/ /g, "-");
    setRunningModules((prev) => new Set([...prev, name]));
    const data = await api.call(`/module/${moduleId}/demo`);
    setRunningModules((prev) => {
      const next = new Set(prev);
      next.delete(name);
      return next;
    });
    if (data) setResult({ module: `${name} (Demo)`, data });
  };

  const demoAll = async () => {
    setDemoAllRunning(true);
    const data = await api.call("/batch/demo-all", { method: "POST" });
    setDemoAllRunning(false);
    if (data) setResult({ module: "Batch Demo All", data });
  };

  // ── Tabs config ──
  const tabs = [
    { id: "modules", label: "Modules", icon: "⬡" },
    { id: "autopilot", label: "Q-AUTOPILOT", icon: "🤖" },
    { id: "queue", label: "Queue", icon: "📋" },
    { id: "cache", label: "Cache", icon: "💾" },
  ];

  return (
    <div style={{
      minHeight: "100vh",
      background: "#0a0e1a",
      color: "#e2e8f0",
      fontFamily: "'Inter', 'Segoe UI', sans-serif",
      position: "relative",
      overflow: "hidden",
    }}>
      {/* CSS Animations */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Outfit:wght@400;600;700;800&display=swap');
        
        @keyframes qcorePulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
        @keyframes qcoreSlideIn {
          from { opacity: 0; transform: translateY(-8px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes qcoreFadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        @keyframes qcoreGlow {
          0%, 100% { opacity: 0.3; }
          50% { opacity: 0.6; }
        }
        @keyframes qcoreScanline {
          0% { transform: translateY(-100%); }
          100% { transform: translateY(100vh); }
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #334155; }
      `}</style>

      {/* Background effects */}
      <div style={{
        position: "fixed",
        inset: 0,
        background: "radial-gradient(ellipse at 20% 50%, rgba(0,240,255,0.04) 0%, transparent 50%), radial-gradient(ellipse at 80% 20%, rgba(168,85,247,0.04) 0%, transparent 50%), radial-gradient(ellipse at 50% 80%, rgba(74,222,128,0.03) 0%, transparent 50%)",
        pointerEvents: "none",
        zIndex: 0,
      }} />

      {/* Grid overlay */}
      <div style={{
        position: "fixed",
        inset: 0,
        backgroundImage: `
          linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px),
          linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px)
        `,
        backgroundSize: "60px 60px",
        pointerEvents: "none",
        zIndex: 0,
      }} />

      {/* ═══ HEADER ═══ */}
      <header style={{
        position: "relative",
        zIndex: 10,
        borderBottom: "1px solid rgba(255,255,255,0.06)",
        padding: "16px 32px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        background: "rgba(10,14,26,0.8)",
        backdropFilter: "blur(20px)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          {/* Logo mark */}
          <div style={{
            width: 40,
            height: 40,
            borderRadius: 10,
            background: "linear-gradient(135deg, #00f0ff22, #a855f722)",
            border: "1px solid rgba(0,240,255,0.3)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 18,
            fontWeight: 800,
            fontFamily: "'Outfit', sans-serif",
            color: "#00f0ff",
          }}>
            Q
          </div>
          <div>
            <h1 style={{
              margin: 0,
              fontSize: 20,
              fontWeight: 800,
              fontFamily: "'Outfit', sans-serif",
              letterSpacing: "-0.02em",
              background: "linear-gradient(135deg, #00f0ff, #a855f7)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
            }}>
              Q-CORE SYSTEMS
            </h1>
            <p style={{
              margin: 0,
              fontSize: 11,
              color: "#64748b",
              fontFamily: "'JetBrains Mono', monospace",
              letterSpacing: "0.05em",
            }}>
              POST-QUANTUM CYBERSECURITY PLATFORM · 55 MODULES
            </p>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <HealthIndicator api={api} />
          <button
            onClick={demoAll}
            disabled={demoAllRunning}
            style={{
              background: demoAllRunning
                ? "rgba(168,85,247,0.2)"
                : "linear-gradient(135deg, rgba(0,240,255,0.15), rgba(168,85,247,0.15))",
              border: "1px solid rgba(0,240,255,0.3)",
              borderRadius: 10,
              padding: "8px 18px",
              color: "#e2e8f0",
              fontSize: 12,
              fontFamily: "'JetBrains Mono', monospace",
              fontWeight: 600,
              cursor: demoAllRunning ? "wait" : "pointer",
              transition: "all 0.2s",
            }}
          >
            {demoAllRunning ? "⏳ Running all..." : "▶ Demo All 55"}
          </button>
        </div>
      </header>

      {/* ═══ MAIN LAYOUT ═══ */}
      <div style={{
        position: "relative",
        zIndex: 10,
        display: "grid",
        gridTemplateColumns: "1fr 380px",
        gap: 0,
        height: "calc(100vh - 73px)",
      }}>
        {/* LEFT — Main Content */}
        <div style={{
          padding: 24,
          overflowY: "auto",
          borderRight: "1px solid rgba(255,255,255,0.06)",
        }}>
          {/* Tab Navigation */}
          <div style={{
            display: "flex",
            gap: 4,
            marginBottom: 24,
            background: "rgba(255,255,255,0.03)",
            borderRadius: 12,
            padding: 4,
            width: "fit-content",
          }}>
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  background: activeTab === tab.id
                    ? "rgba(0,240,255,0.12)"
                    : "transparent",
                  border: activeTab === tab.id
                    ? "1px solid rgba(0,240,255,0.25)"
                    : "1px solid transparent",
                  borderRadius: 8,
                  padding: "8px 18px",
                  color: activeTab === tab.id ? "#00f0ff" : "#64748b",
                  fontSize: 13,
                  fontWeight: 600,
                  cursor: "pointer",
                  transition: "all 0.2s",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <span style={{ fontSize: 14 }}>{tab.icon}</span>
                {tab.label}
              </button>
            ))}
          </div>

          {/* ── MODULES TAB ── */}
          {activeTab === "modules" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
              {/* Stats bar */}
              <div style={{
                display: "flex",
                gap: 16,
                flexWrap: "wrap",
              }}>
                {[
                  { label: "Total Modules", value: "55", color: "#00f0ff" },
                  { label: "Categories", value: MODULE_CATEGORIES.length.toString(), color: "#a855f7" },
                  { label: "Running", value: runningModules.size.toString(), color: "#4ade80" },
                  { label: "Workflows", value: "4", color: "#facc15" },
                ].map((stat) => (
                  <div key={stat.label} style={{
                    background: "rgba(255,255,255,0.03)",
                    border: "1px solid rgba(255,255,255,0.06)",
                    borderRadius: 10,
                    padding: "12px 20px",
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                  }}>
                    <span style={{
                      color: stat.color,
                      fontSize: 24,
                      fontWeight: 700,
                      fontFamily: "'JetBrains Mono', monospace",
                    }}>
                      {stat.value}
                    </span>
                    <span style={{ color: "#64748b", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.05em" }}>
                      {stat.label}
                    </span>
                  </div>
                ))}
              </div>

              {/* Category cards */}
              {MODULE_CATEGORIES.map((cat) => (
                <GlassCard key={cat.name}>
                  <div style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    marginBottom: 14,
                  }}>
                    <span style={{ fontSize: 18 }}>{cat.icon}</span>
                    <h2 style={{
                      margin: 0,
                      fontSize: 15,
                      fontWeight: 700,
                      fontFamily: "'Outfit', sans-serif",
                      color: cat.color,
                    }}>
                      {cat.name}
                    </h2>
                    <span style={{
                      color: "#475569",
                      fontSize: 11,
                      fontFamily: "'JetBrains Mono', monospace",
                      background: "rgba(255,255,255,0.04)",
                      padding: "2px 8px",
                      borderRadius: 4,
                    }}>
                      {cat.modules.length}
                    </span>
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                    {cat.modules.map((mod) => (
                      <ModuleChip
                        key={mod}
                        name={mod}
                        color={cat.color}
                        onRun={runModule}
                        onDemo={demoModule}
                        isRunning={runningModules.has(mod)}
                      />
                    ))}
                  </div>
                </GlassCard>
              ))}
            </div>
          )}

          {/* ── AUTOPILOT TAB ── */}
          {activeTab === "autopilot" && (
            <div>
              <div style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                marginBottom: 20,
              }}>
                <span style={{ fontSize: 28 }}>🤖</span>
                <div>
                  <h2 style={{
                    margin: 0,
                    fontSize: 22,
                    fontWeight: 800,
                    fontFamily: "'Outfit', sans-serif",
                    color: "#4ade80",
                  }}>
                    Q-AUTOPILOT
                  </h2>
                  <p style={{
                    margin: 0,
                    color: "#64748b",
                    fontSize: 12,
                    fontFamily: "'JetBrains Mono', monospace",
                  }}>
                    Autonomous SOC Orchestrator · 37 modules · 4 workflows · 6 event types
                  </p>
                </div>
              </div>
              <GlassCard>
                <AutopilotPanel api={api} />
              </GlassCard>
            </div>
          )}

          {/* ── QUEUE TAB ── */}
          {activeTab === "queue" && (
            <div>
              <h2 style={{
                fontSize: 18,
                fontWeight: 700,
                fontFamily: "'Outfit', sans-serif",
                color: "#facc15",
                marginBottom: 16,
                display: "flex",
                alignItems: "center",
                gap: 10,
              }}>
                📋 Task Queue
                <span style={{
                  color: "#64748b",
                  fontSize: 11,
                  fontFamily: "'JetBrains Mono', monospace",
                  fontWeight: 400,
                }}>
                  3 concurrent workers
                </span>
              </h2>
              <GlassCard>
                <QueuePanel api={api} />
              </GlassCard>
            </div>
          )}

          {/* ── CACHE TAB ── */}
          {activeTab === "cache" && (
            <div>
              <h2 style={{
                fontSize: 18,
                fontWeight: 700,
                fontFamily: "'Outfit', sans-serif",
                color: "#a855f7",
                marginBottom: 16,
                display: "flex",
                alignItems: "center",
                gap: 10,
              }}>
                💾 Redis Cache
                <span style={{
                  color: "#64748b",
                  fontSize: 11,
                  fontFamily: "'JetBrains Mono', monospace",
                  fontWeight: 400,
                }}>
                  TTL 1 hour · Memurai on localhost:6379
                </span>
              </h2>
              <GlassCard>
                <CacheStats api={api} />
              </GlassCard>
            </div>
          )}
        </div>

        {/* RIGHT — Live Feed Sidebar */}
        <div style={{
          padding: 20,
          background: "rgba(0,0,0,0.15)",
          display: "flex",
          flexDirection: "column",
          height: "100%",
          overflow: "hidden",
        }}>
          <LiveFeed messages={wsMessages} connected={wsConnected} />
        </div>
      </div>

      {/* ═══ RESULT MODAL ═══ */}
      <ResultModal result={result} onClose={() => setResult(null)} />

      {/* ═══ Error toast ═══ */}
      {api.error && (
        <div style={{
          position: "fixed",
          bottom: 24,
          left: "50%",
          transform: "translateX(-50%)",
          background: "rgba(244,63,94,0.15)",
          border: "1px solid #f43f5e44",
          borderRadius: 12,
          padding: "10px 20px",
          color: "#f43f5e",
          fontSize: 12,
          fontFamily: "'JetBrains Mono', monospace",
          zIndex: 999,
          animation: "qcoreSlideIn 0.3s ease",
          backdropFilter: "blur(12px)",
        }}>
          ⚠ {api.error}
        </div>
      )}
    </div>
  );
}
