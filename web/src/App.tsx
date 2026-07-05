import { useEffect, useState, useRef } from 'react';
import { Activity, ShieldAlert, ShieldCheck, Database, Server, ServerCrash } from 'lucide-react';
import './index.css';

interface AuditEvent {
  time: string;
  client_id: string;
  sql: string;
  status: 'allowed' | 'blocked';
  reason?: string;
}

interface StatusResponse {
  active_connections: number;
  pool_connections: number;
  total_allowed: number;
  total_blocked: number;
  events: AuditEvent[];
  pool_ready: boolean;
}

function App() {
  const [status, setStatus] = useState<StatusResponse>({
    active_connections: 0,
    pool_connections: 0,
    total_allowed: 0,
    total_blocked: 0,
    events: [],
    pool_ready: false,
  });

  const [connected, setConnected] = useState(false);
  const endOfFeedRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await fetch('/api/status');
        if (res.ok) {
          const data = await res.json();
          setStatus(data);
          setConnected(true);
        } else {
          setConnected(false);
        }
      } catch (err) {
        setConnected(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    // Scroll to bottom of feed when new events arrive
    endOfFeedRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [status.events]);

  return (
    <div className="layout-container">
      <header>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div className="glow-text">
            <Activity color="var(--accent-color)" size={32} />
          </div>
          <h1 className="glow-text">AgentIAM <span style={{ fontWeight: 300, color: 'var(--text-secondary)' }}>Security Console</span></h1>
        </div>
        
        <div className="status-indicator" style={{ 
          background: connected ? 'var(--success-bg)' : 'var(--danger-bg)',
          borderColor: connected ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
          color: connected ? 'var(--success-color)' : 'var(--danger-color)'
        }}>
          <div className="pulse" style={{ backgroundColor: connected ? 'var(--success-color)' : 'var(--danger-color)' }}></div>
          {connected ? 'SYSTEM ONLINE' : 'DISCONNECTED'}
        </div>
      </header>

      <div className="stats-grid">
        <div className="glass-panel stat-card">
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span className="stat-label">Downstream Active</span>
            <Server size={20} color="var(--accent-color)" />
          </div>
          <span className="stat-value glow-text" style={{ color: 'var(--accent-color)' }}>
            {status.active_connections}
          </span>
        </div>
        <div className="glass-panel stat-card">
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span className="stat-label">Upstream Pool</span>
            {status.pool_ready ? <Database size={20} color="var(--success-color)" /> : <ServerCrash size={20} color="var(--danger-color)" />}
          </div>
          <span className="stat-value">{status.pool_connections}</span>
        </div>
        <div className="glass-panel stat-card">
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span className="stat-label">Queries Allowed</span>
            <ShieldCheck size={20} color="var(--success-color)" />
          </div>
          <span className="stat-value">{status.total_allowed}</span>
        </div>
        <div className="glass-panel stat-card">
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span className="stat-label">Queries Blocked</span>
            <ShieldAlert size={20} color="var(--danger-color)" />
          </div>
          <span className="stat-value" style={{ color: status.total_blocked > 0 ? 'var(--danger-color)' : 'inherit' }}>
            {status.total_blocked}
          </span>
        </div>
      </div>

      <div className="glass-panel feed-container">
        <div className="feed-header">
          <h2 className="feed-title">Live Audit Stream</h2>
          <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Monitoring all AI Agents...</span>
        </div>
        
        <div className="event-list">
          {status.events.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-secondary)' }}>
              No queries intercepted yet. Waiting for traffic...
            </div>
          ) : (
            status.events.map((evt, idx) => (
              <div key={idx} className={`event-card ${evt.status}`}>
                <div className="event-header">
                  <div className="event-meta">
                    <span style={{ fontFamily: 'Fira Code, monospace' }}>{new Date(evt.time).toLocaleTimeString()}</span>
                    <span>|</span>
                    <span style={{ fontWeight: 600, color: '#e5e7eb' }}>{evt.client_id}</span>
                  </div>
                  <span className={`badge ${evt.status}`}>{evt.status}</span>
                </div>
                
                <div className="code-block">{evt.sql}</div>
                
                {evt.status === 'blocked' && evt.reason && (
                  <div className="block-reason">
                    <ShieldAlert size={16} />
                    <span>Policy violation: {evt.reason}</span>
                  </div>
                )}
              </div>
            ))
          )}
          <div ref={endOfFeedRef} />
        </div>
      </div>
    </div>
  );
}

export default App;
