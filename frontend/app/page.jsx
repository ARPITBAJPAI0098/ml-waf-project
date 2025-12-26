'use client';
// @ts-nocheck
import { useState, useEffect } from 'react';

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const [statsRes, logsRes] = await Promise.all([
        fetch(`${API_URL}/api/stats`),
        fetch(`${API_URL}/api/logs?limit=10`)
      ]);
      
      const statsData = await statsRes.json();
      const logsData = await logsRes.json();
      
      setStats(statsData);
      setLogs(logsData.logs);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching data:', error);
    }
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', background: '#0f172a' }}>
        <div style={{ color: '#fff', fontSize: '24px' }}>Loading ML-WAF Dashboard...</div>
      </div>
    );
  }

  return (
    <div style={{ minHeight: '100vh', background: '#0f172a', color: '#fff', padding: '2rem' }}>
      {/* Header */}
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '2.5rem', fontWeight: 'bold', marginBottom: '0.5rem' }}>
          🛡️ ML-WAF Dashboard
        </h1>
        <p style={{ color: '#94a3b8' }}>Real-time Web Application Firewall Monitoring</p>
      </div>

      {/* Stats Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
        <div style={{ background: '#1e293b', padding: '1.5rem', borderRadius: '12px', border: '1px solid #334155' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <span style={{ color: '#94a3b8' }}>Total Requests</span>
            <span style={{ fontSize: '24px' }}>📊</span>
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 'bold' }}>{stats?.total_requests || 0}</div>
        </div>

        <div style={{ background: '#1e293b', padding: '1.5rem', borderRadius: '12px', border: '1px solid #334155' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <span style={{ color: '#94a3b8' }}>Threats Blocked</span>
            <span style={{ fontSize: '24px' }}>🚨</span>
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#ef4444' }}>{stats?.malicious_requests || 0}</div>
        </div>

        <div style={{ background: '#1e293b', padding: '1.5rem', borderRadius: '12px', border: '1px solid #334155' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <span style={{ color: '#94a3b8' }}>Block Rate</span>
            <span style={{ fontSize: '24px' }}>📈</span>
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#10b981' }}>{stats?.blocked_percentage || 0}%</div>
        </div>
      </div>

      {/* Recent Logs */}
      <div style={{ background: '#1e293b', padding: '1.5rem', borderRadius: '12px', border: '1px solid #334155' }}>
        <h2 style={{ fontSize: '1.5rem', fontWeight: 'bold', marginBottom: '1rem' }}>Recent Activity</h2>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #334155' }}>
                <th style={{ padding: '0.75rem', textAlign: 'left', color: '#94a3b8' }}>Time</th>
                <th style={{ padding: '0.75rem', textAlign: 'left', color: '#94a3b8' }}>Method</th>
                <th style={{ padding: '0.75rem', textAlign: 'left', color: '#94a3b8' }}>Path</th>
                <th style={{ padding: '0.75rem', textAlign: 'left', color: '#94a3b8' }}>IP</th>
                <th style={{ padding: '0.75rem', textAlign: 'left', color: '#94a3b8' }}>Status</th>
                <th style={{ padding: '0.75rem', textAlign: 'left', color: '#94a3b8' }}>Threat</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log, index) => (
                <tr key={index} style={{ borderBottom: '1px solid #334155' }}>
                  <td style={{ padding: '0.75rem' }}>{new Date(log.timestamp).toLocaleTimeString()}</td>
                  <td style={{ padding: '0.75rem' }}>
                    <span style={{ 
                      background: log.method === 'GET' ? '#1e40af' : '#be123c',
                      padding: '0.25rem 0.5rem',
                      borderRadius: '4px',
                      fontSize: '0.875rem'
                    }}>
                      {log.method}
                    </span>
                  </td>
                  <td style={{ padding: '0.75rem', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {log.path}
                  </td>
                  <td style={{ padding: '0.75rem' }}>{log.ip_address}</td>
                  <td style={{ padding: '0.75rem' }}>
                    {log.is_malicious ? (
                      <span style={{ color: '#ef4444' }}>🚫 BLOCKED</span>
                    ) : (
                      <span style={{ color: '#10b981' }}>✅ ALLOWED</span>
                    )}
                  </td>
                  <td style={{ padding: '0.75rem' }}>
                    <span style={{
                      background: log.is_malicious ? '#7f1d1d' : '#064e3b',
                      padding: '0.25rem 0.5rem',
                      borderRadius: '4px',
                      fontSize: '0.875rem'
                    }}>
                      {log.threat_type}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Footer */}
      <div style={{ marginTop: '2rem', textAlign: 'center', color: '#64748b' }}>
        <p>ML-WAF v1.0.0 | Powered by Machine Learning 🤖</p>
      </div>
    </div>
  );
}