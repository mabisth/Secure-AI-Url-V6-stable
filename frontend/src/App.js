import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [stats, setStats] = useState(null);
  const [error, setError] = useState('');
  const [scanHistory, setScanHistory] = useState([]);
  
  const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/stats`);
      if (response.ok) {
        const data = await response.json();
        setStats(data);
        setScanHistory(data.recent_scans || []);
      }
    } catch (err) {
      console.error('Failed to fetch stats:', err);
    }
  };

  const scanUrl = async () => {
    if (!url.trim()) {
      setError('Please enter a URL to scan');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await fetch(`${BACKEND_URL}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url.trim() }),
      });

      if (response.ok) {
        const data = await response.json();
        setResult(data);
        fetchStats(); // Refresh stats after scan
      } else {
        const errorData = await response.json();
        setError(errorData.detail || 'Scan failed');
      }
    } catch (err) {
      setError('Network error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (score) => {
    if (score >= 80) return 'text-red-600';
    if (score >= 60) return 'text-orange-600';
    if (score >= 40) return 'text-yellow-600';
    return 'text-green-600';
  };

  const getRiskBg = (score) => {
    if (score >= 80) return 'bg-red-100 border-red-300';
    if (score >= 60) return 'bg-orange-100 border-orange-300';
    if (score >= 40) return 'bg-yellow-100 border-yellow-300';
    return 'bg-green-100 border-green-300';
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      scanUrl();
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Hero Section */}
      <div className="relative overflow-hidden">
        <div className="absolute inset-0 bg-black opacity-50"></div>
        <img 
          src="https://images.unsplash.com/photo-1550751827-4bd374c3f58b?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2Nzh8MHwxfHNlYXJjaHwxfHxjeWJlcnNlY3VyaXR5fGVufDB8fHx8MTc1MzIwNDUxMHww&ixlib=rb-4.1.0&q=85"
          alt="Cybersecurity Background"
          className="absolute inset-0 w-full h-full object-cover"
        />
        <div className="relative z-10 container mx-auto px-4 py-16">
          <div className="text-center text-white mb-12">
            <h1 className="text-5xl md:text-7xl font-bold mb-6 bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              URL Security Scanner
            </h1>
            <p className="text-xl md:text-2xl mb-8 text-gray-200">
              Advanced AI-powered malicious URL detection and threat analysis
            </p>
            <div className="flex flex-wrap justify-center gap-4 text-sm">
              <span className="bg-cyan-500/20 px-4 py-2 rounded-full border border-cyan-400">
                🛡️ Real-time Analysis
              </span>
              <span className="bg-purple-500/20 px-4 py-2 rounded-full border border-purple-400">
                🧠 AI-Powered Detection
              </span>
              <span className="bg-blue-500/20 px-4 py-2 rounded-full border border-blue-400">
                ⚡ Instant Results
              </span>
            </div>
          </div>

          {/* Scanner Interface */}
          <div className="max-w-4xl mx-auto bg-white/10 backdrop-blur-md rounded-2xl p-8 border border-white/20 shadow-2xl">
            <div className="mb-6">
              <label className="block text-white text-lg font-semibold mb-4">
                Enter URL to analyze:
              </label>
              <div className="flex gap-4">
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="https://example.com"
                  className="flex-1 px-6 py-4 rounded-xl border-2 border-white/30 bg-white/10 text-white placeholder-gray-300 focus:outline-none focus:border-cyan-400 focus:bg-white/20 transition-all duration-300 text-lg"
                />
                <button
                  onClick={scanUrl}
                  disabled={loading}
                  className="px-8 py-4 bg-gradient-to-r from-cyan-500 to-blue-600 text-white rounded-xl font-semibold hover:from-cyan-600 hover:to-blue-700 focus:outline-none focus:ring-4 focus:ring-cyan-300 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-lg"
                >
                  {loading ? (
                    <div className="flex items-center gap-2">
                      <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                      Scanning...
                    </div>
                  ) : (
                    'Scan URL'
                  )}
                </button>
              </div>
            </div>

            {error && (
              <div className="mb-6 p-4 bg-red-500/20 border border-red-400 rounded-xl text-red-200">
                ❌ {error}
              </div>
            )}

            {/* Results */}
            {result && (
              <div className="space-y-6">
                {/* Risk Score */}
                <div className={`p-6 rounded-xl border-2 ${getRiskBg(result.risk_score)}`}>
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-2xl font-bold text-gray-800">Security Analysis</h3>
                    <div className="text-right">
                      <div className={`text-4xl font-bold ${getRiskColor(result.risk_score)}`}>
                        {result.risk_score}/100
                      </div>
                      <div className="text-sm text-gray-600">Risk Score</div>
                    </div>
                  </div>
                  
                  <div className="grid md:grid-cols-2 gap-4">
                    <div>
                      <div className="text-sm text-gray-600 mb-1">Threat Category</div>
                      <div className={`text-xl font-semibold ${getRiskColor(result.risk_score)}`}>
                        {result.threat_category}
                      </div>
                    </div>
                    <div>
                      <div className="text-sm text-gray-600 mb-1">Status</div>
                      <div className={`text-xl font-semibold ${result.is_malicious ? 'text-red-600' : 'text-green-600'}`}>
                        {result.is_malicious ? '🚨 Malicious' : '✅ Safe'}
                      </div>
                    </div>
                  </div>

                  {/* Risk Progress Bar */}
                  <div className="mt-4">
                    <div className="flex justify-between text-sm text-gray-600 mb-2">
                      <span>Safe</span>
                      <span>Risk Level</span>
                      <span>Dangerous</span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-3">
                      <div 
                        className={`h-3 rounded-full transition-all duration-1000 ${
                          result.risk_score >= 80 ? 'bg-red-500' :
                          result.risk_score >= 60 ? 'bg-orange-500' :
                          result.risk_score >= 40 ? 'bg-yellow-500' : 'bg-green-500'
                        }`}
                        style={{ width: `${result.risk_score}%` }}
                      ></div>
                    </div>
                  </div>
                </div>

                {/* Recommendations */}
                <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
                  <h4 className="text-xl font-bold text-white mb-4">🔍 Security Recommendations</h4>
                  <ul className="space-y-2">
                    {result.recommendations.map((rec, index) => (
                      <li key={index} className="text-gray-200 flex items-start gap-2">
                        <span className="text-cyan-400 mt-1">•</span>
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Threat Indicators */}
                {result.analysis_details.threat_indicators.length > 0 && (
                  <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
                    <h4 className="text-xl font-bold text-white mb-4">⚠️ Threat Indicators</h4>
                    <div className="flex flex-wrap gap-2">
                      {result.analysis_details.threat_indicators.map((indicator, index) => (
                        <span key={index} className="px-3 py-1 bg-red-500/20 border border-red-400 rounded-full text-red-200 text-sm">
                          {indicator}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Detailed Analysis */}
                <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
                  <h4 className="text-xl font-bold text-white mb-4">📊 Detailed Analysis</h4>
                  <div className="grid md:grid-cols-3 gap-6 text-sm">
                    <div>
                      <h5 className="text-cyan-400 font-semibold mb-2">Lexical Analysis</h5>
                      <div className="space-y-1 text-gray-300">
                        <div>URL Length: {result.analysis_details.lexical_analysis.url_length}</div>
                        <div>Subdomains: {result.analysis_details.lexical_analysis.subdomain_count}</div>
                        <div>Suspicious Characters: {result.analysis_details.lexical_analysis.suspicious_chars}</div>
                        <div>IP Address: {result.analysis_details.lexical_analysis.has_ip_address ? 'Yes' : 'No'}</div>
                      </div>
                    </div>
                    <div>
                      <h5 className="text-purple-400 font-semibold mb-2">Content Analysis</h5>
                      <div className="space-y-1 text-gray-300">
                        <div>Phishing Keywords: {result.analysis_details.content_analysis.phishing_keywords}</div>
                        <div>Malware Indicators: {result.analysis_details.content_analysis.malware_indicators}</div>
                        <div>URL Shortener: {result.analysis_details.content_analysis.url_shortener ? 'Yes' : 'No'}</div>
                        <div>Homograph Attack: {result.analysis_details.content_analysis.homograph_attack ? 'Yes' : 'No'}</div>
                      </div>
                    </div>
                    <div>
                      <h5 className="text-green-400 font-semibold mb-2">Domain Analysis</h5>
                      <div className="space-y-1 text-gray-300">
                        <div>SSL Certificate: {result.analysis_details.domain_analysis.has_ssl ? 'Yes' : 'No'}</div>
                        <div>Trusted Domain: {result.analysis_details.domain_analysis.is_trusted_domain ? 'Yes' : 'No'}</div>
                        <div>MX Records: {result.analysis_details.domain_analysis.mx_records_exist ? 'Yes' : 'No'}</div>
                        <div>DNS Time: {Math.round(result.analysis_details.domain_analysis.dns_resolution_time)}ms</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Statistics Section */}
      {stats && (
        <div className="py-16 bg-slate-800/50">
          <div className="container mx-auto px-4">
            <h2 className="text-3xl font-bold text-center text-white mb-12">Platform Statistics</h2>
            <div className="grid md:grid-cols-4 gap-6 mb-12">
              <div className="bg-white/10 backdrop-blur-sm rounded-xl p-6 border border-white/20 text-center">
                <div className="text-3xl font-bold text-cyan-400 mb-2">{stats.total_scans}</div>
                <div className="text-gray-300">Total Scans</div>
              </div>
              <div className="bg-white/10 backdrop-blur-sm rounded-xl p-6 border border-white/20 text-center">
                <div className="text-3xl font-bold text-red-400 mb-2">{stats.malicious_urls_detected}</div>
                <div className="text-gray-300">Malicious URLs</div>
              </div>
              <div className="bg-white/10 backdrop-blur-sm rounded-xl p-6 border border-white/20 text-center">
                <div className="text-3xl font-bold text-green-400 mb-2">{stats.safe_urls}</div>
                <div className="text-gray-300">Safe URLs</div>
              </div>
              <div className="bg-white/10 backdrop-blur-sm rounded-xl p-6 border border-white/20 text-center">
                <div className="text-3xl font-bold text-purple-400 mb-2">{stats.detection_rate}%</div>
                <div className="text-gray-300">Detection Rate</div>
              </div>
            </div>

            {/* Recent Scans */}
            {scanHistory.length > 0 && (
              <div className="bg-white/10 backdrop-blur-sm rounded-xl p-6 border border-white/20">
                <h3 className="text-xl font-bold text-white mb-4">Recent Scans</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-white/20">
                        <th className="text-left py-2 text-gray-300">URL</th>
                        <th className="text-left py-2 text-gray-300">Risk Score</th>
                        <th className="text-left py-2 text-gray-300">Category</th>
                        <th className="text-left py-2 text-gray-300">Time</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanHistory.slice(0, 5).map((scan, index) => (
                        <tr key={index} className="border-b border-white/10">
                          <td className="py-2 text-gray-300 truncate max-w-xs">
                            {scan.url.length > 50 ? `${scan.url.substring(0, 50)}...` : scan.url}
                          </td>
                          <td className={`py-2 font-semibold ${getRiskColor(scan.risk_score)}`}>
                            {scan.risk_score}/100
                          </td>
                          <td className="py-2 text-gray-300">{scan.threat_category}</td>
                          <td className="py-2 text-gray-400 text-xs">
                            {formatTimestamp(scan.scan_timestamp)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="bg-slate-900 text-center py-8 border-t border-white/10">
        <div className="container mx-auto px-4">
          <p className="text-gray-400">
            🛡️ Advanced URL Security Scanner - Protecting you from malicious threats
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;