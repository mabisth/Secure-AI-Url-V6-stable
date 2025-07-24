import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [stats, setStats] = useState(null);
  const [error, setError] = useState('');
  const [scanHistory, setScanHistory] = useState([]);
  const [scanType, setScanType] = useState('standard');
  const [showDetailedReport, setShowDetailedReport] = useState(false);
  
  // Bulk scanning state
  const [bulkUrls, setBulkUrls] = useState('');
  const [bulkJobId, setBulkJobId] = useState(null);
  const [bulkStatus, setBulkStatus] = useState(null);
  const [bulkLoading, setBulkLoading] = useState(false);
  
  // Analytics state
  const [trends, setTrends] = useState(null);
  const [campaigns, setCampaigns] = useState([]);
  
  const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

  useEffect(() => {
    fetchStats();
    fetchTrends();
    fetchCampaigns();
  }, []);

  useEffect(() => {
    let interval;
    if (bulkJobId && bulkStatus?.status === 'processing') {
      interval = setInterval(() => {
        fetchBulkStatus(bulkJobId);
      }, 2000);
    }
    return () => clearInterval(interval);
  }, [bulkJobId, bulkStatus]);

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

  const fetchTrends = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/analytics/trends`);
      if (response.ok) {
        const data = await response.json();
        setTrends(data);
      }
    } catch (err) {
      console.error('Failed to fetch trends:', err);
    }
  };

  const fetchCampaigns = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/campaigns`);
      if (response.ok) {
        const data = await response.json();
        setCampaigns(data.campaigns || []);
      }
    } catch (err) {
      console.error('Failed to fetch campaigns:', err);
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
        fetchStats();
        fetchCampaigns();
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

  const startBulkScan = async () => {
    const urls = bulkUrls.split('\n').filter(line => line.trim()).map(line => line.trim());
    
    if (urls.length === 0) {
      setError('Please enter URLs to scan (one per line)');
      return;
    }

    setBulkLoading(true);
    setError('');

    try {
      const response = await fetch(`${BACKEND_URL}/api/scan/bulk`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ urls }),
      });

      if (response.ok) {
        const data = await response.json();
        setBulkJobId(data.job_id);
        setBulkStatus(data);
      } else {
        const errorData = await response.json();
        setError(errorData.detail || 'Bulk scan failed');
      }
    } catch (err) {
      setError('Network error occurred. Please try again.');
    } finally {
      setBulkLoading(false);
    }
  };

  const fetchBulkStatus = async (jobId) => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/scan/bulk/${jobId}`);
      if (response.ok) {
        const data = await response.json();
        setBulkStatus(data);
        if (data.status === 'completed') {
          fetchStats();
        }
      }
    } catch (err) {
      console.error('Failed to fetch bulk status:', err);
    }
  };

  const downloadBulkResults = (format = 'csv') => {
    if (bulkJobId && bulkStatus?.status === 'completed') {
      window.open(`${BACKEND_URL}/api/scan/bulk/${bulkJobId}/export?format=${format}`, '_blank');
    }
  };

  const getRiskColor = (score) => {
    if (score >= 85) return 'text-red-700';
    if (score >= 70) return 'text-red-600';
    if (score >= 50) return 'text-orange-600';
    if (score >= 30) return 'text-yellow-600';
    return 'text-green-600';
  };

  const getRiskBg = (score) => {
    if (score >= 85) return 'bg-red-200 border-red-400';
    if (score >= 70) return 'bg-red-100 border-red-300';
    if (score >= 50) return 'bg-orange-100 border-orange-300';
    if (score >= 30) return 'bg-yellow-100 border-yellow-300';
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

  const renderMLInsights = (mlPredictions) => {
    if (!mlPredictions) return null;

    return (
      <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
        <h4 className="text-xl font-bold text-white mb-4">🧠 AI/ML Analysis</h4>
        <div className="grid md:grid-cols-2 gap-4 text-sm">
          <div>
            <div className="text-cyan-400 font-semibold mb-2">Neural Network Predictions</div>
            <div className="space-y-2 text-gray-300">
              <div className="flex justify-between">
                <span>Phishing Probability:</span>
                <span className={`font-semibold ${mlPredictions.phishing_probability > 0.7 ? 'text-red-400' : 'text-green-400'}`}>
                  {(mlPredictions.phishing_probability * 100).toFixed(1)}%
                </span>
              </div>
              <div className="flex justify-between">
                <span>Malware Probability:</span>
                <span className={`font-semibold ${mlPredictions.malware_probability > 0.7 ? 'text-red-400' : 'text-green-400'}`}>
                  {(mlPredictions.malware_probability * 100).toFixed(1)}%
                </span>
              </div>
              <div className="flex justify-between">
                <span>Ensemble Score:</span>
                <span className={`font-semibold ${mlPredictions.ensemble_score > 0.7 ? 'text-red-400' : 'text-green-400'}`}>
                  {(mlPredictions.ensemble_score * 100).toFixed(1)}%
                </span>
              </div>
            </div>
          </div>
          <div>
            <div className="text-purple-400 font-semibold mb-2">Content Analysis</div>
            <div className="space-y-2 text-gray-300">
              <div className="flex justify-between">
                <span>Content Similarity:</span>
                <span className="font-semibold text-blue-400">
                  {mlPredictions.content_similarity_score?.toFixed(2) || 'N/A'}
                </span>
              </div>
              <div>
                <span className="text-xs text-gray-400">
                  Advanced machine learning models analyze URL patterns, content structure, and behavioral indicators
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderBlacklistAnalysis = (blacklistAnalysis) => {
    if (!blacklistAnalysis) return null;

    return (
      <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
        <h4 className="text-xl font-bold text-white mb-4">🛡️ Blacklist Status (Sucuri-like)</h4>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-gray-300">Reputation Score:</span>
            <span className={`text-2xl font-bold ${
              blacklistAnalysis.reputation_score >= 80 ? 'text-green-400' :
              blacklistAnalysis.reputation_score >= 60 ? 'text-yellow-400' :
              'text-red-400'
            }`}>
              {blacklistAnalysis.reputation_score}/100
            </span>
          </div>
          
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <div className="text-sm text-gray-400 mb-1">Sources Checked:</div>
              <div className="text-lg text-cyan-400 font-semibold">
                {blacklistAnalysis.total_sources_checked}
              </div>
            </div>
            <div>
              <div className="text-sm text-gray-400 mb-1">Malicious Reports:</div>
              <div className={`text-lg font-semibold ${
                blacklistAnalysis.sources_reporting_malicious > 0 ? 'text-red-400' : 'text-green-400'
              }`}>
                {blacklistAnalysis.sources_reporting_malicious}
              </div>
            </div>
          </div>

          {blacklistAnalysis.is_blacklisted && blacklistAnalysis.blacklist_sources.length > 0 && (
            <div>
              <h5 className="text-red-400 font-semibold mb-2">⚠️ Blacklisted By:</h5>
              <div className="space-y-1">
                {blacklistAnalysis.blacklist_sources.map((source, index) => (
                  <div key={index} className="text-red-300 text-sm flex items-center gap-2">
                    <span className="w-2 h-2 bg-red-400 rounded-full"></span>
                    {source}
                  </div>
                ))}
              </div>
            </div>
          )}

          {!blacklistAnalysis.is_blacklisted && (
            <div className="bg-green-500/10 border border-green-400/30 rounded-lg p-3">
              <div className="text-green-400 font-semibold">✅ Clean Status</div>
              <div className="text-green-300 text-sm">No blacklist reports found across {blacklistAnalysis.total_sources_checked} security sources</div>
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderSecurityHeaders = (securityHeaders) => {
    if (!securityHeaders) return null;

    return (
      <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
        <h4 className="text-xl font-bold text-white mb-4">🔒 Security Headers Analysis</h4>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-gray-300">Security Score:</span>
            <span className={`text-2xl font-bold ${
              securityHeaders.security_score >= 80 ? 'text-green-400' :
              securityHeaders.security_score >= 60 ? 'text-yellow-400' :
              securityHeaders.security_score >= 40 ? 'text-orange-400' :
              'text-red-400'
            }`}>
              {securityHeaders.security_score}/100
            </span>
          </div>

          <div className="grid md:grid-cols-2 gap-6">
            {securityHeaders.headers_present && securityHeaders.headers_present.length > 0 && (
              <div>
                <h5 className="text-green-400 font-semibold mb-2">✅ Present Headers</h5>
                <div className="space-y-1">
                  {securityHeaders.headers_present.map((header, index) => (
                    <div key={index} className="text-green-300 text-sm bg-green-500/10 px-2 py-1 rounded">
                      {header}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {securityHeaders.headers_missing && securityHeaders.headers_missing.length > 0 && (
              <div>
                <h5 className="text-red-400 font-semibold mb-2">❌ Missing Headers</h5>
                <div className="space-y-1">
                  {securityHeaders.headers_missing.map((header, index) => (
                    <div key={index} className="text-red-300 text-sm bg-red-500/10 px-2 py-1 rounded">
                      {header}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {securityHeaders.recommendations && securityHeaders.recommendations.length > 0 && (
            <div>
              <h5 className="text-yellow-400 font-semibold mb-2">💡 Recommendations</h5>
              <div className="space-y-1">
                {securityHeaders.recommendations.map((rec, index) => (
                  <div key={index} className="text-yellow-300 text-sm flex items-start gap-2">
                    <span className="text-yellow-400 mt-1">•</span>
                    {rec}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderSoftwareAnalysis = (softwareAnalysis) => {
    if (!softwareAnalysis) return null;

    return (
      <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
        <h4 className="text-xl font-bold text-white mb-4">🔧 Software Analysis</h4>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-gray-300">Vulnerability Risk:</span>
            <span className={`text-lg font-bold px-3 py-1 rounded-full ${
              softwareAnalysis.vulnerability_risk === 'High' ? 'bg-red-500/20 text-red-400' :
              softwareAnalysis.vulnerability_risk === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
              'bg-green-500/20 text-green-400'
            }`}>
              {softwareAnalysis.vulnerability_risk}
            </span>
          </div>

          {softwareAnalysis.detected_software && softwareAnalysis.detected_software.length > 0 && (
            <div>
              <h5 className="text-cyan-400 font-semibold mb-2">🔍 Detected Software</h5>
              <div className="flex flex-wrap gap-2">
                {softwareAnalysis.detected_software.map((software, index) => (
                  <span key={index} className="text-cyan-300 text-sm bg-cyan-500/10 px-3 py-1 rounded-full">
                    {software}
                  </span>
                ))}
              </div>
            </div>
          )}

          {softwareAnalysis.outdated_components && softwareAnalysis.outdated_components.length > 0 && (
            <div>
              <h5 className="text-red-400 font-semibold mb-2">⚠️ Outdated Components</h5>
              <div className="space-y-1">
                {softwareAnalysis.outdated_components.map((component, index) => (
                  <div key={index} className="text-red-300 text-sm bg-red-500/10 px-2 py-1 rounded">
                    {component}
                  </div>
                ))}
              </div>
            </div>
          )}

          {softwareAnalysis.recommendations && softwareAnalysis.recommendations.length > 0 && (
            <div>
              <h5 className="text-purple-400 font-semibold mb-2">📋 Update Recommendations</h5>
              <div className="space-y-1">
                {softwareAnalysis.recommendations.map((rec, index) => (
                  <div key={index} className="text-purple-300 text-sm flex items-start gap-2">
                    <span className="text-purple-400 mt-1">•</span>
                    {rec}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderCampaignInfo = (campaignInfo) => {
    if (!campaignInfo) return null;

    return (
      <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
        <h4 className="text-xl font-bold text-white mb-4">🎯 Campaign Detection</h4>
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-gray-300">Campaign ID:</span>
            <span className="text-cyan-400 font-mono">{campaignInfo.campaign_id}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-gray-300">Campaign Size:</span>
            <span className="text-orange-400 font-semibold">{campaignInfo.campaign_size} URLs</span>
          </div>
          <div>
            <span className="text-gray-300">First Seen:</span>
            <span className="text-green-400 ml-2">{formatTimestamp(campaignInfo.first_seen)}</span>
          </div>
          {campaignInfo.similar_urls && (
            <div>
              <h5 className="text-purple-400 font-semibold mb-2">Similar URLs in Campaign</h5>
              <div className="space-y-1 max-h-24 overflow-y-auto">
                {campaignInfo.similar_urls.map((similarUrl, index) => (
                  <div key={index} className="text-gray-400 text-xs font-mono bg-black/20 rounded px-2 py-1">
                    {similarUrl}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderBulkScanner = () => (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-3xl font-bold text-white mb-4">📊 Bulk URL Scanner</h2>
        <p className="text-gray-300">Analyze multiple URLs simultaneously with CSV export</p>
      </div>

      <div className="bg-white/10 backdrop-blur-md rounded-2xl p-8 border border-white/20">
        <div className="mb-6">
          <label className="block text-white text-lg font-semibold mb-4">
            Enter URLs (one per line):
          </label>
          <textarea
            value={bulkUrls}
            onChange={(e) => setBulkUrls(e.target.value)}
            placeholder="https://example1.com&#10;https://example2.com&#10;https://example3.com"
            rows="8"
            className="w-full px-6 py-4 rounded-xl border-2 border-white/30 bg-white/10 text-white placeholder-gray-300 focus:outline-none focus:border-cyan-400 focus:bg-white/20 transition-all duration-300 text-sm resize-vertical"
          />
        </div>

        <button
          onClick={startBulkScan}
          disabled={bulkLoading}
          className="w-full px-8 py-4 bg-gradient-to-r from-purple-500 to-pink-600 text-white rounded-xl font-semibold hover:from-purple-600 hover:to-pink-700 focus:outline-none focus:ring-4 focus:ring-purple-300 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-lg"
        >
          {bulkLoading ? (
            <div className="flex items-center justify-center gap-2">
              <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
              Starting Bulk Scan...
            </div>
          ) : (
            'Start Bulk Scan'
          )}
        </button>

        {/* Bulk Scan Progress */}
        {bulkStatus && (
          <div className="mt-6 bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
            <h4 className="text-xl font-bold text-white mb-4">📈 Scan Progress</h4>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-gray-300">Status:</span>
                <span className={`font-semibold px-3 py-1 rounded-full text-sm ${
                  bulkStatus.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                  bulkStatus.status === 'processing' ? 'bg-yellow-500/20 text-yellow-400 animate-pulse' :
                  'bg-blue-500/20 text-blue-400'
                }`}>
                  {bulkStatus.status.toUpperCase()}
                </span>
              </div>
              
              <div>
                <div className="flex justify-between text-sm text-gray-300 mb-2">
                  <span>Progress</span>
                  <span>{bulkStatus.processed_urls || 0} / {bulkStatus.total_urls}</span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-3">
                  <div 
                    className="h-3 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-full transition-all duration-300"
                    style={{ 
                      width: `${((bulkStatus.processed_urls || 0) / bulkStatus.total_urls) * 100}%` 
                    }}
                  ></div>
                </div>
              </div>

              {bulkStatus.status === 'completed' && (
                <div className="flex gap-4 mt-4">
                  <button
                    onClick={() => downloadBulkResults('csv')}
                    className="flex-1 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors"
                  >
                    📊 Download CSV
                  </button>
                  <button
                    onClick={() => downloadBulkResults('json')}
                    className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                  >
                    📄 Download JSON
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );

  const renderAnalytics = () => (
    <div className="space-y-8">
      <div className="text-center">
        <h2 className="text-3xl font-bold text-white mb-4">📈 Advanced Analytics</h2>
        <p className="text-gray-300">Comprehensive threat intelligence and trend analysis</p>
      </div>

      {/* Enhanced Statistics Grid */}
      {stats && (
        <div>
          <h3 className="text-2xl font-bold text-white mb-6">📊 Platform Overview</h3>
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div className="bg-gradient-to-br from-cyan-500/20 to-blue-600/20 backdrop-blur-sm rounded-xl p-6 border border-cyan-400/30">
              <div className="text-3xl font-bold text-cyan-400 mb-2">{stats.total_scans}</div>
              <div className="text-gray-300">Total Scans</div>
              <div className="text-xs text-cyan-300 mt-1">All time</div>
            </div>
            <div className="bg-gradient-to-br from-red-500/20 to-pink-600/20 backdrop-blur-sm rounded-xl p-6 border border-red-400/30">
              <div className="text-3xl font-bold text-red-400 mb-2">{stats.malicious_urls_detected}</div>
              <div className="text-gray-300">Threats Detected</div>
              <div className="text-xs text-red-300 mt-1">Malicious URLs blocked</div>
            </div>
            <div className="bg-gradient-to-br from-purple-500/20 to-indigo-600/20 backdrop-blur-sm rounded-xl p-6 border border-purple-400/30">
              <div className="text-3xl font-bold text-purple-400 mb-2">{stats.campaign_count || 0}</div>
              <div className="text-gray-300">Active Campaigns</div>
              <div className="text-xs text-purple-300 mt-1">Threat campaigns identified</div>
            </div>
            <div className="bg-gradient-to-br from-green-500/20 to-emerald-600/20 backdrop-blur-sm rounded-xl p-6 border border-green-400/30">
              <div className="text-3xl font-bold text-green-400 mb-2">{stats.detection_rate}%</div>
              <div className="text-gray-300">Detection Rate</div>
              <div className="text-xs text-green-300 mt-1">AI accuracy score</div>
            </div>
          </div>
        </div>
      )}

      {/* Threat Categories Distribution */}
      {stats?.threat_categories && (
        <div className="bg-white/10 backdrop-blur-md rounded-2xl p-8 border border-white/20">
          <h3 className="text-2xl font-bold text-white mb-6">🎯 Threat Categories</h3>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
            {Object.entries(stats.threat_categories).map(([category, count]) => (
              <div key={category} className="bg-white/5 rounded-lg p-4 border border-white/10">
                <div className="flex justify-between items-center">
                  <span className="text-gray-300">{category}</span>
                  <span className={`font-bold text-lg ${getRiskColor(category === 'Critical Risk' ? 90 : category === 'High Risk' ? 75 : category === 'Moderate Risk' ? 50 : 20)}`}>
                    {count}
                  </span>
                </div>
                <div className="mt-2 bg-gray-700 rounded-full h-2">
                  <div 
                    className={`h-2 rounded-full ${
                      category === 'Critical Risk' ? 'bg-red-500' :
                      category === 'High Risk' ? 'bg-orange-500' :
                      category === 'Moderate Risk' ? 'bg-yellow-500' :
                      'bg-green-500'
                    }`}
                    style={{ width: `${(count / Math.max(...Object.values(stats.threat_categories))) * 100}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Daily Trends */}
      {stats?.daily_stats && (
        <div className="bg-white/10 backdrop-blur-md rounded-2xl p-8 border border-white/20">
          <h3 className="text-2xl font-bold text-white mb-6">📊 7-Day Trends</h3>
          <div className="space-y-4">
            {stats.daily_stats.map((day, index) => (
              <div key={day.date} className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
                <div className="flex-1">
                  <div className="text-white font-semibold">{new Date(day.date).toLocaleDateString()}</div>
                  <div className="text-gray-400 text-sm">{day.total_scans} scans, {day.malicious_count} threats</div>
                </div>
                <div className="text-right">
                  <div className={`text-lg font-bold ${getRiskColor(day.detection_rate)}`}>
                    {day.detection_rate}%
                  </div>
                  <div className="text-gray-400 text-xs">detection rate</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Active Campaigns */}
      {campaigns.length > 0 && (
        <div className="bg-white/10 backdrop-blur-md rounded-2xl p-8 border border-white/20">
          <h3 className="text-2xl font-bold text-white mb-6">🎯 Active Threat Campaigns</h3>
          <div className="space-y-4">
            {campaigns.slice(0, 5).map((campaign, index) => (
              <div key={campaign.campaign_id} className="bg-white/5 rounded-lg p-4 border border-white/10">
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <div className="text-cyan-400 font-mono text-sm">#{campaign.campaign_id}</div>
                    <div className="text-white font-semibold mt-1">Campaign Pattern</div>
                    <div className="text-gray-400 text-sm font-mono">{campaign.signature_pattern}</div>
                  </div>
                  <div className="text-right">
                    <div className="text-orange-400 font-bold text-lg">{campaign.url_count}</div>
                    <div className="text-gray-400 text-xs">URLs detected</div>
                  </div>
                </div>
                <div className="mt-3 flex justify-between items-center text-sm">
                  <span className="text-gray-400">First seen: {formatTimestamp(campaign.first_seen)}</span>
                  <span className={`px-2 py-1 rounded-full text-xs font-semibold ${getRiskBg(campaign.risk_level)} ${getRiskColor(campaign.risk_level)}`}>
                    Risk: {campaign.risk_level}/100
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Navigation */}
      <nav className="bg-black/20 backdrop-blur-sm border-b border-white/10">
        <div className="container mx-auto px-4">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-4">
              <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                🛡️ E-Skimming Shield
              </h1>
              <span className="text-xs bg-red-500/20 text-red-400 px-2 py-1 rounded-full">v3.0 - Compliance</span>
            </div>
            <div className="flex space-x-1">
              {[
                { id: 'scanner', label: '🔍 Scanner', icon: '🔍' },
                { id: 'bulk', label: '📊 Bulk Scan', icon: '📊' },
                { id: 'analytics', label: '📈 Analytics', icon: '📈' }
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-4 py-2 rounded-lg font-semibold transition-all duration-300 ${
                    activeTab === tab.id
                      ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-400/30'
                      : 'text-gray-300 hover:text-white hover:bg-white/10'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </nav>

      <div className="container mx-auto px-4 py-8">
        {error && (
          <div className="mb-6 p-4 bg-red-500/20 border border-red-400 rounded-xl text-red-200 flex items-center gap-2">
            ❌ {error}
            <button onClick={() => setError('')} className="ml-auto text-red-300 hover:text-red-100">✕</button>
          </div>
        )}

        {/* Main Content */}
        {activeTab === 'scanner' && (
          <div className="space-y-8">
            {/* Hero Section */}
            <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-slate-800/80 via-purple-900/60 to-slate-800/80 backdrop-blur-md border border-white/10">
              <div className="p-12 text-center text-white">
                <h1 className="text-5xl md:text-7xl font-bold mb-6 bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                  E-Skimming Protection
                </h1>
                <p className="text-xl md:text-2xl mb-8 text-gray-200">
                  Regulatory compliance for payment services with daily merchant scanning
                </p>
                <div className="flex flex-wrap justify-center gap-4 text-sm">
                  <span className="bg-red-500/20 px-4 py-2 rounded-full border border-red-400">
                    💳 E-Skimming Detection
                  </span>
                  <span className="bg-green-500/20 px-4 py-2 rounded-full border border-green-400">
                    🏛️ Regulatory Compliance
                  </span>
                  <span className="bg-blue-500/20 px-4 py-2 rounded-full border border-blue-400">
                    🚫 Transaction Halting
                  </span>
                </div>
              </div>
            </div>

            {/* Scanner Interface */}
            <div className="bg-white/10 backdrop-blur-md rounded-2xl p-8 border border-white/20 shadow-2xl">
              <div className="mb-6">
                <label className="block text-white text-lg font-semibold mb-4">
                  Enter URL for E-Skimming Analysis:
                </label>
                
                {/* Scan Type Selection */}
                <div className="mb-4 flex gap-2">
                  <button
                    onClick={() => setScanType('standard')}
                    className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all ${
                      scanType === 'standard' 
                        ? 'bg-blue-500/20 text-blue-300 border border-blue-400' 
                        : 'bg-white/10 text-gray-300 hover:bg-white/20'
                    }`}
                  >
                    🔍 Standard
                  </button>
                  <button
                    onClick={() => setScanType('e_skimming')}
                    className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all ${
                      scanType === 'e_skimming' 
                        ? 'bg-red-500/20 text-red-300 border border-red-400' 
                        : 'bg-white/10 text-gray-300 hover:bg-white/20'
                    }`}
                  >
                    💳 E-Skimming
                  </button>
                  <button
                    onClick={() => setScanType('payment_gateway')}
                    className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all ${
                      scanType === 'payment_gateway' 
                        ? 'bg-green-500/20 text-green-300 border border-green-400' 
                        : 'bg-white/10 text-gray-300 hover:bg-white/20'
                    }`}
                  >
                    🏦 Payment Gateway
                  </button>
                </div>

                <div className="flex gap-4">
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    onKeyPress={handleKeyPress}
                    placeholder="https://checkout.merchant.com"
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
                        Analyzing...
                      </div>
                    ) : (
                      'Scan for E-Skimming'
                    )}
                  </button>
                </div>
              </div>

              {/* Enhanced Results */}
              {result && (
                <div className="space-y-6">
                  {/* Risk Score */}
                  <div className={`p-6 rounded-xl border-2 ${getRiskBg(result.risk_score)}`}>
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-2xl font-bold text-gray-800">🛡️ Security Analysis</h3>
                      <div className="text-right">
                        <div className={`text-4xl font-bold ${getRiskColor(result.risk_score)}`}>
                          {result.risk_score}/100
                        </div>
                        <div className="text-sm text-gray-600">AI Risk Score</div>
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

                    {/* Enhanced Risk Progress Bar */}
                    <div className="mt-4">
                      <div className="flex justify-between text-sm text-gray-600 mb-2">
                        <span>Safe</span>
                        <span>AI Risk Assessment</span>
                        <span>Critical</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-4">
                        <div 
                          className={`h-4 rounded-full transition-all duration-1000 ${
                            result.risk_score >= 85 ? 'bg-gradient-to-r from-red-600 to-red-800' :
                            result.risk_score >= 70 ? 'bg-gradient-to-r from-red-500 to-orange-600' :
                            result.risk_score >= 50 ? 'bg-gradient-to-r from-orange-500 to-yellow-500' :
                            result.risk_score >= 30 ? 'bg-gradient-to-r from-yellow-500 to-green-500' :
                            'bg-gradient-to-r from-green-500 to-green-600'
                          }`}
                          style={{ width: `${result.risk_score}%` }}
                        ></div>
                      </div>
                    </div>
                  </div>

                  {/* Enhanced Sucuri-like Analysis Sections */}
                  
                  {/* Blacklist Analysis */}
                  {result.analysis_details?.blacklist_analysis && renderBlacklistAnalysis(result.analysis_details.blacklist_analysis)}
                  
                  {/* Security Headers Analysis */}
                  {result.analysis_details?.security_headers && renderSecurityHeaders(result.analysis_details.security_headers)}
                  
                  {/* Software Analysis */}
                  {result.analysis_details?.software_analysis && renderSoftwareAnalysis(result.analysis_details.software_analysis)}

                  {/* ML Predictions */}
                  {renderMLInsights(result.ml_predictions)}

                  {/* Campaign Information */}
                  {renderCampaignInfo(result.campaign_info)}

                  {/* Enhanced Recommendations */}
                  <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
                    <h4 className="text-xl font-bold text-white mb-4">🔍 AI Security Recommendations</h4>
                    <ul className="space-y-2">
                      {result.recommendations.map((rec, index) => (
                        <li key={index} className="text-gray-200 flex items-start gap-2">
                          <span className="text-cyan-400 mt-1">•</span>
                          {rec}
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Enhanced Threat Indicators */}
                  {result.analysis_details.threat_indicators.length > 0 && (
                    <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
                      <h4 className="text-xl font-bold text-white mb-4">⚠️ Detected Threat Indicators</h4>
                      <div className="flex flex-wrap gap-2">
                        {result.analysis_details.threat_indicators.map((indicator, index) => (
                          <span key={index} className="px-3 py-1 bg-red-500/20 border border-red-400 rounded-full text-red-200 text-sm">
                            {indicator}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Enhanced Detailed Analysis */}
                  <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
                    <h4 className="text-xl font-bold text-white mb-4">📊 Comprehensive Technical Analysis</h4>
                    <div className="grid md:grid-cols-3 gap-6 text-sm">
                      <div>
                        <h5 className="text-cyan-400 font-semibold mb-2">Lexical Analysis</h5>
                        <div className="space-y-1 text-gray-300">
                          <div>URL Length: {result.analysis_details.lexical_analysis.url_length}</div>
                          <div>Subdomains: {result.analysis_details.lexical_analysis.subdomain_count}</div>
                          <div>Suspicious Chars: {result.analysis_details.lexical_analysis.suspicious_chars}</div>
                          <div>Entropy: {result.analysis_details.lexical_analysis.entropy?.toFixed(2) || 'N/A'}</div>
                          <div>IP Address: {result.analysis_details.lexical_analysis.has_ip_address ? 'Yes' : 'No'}</div>
                        </div>
                      </div>
                      <div>
                        <h5 className="text-purple-400 font-semibold mb-2">Content Analysis</h5>
                        <div className="space-y-1 text-gray-300">
                          <div>Phishing Keywords: {result.analysis_details.content_analysis.phishing_keywords}</div>
                          <div>Malware Indicators: {result.analysis_details.content_analysis.malware_indicators}</div>
                          <div>Pattern Matches: {result.analysis_details.content_analysis.pattern_matches || 0}</div>
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
                          <div>Domain Age: {result.analysis_details.domain_analysis.domain_age_days || 'Unknown'} days</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'bulk' && renderBulkScanner()}
        {activeTab === 'analytics' && renderAnalytics()}
      </div>

      {/* Enhanced Footer */}
      <footer className="bg-slate-900 text-center py-8 border-t border-white/10 mt-16">
        <div className="container mx-auto px-4">
          <p className="text-gray-400 mb-2">
            🛡️ E-Skimming Shield v3.0 - Regulatory Compliance Platform
          </p>
          <p className="text-gray-500 text-sm">
            Compliant with Retail Payment Services and Card Schemes Regulation • Daily Merchant Scanning • Transaction Halt Protection
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;