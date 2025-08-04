import React, { useState, useEffect, Fragment } from 'react';
import './App.css';

function App() {
  // State management
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('scanner');
  const [scanType, setScanType] = useState('basic');
  const [bulkUrls, setBulkUrls] = useState('');
  const [bulkResults, setBulkResults] = useState([]);
  const [bulkLoading, setBulkLoading] = useState(false);
  const [stats, setStats] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [bulkJobId, setBulkJobId] = useState(null);
  const [bulkStatus, setBulkStatus] = useState(null);
  const [companies, setCompanies] = useState([]);
  const [showRegistrationForm, setShowRegistrationForm] = useState(false);
  const [newCompany, setNewCompany] = useState({
    company_name: '',
    website_url: '',
    contact_email: '',
    industry: '',
    preferred_scan_frequency: 'daily',
    additional_notes: ''
  });
  const [selectedCompany, setSelectedCompany] = useState(null);
  const [companyScanHistory, setCompanyScanHistory] = useState([]);
  
  // Authentication state
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [showLogin, setShowLogin] = useState(false);
  const [loginData, setLoginData] = useState({ username: '', password: '' });
  const [error, setError] = useState('');

  const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

  // Effects and functions (keeping existing code)
  useEffect(() => {
    fetchStats();
  }, []);

  useEffect(() => {
    if (!bulkJobId || bulkStatus?.status === 'completed' || bulkStatus?.status === 'failed') return;
    
    const interval = setInterval(async () => {
      try {
        const response = await fetch(`${BACKEND_URL}/api/bulk-scan-status/${bulkJobId}`);
        if (response.ok) {
          const status = await response.json();
          setBulkStatus(status);
          
          if (status.status === 'completed' && status.results) {
            setBulkResults(status.results);
            clearInterval(interval);
          } else if (status.status === 'failed') {
            setError('Bulk scan failed');
            clearInterval(interval);
          }
        }
      } catch (error) {
        console.error('Error polling status:', error);
      }
    }, 2000);
    
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
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  const fetchCompanies = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/companies`);
      if (response.ok) {
        const data = await response.json();
        setCompanies(data);
      }
    } catch (error) {
      console.error('Error fetching companies:', error);
    }
  };

  const fetchCompanyScanHistory = async (companyId) => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/scan-history?company_id=${companyId}`);
      if (response.ok) {
        const data = await response.json();
        setCompanyScanHistory(data);
      }
    } catch (error) {
      console.error('Error fetching scan history:', error);
    }
  };

  const handleLogin = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(loginData),
      });

      if (response.ok) {
        const data = await response.json();
        console.log('Login response:', data); // Debug log
        if (data.success || data.user_id) {
          setIsAuthenticated(true);
          setShowLogin(false);
          setError('');
          setLoginData({ username: '', password: '' });
          fetchCompanies();
        } else {
          setError(data.message || 'Login failed');
        }
      } else {
        setError('Invalid credentials');
      }
    } catch (error) {
      console.error('Login error:', error);
      setError('Connection failed');
    }
  };

  const logout = () => {
    setIsAuthenticated(false);
    setActiveTab('scanner');
    setCompanies([]);
    setSelectedCompany(null);
    setCompanyScanHistory([]);
  };

  const handleCompanyRegistration = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/register-company`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(newCompany),
      });

      if (response.ok) {
        const data = await response.json();
        setCompanies([...companies, data]);
        setShowRegistrationForm(false);
        setNewCompany({
          company_name: '',
          website_url: '',
          contact_email: '',
          industry: '',
          preferred_scan_frequency: 'daily',
          additional_notes: ''
        });
      } else {
        console.error('Failed to register company');
      }
    } catch (error) {
      console.error('Error registering company:', error);
    }
  };

  const triggerCompanyScan = async (companyId, scanType) => {
    try {
      // This would trigger a scan for a specific company
      console.log(`Triggering ${scanType} scan for company ${companyId}`);
      // Implementation would depend on backend API
    } catch (error) {
      console.error('Error triggering company scan:', error);
    }
  };

  const handleScan = async () => {
    setLoading(true);
    setError('');
    
    try {
      const response = await fetch(`${BACKEND_URL}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          url, 
          scan_type: scanType === 'detailed' ? 'detailed' : scanType === 'e_skimming' ? 'e_skimming' : 'basic'
        }),
      });

      if (response.ok) {
        const data = await response.json();
        console.log('Full scan response:', data); // Debug log
        
        // Transform backend data to match frontend expectations
        const transformedResult = {
          risk_score: data.risk_score || 0,
          is_malicious: data.is_malicious || false,
          threat_category: data.threat_category || 'unknown',
          scan_duration: data.scan_duration || 'N/A',
          scan_timestamp: data.scan_timestamp || new Date().toISOString(),
          
          // Map analysis details
          domain_analysis: {
            domain_age: data.analysis_details?.domain_age || 'Unknown',
            registrar: data.analysis_details?.registrar || 'N/A',
            country: data.analysis_details?.country || 'Unknown',
            ssl_valid: data.analysis_details?.ssl_valid !== false,
            reputation_score: data.analysis_details?.reputation_score || data.risk_score || 0
          },
          
          // Map detailed report sections
          dns_availability: data.analysis_details?.detailed_report?.dns_availability_check ? {
            is_online: data.analysis_details.detailed_report.dns_availability_check.url_online,
            response_time: data.analysis_details.detailed_report.dns_availability_check.response_time_ms,
            http_status: data.analysis_details.detailed_report.dns_availability_check.http_status_code,
            dns_resolvers: data.analysis_details.detailed_report.dns_availability_check.dns_resolvers
          } : null,
          
          // Map detailed analysis for detailed scans
          detailed_analysis: scanType === 'detailed' && data.analysis_details?.detailed_report ? {
            ssl_analysis: {
              certificate_valid: data.analysis_details.detailed_report.ssl_detailed_analysis?.certificate_valid !== false,
              issuer: data.analysis_details.detailed_report.ssl_detailed_analysis?.certificate_issuer || 'N/A',
              expiration_date: data.analysis_details.detailed_report.ssl_detailed_analysis?.expiration_date || 'N/A',
              ssl_grade: data.analysis_details.detailed_report.ssl_detailed_analysis?.grade || 'N/A',
              protocol_version: data.analysis_details.detailed_report.ssl_detailed_analysis?.protocol_version || 'N/A',
              vulnerabilities: data.analysis_details.detailed_report.ssl_detailed_analysis?.vulnerabilities || []
            },
            email_security: {
              spf_valid: data.analysis_details.detailed_report.email_security_records?.spf_record_valid !== false,
              dmarc_valid: data.analysis_details.detailed_report.email_security_records?.dmarc_policy_present !== false,
              dkim_valid: data.analysis_details.detailed_report.email_security_records?.dkim_signature_valid !== false
            },
            threat_intelligence: {
              blacklist_status: data.analysis_details.detailed_report.comprehensive_threat_assessment?.blacklist_status || 'clean',
              malware_detected: data.analysis_details.detailed_report.comprehensive_threat_assessment?.malware_detected || false,
              phishing_risk: data.analysis_details.detailed_report.comprehensive_threat_assessment?.phishing_risk_level || 'low'
            }
          } : null,
          
          // Map ML predictions
          ml_predictions: data.ml_predictions || {},
          
          // Map content analysis
          content_analysis: {
            page_title: data.analysis_details?.content_analysis?.page_title || 'N/A',
            forms_count: data.analysis_details?.content_analysis?.forms_detected || 0,
            external_links_count: data.analysis_details?.content_analysis?.external_links || 0,
            javascript_count: data.analysis_details?.content_analysis?.javascript_files || 0,
            suspicious_keywords_count: data.analysis_details?.content_analysis?.suspicious_patterns || 0,
            content_size: data.analysis_details?.content_analysis?.content_size || 0
          },
          
          // Map technical details
          technical_details: {
            server: data.analysis_details?.technical_details?.server_info || 'Unknown',
            technologies: data.analysis_details?.technical_details?.technologies || [],
            ip_address: data.analysis_details?.technical_details?.ip_address || 'N/A',
            location: data.analysis_details?.technical_details?.geolocation || 'Unknown'
          },
          
          // Map threats and recommendations
          threats: data.analysis_details?.detected_threats || [],
          recommendations: data.recommendations || [
            'Monitor this URL for changes',
            'Implement additional security measures',
            'Regular security assessments recommended'
          ]
        };
        
        console.log('Transformed result:', transformedResult); // Debug log
        setResult(transformedResult);
        fetchStats(); // Refresh stats after scan
      } else {
        setError('Failed to scan URL');
      }
    } catch (error) {
      setError('Error connecting to server');
      console.error('Scan error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleBulkScan = async () => {
    setBulkLoading(true);
    setBulkResults([]);
    setBulkStatus(null);
    setError('');
    
    try {
      const urlList = bulkUrls.split('\n').filter(u => u.trim() !== '').map(u => u.trim());
      
      const response = await fetch(`${BACKEND_URL}/api/bulk-scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          urls: urlList,
          scan_type: scanType
        }),
      });

      if (response.ok) {
        const data = await response.json();
        setBulkJobId(data.job_id);
        setBulkStatus({ status: 'processing' });
      } else {
        setError('Failed to start bulk scan');
        setBulkLoading(false);
      }
    } catch (error) {
      setError('Error connecting to server');
      setBulkLoading(false);
      console.error('Bulk scan error:', error);
    }
  };

  const renderBulkScanner = () => (
    <div className="max-w-6xl mx-auto space-y-8">
      {/* Bulk Scanner Header */}
      <div className="text-center">
        <h2 className="text-3xl font-bold text-white mb-4">⚡ Bulk URL Scanner</h2>
        <p className="text-gray-300">Scan multiple URLs simultaneously for comprehensive threat analysis</p>
      </div>

      {/* Bulk Input Section */}
      <div className="bg-white/10 backdrop-blur-md rounded-2xl p-8 border border-white/20">
        <div className="space-y-6">
          <div>
            <label className="block text-white text-lg font-semibold mb-4">📋 Enter URLs (one per line):</label>
            <textarea
              value={bulkUrls}
              onChange={(e) => setBulkUrls(e.target.value)}
              placeholder="https://example1.com&#10;https://example2.com&#10;https://example3.com"
              className="w-full h-40 px-4 py-3 rounded-lg border-2 border-white/30 bg-white/10 text-white placeholder-gray-400 focus:outline-none focus:border-cyan-400 resize-none font-mono text-sm"
              disabled={bulkLoading}
            />
            <div className="flex justify-between text-sm text-gray-400 mt-2">
              <span>{bulkUrls.split('\n').filter(u => u.trim() !== '').length} URLs entered</span>
              <span>Maximum 50 URLs per batch</span>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row gap-4 items-center">
            <div className="flex-1">
              <label className="block text-white text-sm font-semibold mb-2">Scan Type:</label>
              <select
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
                className="w-full px-4 py-3 rounded-lg border border-white/30 bg-white/10 text-white focus:outline-none focus:border-cyan-400"
                disabled={bulkLoading}
              >
                <option value="basic">Basic Analysis</option>
                <option value="detailed">Detailed Security Report</option>
                <option value="e_skimming">E-Skimming Detection</option>
              </select>
            </div>
            <div className="flex-1 flex justify-end">
              <button
                onClick={handleBulkScan}
                disabled={bulkLoading || !bulkUrls.trim()}
                className="px-8 py-3 bg-gradient-to-r from-purple-500 to-pink-600 hover:from-purple-600 hover:to-pink-700 disabled:from-gray-600 disabled:to-gray-700 text-white font-semibold rounded-xl transition-all duration-300 transform hover:scale-105 disabled:scale-100"
              >
                {bulkLoading ? '🔄 Processing...' : '🚀 Start Bulk Scan'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Bulk Status Display */}
      {bulkStatus && (
        <div className="bg-white/10 backdrop-blur-md rounded-2xl p-6 border border-white/20">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className={`w-3 h-3 rounded-full ${
                bulkStatus.status === 'completed' ? 'bg-green-400' :
                bulkStatus.status === 'processing' ? 'bg-yellow-400 animate-pulse' :
                bulkStatus.status === 'failed' ? 'bg-red-400' : 'bg-blue-400'
              }`}></div>
              <span className="text-white font-semibold capitalize">{bulkStatus.status}</span>
            </div>
            <div className="text-gray-300">
              {bulkStatus.processed_count || 0} / {bulkStatus.total_count || 0} URLs processed
            </div>
          </div>
          
          {bulkStatus.status === 'processing' && (
            <div className="mt-4">
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div 
                  className="bg-gradient-to-r from-cyan-400 to-blue-500 h-2 rounded-full transition-all duration-500"
                  style={{ width: `${((bulkStatus.processed_count || 0) / (bulkStatus.total_count || 1)) * 100}%` }}
                ></div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Bulk Results Display */}
      {bulkResults.length > 0 && (
        <div className="bg-white/10 backdrop-blur-md rounded-2xl p-8 border border-white/20">
          <h3 className="text-2xl font-bold text-white mb-6">📊 Bulk Scan Results</h3>
          
          <div className="space-y-4">
            {bulkResults.map((urlResult, index) => (
              <div key={index} className="bg-white/5 rounded-lg p-4 border border-white/10">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex-1 min-w-0">
                    <div className="text-cyan-400 font-medium truncate">{urlResult.url}</div>
                    <div className="flex items-center space-x-4 mt-1">
                      <span className={`px-2 py-1 rounded text-xs font-semibold ${
                        urlResult.risk_score >= 70 ? 'bg-red-500/20 text-red-400' :
                        urlResult.risk_score >= 40 ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-green-500/20 text-green-400'
                      }`}>
                        Risk: {urlResult.risk_score}%
                      </span>
                      <span className="text-gray-400 text-xs">
                        {urlResult.scan_duration}ms
                      </span>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={`text-lg font-bold ${
                      urlResult.risk_score >= 70 ? 'text-red-400' :
                      urlResult.risk_score >= 40 ? 'text-yellow-400' :
                      'text-green-400'
                    }`}>
                      {urlResult.risk_score >= 70 ? '🚨 HIGH' :
                       urlResult.risk_score >= 40 ? '⚠️ MEDIUM' : '✅ SAFE'}
                    </div>
                  </div>
                </div>
                
                {urlResult.threats && urlResult.threats.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-white/10">
                    <div className="text-sm text-gray-300 mb-2">🔍 Detected Threats:</div>
                    <div className="flex flex-wrap gap-2">
                      {urlResult.threats.slice(0, 3).map((threat, threatIndex) => (
                        <span key={threatIndex} className="px-2 py-1 bg-red-500/20 text-red-300 rounded text-xs">
                          {threat}
                        </span>
                      ))}
                      {urlResult.threats.length > 3 && (
                        <span className="px-2 py-1 bg-gray-500/20 text-gray-400 rounded text-xs">
                          +{urlResult.threats.length - 3} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
          
          <div className="mt-6 p-4 bg-white/5 rounded-lg">
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <div className="text-green-400 text-xl font-bold">
                  {bulkResults.filter(r => r.risk_score < 40).length}
                </div>
                <div className="text-gray-400 text-sm">Safe URLs</div>
              </div>
              <div>
                <div className="text-yellow-400 text-xl font-bold">
                  {bulkResults.filter(r => r.risk_score >= 40 && r.risk_score < 70).length}
                </div>
                <div className="text-gray-400 text-sm">Medium Risk</div>
              </div>
              <div>
                <div className="text-red-400 text-xl font-bold">
                  {bulkResults.filter(r => r.risk_score >= 70).length}
                </div>
                <div className="text-gray-400 text-sm">High Risk</div>
              </div>
            </div>
          </div>
        </div>
      )}
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
              <div className="text-xs text-purple-300 mt-1">Security monitoring</div>
            </div>
            <div className="bg-gradient-to-br from-green-500/20 to-emerald-600/20 backdrop-blur-sm rounded-xl p-6 border border-green-400/30">
              <div className="text-3xl font-bold text-green-400 mb-2">{stats.safe_urls}</div>
              <div className="text-gray-300">Safe URLs</div>
              <div className="text-xs text-green-300 mt-1">Clean & verified</div>
            </div>
          </div>
        </div>
      )}

      {/* Recent Scans */}
      {scanHistory.length > 0 && (
        <div>
          <h3 className="text-2xl font-bold text-white mb-6">🕒 Recent Security Scans</h3>
          <div className="bg-white/10 backdrop-blur-md rounded-2xl p-6 border border-white/20">
            <div className="space-y-4">
              {scanHistory.slice(0, 10).map((scan, index) => (
                <div key={index} className="flex items-center justify-between p-4 bg-white/5 rounded-lg border border-white/10">
                  <div className="flex items-center space-x-4">
                    <div className={`w-3 h-3 rounded-full ${
                      scan.risk_score >= 70 ? 'bg-red-400' :
                      scan.risk_score >= 40 ? 'bg-yellow-400' :
                      'bg-green-400'
                    }`}></div>
                    <div className="flex-1">
                      <div className="text-cyan-400 font-medium mb-1">{scan.url}</div>
                      <div className="flex items-center space-x-4 text-sm text-gray-400">
                        <span>Risk: {scan.risk_score}%</span>
                        <span>•</span>
                        <span>{new Date(scan.timestamp).toLocaleDateString()}</span>
                      </div>
                    </div>
                  </div>
                  <div className={`px-3 py-1 rounded-full text-xs font-semibold ${
                    scan.risk_score >= 70 ? 'bg-red-500/20 text-red-400' :
                    scan.risk_score >= 40 ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-green-500/20 text-green-400'
                  }`}>
                    {scan.risk_score >= 70 ? 'HIGH RISK' :
                     scan.risk_score >= 40 ? 'MEDIUM' : 'SAFE'}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Threat Intelligence Summary */}
      {stats && stats.threat_categories && (
        <div>
          <h3 className="text-2xl font-bold text-white mb-6">🛡️ Threat Intelligence</h3>
          <div className="bg-white/10 backdrop-blur-md rounded-2xl p-6 border border-white/20">
            <div className="grid md:grid-cols-3 gap-6">
              {stats.threat_categories.map((category, index) => (
                <div key={index} className="text-center">
                  <div className="text-2xl font-bold text-orange-400 mb-2">{category.count}</div>
                  <div className="text-gray-300 capitalize">{category.type.replace('_', ' ')}</div>
                  <div className="text-xs text-gray-400 mt-1">{category.detection_rate}% detection rate</div>
                </div>
              ))}
            </div>
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
              <span className="px-3 py-1 bg-purple-500/20 text-purple-300 rounded-full text-sm font-semibold">
                v3.0 - Compliance
              </span>
            </div>
            
            {/* Navigation Tabs */}
            <div className="flex items-center space-x-6">
              <div className="flex space-x-1 bg-white/10 rounded-lg p-1">
                {[
                  { id: 'scanner', label: '🔍 Scanner', icon: '🔍' },
                  ...(isAuthenticated ? [
                    { id: 'bulk', label: '⚡ Bulk Scan', icon: '⚡' },
                    { id: 'analytics', label: '📊 Analytics', icon: '📊' },
                    { id: 'companies', label: '🏢 Companies', icon: '🏢' }
                  ] : [])
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`px-4 py-2 rounded-md text-sm font-medium transition-all duration-200 ${
                      activeTab === tab.id
                        ? 'bg-white/20 text-white shadow-sm'
                        : 'text-gray-400 hover:text-white hover:bg-white/10'
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>
              
              {/* Authentication */}
              <div className="flex items-center space-x-4">
                {isAuthenticated ? (
                  <div className="flex items-center space-x-3">
                    <span className="text-green-400 text-sm">✅ Authenticated</span>
                    <button
                      onClick={logout}
                      className="px-4 py-2 bg-red-500/20 text-red-300 rounded-lg hover:bg-red-500/30 text-sm font-medium"
                    >
                      Logout
                    </button>
                  </div>
                ) : (
                  <button
                    onClick={() => setShowLogin(true)}
                    className="px-4 py-2 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white rounded-lg text-sm font-medium"
                  >
                    🔑 Login
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="container mx-auto px-4 py-8">
        {/* Scanner Tab */}
        {activeTab === 'scanner' && (
          <div className="max-w-4xl mx-auto space-y-8">
            {/* Hero Section */}
            <div className="text-center space-y-6">
              <h2 className="text-4xl md:text-5xl font-bold text-white leading-tight">
                AI-Powered Malicious 
                <span className="bg-gradient-to-r from-red-400 to-pink-500 bg-clip-text text-transparent"> URL Detection</span>
              </h2>
              <p className="text-xl text-gray-300 max-w-3xl mx-auto">
                Advanced machine learning algorithms detect phishing, malware, and suspicious domains in real-time. 
                Protect your users and systems with enterprise-grade security analysis.
              </p>
            </div>

            {/* Scan Input Section */}
            <div className="bg-white/10 backdrop-blur-md rounded-2xl p-8 border border-white/20">
              <div className="space-y-6">
                <div>
                  <label className="block text-white text-lg font-semibold mb-4">🔗 Enter URL to analyze:</label>
                  <input
                    type="url"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://example.com"
                    className="w-full px-6 py-4 text-lg rounded-lg border-2 border-white/30 bg-white/10 text-white placeholder-gray-400 focus:outline-none focus:border-cyan-400 transition-colors duration-300"
                    disabled={loading}
                  />
                </div>

                <div className="flex flex-col sm:flex-row gap-4 items-center">
                  <div className="flex-1">
                    <label className="block text-white text-sm font-semibold mb-2">Analysis Type:</label>
                    <select
                      value={scanType}
                      onChange={(e) => setScanType(e.target.value)}
                      className="w-full px-4 py-3 rounded-lg border border-white/30 bg-white/10 text-white focus:outline-none focus:border-cyan-400"
                      disabled={loading}
                    >
                      <option value="basic">⚡ Quick Scan</option>
                      <option value="detailed">🔍 Detailed Security Report</option>
                      <option value="e_skimming">💳 E-Skimming Detection</option>
                    </select>
                  </div>
                  <div className="flex-1 flex justify-end">
                    <button
                      onClick={handleScan}
                      disabled={loading || !url.trim()}
                      className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-600 hover:to-blue-700 disabled:from-gray-600 disabled:to-gray-700 text-white font-semibold rounded-xl transition-all duration-300 transform hover:scale-105 disabled:scale-100"
                    >
                      {loading ? '🔄 Analyzing...' : '🚀 Analyze URL'}
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Error Display */}
            {error && (
              <div className="bg-red-500/10 border border-red-400/20 rounded-lg p-4">
                <div className="flex items-center space-x-2">
                  <span className="text-red-400">❌</span>
                  <span className="text-red-300">{error}</span>
                </div>
              </div>
            )}

            {/* Results Section */}
            {result && (
              <div className="space-y-6">
                {/* Risk Score Header */}
                <div className={`bg-gradient-to-r ${
                  result.risk_score >= 70 ? 'from-red-500/20 to-pink-600/20 border-red-400/30' :
                  result.risk_score >= 40 ? 'from-yellow-500/20 to-orange-600/20 border-yellow-400/30' :
                  'from-green-500/20 to-emerald-600/20 border-green-400/30'
                } backdrop-blur-sm rounded-2xl p-8 border`}>
                  <div className="text-center">
                    <div className={`text-6xl font-bold mb-4 ${
                      result.risk_score >= 70 ? 'text-red-400' :
                      result.risk_score >= 40 ? 'text-yellow-400' :
                      'text-green-400'
                    }`}>
                      {result.risk_score}%
                    </div>
                    <div className="text-2xl text-white font-semibold mb-2">
                      {result.risk_score >= 70 ? '🚨 HIGH RISK' :
                       result.risk_score >= 40 ? '⚠️ MEDIUM RISK' : '✅ SAFE'}
                    </div>
                    <div className="text-gray-300">
                      Analysis completed in {result.scan_duration || 'N/A'}ms
                    </div>
                  </div>
                </div>

                <div className="space-y-6">
                  {/* Detected Threat Indicators - Moved to Second Position */}
                  {result.threats && result.threats.length > 0 && (
                    <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
                      <h4 className="text-xl font-bold text-white mb-4">🚨 Detected Threat Indicators</h4>
                      <div className="grid gap-3">
                        {result.threats.map((threat, index) => (
                          <div key={index} className="flex items-center space-x-3 p-3 bg-red-500/10 rounded-lg border border-red-400/20">
                            <span className="text-red-400 text-lg">⚠️</span>
                            <span className="text-red-300 font-medium">{threat}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Domain Analysis */}
                  {result.domain_analysis && (
                    <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
                      <h4 className="text-xl font-bold text-white mb-4">🌐 Domain Intelligence</h4>
                      <div className="grid md:grid-cols-2 gap-6">
                        <div className="space-y-3">
                          <div className="flex justify-between">
                            <span className="text-gray-400">Domain Age:</span>
                            <span className="text-white">{result.domain_analysis.domain_age || 'Unknown'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Registrar:</span>
                            <span className="text-white">{result.domain_analysis.registrar || 'N/A'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Country:</span>
                            <span className="text-white">{result.domain_analysis.country || 'Unknown'}</span>
                          </div>
                        </div>
                        <div className="space-y-3">
                          <div className="flex justify-between">
                            <span className="text-gray-400">SSL Certificate:</span>
                            <span className={`${result.domain_analysis.ssl_valid ? 'text-green-400' : 'text-red-400'}`}>
                              {result.domain_analysis.ssl_valid ? '✅ Valid' : '❌ Invalid'}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Reputation Score:</span>
                            <span className={`${
                              result.domain_analysis.reputation_score >= 70 ? 'text-green-400' :
                              result.domain_analysis.reputation_score >= 40 ? 'text-yellow-400' :
                              'text-red-400'
                            }`}>
                              {result.domain_analysis.reputation_score || 'N/A'}%
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* DNS & Availability Results */}
                  {result.dns_availability && (
                    <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
                      <h4 className="text-xl font-bold text-white mb-4">🌍 DNS & Availability Analysis</h4>
                      <div className="grid md:grid-cols-2 gap-6">
                        <div>
                          <h5 className="text-lg font-semibold text-white mb-3">📡 DNS Resolution Status</h5>
                          <div className="space-y-2">
                            {Object.entries(result.dns_availability.dns_resolvers || {}).map(([resolver, status]) => (
                              <div key={resolver} className="flex justify-between items-center">
                                <span className="text-gray-400 capitalize">{resolver}:</span>
                                <span className={`px-2 py-1 rounded text-xs ${
                                  status === 'resolved' ? 'bg-green-500/20 text-green-400' :
                                  status === 'blocked' ? 'bg-red-500/20 text-red-400' :
                                  'bg-gray-500/20 text-gray-400'
                                }`}>
                                  {status || 'unknown'}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                        <div>
                          <h5 className="text-lg font-semibold text-white mb-3">🔒 Availability Status</h5>
                          <div className="space-y-2">
                            <div className="flex justify-between">
                              <span className="text-gray-400">Online Status:</span>
                              <span className={`${
                                result.dns_availability.is_online ? 'text-green-400' : 'text-red-400'
                              }`}>
                                {result.dns_availability.is_online ? '✅ Online' : '❌ Offline'}
                              </span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">Response Time:</span>
                              <span className="text-white">
                                {result.dns_availability.response_time || 'N/A'}ms
                              </span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">HTTP Status:</span>
                              <span className={`${
                                result.dns_availability.http_status >= 200 && result.dns_availability.http_status < 300 
                                  ? 'text-green-400' 
                                  : result.dns_availability.http_status >= 400
                                    ? 'text-red-400'
                                    : 'text-yellow-400'
                              }`}>
                                {result.dns_availability.http_status || 'N/A'}
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Detailed Security Analysis (toggleable) */}
                  {scanType === 'detailed' && result.detailed_analysis && (
                    <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
                      <h4 className="text-xl font-bold text-white mb-4">🔍 Advanced Security Analysis Report</h4>
                      
                      {/* SSL Analysis */}
                      {result.detailed_analysis.ssl_analysis && (
                        <div className="mb-6">
                          <h5 className="text-lg font-semibold text-white mb-3">🔒 SSL/TLS Certificate Analysis</h5>
                          <div className="grid md:grid-cols-2 gap-4">
                            <div className="space-y-2">
                              <div className="flex justify-between">
                                <span className="text-gray-400">Certificate Valid:</span>
                                <span className={`${result.detailed_analysis.ssl_analysis.certificate_valid ? 'text-green-400' : 'text-red-400'}`}>
                                  {result.detailed_analysis.ssl_analysis.certificate_valid ? '✅ Valid' : '❌ Invalid'}
                                </span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-gray-400">Issuer:</span>
                                <span className="text-white text-sm">{result.detailed_analysis.ssl_analysis.issuer || 'N/A'}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-gray-400">Expires:</span>
                                <span className="text-white text-sm">{result.detailed_analysis.ssl_analysis.expiration_date || 'N/A'}</span>
                              </div>
                            </div>
                            <div className="space-y-2">
                              <div className="flex justify-between">
                                <span className="text-gray-400">SSL Grade:</span>
                                <span className={`font-bold ${
                                  result.detailed_analysis.ssl_analysis.ssl_grade === 'A+' || result.detailed_analysis.ssl_analysis.ssl_grade === 'A' ? 'text-green-400' :
                                  result.detailed_analysis.ssl_analysis.ssl_grade === 'B' ? 'text-yellow-400' :
                                  'text-red-400'
                                }`}>
                                  {result.detailed_analysis.ssl_analysis.ssl_grade || 'N/A'}
                                </span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-gray-400">Protocol Version:</span>
                                <span className="text-white text-sm">{result.detailed_analysis.ssl_analysis.protocol_version || 'N/A'}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-gray-400">Vulnerabilities:</span>
                                <span className={`text-sm ${
                                  result.detailed_analysis.ssl_analysis.vulnerabilities && result.detailed_analysis.ssl_analysis.vulnerabilities.length > 0 
                                    ? 'text-red-400' 
                                    : 'text-green-400'
                                }`}>
                                  {result.detailed_analysis.ssl_analysis.vulnerabilities && result.detailed_analysis.ssl_analysis.vulnerabilities.length > 0 
                                    ? `${result.detailed_analysis.ssl_analysis.vulnerabilities.length} found` 
                                    : 'None detected'}
                                </span>
                              </div>
                            </div>
                          </div>
                          {result.detailed_analysis.ssl_analysis.vulnerabilities && result.detailed_analysis.ssl_analysis.vulnerabilities.length > 0 && (
                            <div className="mt-3 p-3 bg-red-500/10 rounded border border-red-400/20">
                              <div className="text-sm text-red-300">
                                <div className="font-semibold mb-2">⚠️ SSL Vulnerabilities Found:</div>
                                <ul className="list-disc list-inside space-y-1">
                                  {result.detailed_analysis.ssl_analysis.vulnerabilities.map((vuln, index) => (
                                    <li key={index}>{vuln}</li>
                                  ))}
                                </ul>
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                      
                      {/* Email Security Records */}
                      {result.detailed_analysis.email_security && (
                        <div className="mb-6">
                          <h5 className="text-lg font-semibold text-white mb-3">📧 Email Security Records</h5>
                          <div className="grid md:grid-cols-3 gap-4">
                            <div className="text-center p-3 bg-white/5 rounded">
                              <div className="text-sm text-gray-400 mb-1">SPF Record</div>
                              <div className={`font-semibold ${result.detailed_analysis.email_security.spf_valid ? 'text-green-400' : 'text-red-400'}`}>
                                {result.detailed_analysis.email_security.spf_valid ? '✅ Valid' : '❌ Missing/Invalid'}
                              </div>
                            </div>
                            <div className="text-center p-3 bg-white/5 rounded">
                              <div className="text-sm text-gray-400 mb-1">DMARC Policy</div>
                              <div className={`font-semibold ${result.detailed_analysis.email_security.dmarc_valid ? 'text-green-400' : 'text-red-400'}`}>
                                {result.detailed_analysis.email_security.dmarc_valid ? '✅ Configured' : '❌ Not Configured'}
                              </div>
                            </div>
                            <div className="text-center p-3 bg-white/5 rounded">
                              <div className="text-sm text-gray-400 mb-1">DKIM Signature</div>
                              <div className={`font-semibold ${result.detailed_analysis.email_security.dkim_valid ? 'text-green-400' : 'text-red-400'}`}>
                                {result.detailed_analysis.email_security.dkim_valid ? '✅ Present' : '❌ Missing'}
                              </div>
                            </div>
                          </div>
                        </div>
                      )}
                      
                      {/* Threat Intelligence */}
                      {result.detailed_analysis.threat_intelligence && (
                        <div className="mb-6">
                          <h5 className="text-lg font-semibold text-white mb-3">🛡️ Threat Intelligence</h5>
                          <div className="space-y-2">
                            <div className="flex justify-between">
                              <span className="text-gray-400">Blacklist Status:</span>
                              <span className={`${
                                result.detailed_analysis.threat_intelligence.blacklist_status === 'clean' ? 'text-green-400' : 'text-red-400'
                              }`}>
                                {result.detailed_analysis.threat_intelligence.blacklist_status === 'clean' ? '✅ Clean' : '🚨 Listed'}
                              </span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">Malware Detected:</span>
                              <span className={`${
                                result.detailed_analysis.threat_intelligence.malware_detected ? 'text-red-400' : 'text-green-400'
                              }`}>
                                {result.detailed_analysis.threat_intelligence.malware_detected ? '🚨 Yes' : '✅ None'}
                              </span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">Phishing Risk:</span>
                              <span className={`${
                                result.detailed_analysis.threat_intelligence.phishing_risk === 'high' ? 'text-red-400' :
                                result.detailed_analysis.threat_intelligence.phishing_risk === 'medium' ? 'text-yellow-400' :
                                'text-green-400'
                              }`}>
                                {result.detailed_analysis.threat_intelligence.phishing_risk || 'low'}
                              </span>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* ML Model Predictions */}
                  {result.ml_predictions && (
                    <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
                      <h4 className="text-xl font-bold text-white mb-4">🤖 AI Model Analysis</h4>
                      <div className="grid md:grid-cols-3 gap-4">
                        {Object.entries(result.ml_predictions).map(([model, prediction]) => (
                          <div key={model} className="text-center p-4 bg-white/5 rounded-lg">
                            <div className="text-sm text-gray-400 mb-2 capitalize">{model.replace('_', ' ')}</div>
                            <div className={`text-lg font-bold ${
                              prediction.confidence >= 0.7 
                                ? prediction.prediction === 'malicious' ? 'text-red-400' : 'text-green-400'
                                : 'text-yellow-400'
                            }`}>
                              {prediction.prediction === 'malicious' ? '🚨 Malicious' : '✅ Safe'}
                            </div>
                            <div className="text-xs text-gray-400 mt-1">
                              {Math.round(prediction.confidence * 100)}% confidence
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Content Analysis */}
                  {result.content_analysis && (
                    <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
                      <h4 className="text-xl font-bold text-white mb-4">📄 Content Analysis</h4>
                      <div className="grid md:grid-cols-2 gap-6">
                        <div className="space-y-3">
                          <div className="flex justify-between">
                            <span className="text-gray-400">Page Title:</span>
                            <span className="text-white text-sm truncate max-w-48">
                              {result.content_analysis.page_title || 'N/A'}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Forms Detected:</span>
                            <span className="text-white">{result.content_analysis.forms_count || 0}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">External Links:</span>
                            <span className="text-white">{result.content_analysis.external_links_count || 0}</span>
                          </div>
                        </div>
                        <div className="space-y-3">
                          <div className="flex justify-between">
                            <span className="text-gray-400">JavaScript Files:</span>
                            <span className="text-white">{result.content_analysis.javascript_count || 0}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Suspicious Keywords:</span>
                            <span className={`${
                              result.content_analysis.suspicious_keywords_count > 0 ? 'text-red-400' : 'text-green-400'
                            }`}>
                              {result.content_analysis.suspicious_keywords_count || 0}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Content Size:</span>
                            <span className="text-white">
                              {result.content_analysis.content_size ? 
                                `${Math.round(result.content_analysis.content_size / 1024)}KB` : 'N/A'}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Technical Details */}
                  {result.technical_details && (
                    <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
                      <h4 className="text-xl font-bold text-white mb-4">🔧 Technical Details</h4>
                      <div className="grid md:grid-cols-2 gap-6">
                        <div className="space-y-3">
                          <div className="flex justify-between">
                            <span className="text-gray-400">Server:</span>
                            <span className="text-white text-sm">{result.technical_details.server || 'Unknown'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Technologies:</span>
                            <div className="flex flex-wrap gap-1">
                              {result.technical_details.technologies?.map((tech, index) => (
                                <span key={index} className="px-2 py-1 bg-blue-500/20 text-blue-300 rounded text-xs">
                                  {tech}
                                </span>
                              )) || <span className="text-white text-sm">N/A</span>}
                            </div>
                          </div>
                        </div>
                        <div className="space-y-3">
                          <div className="flex justify-between">
                            <span className="text-gray-400">IP Address:</span>
                            <span className="text-white text-sm font-mono">
                              {result.technical_details.ip_address || 'N/A'}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Location:</span>
                            <span className="text-white text-sm">
                              {result.technical_details.location || 'Unknown'}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* AI Security Recommendations - Moved to End */}
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
                </div>
              </div>
            )}
          </div>
        )}

        {/* Other tabs content */}
        {activeTab === 'bulk' && isAuthenticated && renderBulkScanner()}
        {activeTab === 'analytics' && isAuthenticated && renderAnalytics()}

        {/* Companies Tab */}
        {activeTab === 'companies' && isAuthenticated && (
          <div className="max-w-6xl mx-auto space-y-8">
            {/* Company Management Header */}
            <div className="bg-white/10 backdrop-blur-md rounded-2xl p-8 border border-white/20">
              <div className="flex justify-between items-center mb-6">
                <div>
                  <h2 className="text-3xl font-bold text-white mb-2">🏢 Company Management</h2>
                  <p className="text-gray-300">Register companies for ongoing security monitoring and compliance tracking</p>
                </div>
                <button
                  onClick={() => setShowRegistrationForm(true)}
                  className="px-6 py-3 bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 text-white font-semibold rounded-xl transition-all duration-300 transform hover:scale-105"
                >
                  ➕ Register New Company
                </button>
              </div>
              
              <div className="grid md:grid-cols-3 gap-6 text-center">
                <div className="bg-white/5 rounded-lg p-4">
                  <div className="text-2xl font-bold text-cyan-400">{companies.length}</div>
                  <div className="text-gray-300">Total Companies</div>
                </div>
                <div className="bg-white/5 rounded-lg p-4">
                  <div className="text-2xl font-bold text-green-400">
                    {companies.filter(c => c.compliance_status === 'compliant').length}
                  </div>
                  <div className="text-gray-300">Compliant</div>
                </div>
                <div className="bg-white/5 rounded-lg p-4">
                  <div className="text-2xl font-bold text-red-400">
                    {companies.filter(c => c.compliance_status === 'non_compliant').length}
                  </div>
                  <div className="text-gray-300">Non-Compliant</div>
                </div>
              </div>
            </div>

            {/* Company Registration Form */}
            {showRegistrationForm && (
              <div className="bg-white/10 backdrop-blur-md rounded-2xl p-8 border border-white/20">
                <div className="flex justify-between items-center mb-6">
                  <h3 className="text-2xl font-bold text-white">Register New Company</h3>
                  <button
                    onClick={() => {
                      setShowRegistrationForm(false);
                      setNewCompany({
                        company_name: '',
                        website_url: '',
                        contact_email: '',
                        industry: '',
                        preferred_scan_frequency: 'daily',
                        additional_notes: ''
                      });
                    }}
                    className="text-gray-400 hover:text-white text-2xl"
                  >
                    ✕
                  </button>
                </div>
                
                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <label className="block text-white text-sm font-semibold mb-2">Company Name</label>
                    <input
                      type="text"
                      value={newCompany.company_name}
                      onChange={(e) => setNewCompany({...newCompany, company_name: e.target.value})}
                      className="w-full px-4 py-3 rounded-lg border border-white/30 bg-white/10 text-white placeholder-gray-400 focus:outline-none focus:border-cyan-400"
                      placeholder="Enter company name"
                    />
                  </div>
                  
                  <div>
                    <label className="block text-white text-sm font-semibold mb-2">Website URL</label>
                    <input
                      type="url"
                      value={newCompany.website_url}
                      onChange={(e) => setNewCompany({...newCompany, website_url: e.target.value})}
                      className="w-full px-4 py-3 rounded-lg border border-white/30 bg-white/10 text-white placeholder-gray-400 focus:outline-none focus:border-cyan-400"
                      placeholder="https://company.com"
                    />
                  </div>
                  
                  <div>
                    <label className="block text-white text-sm font-semibold mb-2">Contact Email</label>
                    <input
                      type="email"
                      value={newCompany.contact_email}
                      onChange={(e) => setNewCompany({...newCompany, contact_email: e.target.value})}
                      className="w-full px-4 py-3 rounded-lg border border-white/30 bg-white/10 text-white placeholder-gray-400 focus:outline-none focus:border-cyan-400"
                      placeholder="contact@company.com"
                    />
                  </div>
                  
                  <div>
                    <label className="block text-white text-sm font-semibold mb-2">Industry</label>
                    <select
                      value={newCompany.industry}
                      onChange={(e) => setNewCompany({...newCompany, industry: e.target.value})}
                      className="w-full px-4 py-3 rounded-lg border border-white/30 bg-white/10 text-white focus:outline-none focus:border-cyan-400"
                    >
                      <option value="">Select Industry</option>
                      <option value="finance">Finance & Banking</option>
                      <option value="ecommerce">E-commerce</option>
                      <option value="healthcare">Healthcare</option>
                      <option value="technology">Technology</option>
                      <option value="retail">Retail</option>
                      <option value="other">Other</option>
                    </select>
                  </div>
                  
                  <div>
                    <label className="block text-white text-sm font-semibold mb-2">Scan Frequency</label>
                    <select
                      value={newCompany.preferred_scan_frequency}
                      onChange={(e) => setNewCompany({...newCompany, preferred_scan_frequency: e.target.value})}
                      className="w-full px-4 py-3 rounded-lg border border-white/30 bg-white/10 text-white focus:outline-none focus:border-cyan-400"
                    >
                      <option value="daily">Daily</option>
                      <option value="weekly">Weekly</option>
                      <option value="monthly">Monthly</option>
                    </select>
                  </div>
                  
                  <div className="md:col-span-2">
                    <label className="block text-white text-sm font-semibold mb-2">Additional Notes</label>
                    <textarea
                      value={newCompany.additional_notes}
                      onChange={(e) => setNewCompany({...newCompany, additional_notes: e.target.value})}
                      className="w-full px-4 py-3 rounded-lg border border-white/30 bg-white/10 text-white placeholder-gray-400 focus:outline-none focus:border-cyan-400 h-24 resize-none"
                      placeholder="Any additional notes or special requirements..."
                    />
                  </div>
                </div>
                
                <div className="flex gap-4 mt-6">
                  <button
                    onClick={() => {
                      setShowRegistrationForm(false);
                      setNewCompany({
                        company_name: '',
                        website_url: '',
                        contact_email: '',
                        industry: '',
                        preferred_scan_frequency: 'daily',
                        additional_notes: ''
                      });
                    }}
                    className="flex-1 px-6 py-3 border border-white/30 text-white rounded-lg hover:bg-white/10 transition-all duration-300"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleCompanyRegistration}
                    className="flex-1 px-6 py-3 bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 text-white font-semibold rounded-lg transition-all duration-300"
                  >
                    Register Company
                  </button>
                </div>
              </div>
            )}

            {/* Companies List */}
            <div className="bg-white/10 backdrop-blur-md rounded-2xl p-8 border border-white/20">
              <h3 className="text-2xl font-bold text-white mb-6">📋 Registered Companies</h3>
              
              {companies.length === 0 ? (
                <div className="text-center py-8">
                  <div className="text-4xl mb-4">🏢</div>
                  <p className="text-gray-300">No companies registered yet</p>
                  <p className="text-gray-500 text-sm mt-2">Register your first company to start monitoring</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {companies.map((company) => (
                    <div key={company.company_id} className="bg-white/5 rounded-lg p-6 border border-white/10">
                      <div className="flex justify-between items-start mb-4">
                        <div className="flex-1">
                          <h4 className="text-xl font-semibold text-white mb-1">{company.company_name}</h4>
                          <a 
                            href={company.website_url} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="text-cyan-400 hover:text-cyan-300 transition-colors"
                          >
                            {company.website_url}
                          </a>
                        </div>
                        <div className="flex gap-2">
                          <button
                            onClick={() => triggerCompanyScan(company.company_id, 'e_skimming')}
                            className="px-3 py-1 bg-red-500/20 text-red-300 rounded text-sm hover:bg-red-500/30 transition-colors"
                          >
                            🔍 E-Skimming Scan
                          </button>
                          <button
                            onClick={() => triggerCompanyScan(company.company_id, 'standard')}
                            className="px-3 py-1 bg-blue-500/20 text-blue-300 rounded text-sm hover:bg-blue-500/30 transition-colors"
                          >
                            🔍 Standard Scan
                          </button>
                          <button
                            onClick={() => {
                              setSelectedCompany(company);
                              fetchCompanyScanHistory(company.company_id);
                            }}
                            className="px-3 py-1 bg-green-500/20 text-green-300 rounded text-sm hover:bg-green-500/30 transition-colors"
                          >
                            📊 View History
                          </button>
                        </div>
                      </div>
                      
                      <div className="grid md:grid-cols-4 gap-4 text-sm">
                        <div>
                          <span className="text-gray-400">Email:</span>
                          <div className="text-white">{company.contact_email}</div>
                        </div>
                        <div>
                          <span className="text-gray-400">Industry:</span>
                          <div className="text-white capitalize">{company.industry}</div>
                        </div>
                        <div>
                          <span className="text-gray-400">Scan Frequency:</span>
                          <div className="text-white capitalize">{company.preferred_scan_frequency}</div>
                        </div>
                        <div>
                          <span className="text-gray-400">Status:</span>
                          <div className={`font-semibold ${
                            company.compliance_status === 'compliant' ? 'text-green-400' :
                            company.compliance_status === 'non_compliant' ? 'text-red-400' :
                            'text-yellow-400'
                          }`}>
                            {company.compliance_status?.replace('_', ' ').toUpperCase() || 'PENDING'}
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Scan History Modal */}
            {selectedCompany && (
              <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                <div className="bg-slate-800 rounded-2xl p-8 max-w-6xl w-full max-h-[80vh] overflow-y-auto">
                  <div className="flex justify-between items-center mb-6">
                    <div>
                      <h3 className="text-2xl font-bold text-white">📊 Scan History</h3>
                      <p className="text-gray-300">{selectedCompany.company_name}</p>
                    </div>
                    <button
                      onClick={() => {
                        setSelectedCompany(null);
                        setCompanyScanHistory([]);
                      }}
                      className="text-gray-400 hover:text-white text-2xl"
                    >
                      ✕
                    </button>
                  </div>
                  
                  <div className="grid md:grid-cols-4 gap-4 mb-6">
                    <div className="bg-white/10 rounded-lg p-4 text-center">
                      <div className="text-2xl font-bold text-cyan-400">{companyScanHistory.length}</div>
                      <div className="text-gray-300 text-sm">Total Scans</div>
                    </div>
                    <div className="bg-white/10 rounded-lg p-4 text-center">
                      <div className={`text-2xl font-bold ${
                        selectedCompany.compliance_status === 'compliant' ? 'text-green-400' :
                        selectedCompany.compliance_status === 'non_compliant' ? 'text-red-400' :
                        'text-yellow-400'
                      }`}>
                        {selectedCompany.compliance_status?.replace('_', ' ').toUpperCase() || 'PENDING'}
                      </div>
                      <div className="text-gray-300 text-sm">Status</div>
                    </div>
                    <div className="bg-white/10 rounded-lg p-4 text-center">
                      <div className="text-2xl font-bold text-purple-400">{selectedCompany.industry}</div>
                      <div className="text-gray-300 text-sm">Industry</div>
                    </div>
                    <div className="bg-white/10 rounded-lg p-4 text-center">
                      <div className="text-2xl font-bold text-orange-400">{selectedCompany.preferred_scan_frequency}</div>
                      <div className="text-gray-300 text-sm">Frequency</div>
                    </div>
                  </div>
                  
                  <h4 className="text-xl font-semibold text-white mb-4">📊 Scan History</h4>
                  
                  {companyScanHistory.length === 0 ? (
                    <div className="text-center py-8">
                      <div className="text-4xl mb-4">📊</div>
                      <p className="text-gray-300">No scan history available</p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {companyScanHistory.map((scan, index) => (
                        <div key={scan.scan_id} className="bg-white/5 rounded-lg p-4 border border-white/10">
                          <div className="flex justify-between items-start mb-2">
                            <div>
                              <div className="flex items-center gap-3">
                                <span className={`px-2 py-1 rounded text-sm font-semibold ${
                                  scan.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                                  scan.status === 'processing' ? 'bg-yellow-500/20 text-yellow-400' :
                                  scan.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                                  'bg-blue-500/20 text-blue-400'
                                }`}>
                                  {scan.status.toUpperCase()}
                                </span>
                                <span className="px-2 py-1 bg-purple-500/20 text-purple-300 rounded text-sm">
                                  {scan.scan_type?.replace('_', ' ').toUpperCase()}
                                </span>
                              </div>
                              <div className="text-gray-300 text-sm mt-2">
                                Started: {new Date(scan.scan_date).toLocaleString()}
                              </div>
                            </div>
                            <div className="text-right">
                              <div className="text-white font-semibold">
                                {scan.summary?.scanned_urls || 0} URLs Scanned
                              </div>
                              {scan.summary && (
                                <div className="text-sm text-gray-300">
                                  {scan.summary.high_risk_urls} High Risk • {scan.summary.compliance_issues} Compliance Issues
                                </div>
                              )}
                            </div>
                          </div>
                          
                          {scan.status === 'completed' && scan.results && scan.results.length > 0 && (
                            <div className="mt-4 pt-4 border-t border-white/10">
                              <div className="grid md:grid-cols-3 gap-4 text-sm">
                                {scan.results.slice(0, 3).map((result, rIndex) => (
                                  <div key={rIndex} className="bg-white/5 rounded p-3">
                                    <div className="text-cyan-400 truncate mb-1">{result.url}</div>
                                    <div className="flex justify-between">
                                      <span className="text-gray-300">Risk:</span>
                                      <span className={`font-semibold ${
                                        result.risk_score >= 70 ? 'text-red-400' :
                                        result.risk_score >= 40 ? 'text-yellow-400' :
                                        'text-green-400'
                                      }`}>
                                        {result.risk_score}%
                                      </span>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

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

        {/* Login Modal */}
        {showLogin && (
          <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-slate-800 rounded-2xl p-8 max-w-md w-full">
              <div className="flex justify-between items-center mb-6">
                <h3 className="text-2xl font-bold text-white">🔑 Admin Login</h3>
                <button
                  onClick={() => setShowLogin(false)}
                  className="text-gray-400 hover:text-white text-2xl"
                >
                  ✕
                </button>
              </div>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-white text-sm font-semibold mb-2">Username</label>
                  <input
                    type="text"
                    value={loginData.username}
                    onChange={(e) => setLoginData({...loginData, username: e.target.value})}
                    className="w-full px-4 py-3 rounded-lg border border-white/30 bg-white/10 text-white focus:outline-none focus:border-cyan-400"
                    placeholder="Enter username"
                    onKeyPress={(e) => e.key === 'Enter' && handleLogin()}
                  />
                </div>
                
                <div>
                  <label className="block text-white text-sm font-semibold mb-2">Password</label>
                  <input
                    type="password"
                    value={loginData.password}
                    onChange={(e) => setLoginData({...loginData, password: e.target.value})}
                    className="w-full px-4 py-3 rounded-lg border border-white/30 bg-white/10 text-white focus:outline-none focus:border-cyan-400"
                    placeholder="Enter password"
                    onKeyPress={(e) => e.key === 'Enter' && handleLogin()}
                  />
                </div>
                
                {error && (
                  <div className="bg-red-500/20 border border-red-400 text-red-300 px-4 py-2 rounded-lg text-sm">
                    {error}
                  </div>
                )}
              </div>
              
              <div className="flex gap-3 mt-6">
                <button
                  onClick={() => setShowLogin(false)}
                  className="flex-1 px-4 py-3 border border-white/30 text-white rounded-lg hover:bg-white/10 transition-all duration-300"
                >
                  Cancel
                </button>
                <button
                  onClick={handleLogin}
                  className="flex-1 px-4 py-3 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white rounded-lg transition-all duration-300"
                >
                  Login
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;