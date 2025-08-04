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

  // Helper function to safely get nested properties
  const safeGet = (obj, path, defaultValue = null) => {
    return path.split('.').reduce((current, key) => {
      return current && typeof current === 'object' && key in current ? current[key] : defaultValue;
    }, obj);
  };

  // Effects and functions
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
        console.log('Login response:', data);
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
      console.log(`Triggering ${scanType} scan for company ${companyId}`);
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
        console.log('Full scan response:', data);
        
        // Enhanced result transformation with comprehensive data mapping
        const transformedResult = {
          // Core analysis data
          risk_score: data.risk_score || 0,
          is_malicious: data.is_malicious || false,
          threat_category: data.threat_category || 'unknown',
          scan_duration: data.scan_duration || 'N/A',
          scan_timestamp: data.scan_timestamp || new Date().toISOString(),
          
          // Detected threats
          threats: Array.isArray(safeGet(data, 'analysis_details.detected_threats')) ? 
            data.analysis_details.detected_threats : [],
          
          // Domain analysis with comprehensive mapping
          domain_analysis: {
            domain_age: safeGet(data, 'analysis_details.domain_analysis.domain_age_days') ? 
              `${Math.floor(safeGet(data, 'analysis_details.domain_analysis.domain_age_days') / 365)} years (${safeGet(data, 'analysis_details.domain_analysis.domain_age_days')} days)` : 'Unknown',
            registrar: safeGet(data, 'analysis_details.domain_analysis.registrar_info', 'N/A'),
            country: safeGet(data, 'analysis_details.domain_analysis.geographic_location', 'Not Available'),
            ssl_valid: safeGet(data, 'analysis_details.domain_analysis.has_ssl', false),
            reputation_score: safeGet(data, 'analysis_details.blacklist_analysis.reputation_score', data.risk_score) || 0
          },
          
          // DNS & Availability - Comprehensive mapping
          dns_availability: safeGet(data, 'analysis_details.detailed_report.dns_availability_check') ? {
            is_online: safeGet(data, 'analysis_details.detailed_report.dns_availability_check.url_online', false),
            response_time: safeGet(data, 'analysis_details.detailed_report.dns_availability_check.response_time_ms', 'N/A'),
            http_status: safeGet(data, 'analysis_details.detailed_report.dns_availability_check.http_status_code', 'N/A'),
            dns_resolvers: safeGet(data, 'analysis_details.detailed_report.dns_availability_check.dns_resolvers', {})
          } : null,
          
          // Detailed analysis - Only for detailed scans
          detailed_analysis: scanType === 'detailed' && safeGet(data, 'analysis_details.detailed_report') ? {
            // SSL Analysis with CORRECT mapping and comprehensive protocol details
            ssl_analysis: {
              certificate_valid: safeGet(data, 'analysis_details.detailed_report.ssl_detailed_analysis.ssl_available', true),
              issuer: safeGet(data, 'analysis_details.domain_analysis.ssl_issuer', 'N/A'),
              expiration_date: safeGet(data, 'analysis_details.domain_analysis.ssl_expires', 'N/A'),
              ssl_grade: safeGet(data, 'analysis_details.detailed_report.ssl_detailed_analysis.grade', 'N/A'),
              protocol_support: safeGet(data, 'analysis_details.detailed_report.ssl_detailed_analysis.protocol_support', {}),
              connection_details: safeGet(data, 'analysis_details.detailed_report.ssl_detailed_analysis.connection_details', {}),
              protocol_version: (() => {
                const protocols = safeGet(data, 'analysis_details.detailed_report.ssl_detailed_analysis.protocol_support', {});
                const enabledProtocols = Object.entries(protocols).filter(([_, enabled]) => enabled).map(([protocol, _]) => protocol);
                const disabledProtocols = Object.entries(protocols).filter(([_, enabled]) => !enabled).map(([protocol, _]) => protocol);
                
                if (enabledProtocols.length > 0) {
                  return `Supported: ${enabledProtocols.join(', ')}`;
                } else if (disabledProtocols.length > 0) {
                  return `All protocols disabled: ${disabledProtocols.join(', ')}`;
                } else {
                  return 'TLS connection issues detected';
                }
              })(),
              vulnerabilities: Array.isArray(safeGet(data, 'analysis_details.detailed_report.ssl_detailed_analysis.vulnerabilities')) ?
                data.analysis_details.detailed_report.ssl_detailed_analysis.vulnerabilities : 
                (safeGet(data, 'analysis_details.detailed_report.ssl_detailed_analysis.security_issues', [])),
              fallback_connection: safeGet(data, 'analysis_details.detailed_report.ssl_detailed_analysis.connection_details.fallback', null)
            },
            
            // Email Security Analysis with CORRECT mapping
            email_security: {
              spf_valid: safeGet(data, 'analysis_details.detailed_report.email_security_records.spf_record') !== null,
              dmarc_valid: safeGet(data, 'analysis_details.detailed_report.email_security_records.dmarc_record') !== null,
              dkim_valid: safeGet(data, 'analysis_details.detailed_report.email_security_records.dkim_selectors_found', []).length > 0,
              email_security_score: safeGet(data, 'analysis_details.detailed_report.email_security_records.email_security_score', 0),
              spf_status: safeGet(data, 'analysis_details.detailed_report.email_security_records.spf_status', 'Not checked'),
              dmarc_status: safeGet(data, 'analysis_details.detailed_report.email_security_records.dmarc_status', 'Not found'),
              dkim_status: safeGet(data, 'analysis_details.detailed_report.email_security_records.dkim_status', 'Not found')
            },
            
            // Threat Intelligence with CORRECT mapping
            threat_intelligence: {
              blacklist_status: safeGet(data, 'analysis_details.blacklist_analysis.is_blacklisted', false) ? 'blacklisted' : 'clean',
              malware_detected: safeGet(data, 'ml_predictions.malware_probability', 0) > 0.5,
              phishing_risk: safeGet(data, 'ml_predictions.phishing_probability', 0) > 0.7 ? 'high' : 
                           safeGet(data, 'ml_predictions.phishing_probability', 0) > 0.3 ? 'medium' : 'low',
              overall_risk_score: safeGet(data, 'analysis_details.detailed_report.comprehensive_threat_assessment.overall_risk_score', 0),
              reputation_score: safeGet(data, 'analysis_details.blacklist_analysis.reputation_score', 0)
            }
          } : null,
          
          // ML Predictions with CORRECT mapping and proper display
          ml_predictions: data.ml_predictions ? {
            phishing_model: {
              prediction: (data.ml_predictions.phishing_probability || 0) > 0.5 ? 'malicious' : 'safe',
              confidence: data.ml_predictions.phishing_probability || 0
            },
            malware_model: {
              prediction: (data.ml_predictions.malware_probability || 0) > 0.5 ? 'malicious' : 'safe', 
              confidence: data.ml_predictions.malware_probability || 0
            },
            e_skimming_model: {
              prediction: (data.ml_predictions.e_skimming_probability || 0) > 0.1 ? 'malicious' : 'safe',
              confidence: data.ml_predictions.e_skimming_probability || 0
            }
          } : {},
          
          // E-Skimming Evidence with proper mapping
          e_skimming_evidence: {
            indicators_found: Array.isArray(safeGet(data, 'analysis_details.e_skimming_analysis.indicators_found')) ?
              data.analysis_details.e_skimming_analysis.indicators_found : [],
            payment_security_score: safeGet(data, 'analysis_details.e_skimming_analysis.payment_security_score', 0),
            trusted_processor: safeGet(data, 'analysis_details.e_skimming_analysis.trusted_processor', false),
            e_skimming_probability: safeGet(data, 'ml_predictions.e_skimming_probability', 0)
          },
          
          // Content Analysis with CORRECT mapping
          content_analysis: {
            page_title: safeGet(data, 'analysis_details.content_analysis.page_title', 'N/A'),
            phishing_keywords: safeGet(data, 'analysis_details.content_analysis.phishing_keywords', 0),
            malware_indicators: safeGet(data, 'analysis_details.content_analysis.malware_indicators', 0),
            pattern_matches: safeGet(data, 'analysis_details.content_analysis.pattern_matches', 0),
            url_shortener: safeGet(data, 'analysis_details.content_analysis.url_shortener', false),
            homograph_attack: safeGet(data, 'analysis_details.content_analysis.homograph_attack', false),
            forms_count: 0, // Not provided in current response
            external_links_count: 0, // Not provided in current response
            javascript_count: 0, // Not provided in current response
            suspicious_keywords_count: safeGet(data, 'analysis_details.content_analysis.phishing_keywords', 0),
            content_size: 0 // Not provided in current response
          },
          
          // Technical Details with CORRECT mapping
          technical_details: {
            server: safeGet(data, 'analysis_details.technical_details.server_info', 'Unknown'),
            technologies: Array.isArray(safeGet(data, 'analysis_details.technical_details.technologies')) ? 
              data.analysis_details.technical_details.technologies : [],
            ip_address: safeGet(data, 'analysis_details.technical_details.ip_address', 'N/A'),
            location: safeGet(data, 'analysis_details.domain_analysis.geographic_location', 'Unknown'),
            dns_resolution_time: safeGet(data, 'analysis_details.domain_analysis.dns_resolution_time', 'N/A'),
            mx_records_exist: safeGet(data, 'analysis_details.domain_analysis.mx_records_exist', false)
          },
          
          // AI Recommendations
          recommendations: Array.isArray(data.recommendations) ? data.recommendations : [
            'Monitor this URL for security changes',
            'Implement additional protective measures if risk score is elevated',
            'Consider implementing advanced threat detection',
            'Review SSL/TLS configuration for optimal security',
            'Implement proper email security records (SPF, DMARC, DKIM)'
          ]
        };
        
        console.log('Transformed result:', transformedResult);
        setResult(transformedResult);
        fetchStats();
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
                  {/* Detected Threat Indicators */}
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
                            {result.dns_availability.dns_resolvers && typeof result.dns_availability.dns_resolvers === 'object' ? 
                              Object.entries(result.dns_availability.dns_resolvers).map(([resolver, statusObj]) => {
                                // Handle both simple status strings and complex status objects
                                let displayStatus = 'unknown';
                                let statusClass = 'bg-gray-500/20 text-gray-400';
                                
                                if (typeof statusObj === 'string' || typeof statusObj === 'boolean') {
                                  displayStatus = typeof statusObj === 'boolean' ? (statusObj ? 'resolved' : 'blocked') : statusObj;
                                } else if (typeof statusObj === 'object' && statusObj !== null) {
                                  // Handle complex status object
                                  displayStatus = statusObj.status || (statusObj.blocked === false ? 'resolved' : 'blocked');
                                }
                                
                                // Set appropriate CSS class
                                if (displayStatus === 'resolved' || displayStatus === true) {
                                  statusClass = 'bg-green-500/20 text-green-400';
                                } else if (displayStatus === 'blocked' || displayStatus === false) {
                                  statusClass = 'bg-red-500/20 text-red-400';
                                }
                                
                                return (
                                  <div key={resolver} className="flex justify-between items-center">
                                    <span className="text-gray-400 capitalize">{resolver}:</span>
                                    <span className={`px-2 py-1 rounded text-xs ${statusClass}`}>
                                      {displayStatus}
                                    </span>
                                  </div>
                                );
                              }) : (
                                <div className="text-gray-400">DNS resolver data not available</div>
                              )
                            }
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

                  {/* Detailed Security Analysis */}
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
                              <div className="text-xs text-gray-500 mt-1">
                                {result.detailed_analysis.email_security.spf_status || 'Status unknown'}
                              </div>
                            </div>
                            <div className="text-center p-3 bg-white/5 rounded">
                              <div className="text-sm text-gray-400 mb-1">DMARC Policy</div>
                              <div className={`font-semibold ${result.detailed_analysis.email_security.dmarc_valid ? 'text-green-400' : 'text-red-400'}`}>
                                {result.detailed_analysis.email_security.dmarc_valid ? '✅ Configured' : '❌ Not Configured'}
                              </div>
                              <div className="text-xs text-gray-500 mt-1">
                                {result.detailed_analysis.email_security.dmarc_status || 'Status unknown'}
                              </div>
                            </div>
                            <div className="text-center p-3 bg-white/5 rounded">
                              <div className="text-sm text-gray-400 mb-1">DKIM Signature</div>
                              <div className={`font-semibold ${result.detailed_analysis.email_security.dkim_valid ? 'text-green-400' : 'text-red-400'}`}>
                                {result.detailed_analysis.email_security.dkim_valid ? '✅ Present' : '❌ Missing'}
                              </div>
                              <div className="text-xs text-gray-500 mt-1">
                                {result.detailed_analysis.email_security.dkim_status || 'Status unknown'}
                              </div>
                            </div>
                          </div>
                          <div className="mt-4 text-center">
                            <div className="text-sm text-gray-400">Email Security Score</div>
                            <div className={`text-2xl font-bold ${
                              result.detailed_analysis.email_security.email_security_score >= 80 ? 'text-green-400' :
                              result.detailed_analysis.email_security.email_security_score >= 60 ? 'text-yellow-400' :
                              'text-red-400'
                            }`}>
                              {result.detailed_analysis.email_security.email_security_score}%
                            </div>
                            <div className="text-xs text-gray-500 mt-1">
                              Based on SPF, DMARC, and DKIM configuration
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
                            {result.detailed_analysis.threat_intelligence.overall_risk_score > 0 && (
                              <div className="flex justify-between">
                                <span className="text-gray-400">Overall Risk Score:</span>
                                <span className={`font-bold ${
                                  result.detailed_analysis.threat_intelligence.overall_risk_score >= 70 ? 'text-red-400' :
                                  result.detailed_analysis.threat_intelligence.overall_risk_score >= 40 ? 'text-yellow-400' :
                                  'text-green-400'
                                }`}>
                                  {result.detailed_analysis.threat_intelligence.overall_risk_score}%
                                </span>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* ML Model Predictions */}
                  {result.ml_predictions && Object.keys(result.ml_predictions).length > 0 && (
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
                            <span className="text-gray-400">Phishing Keywords:</span>
                            <span className={`font-semibold ${result.content_analysis.phishing_keywords > 0 ? 'text-red-400' : 'text-green-400'}`}>
                              {result.content_analysis.phishing_keywords || 0}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Malware Indicators:</span>
                            <span className={`font-semibold ${result.content_analysis.malware_indicators > 0 ? 'text-red-400' : 'text-green-400'}`}>
                              {result.content_analysis.malware_indicators || 0}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Pattern Matches:</span>
                            <span className="text-white">{result.content_analysis.pattern_matches || 0}</span>
                          </div>
                        </div>
                        <div className="space-y-3">
                          <div className="flex justify-between">
                            <span className="text-gray-400">URL Shortener:</span>
                            <span className={`${result.content_analysis.url_shortener ? 'text-yellow-400' : 'text-green-400'}`}>
                              {result.content_analysis.url_shortener ? '⚠️ Yes' : '✅ No'}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Homograph Attack:</span>
                            <span className={`${result.content_analysis.homograph_attack ? 'text-red-400' : 'text-green-400'}`}>
                              {result.content_analysis.homograph_attack ? '🚨 Detected' : '✅ None'}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Suspicious Patterns:</span>
                            <span className={`${result.content_analysis.suspicious_keywords_count > 0 ? 'text-red-400' : 'text-green-400'}`}>
                              {result.content_analysis.suspicious_keywords_count || 0}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* E-Skimming Evidence Section */}
                  {(scanType === 'e_skimming' || scanType === 'detailed') && result.e_skimming_evidence && (
                    <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
                      <h4 className="text-xl font-bold text-white mb-4">💳 E-Skimming Detection Evidence</h4>
                      <div className="grid md:grid-cols-2 gap-6">
                        <div className="space-y-3">
                          <div className="flex justify-between">
                            <span className="text-gray-400">E-Skimming Probability:</span>
                            <span className={`font-bold ${
                              result.e_skimming_evidence.e_skimming_probability > 0.1 ? 'text-red-400' :
                              result.e_skimming_evidence.e_skimming_probability > 0.01 ? 'text-yellow-400' :
                              'text-green-400'
                            }`}>
                              {(result.e_skimming_evidence.e_skimming_probability * 100).toFixed(4)}%
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Payment Security Score:</span>
                            <span className={`font-bold ${
                              result.e_skimming_evidence.payment_security_score >= 80 ? 'text-green-400' :
                              result.e_skimming_evidence.payment_security_score >= 60 ? 'text-yellow-400' :
                              'text-red-400'
                            }`}>
                              {result.e_skimming_evidence.payment_security_score}%
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Trusted Processor:</span>
                            <span className={`${result.e_skimming_evidence.trusted_processor ? 'text-green-400' : 'text-yellow-400'}`}>
                              {result.e_skimming_evidence.trusted_processor ? '✅ Yes' : '⚠️ Unknown'}
                            </span>
                          </div>
                        </div>
                        <div className="space-y-3">
                          <div>
                            <span className="text-gray-400 block mb-2">Indicators Found:</span>
                            {result.e_skimming_evidence.indicators_found.length > 0 ? (
                              <div className="space-y-1">
                                {result.e_skimming_evidence.indicators_found.map((indicator, index) => (
                                  <div key={index} className="px-2 py-1 bg-red-500/20 text-red-300 rounded text-xs">
                                    🚨 {indicator}
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <span className="text-green-400 text-sm">✅ No e-skimming indicators detected</span>
                            )}
                          </div>
                        </div>
                      </div>
                      {result.e_skimming_evidence.e_skimming_probability > 0.01 && (
                        <div className="mt-4 p-3 bg-yellow-500/10 rounded border border-yellow-400/20">
                          <div className="text-yellow-300 text-sm">
                            <div className="font-semibold mb-1">⚠️ E-Skimming Assessment:</div>
                            <div>Low-level probability detected. While not conclusive, exercise caution with payment processing on this domain.</div>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Technical Details */}
                  {result.technical_details && (
                    <div className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/20">
                      <h4 className="text-xl font-bold text-white mb-4">🔧 Technical Details</h4>
                      <div className="grid md:grid-cols-2 gap-6">
                        <div className="space-y-3">
                          <div className="flex justify-between">
                            <span className="text-gray-400">Location:</span>
                            <span className="text-white text-sm">{result.technical_details.location || 'Unknown'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">DNS Resolution Time:</span>
                            <span className="text-white text-sm">
                              {result.technical_details.dns_resolution_time ? `${result.technical_details.dns_resolution_time}ms` : 'N/A'}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">MX Records:</span>
                            <span className={`${result.technical_details.mx_records_exist ? 'text-green-400' : 'text-red-400'}`}>
                              {result.technical_details.mx_records_exist ? '✅ Present' : '❌ Not Found'}
                            </span>
                          </div>
                        </div>
                        <div className="space-y-3">
                          <div className="flex justify-between">
                            <span className="text-gray-400">Server:</span>
                            <span className="text-white text-sm">{result.technical_details.server || 'Unknown'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">IP Address:</span>
                            <span className="text-white text-sm font-mono">
                              {result.technical_details.ip_address || 'N/A'}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Technologies:</span>
                            <div className="flex flex-wrap gap-1">
                              {result.technical_details.technologies && result.technical_details.technologies.length > 0 ? 
                                result.technical_details.technologies.map((tech, index) => (
                                  <span key={index} className="px-2 py-1 bg-blue-500/20 text-blue-300 rounded text-xs">
                                    {tech}
                                  </span>
                                )) : <span className="text-white text-sm">N/A</span>}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* AI Security Recommendations */}
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

        {/* Companies Tab placeholder */}
        {activeTab === 'companies' && isAuthenticated && (
          <div className="max-w-6xl mx-auto space-y-8">
            <div className="text-center">
              <h2 className="text-3xl font-bold text-white mb-4">🏢 Company Management</h2>
              <p className="text-gray-300">Company management features coming soon...</p>
            </div>
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