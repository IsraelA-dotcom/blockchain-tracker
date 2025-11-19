import React, { useState, useEffect } from 'react';
import { Package, MapPin, Clock, Shield, Search, Plus, ChevronRight, CheckCircle, AlertTriangle, User, LogOut, Camera, X, Activity, Users, Eye, AlertCircle as Alert } from 'lucide-react';

const SupplyChainTrackerV2 = () => {
  const [currentUser, setCurrentUser] = useState(null);
  const [showLogin, setShowLogin] = useState(false);
  const [showRegister, setShowRegister] = useState(false);
  const [users, setUsers] = useState([
    { 
      id: 'admin1', 
      username: 'admin', 
      password: 'admin123', 
      role: 'admin', 
      company: 'System Admin',
      verified: true,
      licenseNumber: 'ADMIN-001'
    }
  ]);
  
  const [products, setProducts] = useState([]);
  const [selectedProduct, setSelectedProduct] = useState(null);
  const [showAddForm, setShowAddForm] = useState(false);
  const [showTrackForm, setShowTrackForm] = useState(false);
  const [searchId, setSearchId] = useState('');
  const [showAuditLog, setShowAuditLog] = useState(false);
  const [auditLogs, setAuditLogs] = useState([]);
  const [suspiciousActivities, setSuspiciousActivities] = useState([]);

  const [loginForm, setLoginForm] = useState({ username: '', password: '' });
  const [registerForm, setRegisterForm] = useState({
    username: '',
    password: '',
    company: '',
    role: 'manufacturer',
    licenseNumber: '',
    address: ''
  });

  const [newProduct, setNewProduct] = useState({
    name: '',
    category: 'pharmaceutical',
    manufacturer: '',
    origin: '',
    batchNumber: '',
    photo: null
  });

  const [trackEvent, setTrackEvent] = useState({
    stage: 'manufacturing',
    location: '',
    handler: '',
    notes: '',
    photo: null,
    gps: null
  });

  // Enhanced hash generation with user signature
  const generateHash = (data, userSignature = '') => {
    const str = JSON.stringify(data) + userSignature;
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(16, '0');
  };

  // Add audit log
  const addAuditLog = (action, details, severity = 'info') => {
    const log = {
      id: Date.now(),
      timestamp: new Date().toISOString(),
      user: currentUser?.username || 'Anonymous',
      userId: currentUser?.id || 'anonymous',
      action,
      details,
      severity,
      ipAddress: '127.0.0.1' // In production, get real IP
    };
    setAuditLogs([log, ...auditLogs]);
  };

  // Detect suspicious activity
  const detectSuspiciousActivity = (type, data) => {
    const recentActions = auditLogs.filter(log => 
      log.userId === currentUser?.id && 
      Date.now() - new Date(log.timestamp).getTime() < 60000 // Last minute
    );

    if (recentActions.length > 20) {
      const alert = {
        id: Date.now(),
        type: 'rate_limit',
        message: `User ${currentUser.username} performing ${recentActions.length} actions per minute`,
        severity: 'high',
        timestamp: new Date().toISOString()
      };
      setSuspiciousActivities([alert, ...suspiciousActivities]);
      return true;
    }

    return false;
  };

  // Get geolocation
  const getGeolocation = () => {
    return new Promise((resolve) => {
      if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(
          (position) => {
            resolve({
              lat: position.coords.latitude,
              lng: position.coords.longitude,
              accuracy: position.coords.accuracy
            });
          },
          () => resolve(null)
        );
      } else {
        resolve(null);
      }
    });
  };

  // Login
  const handleLogin = () => {
    const user = users.find(u => 
      u.username === loginForm.username && 
      u.password === loginForm.password
    );

    if (user) {
      setCurrentUser(user);
      setShowLogin(false);
      setLoginForm({ username: '', password: '' });
      addAuditLog('login', `User ${user.username} logged in`, 'info');
    } else {
      alert('Invalid credentials');
      addAuditLog('login_failed', `Failed login attempt for ${loginForm.username}`, 'warning');
    }
  };

  // Register
  const handleRegister = () => {
    if (!registerForm.username || !registerForm.password || !registerForm.company) {
      alert('Please fill all required fields');
      return;
    }

    if (users.some(u => u.username === registerForm.username)) {
      alert('Username already exists');
      return;
    }

    const newUser = {
      id: `user_${Date.now()}`,
      ...registerForm,
      verified: false,
      createdAt: new Date().toISOString()
    };

    setUsers([...users, newUser]);
    setShowRegister(false);
    setRegisterForm({
      username: '',
      password: '',
      company: '',
      role: 'manufacturer',
      licenseNumber: '',
      address: ''
    });
    alert('Registration successful! Pending admin verification.');
    addAuditLog('user_registered', `New user ${newUser.username} registered`, 'info');
  };

  // Logout
  const handleLogout = () => {
    addAuditLog('logout', `User ${currentUser.username} logged out`, 'info');
    setCurrentUser(null);
    setSelectedProduct(null);
  };

  // Verify user (admin only)
  const verifyUser = (userId) => {
    if (currentUser?.role !== 'admin') return;
    
    setUsers(users.map(u => 
      u.id === userId ? { ...u, verified: true } : u
    ));
    addAuditLog('user_verified', `Admin verified user ${userId}`, 'info');
  };

  // Create product with enhanced security
  const createProduct = async () => {
    if (!currentUser) {
      alert('Please login first');
      return;
    }

    if (!currentUser.verified) {
      alert('Your account is not verified yet. Please wait for admin approval.');
      return;
    }

    if (currentUser.role !== 'manufacturer' && currentUser.role !== 'admin') {
      alert('Only manufacturers can register products');
      return;
    }

    if (!newProduct.name || !newProduct.origin) {
      alert('Please fill all required fields');
      return;
    }

    // Check for suspicious activity
    if (detectSuspiciousActivity('product_creation', newProduct)) {
      alert('Suspicious activity detected. Action blocked.');
      return;
    }

    const timestamp = new Date().toISOString();
    const productId = `PRD-${Date.now().toString(36).toUpperCase()}`;
    const gps = await getGeolocation();
    
    const userSignature = generateHash({
      userId: currentUser.id,
      username: currentUser.username,
      company: currentUser.company
    });

    const initialBlock = {
      blockNumber: 0,
      timestamp,
      stage: 'created',
      location: newProduct.origin,
      handler: currentUser.company,
      handlerId: currentUser.id,
      notes: 'Product registered in supply chain',
      previousHash: '0',
      hash: '',
      userSignature,
      photo: newProduct.photo,
      gps
    };

    initialBlock.hash = generateHash({
      ...initialBlock,
      productId,
      ...newProduct
    }, userSignature);

    const product = {
      id: productId,
      name: newProduct.name,
      category: newProduct.category,
      manufacturer: currentUser.company,
      manufacturerId: currentUser.id,
      origin: newProduct.origin,
      batchNumber: newProduct.batchNumber,
      photo: newProduct.photo,
      createdAt: timestamp,
      createdBy: currentUser.username,
      chain: [initialBlock],
      status: 'in-transit',
      verified: currentUser.verified,
      verificationLevel: currentUser.verified ? 'verified' : 'unverified',
      licenseNumber: currentUser.licenseNumber
    };

    setProducts([product, ...products]);
    setNewProduct({
      name: '',
      category: 'pharmaceutical',
      manufacturer: '',
      origin: '',
      batchNumber: '',
      photo: null
    });
    setShowAddForm(false);
    
    addAuditLog('product_created', `Product ${productId} created by ${currentUser.company}`, 'info');
  };

  // Add tracking event with security
  const addTrackingEvent = async () => {
    if (!currentUser) {
      alert('Please login first');
      return;
    }

    if (!trackEvent.location || !trackEvent.handler) {
      alert('Please fill location and handler fields');
      return;
    }

    // Verify user has permission
    const canModify = currentUser.role === 'admin' || 
                      selectedProduct.manufacturerId === currentUser.id ||
                      currentUser.verified;

    if (!canModify) {
      alert('You do not have permission to add checkpoints to this product');
      return;
    }

    const timestamp = new Date().toISOString();
    const previousBlock = selectedProduct.chain[selectedProduct.chain.length - 1];
    const gps = await getGeolocation();
    
    // Check geographic impossibility
    if (previousBlock.gps && gps) {
      const timeDiff = (new Date(timestamp) - new Date(previousBlock.timestamp)) / 1000 / 60; // minutes
      const distance = calculateDistance(previousBlock.gps, gps); // km
      const speed = distance / (timeDiff / 60); // km/h
      
      if (speed > 900) { // Faster than airplane
        const alert = {
          id: Date.now(),
          type: 'impossible_movement',
          message: `Product moved ${distance}km in ${timeDiff} minutes (${speed}km/h) - Physically impossible`,
          severity: 'critical',
          timestamp
        };
        setSuspiciousActivities([alert, ...suspiciousActivities]);
        
        if (confirm('Suspicious movement detected! This checkpoint seems physically impossible. Continue anyway?')) {
          // Allow admin override
        } else {
          return;
        }
      }
    }

    const userSignature = generateHash({
      userId: currentUser.id,
      username: currentUser.username,
      company: currentUser.company
    });
    
    const newBlock = {
      blockNumber: selectedProduct.chain.length,
      timestamp,
      stage: trackEvent.stage,
      location: trackEvent.location,
      handler: trackEvent.handler,
      handlerId: currentUser.id,
      notes: trackEvent.notes,
      previousHash: previousBlock.hash,
      hash: '',
      userSignature,
      photo: trackEvent.photo,
      gps
    };

    newBlock.hash = generateHash({
      ...newBlock,
      productId: selectedProduct.id
    }, userSignature);

    const updatedProduct = {
      ...selectedProduct,
      chain: [...selectedProduct.chain, newBlock],
      status: trackEvent.stage === 'delivered' ? 'delivered' : 'in-transit',
      lastUpdatedBy: currentUser.username,
      lastUpdatedAt: timestamp
    };

    setProducts(products.map(p => p.id === selectedProduct.id ? updatedProduct : p));
    setSelectedProduct(updatedProduct);
    setTrackEvent({
      stage: 'manufacturing',
      location: '',
      handler: '',
      notes: '',
      photo: null,
      gps: null
    });
    setShowTrackForm(false);
    
    addAuditLog('checkpoint_added', `Checkpoint added to ${selectedProduct.id} at ${trackEvent.location}`, 'info');
  };

  // Calculate distance between two GPS points (Haversine formula)
  const calculateDistance = (gps1, gps2) => {
    const R = 6371; // Earth's radius in km
    const dLat = (gps2.lat - gps1.lat) * Math.PI / 180;
    const dLon = (gps2.lng - gps1.lng) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(gps1.lat * Math.PI / 180) * Math.cos(gps2.lat * Math.PI / 180) *
              Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
  };

  // Search product
  const searchProduct = () => {
    const product = products.find(p => p.id === searchId.trim());
    if (product) {
      setSelectedProduct(product);
      setSearchId('');
      addAuditLog('product_searched', `Product ${searchId} searched`, 'info');
    } else {
      alert('Product not found');
    }
  };

  // Enhanced chain verification with user signature check
  const verifyChain = (product) => {
    for (let i = 1; i < product.chain.length; i++) {
      const block = product.chain[i];
      const previousBlock = product.chain[i - 1];
      
      if (block.previousHash !== previousBlock.hash) {
        return { valid: false, reason: 'Hash mismatch' };
      }

      // Verify user signature exists
      if (!block.userSignature) {
        return { valid: false, reason: 'Missing user signature' };
      }

      // Verify handler exists in users
      const handler = users.find(u => u.id === block.handlerId);
      if (!handler) {
        return { valid: false, reason: 'Unknown handler' };
      }
    }
    return { valid: true, reason: 'All checks passed' };
  };

  // Handle photo upload
  const handlePhotoUpload = (e, setter) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setter(prev => ({ ...prev, photo: reader.result }));
      };
      reader.readAsDataURL(file);
    }
  };

  const getStageColor = (stage) => {
    const colors = {
      created: 'bg-blue-100 text-blue-800',
      manufacturing: 'bg-purple-100 text-purple-800',
      quality_check: 'bg-yellow-100 text-yellow-800',
      warehouse: 'bg-orange-100 text-orange-800',
      distribution: 'bg-cyan-100 text-cyan-800',
      retail: 'bg-green-100 text-green-800',
      delivered: 'bg-emerald-100 text-emerald-800'
    };
    return colors[stage] || 'bg-gray-100 text-gray-800';
  };

  const getStatusBadge = (product) => {
    const verification = verifyChain(product);
    
    if (!verification.valid) {
      return <span className="px-3 py-1 bg-red-100 text-red-800 rounded-full text-sm font-semibold flex items-center gap-1">
        <AlertTriangle size={14} />
        TAMPERED
      </span>;
    }
    
    if (!product.verified) {
      return <span className="px-3 py-1 bg-yellow-100 text-yellow-800 rounded-full text-sm font-semibold flex items-center gap-1">
        <Alert size={14} />
        Unverified
      </span>;
    }

    if (product.status === 'delivered') {
      return <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm font-semibold flex items-center gap-1">
        <CheckCircle size={14} />
        Delivered
      </span>;
    }
    
    return <span className="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm font-semibold">In Transit</span>;
  };

  const getVerificationBadge = (user) => {
    if (user.verified) {
      return <CheckCircle size={16} className="text-green-600" />;
    }
    return <AlertTriangle size={16} className="text-yellow-600" />;
  };

  // If not logged in, show login screen
  if (!currentUser) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 flex items-center justify-center p-6">
        <div className="bg-white rounded-xl shadow-2xl p-8 max-w-md w-full">
          <div className="flex items-center gap-3 mb-6">
            <div className="w-12 h-12 bg-blue-600 rounded-lg flex items-center justify-center">
              <Shield className="text-white" size={28} />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">Supply Chain Tracker</h1>
              <p className="text-gray-600 text-sm">Secure & Verified</p>
            </div>
          </div>

          {!showLogin && !showRegister && (
            <div className="space-y-3">
              <button
                onClick={() => setShowLogin(true)}
                className="w-full py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium"
              >
                Login
              </button>
              <button
                onClick={() => setShowRegister(true)}
                className="w-full py-3 border-2 border-blue-600 text-blue-600 rounded-lg hover:bg-blue-50 transition-colors font-medium"
              >
                Register Company
              </button>
              <button
                onClick={() => {
                  setCurrentUser({ id: 'guest', username: 'Guest', role: 'customer', verified: false });
                }}
                className="w-full py-3 border-2 border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors font-medium"
              >
                Continue as Guest (View Only)
              </button>
            </div>
          )}

          {showLogin && (
            <div className="space-y-4">
              <h2 className="text-xl font-bold mb-4">Login</h2>
              <input
                type="text"
                placeholder="Username"
                value={loginForm.username}
                onChange={(e) => setLoginForm({...loginForm, username: e.target.value})}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
              />
              <input
                type="password"
                placeholder="Password"
                value={loginForm.password}
                onChange={(e) => setLoginForm({...loginForm, password: e.target.value})}
                onKeyPress={(e) => e.key === 'Enter' && handleLogin()}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
              />
              <div className="flex gap-3">
                <button
                  onClick={() => setShowLogin(false)}
                  className="flex-1 py-3 border-2 border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors font-medium"
                >
                  Back
                </button>
                <button
                  onClick={handleLogin}
                  className="flex-1 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium"
                >
                  Login
                </button>
              </div>
              <p className="text-sm text-gray-600 text-center mt-4">
                Demo: username: <strong>admin</strong>, password: <strong>admin123</strong>
              </p>
            </div>
          )}

          {showRegister && (
            <div className="space-y-4">
              <h2 className="text-xl font-bold mb-4">Register Company</h2>
              <input
                type="text"
                placeholder="Username *"
                value={registerForm.username}
                onChange={(e) => setRegisterForm({...registerForm, username: e.target.value})}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
              />
              <input
                type="password"
                placeholder="Password *"
                value={registerForm.password}
                onChange={(e) => setRegisterForm({...registerForm, password: e.target.value})}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
              />
              <input
                type="text"
                placeholder="Company Name *"
                value={registerForm.company}
                onChange={(e) => setRegisterForm({...registerForm, company: e.target.value})}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
              />
              <select
                value={registerForm.role}
                onChange={(e) => setRegisterForm({...registerForm, role: e.target.value})}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
              >
                <option value="manufacturer">Manufacturer</option>
                <option value="distributor">Distributor</option>
                <option value="retailer">Retailer</option>
                <option value="inspector">Quality Inspector</option>
              </select>
              <input
                type="text"
                placeholder="License Number"
                value={registerForm.licenseNumber}
                onChange={(e) => setRegisterForm({...registerForm, licenseNumber: e.target.value})}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
              />
              <input
                type="text"
                placeholder="Business Address"
                value={registerForm.address}
                onChange={(e) => setRegisterForm({...registerForm, address: e.target.value})}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
              />
              <div className="flex gap-3">
                <button
                  onClick={() => setShowRegister(false)}
                  className="flex-1 py-3 border-2 border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors font-medium"
                >
                  Back
                </button>
                <button
                  onClick={handleRegister}
                  className="flex-1 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium"
                >
                  Register
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="bg-white rounded-xl shadow-lg p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 bg-blue-600 rounded-lg flex items-center justify-center">
                <Shield className="text-white" size={28} />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Blockchain Supply Chain</h1>
                <p className="text-gray-600 text-sm">Secure & Transparent Tracking</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="text-right">
                <div className="flex items-center gap-2">
                  <p className="font-semibold text-gray-900">{currentUser.company || currentUser.username}</p>
                  {getVerificationBadge(currentUser)}
                </div>
                <p className="text-sm text-gray-600 capitalize">{currentUser.role}</p>
              </div>
              {currentUser.role === 'admin' && (
                <button
                  onClick={() => setShowAuditLog(!showAuditLog)}
                  className="p-2 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors"
                  title="View Audit Log"
                >
                  <Activity size={20} />
                </button>
              )}
              <button
                onClick={handleLogout}
                className="p-2 bg-red-100 text-red-600 rounded-lg hover:bg-red-200 transition-colors"
              >
                <LogOut size={20} />
              </button>
            </div>
          </div>

          {!currentUser.verified && currentUser.role !== 'customer' && (
            <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg flex items-center gap-2">
              <AlertTriangle size={20} className="text-yellow-600" />
              <span className="text-sm text-yellow-800">
                Your account is pending verification. You can view products but cannot register new ones.
              </span>
            </div>
          )}

          {suspiciousActivities.length > 0 && currentUser.role === 'admin' && (
            <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle size={20} className="text-red-600" />
                <span className="font-semibold text-red-900">Suspicious Activities Detected</span>
              </div>
              {suspiciousActivities.slice(0, 3).map(alert => (
                <div key={alert.id} className="text-sm text-red-800 ml-7">
                  • {alert.message}
                </div>
              ))}
            </div>
          )}

          <div className="flex gap-2">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-3 text-gray-400" size={20} />
              <input
                type="text"
                value={searchId}
                onChange={(e) => setSearchId(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && searchProduct()}
                placeholder="Enter Product ID to track..."
                className="w-full pl-10 pr-4 py-3 border-2 border-gray-200 rounded-lg focus:border-blue-500 focus:outline-none"
              />
            </div>
            <button
              onClick={searchProduct}
              className="px-6 py-3 bg-gray-900 text-white rounded-lg hover:bg-gray-800 transition-colors font-medium"
            >
              Track
            </button>
            {(currentUser.role === 'manufacturer' || currentUser.role === 'admin') && currentUser.verified && (
              <button
                onClick={() => setShowAddForm(true)}
                className="flex items-center gap-2 px-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium"
              >
                <Plus size={20} />
                Add Product
              </button>
            )}
          </div>
        </div>

        {currentUser.role === 'admin' && showAuditLog && (
          <div className="bg-white rounded-xl shadow-lg p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-bold text-gray-900">Admin Dashboard</h2>
              <button onClick={() => setShowAuditLog(false)} className="text-gray-500 hover:text-gray-700">
                <X size={20} />
              </button>
            </div>

            <div className="mb-6">
              <h3 className="font-semibold text-gray-900 mb-3">Pending Verifications</h3>
              <div className="space-y-2">
                {users.filter(u => !u.verified && u.role !== 'admin').map(user => (
                  <div key={user.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div>
                      <p className="font-semibold">{user.company}</p>
                      <p className="text-sm text-gray-600">{user.username} • {user.role}</p>
                      <p className="text-xs text-gray-500">License: {user.licenseNumber || 'N/A'}</p>
                    </div>
                    <button
                      onClick={() => verifyUser(user.id)}
                      className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors text-sm font-medium"
                    >
                      Verify
                    </button>
                  </div>
                ))}
                {users.filter(u => !u.verified && u.role !== 'admin').length === 0 && (
                  <p className="text-gray-500 text-sm">No pending verifications</p>
                )}
              </div>
            </div>

            <div>
              <h3 className="font-semibold text-gray-900 mb-3">Recent Activity</h3>
              <div className="max-h-64 overflow-y-auto space-y-2">
                {auditLogs.slice(0, 20).map(log => (
                  <div key={log.id} className={`p-3 rounded-lg text-sm ${
                    log.severity === 'warning' ? 'bg-yellow-50' : 
                    log.severity === 'critical' ? 'bg-red-50' : 'bg-gray-50'
                  }`}>
                    <div className="flex items-center justify-between">
                      <span className="font-semibold">{log.action}</span>
                      <span className="text-xs text-gray-500">
                        {new Date(log.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-gray-700 mt-1">{log.details}</p>
                    <p className="text-xs text-gray-500 mt-1">User: {log.user}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1">
            <div className="bg-white rounded-xl shadow-lg p-6">
              <h2 className="text-lg font-bold text-gray-900 mb-4">
                Products ({products.length})
              </h2>
              <div className="space-y-3 max-h-[600px] overflow-y-auto">
                {products.length === 0 ? (
                  <div className="text-center py-8 text-gray-500">
                    <Package size={48} className="mx-auto mb-3 opacity-30" />
                    <p>No products yet</p>
                    <p className="text-sm">Add your first product</p>
                  </div>
                ) : (
                  products.map(product => (
                    <div
                      key={product.id}
                      onClick={() => setSelectedProduct(product)}
                      className={`p-4 border-2 rounded-lg cursor-pointer transition-all ${
                        selectedProduct?.id === product.id
                          ? 'border-blue-500 bg-blue-50'
                          : 'border-gray-200 hover:border-gray-300'
                      }`}
                    >
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex-1">
                          <h3 className="font-bold text-gray-900">{product.name}</h3>
                          <p className="text-sm text-gray-600 font-mono">{product.id}</p>
                        </div>
                        {getStatusBadge(product)}
                      </div>
                      <div className="flex items-center gap-2 text-sm text-gray-600">
                        <MapPin size={14} />
                        <span>{product.origin}</span>
                      </div>
                      <div className="flex items-center gap-2 text-sm text-gray-600 mt-1">
                        <Package size={14} />
                        <span>{product.chain.length} checkpoints</span>
                      </div>
                      <div className="flex items-center gap-2 text-sm text-gray-600 mt-1">
                        <User size={14} />
                        <span>{product.manufacturer}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          <div className="lg:col-span-2">
            {selectedProduct ? (
              <div className="space-y-6">
                <div className="bg-white rounded-xl shadow-lg p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <h2 className="text-2xl font-bold text-gray-900 mb-2">
                        {selectedProduct.name}
                      </h2>
                      <p className="text-gray-600 font-mono text-sm">{selectedProduct.id}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      {(() => {
                        const verification = verifyChain(selectedProduct);
                        return verification.valid ? (
                          <div className="flex items-center gap-2 text-green-600">
                            <CheckCircle size={20} />
                            <span className="font-semibold">Verified</span>
                          </div>
                        ) : (
                          <div className="flex items-center gap-2 text-red-600">
                            <AlertTriangle size={20} />
                            <span className="font-semibold">Tampered</span>
                          </div>
                        );
                      })()}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4 mb-4">
                    <div>
                      <p className="text-sm text-gray-600">Category</p>
                      <p className="font-semibold capitalize">{selectedProduct.category}</p>
                    </div>
                    <div>
                      <p className="text-sm text-gray-600">Manufacturer</p>
                      <div className="flex items-center gap-1">
                        <p className="font-semibold">{selectedProduct.manufacturer}</p>
                        {selectedProduct.verified && <CheckCircle size={14} className="text-green-600" />}
                      </div>
                    </div>
                    <div>
                      <p className="text-sm text-gray-600">Origin</p>
                      <p className="font-semibold">{selectedProduct.origin}</p>
                    </div>
                    <div>
                      <p className="text-sm text-gray-600">Batch Number</p>
                      <p className="font-semibold">{selectedProduct.batchNumber || 'N/A'}</p>
                    </div>
                    <div>
                      <p className="text-sm text-gray-600">License #</p>
                      <p className="font-semibold">{selectedProduct.licenseNumber || 'N/A'}</p>
                    </div>
                    <div>
                      <p className="text-sm text-gray-600">Created By</p>
                      <p className="font-semibold">{selectedProduct.createdBy}</p>
                    </div>
                  </div>

                  {currentUser.role !== 'customer' && currentUser.verified && (
                    <button
                      onClick={() => setShowTrackForm(true)}
                      className="w-full py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium"
                    >
                      Add Checkpoint
                    </button>
                  )}
                </div>

                <div className="bg-white rounded-xl shadow-lg p-6">
                  <h3 className="text-lg font-bold text-gray-900 mb-4">
                    Supply Chain History
                  </h3>
                  <div className="space-y-4">
                    {selectedProduct.chain.map((block, index) => (
                      <div key={index} className="relative pl-8 pb-4 border-l-2 border-blue-200 last:border-0">
                        <div className="absolute left-0 top-0 w-4 h-4 bg-blue-600 rounded-full -translate-x-[9px]"></div>
                        
                        <div className="bg-gray-50 rounded-lg p-4">
                          <div className="flex items-center justify-between mb-2">
                            <span className={`px-3 py-1 rounded-full text-xs font-bold ${getStageColor(block.stage)}`}>
                              {block.stage.replace('_', ' ').toUpperCase()}
                            </span>
                            <span className="text-sm text-gray-600">
                              Block #{block.blockNumber}
                            </span>
                          </div>
                          
                          <div className="grid grid-cols-2 gap-3 text-sm mb-3">
                            <div>
                              <p className="text-gray-600">Location</p>
                              <p className="font-semibold">{block.location}</p>
                            </div>
                            <div>
                              <p className="text-gray-600">Handler</p>
                              <p className="font-semibold">{block.handler}</p>
                            </div>
                          </div>

                          {block.gps && (
                            <div className="text-xs text-gray-600 mb-2">
                              📍 GPS: {block.gps.lat.toFixed(4)}, {block.gps.lng.toFixed(4)}
                            </div>
                          )}

                          {block.photo && (
                            <div className="mb-3">
                              <img src={block.photo} alt="Checkpoint" className="w-full h-32 object-cover rounded-lg" />
                            </div>
                          )}

                          {block.notes && (
                            <p className="text-sm text-gray-700 mb-3">{block.notes}</p>
                          )}

                          <div className="text-xs text-gray-500 space-y-1">
                            <div className="flex items-center gap-2">
                              <Clock size={12} />
                              <span>{new Date(block.timestamp).toLocaleString()}</span>
                            </div>
                            <div className="font-mono bg-gray-100 px-2 py-1 rounded break-all">
                              Hash: {block.hash}
                            </div>
                            {block.previousHash !== '0' && (
                              <div className="font-mono bg-gray-100 px-2 py-1 rounded break-all">
                                Prev: {block.previousHash}
                              </div>
                            )}
                            {block.userSignature && (
                              <div className="font-mono bg-green-50 px-2 py-1 rounded break-all text-green-700">
                                ✓ Signed: {block.userSignature.substring(0, 16)}...
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-white rounded-xl shadow-lg p-12 text-center">
                <Package size={64} className="mx-auto mb-4 text-gray-300" />
                <h3 className="text-xl font-bold text-gray-900 mb-2">No Product Selected</h3>
                <p className="text-gray-600">Select a product from the list or search by ID</p>
              </div>
            )}
          </div>
        </div>

        {showAddForm && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white rounded-xl shadow-2xl max-w-md w-full p-6 max-h-[90vh] overflow-y-auto">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Register New Product</h3>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-1">
                    Product Name *
                  </label>
                  <input
                    type="text"
                    value={newProduct.name}
                    onChange={(e) => setNewProduct({...newProduct, name: e.target.value})}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
                    placeholder="e.g., Paracetamol 500mg"
                  />
                </div>

                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-1">
                    Category *
                  </label>
                  <select
                    value={newProduct.category}
                    onChange={(e) => setNewProduct({...newProduct, category: e.target.value})}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
                  >
                    <option value="pharmaceutical">Pharmaceutical</option>
                    <option value="food">Food & Beverage</option>
                    <option value="electronics">Electronics</option>
                    <option value="textiles">Textiles</option>
                    <option value="automotive">Automotive</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-1">
                    Origin Location *
                  </label>
                  <input
                    type="text"
                    value={newProduct.origin}
                    onChange={(e) => setNewProduct({...newProduct, origin: e.target.value})}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
                    placeholder="City, Country"
                  />
                </div>

                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-1">
                    Batch Number
                  </label>
                  <input
                    type="text"
                    value={newProduct.batchNumber}
                    onChange={(e) => setNewProduct({...newProduct, batchNumber: e.target.value})}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
                    placeholder="Optional"
                  />
                </div>

                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-1">
                    Product Photo
                  </label>
                  <input
                    type="file"
                    accept="image/*"
                    onChange={(e) => handlePhotoUpload(e, setNewProduct)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
                  />
                  {newProduct.photo && (
                    <img src={newProduct.photo} alt="Preview" className="mt-2 w-full h-32 object-cover rounded-lg" />
                  )}
                </div>
              </div>

              <div className="flex gap-3 mt-6">
                <button
                  onClick={() => setShowAddForm(false)}
                  className="flex-1 py-2 border-2 border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors font-medium"
                >
                  Cancel
                </button>
                <button
                  onClick={createProduct}
                  className="flex-1 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium"
                >
                  Register
                </button>
              </div>
            </div>
          </div>
        )}

        {showTrackForm && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white rounded-xl shadow-2xl max-w-md w-full p-6 max-h-[90vh] overflow-y-auto">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Add Checkpoint</h3>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-1">
                    Stage *
                  </label>
                  <select
                    value={trackEvent.stage}
                    onChange={(e) => setTrackEvent({...trackEvent, stage: e.target.value})}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
                  >
                    <option value="manufacturing">Manufacturing</option>
                    <option value="quality_check">Quality Check</option>
                    <option value="warehouse">Warehouse</option>
                    <option value="distribution">Distribution</option>
                    <option value="retail">Retail</option>
                    <option value="delivered">Delivered</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-1">
                    Location *
                  </label>
                  <input
                    type="text"
                    value={trackEvent.location}
                    onChange={(e) => setTrackEvent({...trackEvent, location: e.target.value})}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
                    placeholder="City, Country"
                  />
                </div>

                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-1">
                    Handler *
                  </label>
                  <input
                    type="text"
                    value={trackEvent.handler}
                    onChange={(e) => setTrackEvent({...trackEvent, handler: e.target.value})}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
                    placeholder="Person or company"
                  />
                </div>

                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-1">
                    Notes
                  </label>
                  <textarea
                    value={trackEvent.notes}
                    onChange={(e) => setTrackEvent({...trackEvent, notes: e.target.value})}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
                    rows="3"
                    placeholder="Additional information"
                  />
                </div>

                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-1">
                    Photo Evidence
                  </label>
                  <input
                    type="file"
                    accept="image/*"
                    onChange={(e) => handlePhotoUpload(e, setTrackEvent)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
                  />
                  {trackEvent.photo && (
                    <img src={trackEvent.photo} alt="Preview" className="mt-2 w-full h-32 object-cover rounded-lg" />
                  )}
                </div>
              </div>

              <div className="flex gap-3 mt-6">
                <button
                  onClick={() => setShowTrackForm(false)}
                  className="flex-1 py-2 border-2 border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors font-medium"
                >
                  Cancel
                </button>
                <button
                  onClick={addTrackingEvent}
                  className="flex-1 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium"
                >
                  Add
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default SupplyChainTrackerV2;
