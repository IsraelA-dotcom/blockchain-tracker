const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3002;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// In-memory storage (use MongoDB/PostgreSQL in production)
let users = [
  {
    id: 'admin1',
    username: 'admin',
    password: bcrypt.hashSync('admin123', 10),
    role: 'admin',
    company: 'System Admin',
    verified: true,
    licenseNumber: 'ADMIN-001',
    createdAt: new Date().toISOString()
  }
];

let products = [];
let auditLogs = [];
let suspiciousActivities = [];

// Middleware: Verify JWT token
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = users.find(u => u.id === decoded.userId);
    if (!req.user) {
      return res.status(401).json({ error: 'User not found' });
    }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Middleware: Admin only
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Add audit log
const addAuditLog = (userId, username, action, details, severity = 'info') => {
  const log = {
    id: Date.now().toString(),
    timestamp: new Date().toISOString(),
    userId,
    user: username,
    action,
    details,
    severity,
    ipAddress: '127.0.0.1'
  };
  auditLogs.unshift(log);
  
  // Keep only last 1000 logs
  if (auditLogs.length > 1000) {
    auditLogs = auditLogs.slice(0, 1000);
  }
};

// Generate hash for blockchain
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

// Calculate distance between GPS coordinates
const calculateDistance = (gps1, gps2) => {
  const R = 6371;
  const dLat = (gps2.lat - gps1.lat) * Math.PI / 180;
  const dLon = (gps2.lng - gps1.lng) * Math.PI / 180;
  const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
            Math.cos(gps1.lat * Math.PI / 180) * Math.cos(gps2.lat * Math.PI / 180) *
            Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
};

// Routes

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Register user
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, company, role, licenseNumber, address } = req.body;

    if (!username || !password || !company) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (users.some(u => u.username === username)) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: `user_${Date.now()}`,
      username,
      password: hashedPassword,
      company,
      role: role || 'manufacturer',
      licenseNumber,
      address,
      verified: false,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    addAuditLog(newUser.id, username, 'user_registered', `New user ${username} registered`, 'info');

    res.json({ 
      message: 'Registration successful. Pending admin verification.',
      userId: newUser.id 
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);
    if (!user) {
      addAuditLog('unknown', username, 'login_failed', `Failed login attempt for ${username}`, 'warning');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      addAuditLog(user.id, username, 'login_failed', `Failed login attempt`, 'warning');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
    
    const userResponse = { ...user };
    delete userResponse.password;

    addAuditLog(user.id, username, 'login', `User logged in`, 'info');

    res.json({ token, user: userResponse });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
app.get('/api/user', authenticate, (req, res) => {
  const userResponse = { ...req.user };
  delete userResponse.password;
  res.json(userResponse);
});

// Get all users (admin only)
app.get('/api/users', authenticate, requireAdmin, (req, res) => {
  const usersResponse = users.map(u => {
    const user = { ...u };
    delete user.password;
    return user;
  });
  res.json(usersResponse);
});

// Verify user (admin only)
app.post('/api/users/:userId/verify', authenticate, requireAdmin, (req, res) => {
  const { userId } = req.params;
  const user = users.find(u => u.id === userId);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  user.verified = true;
  addAuditLog(req.user.id, req.user.username, 'user_verified', `Admin verified user ${user.username}`, 'info');

  res.json({ message: 'User verified successfully' });
});

// Create product
app.post('/api/products', authenticate, async (req, res) => {
  try {
    if (!req.user.verified && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Account not verified' });
    }

    if (req.user.role !== 'manufacturer' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only manufacturers can register products' });
    }

    const { name, category, origin, batchNumber, photo, gps } = req.body;

    if (!name || !origin) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check rate limiting
    const recentProducts = auditLogs.filter(log => 
      log.userId === req.user.id && 
      log.action === 'product_created' &&
      Date.now() - new Date(log.timestamp).getTime() < 60000
    );

    if (recentProducts.length > 10) {
      addAuditLog(req.user.id, req.user.username, 'rate_limit_exceeded', 
        `User creating too many products (${recentProducts.length}/min)`, 'warning');
      return res.status(429).json({ error: 'Rate limit exceeded. Too many products created.' });
    }

    const timestamp = new Date().toISOString();
    const productId = `PRD-${Date.now().toString(36).toUpperCase()}`;

    const userSignature = generateHash({
      userId: req.user.id,
      username: req.user.username,
      company: req.user.company
    });

    const initialBlock = {
      blockNumber: 0,
      timestamp,
      stage: 'created',
      location: origin,
      handler: req.user.company,
      handlerId: req.user.id,
      notes: 'Product registered in supply chain',
      previousHash: '0',
      hash: '',
      userSignature,
      photo,
      gps
    };

    initialBlock.hash = generateHash({
      ...initialBlock,
      productId,
      name,
      category,
      origin,
      batchNumber
    }, userSignature);

    const product = {
      id: productId,
      name,
      category: category || 'pharmaceutical',
      manufacturer: req.user.company,
      manufacturerId: req.user.id,
      origin,
      batchNumber,
      photo,
      createdAt: timestamp,
      createdBy: req.user.username,
      chain: [initialBlock],
      status: 'in-transit',
      verified: req.user.verified,
      verificationLevel: req.user.verified ? 'verified' : 'unverified',
      licenseNumber: req.user.licenseNumber
    };

    products.unshift(product);
    addAuditLog(req.user.id, req.user.username, 'product_created', 
      `Product ${productId} created`, 'info');

    res.json(product);
  } catch (err) {
    console.error('Product creation error:', err);
    res.status(500).json({ error: 'Product creation failed' });
  }
});

// Get all products
app.get('/api/products', (req, res) => {
  res.json(products);
});

// Get product by ID
app.get('/api/products/:productId', (req, res) => {
  const { productId } = req.params;
  const product = products.find(p => p.id === productId);

  if (!product) {
    return res.status(404).json({ error: 'Product not found' });
  }

  res.json(product);
});

// Add checkpoint to product
app.post('/api/products/:productId/checkpoint', authenticate, async (req, res) => {
  try {
    const { productId } = req.params;
    const { stage, location, handler, notes, photo, gps } = req.body;

    const product = products.find(p => p.id === productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // Permission check
    const canModify = req.user.role === 'admin' || 
                      product.manufacturerId === req.user.id ||
                      req.user.verified;

    if (!canModify) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    if (!location || !handler) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const timestamp = new Date().toISOString();
    const previousBlock = product.chain[product.chain.length - 1];

    // Geographic impossibility check
    if (previousBlock.gps && gps) {
      const timeDiff = (new Date(timestamp) - new Date(previousBlock.timestamp)) / 1000 / 60;
      const distance = calculateDistance(previousBlock.gps, gps);
      const speed = distance / (timeDiff / 60);

      if (speed > 900) {
        const alert = {
          id: Date.now().toString(),
          type: 'impossible_movement',
          message: `Product ${productId} moved ${distance.toFixed(2)}km in ${timeDiff.toFixed(2)} minutes (${speed.toFixed(2)}km/h)`,
          severity: 'critical',
          timestamp,
          productId,
          userId: req.user.id
        };
        suspiciousActivities.unshift(alert);
        
        addAuditLog(req.user.id, req.user.username, 'suspicious_movement',
          `Physically impossible movement detected for ${productId}`, 'critical');
      }
    }

    const userSignature = generateHash({
      userId: req.user.id,
      username: req.user.username,
      company: req.user.company
    });

    const newBlock = {
      blockNumber: product.chain.length,
      timestamp,
      stage,
      location,
      handler,
      handlerId: req.user.id,
      notes,
      previousHash: previousBlock.hash,
      hash: '',
      userSignature,
      photo,
      gps
    };

    newBlock.hash = generateHash({
      ...newBlock,
      productId
    }, userSignature);

    product.chain.push(newBlock);
    product.status = stage === 'delivered' ? 'delivered' : 'in-transit';
    product.lastUpdatedBy = req.user.username;
    product.lastUpdatedAt = timestamp;

    addAuditLog(req.user.id, req.user.username, 'checkpoint_added',
      `Checkpoint added to ${productId} at ${location}`, 'info');

    res.json(product);
  } catch (err) {
    console.error('Checkpoint error:', err);
    res.status(500).json({ error: 'Failed to add checkpoint' });
  }
});

// Verify product chain integrity
app.get('/api/products/:productId/verify', (req, res) => {
  const { productId } = req.params;
  const product = products.find(p => p.id === productId);

  if (!product) {
    return res.status(404).json({ error: 'Product not found' });
  }

  for (let i = 1; i < product.chain.length; i++) {
    const block = product.chain[i];
    const previousBlock = product.chain[i - 1];

    if (block.previousHash !== previousBlock.hash) {
      return res.json({ 
        valid: false, 
        reason: 'Hash mismatch',
        blockNumber: i
      });
    }

    if (!block.userSignature) {
      return res.json({ 
        valid: false, 
        reason: 'Missing user signature',
        blockNumber: i
      });
    }

    const handler = users.find(u => u.id === block.handlerId);
    if (!handler) {
      return res.json({ 
        valid: false, 
        reason: 'Unknown handler',
        blockNumber: i
      });
    }
  }

  res.json({ valid: true, reason: 'All checks passed' });
});

// Get audit logs (admin only)
app.get('/api/audit-logs', authenticate, requireAdmin, (req, res) => {
  res.json(auditLogs.slice(0, 100));
});

// Get suspicious activities (admin only)
app.get('/api/suspicious-activities', authenticate, requireAdmin, (req, res) => {
  res.json(suspiciousActivities);
});

// Serve index.html for root
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Supply Chain Backend running on port ${PORT}`);
});
