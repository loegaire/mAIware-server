const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// In-memory storage (use Redis/MongoDB in production)
const scanResults = [];
const clients = new Map(); // Track active clients

// --- API Endpoints ---

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        totalScans: scanResults.length,
        activeClients: clients.size,
        timestamp: new Date().toISOString() 
    });
});

// Submit scan result from client
app.post('/api/submit-scan', (req, res) => {
    try {
        const scanData = req.body;
        
        // Validate required fields
        if (!scanData.detected_filename || !scanData.classification) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        // Add server metadata
        const scanEntry = {
            ...scanData,
            serverTimestamp: new Date().toISOString(),
            scanId: `scan-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            clientIp: req.ip || req.connection.remoteAddress
        };
        
        // Store result
        scanResults.unshift(scanEntry); // Add to beginning
        
        // Keep only last 1000 scans
        if (scanResults.length > 1000) {
            scanResults.pop();
        }
        
        // Update client tracking
        const clientId = scanData.systemInfo?.ip || req.ip;
        clients.set(clientId, {
            lastSeen: new Date().toISOString(),
            totalScans: (clients.get(clientId)?.totalScans || 0) + 1
        });
        
        console.log(`✅ Received scan: ${scanData.detected_filename} → ${scanData.classification}`);
        
        res.json({ 
            success: true, 
            scanId: scanEntry.scanId,
            message: 'Scan result recorded' 
        });
        
    } catch (error) {
        console.error('Submit error:', error);
        res.status(500).json({ error: 'Failed to record scan' });
    }
});

// Get all scans (for dashboard)
app.get('/api/scans', (req, res) => {
    const limit = parseInt(req.query.limit) || 100;
    const offset = parseInt(req.query.offset) || 0;
    
    const paginatedScans = scanResults.slice(offset, offset + limit);
    
    res.json({
        total: scanResults.length,
        scans: paginatedScans
    });
});

// Get statistics
app.get('/api/stats', (req, res) => {
    const now = Date.now();
    const last24h = now - 24 * 60 * 60 * 1000;
    const last7d = now - 7 * 24 * 60 * 60 * 1000;
    
    const recent24h = scanResults.filter(s => 
        new Date(s.serverTimestamp).getTime() > last24h
    );
    
    const recent7d = scanResults.filter(s => 
        new Date(s.serverTimestamp).getTime() > last7d
    );
    
    const malwareCount = scanResults.filter(s => 
        s.classification === 'Malware'
    ).length;
    
    const suspiciousCount = scanResults.filter(s => 
        s.classification === 'Suspicious'
    ).length;
    
    const benignCount = scanResults.filter(s => 
        s.classification === 'Benign'
    ).length;
    
    // Count active clients (seen in last 10 minutes)
    const activeClients = Array.from(clients.values()).filter(c => 
        new Date(c.lastSeen).getTime() > now - 10 * 60 * 1000
    ).length;
    
    res.json({
        totalScans: scanResults.length,
        scans24h: recent24h.length,
        scans7d: recent7d.length,
        malwareCount,
        suspiciousCount,
        benignCount,
        activeClients,
        clients: clients.size
    });
});

// NEW: Get daily analysis data for chart
app.get('/api/daily-scans', (req, res) => {
    const days = parseInt(req.query.days) || 30; // Default to last 30 days
    
    // Create a map to store counts per day
    const dailyCounts = new Map();
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    // Initialize the last N days with 0 counts
    for (let i = days - 1; i >= 0; i--) {
        const date = new Date(today);
        date.setDate(date.getDate() - i);
        const dateKey = date.toISOString().split('T')[0]; // YYYY-MM-DD
        dailyCounts.set(dateKey, {
            date: dateKey,
            total: 0,
            malware: 0,
            suspicious: 0,
            benign: 0
        });
    }
    
    // Count scans by day
    scanResults.forEach(scan => {
        const scanDate = new Date(scan.serverTimestamp);
        scanDate.setHours(0, 0, 0, 0);
        const dateKey = scanDate.toISOString().split('T')[0];
        
        if (dailyCounts.has(dateKey)) {
            const counts = dailyCounts.get(dateKey);
            counts.total++;
            
            if (scan.classification === 'Malware') {
                counts.malware++;
            } else if (scan.classification === 'Suspicious') {
                counts.suspicious++;
            } else if (scan.classification === 'Benign') {
                counts.benign++;
            }
        }
    });
    
    // Convert map to array sorted by date
    const result = Array.from(dailyCounts.values()).sort((a, b) => 
        a.date.localeCompare(b.date)
    );
    
    res.json({ days: result });
});

// Serve dashboard HTML
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`🖥️  mAIware Server Dashboard running on http://localhost:${PORT}`);
    console.log(`📊 Dashboard: http://localhost:${PORT}`);
    console.log(`🔌 API endpoint: http://localhost:${PORT}/api/submit-scan`);
});

// Cleanup old client entries every hour
setInterval(() => {
    const oneHourAgo = Date.now() - 60 * 60 * 1000;
    for (const [clientId, data] of clients.entries()) {
        if (new Date(data.lastSeen).getTime() < oneHourAgo) {
            clients.delete(clientId);
        }
    }
}, 60 * 60 * 1000);