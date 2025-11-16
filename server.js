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
const sseClients = []; // Track SSE connections for dashboard updates

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

// SSE endpoint for real-time dashboard updates
app.get('/api/events', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    // Send initial connection message
    res.write('data: {"type":"connected"}\n\n');

    // Add this client to the list
    sseClients.push(res);

    // Remove client on disconnect
    req.on('close', () => {
        const index = sseClients.indexOf(res);
        if (index !== -1) {
            sseClients.splice(index, 1);
        }
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
        
        // Notify all connected dashboard clients via SSE
        const notification = JSON.stringify({ 
            type: 'new-scan', 
            scan: scanEntry 
        });
        sseClients.forEach(client => {
            client.write(`data: ${notification}\n\n`);
        });
        
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

// Get malware source distribution
app.get('/api/malware-sources', (req, res) => {
    try {
        const sources = {
            'Email Attachment': 0,
            'Web Download': 0,
            'USB/External Drive': 0,
            'Internal Network': 0,
            'Unknown': 0
        };
        
        scanResults.forEach(scan => {
            const filename = scan.detected_filename?.toLowerCase() || '';
            
            // Categorize based on file patterns and extensions
            if (filename.match(/\.(doc|docx|xls|xlsx|pdf|zip|rar|7z)$/)) {
                sources['Email Attachment']++;
            } else if (filename.match(/\.(exe|msi|dmg|pkg|deb|rpm)$/)) {
                sources['Web Download']++;
            } else if (filename.match(/\.(dll|sys|bin)$/)) {
                sources['Internal Network']++;
            } else if (filename.match(/\.(jpg|png|gif|mp3|mp4|avi|mov)$/)) {
                sources['USB/External Drive']++;
            } else {
                sources['Unknown']++;
            }
        });
        
        // Convert to array format for Chart.js
        const data = Object.entries(sources).map(([source, count]) => ({
            source,
            count
        }));
        
        res.json({ sources: data });
        
    } catch (error) {
        console.error('Malware sources error:', error);
        res.status(500).json({ error: 'Failed to get malware sources' });
    }
});

// Simple IP to location mapping for demo purposes
// In production, use MaxMind GeoIP2 or a geolocation API service
function getLocationFromIP(ip) {
    // Handle localhost and local IPs - assign diverse demo locations
    if (ip === '::1' || ip === '127.0.0.1' || ip.includes('::1') || ip.startsWith('127.')) {
        // Use a consistent hash of the IP to always assign to the same location
        const ipHash = ip.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
        const locationIndex = ipHash % 18;
        const demoLocations = [
            { lat: 37.7749, lng: -122.4194, city: 'San Francisco', country: 'USA' },
            { lat: 40.7128, lng: -74.0060, city: 'New York', country: 'USA' },
            { lat: 51.5074, lng: -0.1278, city: 'London', country: 'UK' },
            { lat: 48.8566, lng: 2.3522, city: 'Paris', country: 'France' },
            { lat: 35.6762, lng: 139.6503, city: 'Tokyo', country: 'Japan' },
            { lat: -33.8688, lng: 151.2093, city: 'Sydney', country: 'Australia' },
            { lat: 52.5200, lng: 13.4050, city: 'Berlin', country: 'Germany' },
            { lat: 55.7558, lng: 37.6173, city: 'Moscow', country: 'Russia' },
            { lat: 19.4326, lng: -99.1332, city: 'Mexico City', country: 'Mexico' },
            { lat: -23.5505, lng: -46.6333, city: 'São Paulo', country: 'Brazil' },
            { lat: 1.3521, lng: 103.8198, city: 'Singapore', country: 'Singapore' },
            { lat: 25.2048, lng: 55.2708, city: 'Dubai', country: 'UAE' },
            { lat: 28.6139, lng: 77.2090, city: 'New Delhi', country: 'India' },
            { lat: 39.9042, lng: 116.4074, city: 'Beijing', country: 'China' },
            { lat: 37.5665, lng: 126.9780, city: 'Seoul', country: 'South Korea' },
            { lat: 43.6532, lng: -79.3832, city: 'Toronto', country: 'Canada' },
            { lat: -34.6037, lng: -58.3816, city: 'Buenos Aires', country: 'Argentina' },
            { lat: 59.3293, lng: 18.0686, city: 'Stockholm', country: 'Sweden' },
        ];
        return demoLocations[locationIndex];
    }
    
    // Sample IP to location mapping for demo
    const ipLocations = {
        '192.168': { lat: 37.7749, lng: -122.4194, city: 'San Francisco', country: 'USA' },
        '10.0': { lat: 40.7128, lng: -74.0060, city: 'New York', country: 'USA' },
        '172.16': { lat: 51.5074, lng: -0.1278, city: 'London', country: 'UK' },
        '172.17': { lat: 48.8566, lng: 2.3522, city: 'Paris', country: 'France' },
        '172.18': { lat: 35.6762, lng: 139.6503, city: 'Tokyo', country: 'Japan' },
        '172.19': { lat: -33.8688, lng: 151.2093, city: 'Sydney', country: 'Australia' },
        '172.20': { lat: 52.5200, lng: 13.4050, city: 'Berlin', country: 'Germany' },
        '172.21': { lat: 55.7558, lng: 37.6173, city: 'Moscow', country: 'Russia' },
        '172.22': { lat: 19.4326, lng: -99.1332, city: 'Mexico City', country: 'Mexico' },
        '172.23': { lat: -23.5505, lng: -46.6333, city: 'São Paulo', country: 'Brazil' },
    };
    
    // Default locations for common IP patterns
    const defaultLocations = [
        { lat: 1.3521, lng: 103.8198, city: 'Singapore', country: 'Singapore' },
        { lat: 25.2048, lng: 55.2708, city: 'Dubai', country: 'UAE' },
        { lat: 28.6139, lng: 77.2090, city: 'New Delhi', country: 'India' },
        { lat: 39.9042, lng: 116.4074, city: 'Beijing', country: 'China' },
        { lat: 37.5665, lng: 126.9780, city: 'Seoul', country: 'South Korea' },
        { lat: 43.6532, lng: -79.3832, city: 'Toronto', country: 'Canada' },
        { lat: -34.6037, lng: -58.3816, city: 'Buenos Aires', country: 'Argentina' },
        { lat: 59.3293, lng: 18.0686, city: 'Stockholm', country: 'Sweden' },
    ];
    
    // Check for known IP prefixes
    for (const [prefix, location] of Object.entries(ipLocations)) {
        if (ip.startsWith(prefix)) {
            return location;
        }
    }
    
    // For unknown IPs, assign a random location from defaults
    const hash = ip.split('.').reduce((acc, part) => acc + parseInt(part || 0), 0);
    return defaultLocations[hash % defaultLocations.length];
}

// Get geographic data for IP addresses with malware detections
app.get('/api/geo-data', (req, res) => {
    try {
        // Group scans by IP address
        const ipData = new Map();
        
        scanResults.forEach(scan => {
            const ip = scan.systemInfo?.ip || scan.clientIp || 'Unknown';
            
            if (ip === 'Unknown') {
                return; // Skip unknown addresses
            }
            
            if (!ipData.has(ip)) {
                const location = getLocationFromIP(ip);
                ipData.set(ip, {
                    ip: ip,
                    location: location,
                    scans: [],
                    malwareCount: 0,
                    suspiciousCount: 0,
                    benignCount: 0,
                    totalScans: 0
                });
            }
            
            const data = ipData.get(ip);
            data.scans.push({
                filename: scan.detected_filename,
                classification: scan.classification,
                timestamp: scan.serverTimestamp
            });
            data.totalScans++;
            
            if (scan.classification === 'Malware') {
                data.malwareCount++;
            } else if (scan.classification === 'Suspicious') {
                data.suspiciousCount++;
            } else if (scan.classification === 'Benign') {
                data.benignCount++;
            }
        });
        
        // Convert map to array
        const geoDataArray = Array.from(ipData.values());
        
        res.json({
            total: geoDataArray.length,
            locations: geoDataArray
        });
        
    } catch (error) {
        console.error('Geo data error:', error);
        res.status(500).json({ error: 'Failed to get geographic data' });
    }
});

// Get threat vector correlations for the interactive graph
app.get('/api/threat-correlations', (req, res) => {
    try {
        const nodes = [];
        const links = [];
        const nodeMap = new Map();
        let nodeId = 0;
        
        // Helper to get or create node
        const getNodeId = (label, type, group) => {
            const key = `${type}:${label}`;
            if (!nodeMap.has(key)) {
                const id = nodeId++;
                nodeMap.set(key, id);
                nodes.push({
                    id,
                    label,
                    type,
                    group,
                    count: 0,
                    details: []
                });
            }
            return nodeMap.get(key);
        };
        
        // Process all scans and build relationships
        const malwareFamilies = new Map();
        
        scanResults.forEach(scan => {
            const family = scan.malware_family || (scan.classification === 'Malware' ? 'Unknown Malware' : null);
            if (!family) return;
            
            const agentId = scan.systemInfo?.hostname || scan.clientIp || 'Unknown Agent';
            
            // Get or create malware family node
            const familyId = getNodeId(family, 'malware', 1);
            const familyNode = nodes.find(n => n.id === familyId);
            familyNode.count++;
            familyNode.details.push(scan.detected_filename);
            
            // Track family data for correlation
            if (!malwareFamilies.has(family)) {
                malwareFamilies.set(family, {
                    agents: new Set(),
                    apis: new Map(),
                    strings: new Map(),
                    files: []
                });
            }
            const familyData = malwareFamilies.get(family);
            familyData.agents.add(agentId);
            familyData.files.push(scan.detected_filename);
            
            // Create agent node and link
            const agentNodeId = getNodeId(agentId, 'agent', 2);
            const agentNode = nodes.find(n => n.id === agentNodeId);
            agentNode.count++;
            links.push({
                source: familyId,
                target: agentNodeId,
                type: 'detected_by',
                strength: 2
            });
            
            // Process API imports
            const apis = scan.key_findings?.api_imports || [];
            apis.forEach(api => {
                const apiId = getNodeId(api, 'api', 3);
                const apiNode = nodes.find(n => n.id === apiId);
                apiNode.count++;
                
                // Track API frequency for this family
                const apiCount = familyData.apis.get(api) || 0;
                familyData.apis.set(api, apiCount + 1);
                
                // Link malware to API (avoid duplicates)
                if (!links.find(l => l.source === familyId && l.target === apiId)) {
                    links.push({
                        source: familyId,
                        target: apiId,
                        type: 'uses_api',
                        strength: 1
                    });
                }
            });
            
            // Process suspicious strings
            const strings = scan.key_findings?.key_strings || [];
            strings.slice(0, 3).forEach(str => { // Limit to top 3 to avoid clutter
                const strId = getNodeId(str.substring(0, 50), 'string', 4);
                const strNode = nodes.find(n => n.id === strId);
                strNode.count++;
                
                const strCount = familyData.strings.get(str) || 0;
                familyData.strings.set(str, strCount + 1);
                
                if (!links.find(l => l.source === familyId && l.target === strId)) {
                    links.push({
                        source: familyId,
                        target: strId,
                        type: 'contains_string',
                        strength: 1
                    });
                }
            });
        });
        
        // Create correlations between malware families that share common traits
        const familyNodes = nodes.filter(n => n.type === 'malware');
        for (let i = 0; i < familyNodes.length; i++) {
            for (let j = i + 1; j < familyNodes.length; j++) {
                const family1 = familyNodes[i].label;
                const family2 = familyNodes[j].label;
                const data1 = malwareFamilies.get(family1);
                const data2 = malwareFamilies.get(family2);
                
                // Check for shared agents
                const sharedAgents = [...data1.agents].filter(a => data2.agents.has(a));
                
                if (sharedAgents.length > 0) {
                    links.push({
                        source: familyNodes[i].id,
                        target: familyNodes[j].id,
                        type: 'correlated_with',
                        strength: sharedAgents.length
                    });
                }
            }
        }
        
        res.json({
            nodes,
            links,
            metadata: {
                totalNodes: nodes.length,
                totalLinks: links.length,
                malwareFamilies: familyNodes.length
            }
        });
        
    } catch (error) {
        console.error('Threat correlations error:', error);
        res.status(500).json({ error: 'Failed to get threat correlations' });
    }
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