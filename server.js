const express = require('express');
const cors = require('cors');
const path = require('path');
const dgram = require('dgram');
const os = require('os');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const BROADCAST_PORT = 3001;
const DISCOVERY_MESSAGE = 'MAIWARE_SERVER_DISCOVERY';

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// In-memory storage (use Redis/MongoDB in production)
const scanResults = [];
const clients = new Map(); // Track active clients
const sseClients = []; // Track SSE connections for dashboard updates
const ACTIVE_CLIENT_WINDOW_MS = 10 * 60 * 1000; // 10 minutes

// --- API Endpoints ---

// Get server's local IP addresses
function getLocalIPs() {
    const interfaces = os.networkInterfaces();
    const ips = [];
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                ips.push(iface.address);
            }
        }
    }
    return ips;
}

function getActiveClientCount() {
    const now = Date.now();
    return Array.from(clients.values()).filter(c =>
        new Date(c.lastSeen).getTime() > now - ACTIVE_CLIENT_WINDOW_MS
    ).length;
}

function touchClient(clientId, extra = {}) {
    if (!clientId) {
        return null;
    }

    const prev = clients.get(clientId) || {};
    const updated = {
        ...prev,
        ...extra,
        lastSeen: new Date().toISOString(),
    };

    // Preserve/increment total scans if provided
    if (extra.incrementScan) {
        updated.totalScans = (prev.totalScans || 0) + 1;
    } else if (prev.totalScans && !updated.totalScans) {
        updated.totalScans = prev.totalScans;
    }

    clients.set(clientId, updated);
    return updated;
}

function broadcastClientUpdate(reason = 'heartbeat') {
    const payload = JSON.stringify({
        type: 'client-update',
        reason,
        activeClients: getActiveClientCount(),
        totalClients: clients.size,
        timestamp: new Date().toISOString()
    });

    sseClients.forEach((client) => {
        client.write(`data: ${payload}\n\n`);
    });
}

function getStatsSnapshot() {
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

    const activeClients = getActiveClientCount();

    return {
        totalScans: scanResults.length,
        scans24h: recent24h.length,
        scans7d: recent7d.length,
        malwareCount,
        suspiciousCount,
        benignCount,
        activeClients,
        clients: clients.size,
        activeUsers: activeClients,
        siteVisits: scanResults.length // All-time site visits based on total scans
    };
}

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        service: 'mAIware-server',
        version: '1.0.0',
        totalScans: scanResults.length,
        activeClients: clients.size,
        localIPs: getLocalIPs(),
        hostname: os.hostname(),
        port: PORT,
        timestamp: new Date().toISOString() 
    });
});

// Get LAN users count (active clients for client app)
app.get('/api/lan-users', (req, res) => {
    const activeUsers = getActiveClientCount();
    
    res.json({ 
        lanUsers: activeUsers,
        totalClients: clients.size,
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
    // Send current stats snapshot so dashboard shows accurate counts immediately
    res.write(`data: ${JSON.stringify({ type: 'stats', stats: getStatsSnapshot() })}\n\n`);

    // Add this client to the list
    sseClients.push(res);
    console.log(`📺 Dashboard connected via SSE (${sseClients.length} total connections)`);

    // Remove client on disconnect
    req.on('close', () => {
        const index = sseClients.indexOf(res);
        if (index !== -1) {
            sseClients.splice(index, 1);
        }
        console.log(`📺 Dashboard disconnected (${sseClients.length} remaining)`);
    });
});

// Submit scan result from client
app.post('/api/submit-scan', (req, res) => {
    try {
        const incoming = req.body;

        // Basic validation (allow minimal non-PE payloads that omit some fields)
        if (!incoming || !incoming.detected_filename) {
            return res.status(400).json({ error: 'Missing detected_filename' });
        }

        // Normalize / sanitize scan object
        const scanData = { ...incoming };
        const isPe = scanData.is_pe !== undefined ? !!scanData.is_pe : true; // default true if absent

        // If non-PE: enforce benign, remove PE-only fields
        if (!isPe) {
            scanData.classification = 'Benign';
            delete scanData.malware_family;
            if (scanData.key_findings) {
                delete scanData.key_findings.api_imports;
                delete scanData.key_findings.key_strings;
                delete scanData.key_findings.section_entropy;
                delete scanData.key_findings.packer_detected;
                delete scanData.key_findings.signature;
            }
        } else {
            // Ensure classification exists for PE paths
            if (!scanData.classification) {
                scanData.classification = 'Benign';
            }
        }

        // Add server metadata
        const scanEntry = {
            ...scanData,
            serverTimestamp: new Date().toISOString(),
            scanId: `scan-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            clientIp: req.ip || req.connection.remoteAddress,
            is_pe: isPe
        };

        // Store result (most recent first)
        scanResults.unshift(scanEntry);
        
        // Keep only last 1000 scans
        if (scanResults.length > 1000) {
            scanResults.pop();
        }
        
        // Update client tracking
        const clientId = scanData.systemInfo?.ip || req.ip;
        touchClient(clientId, {
            incrementScan: true,
            agentId: scanData.agent_id,
            hostname: scanData.systemInfo?.hostname || scanData.systemInfo?.agent_hostname
        });
        
        console.log(`✅ Received scan from ${scanData.agent_id || clientId}: ${scanEntry.detected_filename} → ${scanEntry.classification}${scanEntry.is_pe ? '' : ' (non-PE)'}`);
        console.log(`   Client IP: ${clientId}, Total scans in DB: ${scanResults.length}`);
        
        // Invalidate caches on new scan
        noisyAgentsCache = null;
        correlationsCache = null;
        
        // Notify all connected dashboard clients via SSE
        const notification = JSON.stringify({ 
            type: 'new-scan', 
            scan: scanEntry 
        });
        if (sseClients.length > 0) {
            sseClients.forEach(client => {
                client.write(`data: ${notification}\n\n`);
            });
            console.log(`   📡 Broadcasted to ${sseClients.length} dashboard(s)`);
        } else {
            console.log(`   ⚠️  No dashboards connected to receive update`);
        }
        // Notify dashboards about client activity immediately
        broadcastClientUpdate('scan');
        
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
    const activeClients = getActiveClientCount();
    
    res.json({
        totalScans: scanResults.length,
        scans24h: recent24h.length,
        scans7d: recent7d.length,
        malwareCount,
        suspiciousCount,
        benignCount,
        activeClients,
        clients: clients.size,
        activeUsers: activeClients,
        siteVisits: scanResults.length // All-time site visits based on total scans
    });
});

// Heartbeat endpoint for clients to announce presence (used by client app)
app.post('/api/clients/heartbeat', (req, res) => {
    try {
        const payload = req.body || {};
        const clientId = payload.systemInfo?.ip || payload.ip || req.ip;
        const agentId = payload.agent_id || payload.agentId || clientId;

        const updated = touchClient(clientId, {
            agentId,
            hostname: payload.systemInfo?.hostname || payload.systemInfo?.agent_hostname
        });

        broadcastClientUpdate('heartbeat');

        res.json({
            success: true,
            activeClients: getActiveClientCount(),
            totalClients: clients.size,
            client: updated
        });
    } catch (err) {
        console.error('Heartbeat error:', err);
        res.status(500).json({ error: 'Failed to record heartbeat' });
    }
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

// Cache for noisy-agents computation
let noisyAgentsCache = null;
let noisyAgentsCacheTime = 0;
const NOISY_AGENTS_CACHE_TTL = 30000; // 30 seconds

// API: Noisy Agents Over Time (Graph 2)
app.get('/api/noisy-agents', (req, res) => {
    try {
        // Return cached result if still valid
        const now = Date.now();
        if (noisyAgentsCache && (now - noisyAgentsCacheTime) < NOISY_AGENTS_CACHE_TTL) {
            return res.json(noisyAgentsCache);
        }
        
        // Get top 5 agents by threat count (optimized with Map)
        const agentCounts = new Map();
        for (const scan of scanResults) {
            if (scan.classification === 'Suspicious' || scan.classification === 'Malware') {
                const agentId = scan.agent_id || 'Unknown';
                agentCounts.set(agentId, (agentCounts.get(agentId) || 0) + 1);
            }
        }
        
        const topAgents = Array.from(agentCounts.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([id]) => id);
        
        // Get last 14 days of data
        const days = 14;
        const dates = [];
        const agentData = {};
        const dateStrings = [];
        
        // Pre-compute date strings for comparison
        for (let i = days - 1; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            dates.push(`${date.getMonth() + 1}/${date.getDate()}`);
            dateStrings.push(date.toDateString());
        }
        
        // Initialize agent data arrays
        topAgents.forEach(agentId => {
            agentData[agentId] = new Array(days).fill(0);
        });
        
        // Single pass through scans - O(n) instead of O(n*days*agents)
        for (const scan of scanResults) {
            if (scan.classification !== 'Suspicious' && scan.classification !== 'Malware') continue;
            if (!topAgents.includes(scan.agent_id)) continue;
            
            const scanDateStr = new Date(scan.timestamp).toDateString();
            const dayIndex = dateStrings.indexOf(scanDateStr);
            if (dayIndex !== -1) {
                agentData[scan.agent_id][dayIndex]++;
            }
        }
        
        const agents = topAgents.map(agentId => ({
            agentId,
            counts: agentData[agentId]
        }));
        
        const result = { dates, agents };
        
        // Cache the result
        noisyAgentsCache = result;
        noisyAgentsCacheTime = Date.now();
        
        res.json(result);
    } catch (error) {
        console.error('Noisy agents error:', error);
        res.status(500).json({ error: 'Failed to get noisy agents data' });
    }
});

// API: Signature Status vs Classification (Graph 3)
app.get('/api/signature-classification', (req, res) => {
    try {
        const data = {
            benign: { verified: 0, unknown: 0, untrusted: 0 },
            suspicious: { verified: 0, unknown: 0, untrusted: 0 },
            malware: { verified: 0, unknown: 0, untrusted: 0 }
        };
        
        scanResults.forEach(scan => {
            const classification = scan.classification?.toLowerCase() || 'benign';
            const sigLevel = scan.signature?.level?.toLowerCase() || 'unknown';
            
            if (data[classification] && data[classification][sigLevel] !== undefined) {
                data[classification][sigLevel]++;
            }
        });
        
        res.json(data);
    } catch (error) {
        console.error('Signature classification error:', error);
        res.status(500).json({ error: 'Failed to get signature classification data' });
    }
});

// API: Packer Usage vs Classification (Graph 4)
app.get('/api/packer-classification', (req, res) => {
    try {
        const packerData = {};
        
        scanResults.forEach(scan => {
            const packer = scan.packer_detected || 'None';
            const classification = scan.classification?.toLowerCase();
            
            if (!packerData[packer]) {
                packerData[packer] = { benign: 0, malware: 0 };
            }
            
            if (classification === 'benign') {
                packerData[packer].benign++;
            } else if (classification === 'malware' || classification === 'suspicious') {
                packerData[packer].malware++;
            }
        });
        
        // Get top packers
        const sortedPackers = Object.entries(packerData)
            .sort((a, b) => (b[1].benign + b[1].malware) - (a[1].benign + a[1].malware))
            .slice(0, 8);
        
        const packers = sortedPackers.map(([name]) => name);
        const benignCounts = sortedPackers.map(([, counts]) => counts.benign);
        const malwareCounts = sortedPackers.map(([, counts]) => counts.malware);
        
        res.json({ packers, benignCounts, malwareCounts });
    } catch (error) {
        console.error('Packer classification error:', error);
        res.status(500).json({ error: 'Failed to get packer classification data' });
    }
});

// API: Confidence Score Distribution (Graph 5)
app.get('/api/confidence-distribution', (req, res) => {
    try {
        const bins = ['0.0-0.1', '0.1-0.2', '0.2-0.3', '0.3-0.4', '0.4-0.5', 
                      '0.5-0.6', '0.6-0.7', '0.7-0.8', '0.8-0.9', '0.9-1.0'];
        const counts = new Array(10).fill(0);
        
        scanResults.forEach(scan => {
            const confidence = scan.confidence_score;
            if (confidence !== undefined && confidence !== null) {
                const binIndex = Math.min(Math.floor(confidence * 10), 9);
                counts[binIndex]++;
            }
        });
        
        res.json({ bins, counts });
    } catch (error) {
        console.error('Confidence distribution error:', error);
        res.status(500).json({ error: 'Failed to get confidence distribution' });
    }
});

// API: File Entropy Distribution (Graph 6)
app.get('/api/entropy-distribution', (req, res) => {
    try {
        const benignEntropies = [];
        const malwareEntropies = [];
        
        scanResults.forEach(scan => {
            // Try multiple sources for entropy data:
            // 1. pe_metadata.entropy_total (from AI analysis)
            // 2. Calculate average from key_findings.section_entropy array
            let entropy = null;
            
            if (scan.pe_metadata?.entropy_total !== undefined) {
                entropy = scan.pe_metadata.entropy_total;
            } else if (scan.key_findings?.section_entropy && Array.isArray(scan.key_findings.section_entropy)) {
                // Calculate average entropy from section data
                const sections = scan.key_findings.section_entropy;
                if (sections.length > 0) {
                    const totalEntropy = sections.reduce((sum, s) => sum + (s.entropy || 0), 0);
                    entropy = totalEntropy / sections.length;
                }
            }
            
            const classification = scan.classification?.toLowerCase();
            
            if (entropy !== null && entropy !== undefined) {
                if (classification === 'benign') {
                    benignEntropies.push(entropy);
                } else if (classification === 'malware' || classification === 'suspicious') {
                    malwareEntropies.push(entropy);
                }
            }
        });
        
        const calculateStats = (arr) => {
            if (arr.length === 0) return { min: 0, q1: 0, median: 0, q3: 0, max: 0 };
            
            arr.sort((a, b) => a - b);
            return {
                min: arr[0],
                q1: arr[Math.floor(arr.length * 0.25)],
                median: arr[Math.floor(arr.length * 0.5)],
                q3: arr[Math.floor(arr.length * 0.75)],
                max: arr[arr.length - 1]
            };
        };
        
        res.json({
            benign: calculateStats(benignEntropies),
            malware: calculateStats(malwareEntropies)
        });
    } catch (error) {
        console.error('Entropy distribution error:', error);
        res.status(500).json({ error: 'Failed to get entropy distribution' });
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

// Cache for threat correlations
let correlationsCache = null;
let correlationsCacheTime = 0;
const CORRELATIONS_CACHE_TTL = 60000; // 60 seconds

// Get threat vector correlations for the interactive graph
app.get('/api/threat-correlations', (req, res) => {
    try {
        // Return cached result if still valid
        const now = Date.now();
        if (correlationsCache && (now - correlationsCacheTime) < CORRELATIONS_CACHE_TTL) {
            return res.json(correlationsCache);
        }
        
        const nodes = [];
        const links = [];
        const nodeMap = new Map();
        const nodeIndexMap = new Map(); // Fast node lookup by id
        const linkSet = new Set(); // Dedupe links efficiently
        let nodeId = 0;
        
        // Helper to get or create node
        const getNodeId = (label, type, group) => {
            const key = `${type}:${label}`;
            if (!nodeMap.has(key)) {
                const id = nodeId++;
                const node = {
                    id,
                    label,
                    type,
                    group,
                    count: 0,
                    details: []
                };
                nodeMap.set(key, id);
                nodeIndexMap.set(id, node);
                nodes.push(node);
            }
            return nodeMap.get(key);
        };
        
        // Helper to add link with deduplication
        const addLink = (source, target, type, strength) => {
            const linkKey = `${source}-${target}-${type}`;
            if (!linkSet.has(linkKey)) {
                linkSet.add(linkKey);
                links.push({ source, target, type, strength });
            }
        };
        
        // Process all scans and build relationships
        const malwareFamilies = new Map();
        
        scanResults.forEach(scan => {
            const family = scan.malware_family || (scan.classification === 'Malware' ? 'Unknown Malware' : null);
            if (!family) return;
            
            const agentId = scan.systemInfo?.hostname || scan.clientIp || 'Unknown Agent';
            
            // Get or create malware family node
            const familyId = getNodeId(family, 'malware', 1);
            const familyNode = nodeIndexMap.get(familyId);
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
            const agentNode = nodeIndexMap.get(agentNodeId);
            agentNode.count++;
            addLink(familyId, agentNodeId, 'detected_by', 2);
            
            // Process API imports (limit to reduce clutter)
            const apis = (scan.key_findings?.api_imports || []).slice(0, 5);
            for (const api of apis) {
                const apiId = getNodeId(api, 'api', 3);
                const apiNode = nodeIndexMap.get(apiId);
                apiNode.count++;
                
                // Track API frequency for this family
                const apiCount = familyData.apis.get(api) || 0;
                familyData.apis.set(api, apiCount + 1);
                
                addLink(familyId, apiId, 'uses_api', 1);
            }
            
            // Process suspicious strings (limit to top 3)
            const strings = (scan.key_findings?.key_strings || []).slice(0, 3);
            for (const str of strings) {
                const strId = getNodeId(str.substring(0, 50), 'string', 4);
                const strNode = nodeIndexMap.get(strId);
                strNode.count++;
                
                const strCount = familyData.strings.get(str) || 0;
                familyData.strings.set(str, strCount + 1);
                
                addLink(familyId, strId, 'contains_string', 1);
            }
        });
        
        // Create correlations between malware families that share common traits
        // Limit to prevent O(n²) explosion with many families
        const familyNodes = nodes.filter(n => n.type === 'malware').slice(0, 20);
        
        // Use optimized Set intersection instead of filter
        for (let i = 0; i < familyNodes.length; i++) {
            for (let j = i + 1; j < familyNodes.length; j++) {
                const family1 = familyNodes[i].label;
                const family2 = familyNodes[j].label;
                const data1 = malwareFamilies.get(family1);
                const data2 = malwareFamilies.get(family2);
                
                // Fast Set intersection count
                let sharedCount = 0;
                for (const agent of data1.agents) {
                    if (data2.agents.has(agent)) sharedCount++;
                }
                
                if (sharedCount > 0) {
                    addLink(
                        familyNodes[i].id,
                        familyNodes[j].id,
                        'correlated_with',
                        sharedCount
                    );
                }
            }
        }
        
        // Cache the result
        correlationsCache = { nodes, links };
        correlationsCacheTime = Date.now();
        
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

// Get Emerging Threat Intelligence - Top IOCs and threats
app.get('/api/emerging-threats', (req, res) => {
    try {
        // Aggregators for different IOC types
        const malwareFamilies = new Map();
        const suspiciousAPIs = new Map();
        const maliciousStrings = new Map();
        const packers = new Map();
        
        // Track threat severity and recency
        const now = Date.now();
        const last24h = now - 24 * 60 * 60 * 1000;
        
        scanResults.forEach(scan => {
            const timestamp = new Date(scan.serverTimestamp).getTime();
            const isRecent = timestamp > last24h;
            const weight = isRecent ? 2 : 1; // Recent threats weigh more
            
            // Only aggregate from Malware and Suspicious classifications
            if (scan.classification === 'Malware' || scan.classification === 'Suspicious') {
                
                // Aggregate Malware Families
                if (scan.malware_family) {
                    const family = scan.malware_family;
                    const current = malwareFamilies.get(family) || { 
                        count: 0, 
                        recent: 0, 
                        severity: scan.classification === 'Malware' ? 3 : 2,
                        files: [],
                        agents: new Set()
                    };
                    current.count += weight;
                    if (isRecent) current.recent++;
                    current.files.push(scan.detected_filename);
                    current.agents.add(scan.systemInfo?.hostname || scan.clientIp);
                    malwareFamilies.set(family, current);
                }
                
                // Aggregate Suspicious APIs
                const apis = scan.key_findings?.api_imports || [];
                apis.forEach(api => {
                    const current = suspiciousAPIs.get(api) || { 
                        count: 0, 
                        recent: 0,
                        families: new Set() 
                    };
                    current.count += weight;
                    if (isRecent) current.recent++;
                    if (scan.malware_family) current.families.add(scan.malware_family);
                    suspiciousAPIs.set(api, current);
                });
                
                // Aggregate Malicious Strings
                const strings = scan.key_findings?.key_strings || [];
                strings.forEach(str => {
                    const current = maliciousStrings.get(str) || { 
                        count: 0, 
                        recent: 0,
                        families: new Set() 
                    };
                    current.count += weight;
                    if (isRecent) current.recent++;
                    if (scan.malware_family) current.families.add(scan.malware_family);
                    maliciousStrings.set(str, current);
                });
                
                // Aggregate Packers
                const packer = scan.key_findings?.packer_detected;
                if (packer && packer !== 'None') {
                    const current = packers.get(packer) || { 
                        count: 0, 
                        recent: 0,
                        families: new Set() 
                    };
                    current.count += weight;
                    if (isRecent) current.recent++;
                    if (scan.malware_family) current.families.add(scan.malware_family);
                    packers.set(packer, current);
                }
            }
        });
        
        // Helper to convert Map to sorted array
        const toTopN = (map, n = 5) => {
            return Array.from(map.entries())
                .map(([name, data]) => ({
                    name,
                    count: data.count,
                    recent: data.recent,
                    severity: data.severity || 2,
                    details: data.families ? Array.from(data.families) : 
                            (data.files ? data.files.slice(0, 3) : []),
                    agents: data.agents ? data.agents.size : 0
                }))
                .sort((a, b) => {
                    // Sort by: recent activity, then count, then severity
                    if (b.recent !== a.recent) return b.recent - a.recent;
                    if (b.count !== a.count) return b.count - a.count;
                    return (b.severity || 0) - (a.severity || 0);
                })
                .slice(0, n);
        };
        
        res.json({
            timestamp: new Date().toISOString(),
            topMalwareFamilies: toTopN(malwareFamilies, 5),
            topSuspiciousAPIs: toTopN(suspiciousAPIs, 5),
            topMaliciousStrings: toTopN(maliciousStrings, 5),
            topPackers: toTopN(packers, 5),
            summary: {
                totalThreats: scanResults.filter(s => 
                    s.classification === 'Malware' || s.classification === 'Suspicious'
                ).length,
                recentThreats: scanResults.filter(s => {
                    const timestamp = new Date(s.serverTimestamp).getTime();
                    return (timestamp > last24h) && 
                           (s.classification === 'Malware' || s.classification === 'Suspicious');
                }).length
            }
        });
        
    } catch (error) {
        console.error('Emerging threats error:', error);
        res.status(500).json({ error: 'Failed to get emerging threats' });
    }
});

// Threat Modeler - Simulate analysis of hypothetical malware
app.post('/api/threat-model', (req, res) => {
    try {
        const { fileType, packer, signature, apiImports, keyStrings } = req.body;
        
        // Validate inputs
        if (!fileType || !packer || !signature || !apiImports || !keyStrings) {
            return res.status(400).json({ error: 'Missing required parameters' });
        }
        
        // Create a synthetic scan result based on the threat profile
        const crypto = require('crypto');
        const timestamp = Date.now();
        const randomHash = crypto.randomBytes(32).toString('hex');
        
        // Determine classification based on threat indicators
        let classification = 'Benign';
        let confidence = 0.55;
        let malwareFamily = null;
        
        // Scoring system
        let threatScore = 0;
        
        // Packer increases threat score
        if (packer !== 'None') threatScore += 25;
        
        // Signature evaluation
        if (signature.includes('Not Signed') || signature.includes('Self-Signed')) {
            threatScore += 20;
        }
        
        // API analysis - check for malicious APIs
        const maliciousAPIs = ['CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx', 
                               'SetWindowsHookExW', 'URLDownloadToFileW', 'NtInjectThread'];
        const maliciousAPICount = apiImports.filter(api => 
            maliciousAPIs.some(mal => api.includes(mal))
        ).length;
        threatScore += maliciousAPICount * 15;
        
        // String analysis - check for malicious strings
        const maliciousKeywords = ['keylog', 'steal', 'crack', 'patch', 'disable', 
                                   'powershell', 'encrypted', 'ransom', 'payload'];
        const maliciousStringCount = keyStrings.filter(str => 
            maliciousKeywords.some(keyword => str.toLowerCase().includes(keyword))
        ).length;
        threatScore += maliciousStringCount * 20;
        
        // Determine classification
        if (threatScore >= 60) {
            classification = 'Malware';
            confidence = 0.85 + (Math.min(threatScore, 100) / 100) * 0.14;
            
            // Assign malware family based on characteristics
            if (keyStrings.some(s => s.toLowerCase().includes('keylog'))) {
                malwareFamily = 'Spyware.Win32.Keylogger';
            } else if (apiImports.includes('CreateRemoteThread') || apiImports.includes('WriteProcessMemory')) {
                malwareFamily = 'Trojan.Downloader.Win32';
            } else if (keyStrings.some(s => s.toLowerCase().includes('encrypt') || s.toLowerCase().includes('ransom'))) {
                malwareFamily = 'Ransomware.Win32.Locky';
            } else if (apiImports.includes('URLDownloadToFileW')) {
                malwareFamily = 'Dropper.Win32.Emotet';
            } else {
                malwareFamily = 'Masquerader.Win32.Agent';
            }
        } else if (threatScore >= 30) {
            classification = 'Suspicious';
            confidence = 0.65 + (threatScore / 100) * 0.25;
        } else {
            classification = 'Benign';
            confidence = 0.55 + Math.random() * 0.25;
        }
        
        // Build the synthetic scan result
        const syntheticScan = {
            detected_filename: `threat_model_${timestamp}.exe`,
            file_hashes: {
                sha256: randomHash,
                md5: crypto.createHash('md5').update(randomHash).digest('hex')
            },
            classification,
            malware_family: malwareFamily,
            confidence_score: confidence.toFixed(2),
            vendor: { name: 'mAIware Threat Modeler', icon: 'fas fa-flask' },
            key_findings: {
                file_type: fileType,
                packer_detected: packer,
                signature: { 
                    name: signature, 
                    icon: signature.includes('Verified') ? 'fas fa-check-shield' : 'fas fa-times-circle',
                    level: signature.includes('Verified') ? 'verified' : 'untrusted'
                },
                api_imports: apiImports,
                key_strings: keyStrings,
                threat_score: threatScore
            },
            serverTimestamp: new Date().toISOString(),
            scanId: `model-${timestamp}`,
            clientIp: req.ip || 'Threat Modeler',
            isSimulated: true
        };
        
        // Store in scan results
        scanResults.unshift(syntheticScan);
        if (scanResults.length > 1000) {
            scanResults.pop();
        }
        
        // Notify all SSE clients
        const notification = JSON.stringify({ 
            type: 'new-scan', 
            scan: syntheticScan 
        });
        sseClients.forEach(client => {
            client.write(`data: ${notification}\n\n`);
        });
        
        console.log(`🔬 Threat Model analyzed: ${classification} (${confidence.toFixed(2)} confidence)`);
        
        res.json({
            success: true,
            result: syntheticScan
        });
        
    } catch (error) {
        console.error('Threat model error:', error);
        res.status(500).json({ error: 'Failed to analyze threat model' });
    }
});

// Serve dashboard HTML
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// UDP broadcast responder for automatic server discovery
function startBroadcastResponder() {
    const udpServer = dgram.createSocket('udp4');
    
    udpServer.on('message', (msg, rinfo) => {
        if (msg.toString() === DISCOVERY_MESSAGE) {
            const localIPs = getLocalIPs();
            const response = JSON.stringify({
                service: 'mAIware-server',
                port: PORT,
                ips: localIPs,
                hostname: os.hostname()
            });
            udpServer.send(response, rinfo.port, rinfo.address);
        }
    });
    
    udpServer.on('error', (err) => {
        console.log(`⚠️  UDP broadcast responder error: ${err.message}`);
        udpServer.close();
    });
    
    udpServer.bind(BROADCAST_PORT, () => {
        console.log(`📡 UDP discovery responder listening on port ${BROADCAST_PORT}`);
    });
    
    return udpServer;
}

// Start server
app.listen(PORT, HOST, async () => {
    const localUrl = `http://localhost:${PORT}`;
    const localIPs = getLocalIPs();
    const networkUrls = localIPs.length > 0 
        ? localIPs.map(ip => `http://${ip}:${PORT}`).join(', ')
        : `http://<your-ip>:${PORT}`;

    console.log(`🖥️  mAIware Server Dashboard running on ${localUrl} (listening on ${HOST})`);
    console.log(`🌐 Network access: ${networkUrls}`);
    console.log(`📊 Dashboard: ${localUrl}`);
    console.log(`🔌 API endpoint: ${localUrl}/api/submit-scan`);
    
    // Start UDP broadcast responder for client discovery
    startBroadcastResponder();
    
    // Auto-open browser (using dynamic import for ES module)
    if (!process.env.MAIWARE_NO_BROWSER) {
        try {
            const open = (await import('open')).default;
            await open(localUrl);
        } catch (err) {
            console.log('Could not auto-open browser. Please open manually.');
        }
    }
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
