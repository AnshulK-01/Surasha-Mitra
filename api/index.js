const express = require('express');
const cors = require('cors');
const multer = require('multer');
const FormData = require('form-data');
const https = require('https');
const path = require('path');

const app = express();

// Configure multer for memory storage
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// Enable CORS and JSON parsing
app.use(cors());
app.use(express.json());

// Serve static files from the root directory
app.use(express.static(path.join(__dirname, '..')));

// Serve index.html for the root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// VirusTotal configuration
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VIRUSTOTAL_API_URL = 'www.virustotal.com';

// Helper function to make HTTPS requests
function makeRequest(urlOrOptions, options = {}) {
    return new Promise((resolve, reject) => {
        let requestOptions = {};
        
        if (typeof urlOrOptions === 'string') {
            const url = new URL(urlOrOptions);
            requestOptions = {
                hostname: url.hostname,
                path: url.pathname + url.search,
                method: options.method || 'GET',
                headers: options.headers || {}
            };
        } else {
            requestOptions = urlOrOptions;
        }

        // Add default headers
        requestOptions.headers = {
            'User-Agent': 'SurakshaMitra-Scanner',
            'Accept': 'application/json',
            ...requestOptions.headers
        };

        console.log('Making request to:', requestOptions.hostname + requestOptions.path);
        
        const req = https.request(requestOptions, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    const jsonData = JSON.parse(data);
                    console.log('Response received:', jsonData);
                    resolve(jsonData);
                } catch (e) {
                    console.error('Failed to parse response:', data);
                    reject(new Error('Invalid response from server'));
                }
            });
        });

        req.on('error', (error) => {
            console.error('Request error:', error);
            reject(error);
        });

        if (options.body) {
            if (options.body instanceof FormData) {
                options.body.pipe(req);
            } else {
                req.write(options.body);
                req.end();
            }
        } else {
            req.end();
        }
    });
}

// Handler function for file scanning
async function handleFileScan(req, res) {
    try {
        const file = req.file;
        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        console.log('File received:', file.originalname, 'Size:', file.size);

        // First, upload the file
        const formData = new FormData();
        formData.append('file', file.buffer, file.originalname);

        const uploadResponse = await makeRequest('https://www.virustotal.com/vtapi/v2/file/scan', {
            method: 'POST',
            body: formData,
            headers: {
                'apikey': process.env.VIRUSTOTAL_API_KEY
            }
        });

        if (!uploadResponse.scan_id) {
            throw new Error('Failed to get scan ID from VirusTotal');
        }

        // Return the scan ID immediately
        res.json({
            status: 'pending',
            scan_id: uploadResponse.scan_id,
            message: 'File submitted for scanning. Please check results in a few moments.'
        });

    } catch (error) {
        console.error('Error scanning file:', error);
        res.status(500).json({ error: 'Failed to scan file: ' + error.message });
    }
}

// Setup routes with proper error handling
app.post('/api/scan/file', upload.single('file'), async (req, res) => {
    try {
        await handleFileScan(req, res);
    } catch (error) {
        console.error('Error in file scan route:', error);
        res.status(500).json({ error: error.message });
    }
});

// Handler function for URL scanning
async function handleUrlScan(req, res) {
    try {
        const { url } = req.body;
        if (!url) {
            return res.status(400).json({ error: 'No URL provided' });
        }

        // First, submit URL for scanning
        const formData = new FormData();
        formData.append('apikey', process.env.VIRUSTOTAL_API_KEY);
        formData.append('url', url);

        const scanOptions = {
            hostname: VIRUSTOTAL_API_URL,
            path: '/vtapi/v2/url/scan',
            method: 'POST',
            headers: {
                ...formData.getHeaders()
            }
        };

        const scanResult = await makeRequest(scanOptions, formData);
        if (!scanResult.scan_id) {
            throw new Error('Failed to get scan ID from VirusTotal');
        }

        // Return scan ID immediately
        res.json({
            status: 'pending',
            scan_id: scanResult.scan_id,
            message: 'URL submitted for scanning'
        });

    } catch (error) {
        console.error('Error in URL scan:', error);
        res.status(500).json({ error: error.message });
    }
}

// Setup routes with proper error handling
app.post('/api/scan/url', async (req, res) => {
    try {
        await handleUrlScan(req, res);
    } catch (error) {
        console.error('Error in URL scan route:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/scan-results/:scanId', async (req, res) => {
    try {
        const scanId = req.params.scanId;
        const reportUrl = `https://www.virustotal.com/vtapi/v2/file/report?apikey=${process.env.VIRUSTOTAL_API_KEY}&resource=${scanId}`;
        const report = await makeRequest(reportUrl);

        if (report.response_code === 0) {
            return res.json({ status: 'pending', message: 'Scan in progress' });
        }

        res.json(report);
    } catch (error) {
        console.error('Error getting scan results:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/url-results/:scanId', async (req, res) => {
    try {
        const scanId = req.params.scanId;
        const reportUrl = `https://www.virustotal.com/vtapi/v2/url/report?apikey=${process.env.VIRUSTOTAL_API_KEY}&resource=${scanId}`;
        const report = await makeRequest(reportUrl);

        if (report.response_code === 0) {
            return res.json({ status: 'pending', message: 'Scan in progress' });
        }

        res.json(report);
    } catch (error) {
        console.error('Error getting URL scan results:', error);
        res.status(500).json({ error: error.message });
    }
});

// For Vercel serverless deployment
module.exports = async (req, res) => {
    if (!req.url) {
        return res.status(400).json({ error: 'Invalid request' });
    }

    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        return res.status(200).end();
    }

    // Route the request through Express
    return new Promise((resolve) => {
        app(req, res, (result) => {
            resolve(result);
        });
    });
};

// Start the server if running directly (not being imported)
if (require.main === module) {
    const PORT = process.env.PORT || 3002;
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Access the application at http://localhost:${PORT}`);
    });
} 