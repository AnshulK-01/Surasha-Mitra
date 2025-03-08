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
const VIRUSTOTAL_API_KEY = '651a7355320ff34e2288ef9f59ad7111606cd9ded1f6500c01e4afed281c6d03';
const VIRUSTOTAL_API_URL = 'www.virustotal.com';

// Helper function to make HTTPS requests
function makeRequest(options, postData) {
    // Add API version and proper headers
    const defaultHeaders = {
        'User-Agent': 'SurakshaMitra-Scanner',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    };

    options.headers = {
        ...defaultHeaders,
        ...options.headers
    };

    return new Promise((resolve, reject) => {
        console.log('Making request to:', options.hostname + options.path);
        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    const jsonData = JSON.parse(data);
                    console.log('Response received:', jsonData);
                    resolve(jsonData);
                } catch (e) {
                    console.error('Failed to parse response:', data);
                    resolve(data);
                }
            });
        });

        req.on('error', (error) => {
            console.error('Request error:', error);
            reject(error);
        });

        if (postData) {
            if (postData instanceof FormData) {
                postData.pipe(req);
            } else {
                req.write(postData);
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
        if (!req.file) {
            throw new Error('No file uploaded');
        }

        console.log('File received:', {
            name: req.file.originalname,
            size: req.file.size,
            type: req.file.mimetype
        });

        const formData = new FormData();
        formData.append('apikey', VIRUSTOTAL_API_KEY);
        formData.append('file', req.file.buffer, {
            filename: req.file.originalname,
            contentType: req.file.mimetype
        });

        const options = {
            hostname: VIRUSTOTAL_API_URL,
            path: '/vtapi/v2/file/scan',
            method: 'POST',
            headers: {
                ...formData.getHeaders()
            }
        };

        console.log('Uploading file to VirusTotal...');
        const uploadResult = await makeRequest(options, formData);
        console.log('Upload result:', uploadResult);

        if (!uploadResult || !uploadResult.scan_id) {
            console.error('Invalid VirusTotal response:', uploadResult);
            throw new Error('Invalid response from VirusTotal API');
        }

        // Wait for scan to complete
        console.log('Waiting for scan to complete...');
        await new Promise(resolve => setTimeout(resolve, 15000));

        // Get scan results
        console.log('Fetching scan results for scan_id:', uploadResult.scan_id);
        const reportOptions = {
            hostname: VIRUSTOTAL_API_URL,
            path: `/vtapi/v2/file/report?apikey=${VIRUSTOTAL_API_KEY}&resource=${uploadResult.scan_id}`,
            method: 'GET'
        };

        const report = await makeRequest(reportOptions);
        if (!report || report.response_code !== 1) {
            console.error('Invalid scan report:', report);
            throw new Error('Failed to get valid scan results');
        }

        // Transform the report data
        const transformedReport = {
            scan_id: report.scan_id,
            scan_date: report.scan_date,
            positives: report.positives,
            total: report.total,
            scans: report.scans,
            md5: report.md5,
            sha1: report.sha1,
            sha256: report.sha256,
            type: report.type || req.file.mimetype,
            size: req.file.size
        };

        console.log('Scan completed successfully:', {
            positives: transformedReport.positives,
            total: transformedReport.total
        });

        res.json(transformedReport);
    } catch (error) {
        console.error('Error in file scan:', error);
        res.status(500).json({ 
            error: error.message,
            details: error.stack
        });
    }
}

// Handler function for URL scanning
async function handleUrlScan(req, res) {
    try {
        const { url } = req.body;
        if (!url) {
            throw new Error('No URL provided');
        }

        const formData = new FormData();
        formData.append('apikey', VIRUSTOTAL_API_KEY);
        formData.append('url', url);

        const options = {
            hostname: VIRUSTOTAL_API_URL,
            path: '/vtapi/v2/url/scan',
            method: 'POST',
            headers: {
                ...formData.getHeaders()
            }
        };

        const scanResult = await makeRequest(options, formData);
        
        // Wait for scan to complete
        await new Promise(resolve => setTimeout(resolve, 15000));

        // Get scan results
        const reportOptions = {
            hostname: VIRUSTOTAL_API_URL,
            path: `/vtapi/v2/url/report?apikey=${VIRUSTOTAL_API_KEY}&resource=${scanResult.scan_id}`,
            method: 'GET'
        };

        const report = await makeRequest(reportOptions);
        res.json(report);
    } catch (error) {
        console.error('Error in URL scan:', error);
        res.status(500).json({ 
            error: error.message,
            details: error.stack
        });
    }
}

// Setup routes
app.post('/api/scan/file', upload.single('file'), handleFileScan);
app.post('/api/scan/url', handleUrlScan);

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