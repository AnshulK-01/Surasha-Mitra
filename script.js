// API Configuration
const API_URL = window.location.hostname === 'localhost' 
    ? 'http://localhost:3002/api'
    : `${window.location.origin}/api`;  // Use origin in production

// DOM Elements
const fileInput = document.getElementById('fileInput');
const fileUploadArea = document.getElementById('fileUploadArea');
const fileList = document.getElementById('fileList');
const urlInput = document.getElementById('urlInput');
const scanUrlButton = document.getElementById('scanUrl');
const scanResults = document.getElementById('scanResults');

// File Upload Handling
fileUploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    fileUploadArea.style.backgroundColor = 'rgba(26, 35, 126, 0.1)';
});

fileUploadArea.addEventListener('dragleave', () => {
    fileUploadArea.style.backgroundColor = 'transparent';
});

fileUploadArea.addEventListener('drop', (e) => {
    e.preventDefault();
    fileUploadArea.style.backgroundColor = 'transparent';
    const files = e.dataTransfer.files;
    handleFiles(files);
});

fileInput.addEventListener('change', (e) => {
    handleFiles(e.target.files);
});

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function handleFiles(files) {
    fileList.innerHTML = '';
    Array.from(files).forEach(file => {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        const fileSize = formatFileSize(file.size);
        const fileType = file.type || 'Unknown type';
        
        fileItem.innerHTML = `
            <div class="file-info">
                <span class="file-name">${file.name}</span>
                <span class="file-details">${fileSize} • ${fileType}</span>
            </div>
            <button onclick="scanFile('${file.name}')">Scan</button>
        `;
        fileList.appendChild(fileItem);
    });
}

// URL Scanning
scanUrlButton.addEventListener('click', () => {
    const url = urlInput.value.trim();
    if (url) {
        scanUrl(url);
    } else {
        showError('Please enter a valid URL');
    }
});

// Scanning Functions
async function scanFile(fileName) {
    showLoading(`Scanning file: ${fileName}`);
    try {
        const file = fileInput.files[0];
        if (!file) {
            throw new Error('No file selected');
        }

        const formData = new FormData();
        formData.append('file', file);

        console.log('Sending file for scanning:', {
            name: file.name,
            size: file.size,
            type: file.type
        });

        const response = await fetch(`${API_URL}/scan/file`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const errorData = await response.text();
            console.error('Server response:', errorData);
            throw new Error('Failed to scan file: ' + (errorData || response.statusText));
        }

        const data = await response.json();
        console.log('Scan results received:', data);

        if (!data || typeof data.positives === 'undefined') {
            console.error('Invalid scan results:', data);
            throw new Error('Invalid response from server');
        }

        // Process scan results
        const detectedThreats = data.scans ? 
            Object.entries(data.scans)
                .filter(([_, result]) => result.detected)
                .map(([scanner, result]) => ({
                    scanner,
                    threat: result.result,
                    details: result.detail || 'No additional details'
                })) : [];

        displayResults({
            fileName: fileName,
            status: detectedThreats.length === 0 ? 'safe' : 'suspicious',
            details: {
                threats: detectedThreats.map(t => `${t.scanner}: ${t.threat}`),
                scanTime: new Date().toLocaleTimeString(),
                scanDate: data.scan_date || new Date().toISOString(),
                totalScanners: data.total || 0,
                positiveScanners: detectedThreats.length,
                additionalInfo: {
                    'File Type': data.type || file.type || 'Unknown',
                    'File Size': formatFileSize(file.size),
                    'MD5 Hash': data.md5 || 'N/A',
                    'SHA-1 Hash': data.sha1 || 'N/A',
                    'SHA-256 Hash': data.sha256 || 'N/A',
                    'Scan ID': data.scan_id || 'N/A'
                }
            }
        });
    } catch (error) {
        console.error('Scan error:', error);
        showError(`Error scanning file: ${error.message}`);
    }
}

async function scanUrl(url) {
    showLoading(`Scanning URL: ${url}`);
    try {
        const response = await fetch(`${API_URL}/scan/url`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to scan URL');
        }

        displayResults({
            url: url,
            status: data.positives === 0 ? 'safe' : 'suspicious',
            details: {
                threats: data.positives > 0 ? 
                    Object.entries(data.scans)
                        .filter(([_, result]) => result.detected)
                        .map(([scanner, result]) => `${scanner}: ${result.result}`) : [],
                scanTime: new Date().toLocaleTimeString(),
                scanDate: data.scan_date,
                totalScanners: data.total,
                positiveScanners: data.positives,
                additionalInfo: {
                    'Scan ID': data.resource || 'N/A',
                    'Scan Date': new Date(data.scan_date).toLocaleString() || 'N/A',
                    'URL': data.url || url,
                    'Response Code': data.response_code || 'N/A',
                    'Categories': data.categories ? data.categories.join(', ') : 'N/A'
                }
            }
        });
    } catch (error) {
        console.error('Scan error:', error);
        showError(`Error scanning URL: ${error.message}`);
    }
}

// UI Functions
function showLoading(message) {
    scanResults.innerHTML = `
        <div class="loading">
            <i class="fas fa-spinner fa-spin"></i>
            <p>${message}</p>
        </div>
    `;
}

function showError(message) {
    scanResults.innerHTML = `
        <div class="error">
            <i class="fas fa-exclamation-circle"></i>
            <p>${message}</p>
            <p class="error-details">Please check the console (F12) for more details</p>
        </div>
    `;
}

function displayResults(result) {
    const statusColor = result.status === 'safe' ? 'var(--success)' : 'var(--danger)';
    const statusIcon = result.status === 'safe' ? 'fa-shield-alt' : 'fa-exclamation-triangle';
    const statusText = result.status === 'safe' ? 'SAFE' : 'SUSPICIOUS';
    
    // Format scan date if available
    const scanDate = result.details.scanDate ? new Date(result.details.scanDate).toLocaleString() : 'N/A';
    
    scanResults.innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <h3>
                    <i class="fas ${result.fileName ? 'fa-file-alt' : 'fa-link'}"></i>
                    ${result.fileName || result.url}
                </h3>
                <span class="status" style="color: ${statusColor}">
                    <i class="fas ${statusIcon}"></i> ${statusText}
                </span>
            </div>
            <div class="result-details">
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-value">
                            <i class="fas fa-clock"></i>
                        </div>
                        <div class="stat-label">Scan Time</div>
                        <div class="stat-value">${scanDate}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">
                            <i class="fas fa-search"></i>
                        </div>
                        <div class="stat-label">Total Scanners</div>
                        <div class="stat-value">${result.details.totalScanners}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">
                            <i class="fas ${result.status === 'safe' ? 'fa-check-circle' : 'fa-exclamation-circle'}"></i>
                        </div>
                        <div class="stat-label">Positive Results</div>
                        <div class="stat-value">${result.details.positiveScanners}</div>
                    </div>
                </div>
                
                ${result.details.threats.length > 0 ? `
                    <div class="threats">
                        <h4>
                            <i class="fas fa-bug"></i>
                            Threats Detected
                        </h4>
                        <ul>
                            ${result.details.threats.map(threat => `
                                <li>
                                    <i class="fas fa-exclamation-circle"></i>
                                    ${threat}
                                </li>
                            `).join('')}
                        </ul>
                    </div>
                ` : `
                    <div class="threats">
                        <h4>
                            <i class="fas fa-shield-alt"></i>
                            No Threats Detected
                        </h4>
                        <p style="text-align: center; color: var(--success);">
                            <i class="fas fa-check-circle"></i>
                            This ${result.fileName ? 'file' : 'URL'} appears to be safe
                        </p>
                    </div>
                `}

                ${result.details.additionalInfo ? `
                    <div class="additional-info">
                        <h4>
                            <i class="fas fa-info-circle"></i>
                            Additional Information
                        </h4>
                        <div class="info-grid">
                            ${Object.entries(result.details.additionalInfo).map(([key, value]) => `
                                <div class="info-item">
                                    <span class="info-label">${key}</span>
                                    <span class="info-value">${value}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
} 