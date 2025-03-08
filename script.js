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
async function scanFile(file) {
    try {
        const formData = new FormData();
        formData.append('file', file);

        // Show loading state
        updateResults('Uploading file for scanning...', 'loading');

        // First request - Submit file for scanning
        const response = await fetch('/api/scan-file', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error);
        }

        if (data.status === 'pending') {
            // Show pending status
            updateResults('File submitted. Checking results...', 'loading');
            
            // Start polling for results
            await pollScanResults(data.scan_id);
        }

    } catch (error) {
        console.error('Error scanning file:', error);
        updateResults(`Error scanning file: ${error.message}`, 'error');
    }
}

async function pollScanResults(scanId) {
    try {
        let attempts = 0;
        const maxAttempts = 10; // Try for about 50 seconds (10 attempts * 5 second interval)

        const checkResults = async () => {
            if (attempts >= maxAttempts) {
                updateResults('Scan is taking longer than expected. Please check back later.', 'warning');
                return;
            }

            const response = await fetch(`/api/scan-results/${scanId}`);
            const data = await response.json();

            if (data.error) {
                throw new Error(data.error);
            }

            if (data.status === 'pending') {
                attempts++;
                updateResults('Scan in progress... Please wait.', 'loading');
                setTimeout(checkResults, 5000); // Check again in 5 seconds
                return;
            }

            // We have results
            const threatLevel = data.positives > 0 ? 'danger' : 'success';
            const status = data.positives > 0 ? 'Threats detected!' : 'File is safe';
            
            const resultHtml = `
                <h3 class="${threatLevel}">${status}</h3>
                <p>Detection Rate: ${data.positives}/${data.total} scanners</p>
                <p>Scan Date: ${data.scan_date}</p>
                <p>File Hashes:</p>
                <ul>
                    <li>MD5: ${data.md5}</li>
                    <li>SHA256: ${data.sha256}</li>
                </ul>
                <p><a href="${data.permalink}" target="_blank">View Full Report</a></p>
            `;

            updateResults(resultHtml, threatLevel);
        };

        // Start checking
        await checkResults();

    } catch (error) {
        console.error('Error checking scan results:', error);
        updateResults(`Error checking results: ${error.message}`, 'error');
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