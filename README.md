# SurakshaMitra - File & URL Security Scanner

A modern web-based security scanner that allows users to scan files and URLs for potential threats. Built with HTML, CSS, and JavaScript, powered by the VirusTotal API.

## Features

- File upload with drag-and-drop support
- URL scanning capability
- Real-time scanning status updates
- Detailed threat reports from multiple antivirus engines
- Modern and responsive UI
- Navy blue and white theme

## Technologies Used

- HTML5
- CSS3 (with CSS Variables)
- JavaScript (ES6+)
- Font Awesome Icons
- VirusTotal API

## Setup

1. Clone this repository or download the files
2. Get a VirusTotal API key:
   - Sign up at [VirusTotal](https://www.virustotal.com)
   - Go to your profile and get your API key
   - Replace `YOUR_API_KEY_HERE` in `script.js` with your actual API key
3. Open `index.html` in your web browser
4. Start scanning files and URLs!

## Usage

### File Scanning
1. Drag and drop files into the upload area or click to browse
2. Click the "Scan" button next to any uploaded file
3. Wait for the scan to complete (approximately 15-30 seconds)
4. View the detailed scan results from multiple antivirus engines

### URL Scanning
1. Enter the URL you want to scan in the URL input field
2. Click the "Scan URL" button
3. Wait for the scan to complete (approximately 15-30 seconds)
4. View the detailed scan results from multiple antivirus engines

## API Rate Limits

The VirusTotal API has the following rate limits:
- 4 requests per minute for the public API
- 20 requests per minute for the private API
- Maximum file size: 32MB

## Note

This implementation uses the VirusTotal API for actual file and URL scanning. Please be aware of:
1. API rate limits
2. File size restrictions
3. Scanning time requirements (15-30 seconds per scan)
4. The need to keep your API key secure

## License

This project is open source and available under the MIT License. 