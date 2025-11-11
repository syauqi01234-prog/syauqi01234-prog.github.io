// Utility function to get DOM elements by ID
const getElement = id => document.getElementById(id);

// Updates the result display section with given content
const updateResult = (content, display = true) => {
    const result = getElement('result');
    result.style.display = display ? 'block' : 'none';
    result.innerHTML = content;
};

// Shows a loading spinner and message
const showLoading = message => updateResult(`
        <div class="loading">
            <p>${message}</p>
            <div class="spinner"></div>
        </div>
`);

// Displays an error message
const showError = message => updateResult(`<p class="error">${message}</p>`);

// Generic function to make a request to your Vercel API proxy
async function makeRequest(path, options = {}) {
    const response = await fetch(`https://<https://kudosyauqi01234-proggithubio.vercel.app/>/api/${path}`, options);

    // Handle failed requests gracefully
    if (!response.ok) {
        let error;
        try {
            error = await response.json();
        } catch {
            error = { error: { message: response.statusText } };
        }
        throw new Error(error.error?.message || 'Request failed!');
    }

    return response.json(); // Parse response JSON
}

// Handles the process of scanning a URL using the Vercel proxy
async function scanURL() {
    const url = getElement('urlInput').value.trim();
    if (!url) return showError("Please enter a URL!");

    try {
        new URL(url); // Validate URL format
    } catch {
        return showError("Please enter a valid URL (e.g., https://example.com)");
    }

    try {
        showLoading("Submitting URL for scanning...");

        // Submit URL to your proxy API
        const submitResult = await makeRequest("scan-url", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({ url })
        });

        if (!submitResult.data?.id) {
            throw new Error("Failed to get analysis ID");
        }

        // Delay before polling for results
        await new Promise(resolve => setTimeout(resolve, 3000));

        showLoading("Getting scan results...");
        await pollAnalysisResults(submitResult.data.id);
    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}

// Handles the process of scanning a file (NOT SUPPORTED unless you add an api/scan-file.js on your backend!)
async function scanFile() {
    showError("File scan not implemented for proxy backend yet. Ask for file scan code if you want this feature.");
}

// Polls for analysis results, retrying until complete or timeout
async function pollAnalysisResults(analysisId, fileName = '') {
    const maxAttempts = 20;
    let attempts = 0;
    let interval = 2000;

    while (attempts < maxAttempts) {
        try {
            showLoading(`Analyzing${fileName ? ` ${fileName}` : ''}... (${((maxAttempts - attempts) * interval / 1000).toFixed(0)}s remaining)`);

            // Poll proxy for analysis result
            const report = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
                method: "GET",
                headers: {
                    "Accept": "application/json"
                }
            });

            const result = await report.json();
            const status = result.data?.attributes?.status;

            if (!status) throw new Error("Invalid analysis response!");

            if (status === "completed") {
                showFormattedResult(result);
                break;
            }

            if (status === "failed") {
                throw new Error("Analysis failed!");
            }

            if (++attempts >= maxAttempts) {
                throw new Error("Analysis timeout - please try again!");
            }

            // Increase interval between retries
            interval = Math.min(interval * 1.5, 8000);
            await new Promise(resolve => setTimeout(resolve, interval));
        } catch (error) {
            showError(`Error: ${error.message}`);
            break;
        }
    }
}

// Formats and displays analysis results in the UI
function showFormattedResult(data) {
    if (!data?.data?.attributes?.stats) return showError("Invalid response format!");

    const stats = data.data.attributes.stats;
    const total = Object.values(stats).reduce((sum, val) => sum + val, 0);
    if (!total) return showError("No analysis results available!");

    const getPercent = val => ((val / total) * 100).toFixed(1);

    const categories = {
        malicious: { color: 'malicious', label: 'Malicious' },
        suspicious: { color: 'suspicious', label: 'Suspicious' },
        harmless: { color: 'safe', label: 'Clean' },
        undetected: { color: 'undetected', label: 'Undetected' }
    };

    const percents = Object.keys(categories).reduce((acc, key) => {
        acc[key] = getPercent(stats[key]);
        return acc;
    }, {});

    // Determine overall verdict
    const verdict = stats.malicious > 0 ? "Malicious" : stats.suspicious > 0 ? "Suspicious" : "Safe";
    const verdictClass = stats.malicious > 0 ? "malicious" : stats.suspicious > 0 ? "suspicious" : "safe";

    // Render result summary UI
    updateResult(`
        <h3>Scan Report</h3>
        <div class="scan-stats">
            <p><strong>Verdict:</strong> <span class="${verdictClass}">${verdict}</span></p>
            <div class="progress-section">
                <div class="progress-label">
                    <span>Detection Results</span>
                    <span class="progress-percent">${percents.malicious}% Detection Rate</span>
                </div>
                <div class="progress-stacked">
                    ${Object.entries(categories).map(([key, { color }]) => `
                        <div class="progress-bar ${color}" style="width: ${percents[key]}%" title="${categories[key].label}: ${stats[key]} (${percents[key]}%)">
                            <span class="progress-label-overlay">${stats[key]}</span>
                        </div>
                    `).join('')}
                </div>
                <div class="progress-legend">
                    ${Object.entries(categories).map(([key, { color, label }]) => `
                        <div class="legend-item">
                            <span class="legend-color ${color}"></span>
                            <span>${label} (${percents[key]}%)</span>
                        </div>
                    `).join('')}
                </div>
            </div>
            <div class="detection-details">
                ${Object.entries(categories).map(([key, { color, label }]) => `
                    <div class="detail-item ${color}">
                        <span class="detail-label">${label}</span>
                        <span class="detail-value">${stats[key]}</span>
                        <span class="detail-percent">${percents[key]}%<span>
                    </div>
                `).join('')}
            </div>
        </div>
        <button onclick="showFullReport(this.getAttribute('data-report'))" data-report='${JSON.stringify(data)}'>View Full Report</button>
    `);

    // Trigger animation
    setTimeout(() => getElement('result').querySelector('.progress-stacked').classList.add('animate'), 1000);
}

// Displays a detailed report modal with engine-by-engine detection results
function showFullReport(reportData) {
    const data = typeof reportData === 'string' ? JSON.parse(reportData) : reportData;
    const modal = getElement("fullReportModal");
    const results = data.data?.attributes?.results;

    getElement("fullReportContent").innerHTML = `
        <h3>Full Report Details</h3>
        ${results ? `
            <table>
                <tr><th>Engine</th><th>Result</th></tr>
                ${Object.entries(results).map(([engine, { category }]) => `
                    <tr>
                        <td>${engine}</td>
                        <td class="${category === "malicious" ? "malicious" : category === "suspicious" ? "suspicious" : "safe"}">${category}</td>
                    </tr>
                `).join('')}
            </table>
        ` : '<p>No detailed results available!</p>'}
    `;

    modal.style.display = "block";
    modal.offsetHeight;
    modal.classList.add("show");
}

// Closes the full report modal
const closeModal = () => {
    const modal = getElement("fullReportModal");
    modal.classList.remove("show");
    setTimeout(() => modal.style.display = "none", 300);
}

// Close modal on outside click
window.addEventListener('load', () => {
    const modal = getElement("fullReportModal");
    window.addEventListener('click', e => e.target === modal && closeModal());
});
