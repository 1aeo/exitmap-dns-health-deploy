/**
 * Tor Exit DNS Health Dashboard - Application JavaScript
 * Extracted from index.html for CSP compliance (no unsafe-inline)
 */

// Failures table state
const failuresPerPage = 25;
let allFailures = [];
const getTorMetricsUrl = (fp) => fp ? `https://metrics.1aeo.com/relay/${fp}/` : '#';

// All circuit failure type keys (for extracting from metadata)
const CIRCUIT_FAILURE_TYPES = [
    'circuit_timeout', 'circuit_destroyed', 'circuit_channel_closed',
    'circuit_connect_failed', 'circuit_no_path', 'circuit_resource_limit',
    'circuit_hibernating', 'circuit_finished', 'circuit_connection_closed',
    'circuit_io_error', 'circuit_protocol_error', 'circuit_internal_error',
    'circuit_requested', 'circuit_no_service', 'circuit_measurement_expired',
    'circuit_guard_limit', 'circuit_failed'
];

async function loadStats() {
    const contentEl = document.getElementById('results-content');
    const timestampEl = document.getElementById('scan-timestamp');
    
    try {
        const response = await fetch('/latest.json');
        if (!response.ok) throw new Error('Failed to fetch');
        
        const data = await response.json();
        const meta = data.metadata || {};
        const scan = meta.scan || {};
        const cv = meta.cross_validation || {};
        
        // Relay counts (new field names)
        const consensusRelays = meta.consensus_relays || 0;
        const testedRelays = meta.tested_relays || 0;
        const unreachableRelays = meta.unreachable_relays || 0;
        const dnsSuccess = meta.dns_success || 0;
        const dnsSuccessRate = meta.dns_success_rate_percent || 0;
        const reachabilityRate = meta.reachability_rate_percent || 100;
        
        // Calculate DNS errors (from dns_* fields)
        const dnsErrorCount = (meta.dns_timeout || 0) + (meta.dns_fail || 0) + 
                              (meta.dns_wrong_ip || 0) + (meta.dns_socks_error || 0) + 
                              (meta.dns_network_error || 0) + (meta.dns_exception || 0) + 
                              (meta.dns_error || 0);
        
        // Update timestamp in header
        if (meta.timestamp) {
            timestampEl.textContent = formatTimestamp(meta.timestamp);
        }
        
        // Build the unified content
        let html = `
            <!-- Key Metrics -->
            <div class="metrics-grid">
                <div class="metric-item">
                    <div class="metric-value info">${consensusRelays.toLocaleString()}</div>
                    <div class="metric-label">Consensus Exit Relays</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value ${reachabilityRate >= 90 ? 'success' : reachabilityRate >= 75 ? 'warning' : 'error'}">${testedRelays.toLocaleString()}</div>
                    <div class="metric-label">DNS Tested (${reachabilityRate.toFixed(1)}%)</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value ${dnsSuccessRate >= 95 ? 'success' : dnsSuccessRate >= 80 ? 'warning' : 'error'}">${dnsSuccess.toLocaleString()}</div>
                    <div class="metric-label">DNS Success (${dnsSuccessRate.toFixed(1)}%)</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value error">${dnsErrorCount.toLocaleString()}</div>
                    <div class="metric-label">DNS Errors</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value error">${unreachableRelays.toLocaleString()}</div>
                    <div class="metric-label">Unreachable Relays</div>
                </div>
            </div>
        `;
        
        // Row 1: Configuration
        const configItems = [];
        
        // Determine validation mode from scan.type
        let validationMode = 'Single Instance';
        const scanType = scan.type || 'single';
        const scanInstances = scan.instances || 1;
        if (scanType === 'cross_validate') {
            validationMode = `Cross Validation (${scanInstances} instances)`;
        } else if (scanType === 'split') {
            validationMode = `Split (${scanInstances} instances)`;
        }
        configItems.push(`<span class="detail-label">Scan Mode:</span> <span class="detail-value">${validationMode}</span>`);
        
        // DNS Validation Type (wildcard, etc.)
        configItems.push(`<span class="detail-label">DNS Type:</span> <span class="detail-value">${meta.mode || 'wildcard'}</span>`);
        
        if (scanType === 'cross_validate' && cv.relays_improved) {
            configItems.push(`<span class="detail-label">Relays Recovered:</span> <span class="detail-value">${cv.relays_improved.toLocaleString()}</span>`);
        }
        
        html += `
            <div class="details-row">
                <div class="detail-item">
                    <span class="detail-label" style="color: var(--aeo-green);">⚙️ Configuration:</span>
                </div>
                ${configItems.map(d => `<div class="detail-item">${d}</div>`).join('')}
            </div>
        `;
        
        // Row 2: Results breakdown - hierarchical DNS and Circuit errors
        const statusColors = {
            success: 'var(--status-success)',
            dns_timeout: 'var(--status-warning)',
            dns_fail: 'var(--status-error)',
            dns_exception: 'var(--aeo-text-muted)',
            dns_wrong_ip: 'var(--status-purple)',
            dns_socks_error: 'var(--aeo-text-muted)',
            dns_network_error: 'var(--aeo-text-muted)',
            dns_error: 'var(--aeo-text-muted)',
            relay_unreachable: 'var(--status-warning)',
            circuit_timeout: 'var(--status-warning)',
            circuit_destroyed: 'var(--status-error)',
            circuit_channel_closed: 'var(--status-warning)',
            circuit_connect_failed: 'var(--status-warning)',
            circuit_failed: 'var(--aeo-text-muted)'
        };
        
        // DNS Errors (from dns_* metadata fields)
        const dnsErrors = {
            dns_timeout: meta.dns_timeout || 0,
            dns_fail: meta.dns_fail || 0,
            dns_wrong_ip: meta.dns_wrong_ip || 0,
            dns_socks_error: meta.dns_socks_error || 0,
            dns_network_error: meta.dns_network_error || 0,
            dns_exception: meta.dns_exception || 0,
            dns_error: meta.dns_error || 0
        };
        const dnsErrorTotal = Object.values(dnsErrors).reduce((a, b) => a + b, 0);
        const topDnsErrors = Object.entries(dnsErrors)
            .filter(([_, count]) => count > 0)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3);
        
        // Circuit Errors (from flat circuit_* fields)
        const circuitErrors = {};
        CIRCUIT_FAILURE_TYPES.forEach(key => {
            const count = meta[key] || 0;
            if (count > 0) circuitErrors[key] = count;
        });
        const circuitErrorTotal = Object.values(circuitErrors).reduce((a, b) => a + b, 0);
        const topCircuitErrors = Object.entries(circuitErrors)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3);
        
        // Build hierarchical results display
        if (dnsErrorTotal > 0 || circuitErrorTotal > 0) {
            html += `
                <div class="details-row" style="flex-direction: column; gap: 0.75rem;">
                    <div class="detail-item">
                        <span class="detail-label" style="color: var(--aeo-green);">📊 Results:</span>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
            `;
            
            // DNS Errors section
            if (dnsErrorTotal > 0) {
                html += `
                    <div style="background: var(--aeo-dark-tertiary); padding: 0.75rem 1rem; border-radius: 8px;">
                        <div style="font-weight: 600; color: var(--status-error); margin-bottom: 0.4rem; font-size: 0.9rem;">
                            🔴 DNS Errors (${dnsErrorTotal.toLocaleString()})
                        </div>
                        <div style="display: flex; flex-direction: column; gap: 0.15rem; font-size: 0.8rem;">
                            ${topDnsErrors.map(([status, count]) => 
                                `<div style="display: flex; justify-content: space-between; gap: 1rem;"><span style="color: var(--aeo-text-muted);">${status.replace('dns_', '')}</span><span style="color: ${statusColors[status] || 'var(--aeo-text-muted)'}; font-family: monospace;">${count.toLocaleString()}</span></div>`
                            ).join('')}
                        </div>
                    </div>
                `;
            } else {
                html += `<div></div>`; // Empty placeholder for grid
            }
            
            // Circuit Errors section
            if (circuitErrorTotal > 0) {
                html += `
                    <div style="background: var(--aeo-dark-tertiary); padding: 0.75rem 1rem; border-radius: 8px;">
                        <div style="font-weight: 600; color: var(--status-warning); margin-bottom: 0.4rem; font-size: 0.9rem;">
                            🟠 Circuit Errors (${circuitErrorTotal.toLocaleString()})
                        </div>
                        <div style="display: flex; flex-direction: column; gap: 0.15rem; font-size: 0.8rem;">
                            ${topCircuitErrors.map(([status, count]) => 
                                `<div style="display: flex; justify-content: space-between; gap: 1rem;"><span style="color: var(--aeo-text-muted);">${status.replace('circuit_', '')}</span><span style="color: ${statusColors[status] || 'var(--aeo-text-muted)'}; font-family: monospace;">${count.toLocaleString()}</span></div>`
                            ).join('')}
                        </div>
                    </div>
                `;
            } else {
                html += `<div></div>`; // Empty placeholder for grid
            }
            
            html += `
                    </div>
                </div>
            `;
        }
        
        // Row 3-5: Timing (Total, Socket, DNS)
        const timing = meta.timing || {};
        
        // Helper to build timing row
        const buildTimingRow = (label, title, stats, icon) => {
            if (!stats || stats.avg_ms === undefined || stats.avg_ms === null) return '';
            const items = [
                ['Min', stats.min_ms],
                ['Avg', stats.avg_ms],
                ['P50', stats.p50_ms],
                ['P95', stats.p95_ms],
                ['P99', stats.p99_ms],
                ['Max', stats.max_ms]
            ].filter(([_, val]) => val !== undefined && val !== null);
            
            if (items.length === 0) return '';
            return `
                <div class="details-row">
                    <div class="detail-item">
                        <span class="detail-label" style="color: var(--aeo-green); cursor: help;" title="${title}">${icon} ${label}:</span>
                    </div>
                    ${items.map(([lbl, value]) => 
                        `<div class="detail-item"><span class="detail-label">${lbl}:</span> <span class="detail-value">${formatLatency(value)}</span></div>`
                    ).join('')}
                </div>
            `;
        };
        
        // Total timing (Tor circuit + DNS resolution)
        html += buildTimingRow(
            'Latency',
            'Total time including Tor circuit establishment (guard → exit) plus DNS resolution through the exit relay.',
            timing.total,
            '⏱️'
        );
        
        // Compute failures from results (no longer stored in separate array)
        const results = data.results || [];
        allFailures = results.filter(r => r.status !== 'success');
        
        // Failed relays section with pagination
        if (allFailures.length > 0) {
            html += `
                <div class="subsection-header" style="border-top: 1px solid var(--aeo-border-solid); padding-top: 1rem; margin-top: 0;">
                    <span class="subsection-title">⚠️ Failed Relays</span>
                    <span class="subsection-count">${allFailures.length} relays</span>
                </div>
                <div id="failures-table-container"></div>
            `;
        }
        
        contentEl.innerHTML = html;
        
        // Render first page of failures table (after DOM is set)
        if (allFailures.length > 0) displayFailuresPage(0);
        
    } catch (err) {
        contentEl.innerHTML = `
            <div class="error-message">
                Unable to load results. The scan may not have run yet.<br>
                <small>${escapeHtml(err.message)}</small>
            </div>
        `;
        timestampEl.textContent = '—';
    }
}

function formatLatency(ms) {
    if (ms >= 1000) {
        return (ms / 1000).toFixed(2) + 's';
    }
    return Math.round(ms) + 'ms';
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

function formatTimestamp(isoString) {
    try {
        const date = new Date(isoString);
        return date.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            timeZoneName: 'short'
        });
    } catch (e) {
        return isoString;
    }
}

// Shared: pagination controls HTML (prev/next + page info)
function paginationControls(page, totalPages, totalItems, perPage) {
    if (totalPages <= 1) return '';
    const start = page * perPage;
    return `
        <div class="pagination-controls">
            <button class="button page-btn" data-page="${page - 1}" ${page === 0 ? 'disabled' : ''}>← Prev</button>
            <span class="pagination-info">Page ${page + 1} of ${totalPages} <span class="pagination-range">(${start + 1}\u2013${Math.min(start + perPage, totalItems)} of ${totalItems})</span></span>
            <button class="button page-btn" data-page="${page + 1}" ${page === totalPages - 1 ? 'disabled' : ''}>Next →</button>
        </div>`;
}

// Shared: bind click handlers to .page-btn elements within a container
function bindPageButtons(container, callback) {
    container.querySelectorAll('.page-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            if (!this.disabled) callback(parseInt(this.dataset.page, 10));
        });
    });
}

// Display a page of the failures table
function displayFailuresPage(page) {
    const container = document.getElementById('failures-table-container');
    if (!container || allFailures.length === 0) return;

    const totalPages = Math.ceil(allFailures.length / failuresPerPage);
    page = Math.max(0, Math.min(page | 0, totalPages - 1));
    const start = page * failuresPerPage;

    container.innerHTML = `
        <table class="failures-table">
            <thead><tr><th>Nickname</th><th>Fingerprint</th><th>Status</th><th>Error</th></tr></thead>
            <tbody>${allFailures.slice(start, start + failuresPerPage).map(f => {
                const err = f.error || '';
                return `<tr>
                    <td><strong>${escapeHtml(f.exit_nickname || 'Unknown')}</strong></td>
                    <td class="fingerprint"><a href="${getTorMetricsUrl(f.exit_fingerprint)}" target="_blank" rel="noopener">${f.exit_fingerprint || ''}</a></td>
                    <td><span class="status-badge ${f.status || 'error'}">${f.status || 'error'}</span></td>
                    <td style="color: var(--aeo-text-muted); font-size: 0.8rem;" title="${escapeHtml(err)}">${escapeHtml(err.slice(0, 120))}${err.length > 120 ? '...' : ''}</td>
                </tr>`;
            }).join('')}</tbody>
        </table>
        ${paginationControls(page, totalPages, allFailures.length, failuresPerPage)}`;

    bindPageButtons(container, p => {
        displayFailuresPage(p);
        container.previousElementSibling?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
}

// Pagination state for file list
let currentPage = 0;
const filesPerPage = 10;
let allFiles = [];

// Security: Validate filename format
const VALID_FILE = /^dns_health_(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})\.json$/;
const VALID_ARCHIVE = /^archives\/exitmap-\d{6}\.tar\.gz$/;

// Load and display all JSON files with pagination
async function loadFileList() {
    const fileList = document.getElementById('file-list');
    
    try {
        const response = await fetch('/files.json');
        allFiles = await response.json();
        
        if (!allFiles || allFiles.length === 0) {
            fileList.innerHTML = `
                <li class="file-item">
                    <div>
                        <div class="file-name">📂 Historical Results</div>
                        <div class="file-meta">Results will appear here after scan runs</div>
                    </div>
                </li>
            `;
            return;
        }
        
        displayPage(0);
    } catch (error) {
        console.error('Error loading file list:', error);
        fileList.innerHTML = `
            <li class="file-item">
                <div>
                    <div class="file-name">📂 Historical Results</div>
                    <div class="file-meta">Check back after scan runs</div>
                </div>
            </li>
        `;
    }
}

// Display a specific page of results
function displayPage(page) {
    const fileList = document.getElementById('file-list');
    const totalPages = Math.ceil(allFiles.length / filesPerPage);
    page = Math.max(0, Math.min(page | 0, totalPages - 1));
    currentPage = page;
    
    const pageFiles = allFiles.slice(page * filesPerPage, (page + 1) * filesPerPage);
    
    const html = pageFiles.map(filename => {
        const match = VALID_FILE.exec(filename);
        if (!match && !VALID_ARCHIVE.test(filename)) {
            console.warn('Invalid filename rejected:', filename);
            return '';
        }
        
        let displayDate = escapeHtml(filename);
        if (match) {
            const [, y, mo, d, h, mi, s] = match;
            const dateObj = new Date(`${y}-${mo}-${d}T${h}:${mi}:${s}`);
            const timePart = dateObj.toLocaleTimeString('en-US', {
                hour: 'numeric', minute: '2-digit', second: '2-digit', timeZoneName: 'short'
            });
            displayDate = escapeHtml(`${y}-${mo}-${d} ${timePart}`);
        }
        
        const safeFilename = encodeURIComponent(filename);
        return `
            <li class="file-item">
                <div>
                    <div class="file-name">${displayDate}</div>
                    <div class="file-meta">${escapeHtml(filename)}</div>
                </div>
                <div style="display: flex; gap: 0.5rem;">
                    <a href="/${safeFilename}" class="button" target="_blank" rel="noopener noreferrer">👁️ View</a>
                    <a href="/${safeFilename}" class="button" download>⬇️ Download</a>
                </div>
            </li>`;
    }).join('');
    
    // Pagination controls (reuses shared helpers)
    const pagination = totalPages > 1 ? `
        <li class="file-item" style="margin-top: 1rem; border-color: var(--aeo-green); justify-content: center;">
            ${paginationControls(page, totalPages, allFiles.length, filesPerPage)}
        </li>` : '';
    
    fileList.innerHTML = html + pagination;
    bindPageButtons(fileList, displayPage);
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    loadStats();
    loadFileList();
    
    // Refresh stats every 5 minutes
    setInterval(loadStats, 5 * 60 * 1000);
});
