// ============================================================================
// Port Change Highlighting and VLAN Display Module
// Add this to index.php to highlight recently changed ports in red
// ============================================================================

// Global variables for change tracking
let recentlyChangedPorts = {};
let vlanNames = {};

// Load VLAN names
async function loadVLANNames() {
    try {
        const response = await fetch('vlan_api.php?action=get_vlan_names');
        const data = await response.json();
        
        if (data.success) {
            // Create a lookup object for VLAN names
            data.vlans.forEach(vlan => {
                vlanNames[vlan.vlan_id] = {
                    name: vlan.vlan_name,
                    description: vlan.description,
                    color: vlan.color
                };
            });
            console.log('VLAN names loaded:', Object.keys(vlanNames).length);
        }
    } catch (error) {
        console.error('Error loading VLAN names:', error);
    }
}

// Load recently changed ports
async function loadRecentlyChangedPorts(hours = 24) {
    try {
        const response = await fetch(`port_change_api.php?action=get_recently_changed_ports&hours=${hours}`);
        const data = await response.json();
        
        if (data.success) {
            recentlyChangedPorts = data.changed_ports;
            console.log('Recently changed ports loaded:', data.count);
            
            // Apply highlighting to existing ports
            highlightChangedPorts();
        }
    } catch (error) {
        console.error('Error loading changed ports:', error);
    }
}

// Highlight ports that have recent changes
function highlightChangedPorts() {
    document.querySelectorAll('.port-item').forEach(portItem => {
        const switchId = portItem.closest('[data-switch-id]')?.dataset.switchId;
        const portNumber = portItem.dataset.port;
        
        if (switchId && portNumber) {
            const key = `${switchId}_${portNumber}`;
            
            if (recentlyChangedPorts[key]) {
                // Add red border and background to indicate recent change
                portItem.style.borderColor = '#ef4444';
                portItem.style.borderWidth = '3px';
                portItem.style.backgroundColor = '#fee2e2';
                
                // Add a badge to show change count
                const changeInfo = recentlyChangedPorts[key];
                let badge = portItem.querySelector('.change-badge');
                
                if (!badge) {
                    badge = document.createElement('div');
                    badge.className = 'change-badge';
                    badge.style.cssText = `
                        position: absolute;
                        top: -5px;
                        right: -5px;
                        background: #ef4444;
                        color: white;
                        border-radius: 50%;
                        width: 20px;
                        height: 20px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        font-size: 10px;
                        font-weight: bold;
                        z-index: 10;
                    `;
                    portItem.style.position = 'relative';
                    portItem.appendChild(badge);
                }
                
                badge.textContent = changeInfo.change_count;
                badge.title = `${changeInfo.change_count} değişiklik - Son: ${new Date(changeInfo.last_change).toLocaleString('tr-TR')}`;
            }
        }
    });
}

// Get VLAN name for display
function getVLANName(vlanId) {
    if (!vlanId) return '';
    
    const vlan = vlanNames[vlanId];
    if (vlan) {
        return vlan.name;
    }
    
    return `VLAN ${vlanId}`;
}

// Get VLAN color
function getVLANColor(vlanId) {
    if (!vlanId) return '#6c757d';
    
    const vlan = vlanNames[vlanId];
    if (vlan) {
        return vlan.color;
    }
    
    return '#6c757d';
}

// Add VLAN badge to port display
function addVLANBadgeToPort(portItem, vlanId) {
    if (!vlanId) return;
    
    const vlanName = getVLANName(vlanId);
    const vlanColor = getVLANColor(vlanId);
    
    let vlanBadge = portItem.querySelector('.vlan-badge');
    
    if (!vlanBadge) {
        vlanBadge = document.createElement('div');
        vlanBadge.className = 'vlan-badge';
        vlanBadge.style.cssText = `
            position: absolute;
            bottom: 2px;
            left: 2px;
            background: ${vlanColor};
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 9px;
            font-weight: bold;
            z-index: 5;
        `;
        portItem.style.position = 'relative';
        portItem.appendChild(vlanBadge);
    }
    
    vlanBadge.textContent = vlanName;
    vlanBadge.style.background = vlanColor;
    vlanBadge.title = `VLAN ${vlanId}: ${vlanName}`;
}

// Create VLAN filter dropdown
function createVLANFilter() {
    const filterContainer = document.querySelector('.filters-container') || 
                           document.querySelector('.toolbar') ||
                           document.querySelector('.header');
    
    if (!filterContainer) return;
    
    const vlanFilter = document.createElement('select');
    vlanFilter.id = 'vlan-filter';
    vlanFilter.className = 'form-control';
    vlanFilter.style.cssText = `
        max-width: 200px;
        display: inline-block;
        margin-left: 10px;
    `;
    
    vlanFilter.innerHTML = '<option value="">Tüm VLAN\'lar</option>';
    
    // Add VLAN options
    Object.keys(vlanNames).sort((a, b) => parseInt(a) - parseInt(b)).forEach(vlanId => {
        const vlan = vlanNames[vlanId];
        const option = document.createElement('option');
        option.value = vlanId;
        option.textContent = `${vlanId}: ${vlan.name}`;
        vlanFilter.appendChild(option);
    });
    
    // Add change event
    vlanFilter.addEventListener('change', function() {
        filterPortsByVLAN(this.value);
    });
    
    // Add label
    const label = document.createElement('label');
    label.textContent = 'Bağlantı Türü (VLAN): ';
    label.style.marginLeft = '15px';
    
    filterContainer.appendChild(label);
    filterContainer.appendChild(vlanFilter);
}

// Filter ports by VLAN
function filterPortsByVLAN(vlanId) {
    document.querySelectorAll('.port-item').forEach(portItem => {
        const portVlan = portItem.dataset.vlan;
        
        if (!vlanId || portVlan === vlanId) {
            portItem.style.display = '';
        } else {
            portItem.style.display = 'none';
        }
    });
}

// Initialize the module
async function initPortChangeHighlighting() {
    console.log('Initializing port change highlighting and VLAN display...');
    
    // Load VLAN names
    await loadVLANNames();
    
    // Load recently changed ports
    await loadRecentlyChangedPorts(24);
    
    // Create VLAN filter
    setTimeout(() => {
        createVLANFilter();
    }, 1000);
    
    // Refresh changed ports every 5 minutes
    setInterval(() => {
        loadRecentlyChangedPorts(24);
    }, 5 * 60 * 1000);
}

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initPortChangeHighlighting);
} else {
    initPortChangeHighlighting();
}

// Export functions for use in other parts of the application
window.portChangeModule = {
    loadVLANNames,
    loadRecentlyChangedPorts,
    highlightChangedPorts,
    getVLANName,
    getVLANColor,
    addVLANBadgeToPort,
    filterPortsByVLAN
};
