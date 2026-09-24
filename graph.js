/* ==========================================================================
   EmailShield - Cytoscape.js Investigation Network Relationship Graph
   ========================================================================== */

function renderCytoscapeGraph(containerId, graphData) {
  const container = document.getElementById(containerId);
  if (!container || typeof cytoscape === 'undefined') return;

  const cy = cytoscape({
    container: container,
    elements: graphData.elements || [
      // Default Demo Graph Nodes
      { data: { id: 'email', label: 'Email: ST-1024', type: 'email', risk: 'high' } },
      { data: { id: 'sender', label: 'Sender: service-update@...', type: 'sender', risk: 'high' } },
      { data: { id: 'domain', label: 'Domain: mail-auth-verify.xyz', type: 'domain', risk: 'high' } },
      { data: { id: 'ip', label: 'IP: 185.220.101.5', type: 'ip', risk: 'high' } },
      { data: { id: 'geo', label: 'Location: Munich, DE (Tor)', type: 'location', risk: 'medium' } },
      { data: { id: 'url1', label: 'URL: paypal-verification...', type: 'url', risk: 'high' } },
      { data: { id: 'replyto', label: 'Reply-To: hackerserver.info', type: 'sender', risk: 'high' } },

      // Edges
      { data: { source: 'email', target: 'sender', label: 'sent by' } },
      { data: { source: 'sender', target: 'domain', label: 'belongs to' } },
      { data: { source: 'domain', target: 'ip', label: 'resolves to' } },
      { data: { source: 'ip', target: 'geo', label: 'located in' } },
      { data: { source: 'email', target: 'url1', label: 'contains link' } },
      { data: { source: 'email', target: 'replyto', label: 'diverts reply' } }
    ],

    style: [
      {
        selector: 'node',
        style: {
          'background-color': '#2563eb',
          'label': 'data(label)',
          'color': '#ffffff',
          'font-size': '11px',
          'font-family': 'Inter, sans-serif',
          'text-valign': 'bottom',
          'text-margin-y': 6,
          'text-background-color': '#0f172a',
          'text-background-opacity': 0.8,
          'text-background-padding': '3px 6px',
          'text-background-shape': 'roundrectangle',
          'width': 36,
          'height': 36,
          'border-width': 2,
          'border-color': '#ffffff'
        }
      },
      {
        selector: 'node[type = "email"]',
        style: { 'background-color': '#2563eb', 'shape': 'ellipse', 'width': 44, 'height': 44 }
      },
      {
        selector: 'node[type = "sender"]',
        style: { 'background-color': '#8b5cf6', 'shape': 'diamond' }
      },
      {
        selector: 'node[type = "domain"]',
        style: { 'background-color': '#06b6d4', 'shape': 'roundrectangle' }
      },
      {
        selector: 'node[type = "ip"]',
        style: { 'background-color': '#ef4444', 'shape': 'pentagon' }
      },
      {
        selector: 'node[type = "location"]',
        style: { 'background-color': '#f59e0b', 'shape': 'hexagon' }
      },
      {
        selector: 'node[type = "url"]',
        style: { 'background-color': '#dc2626', 'shape': 'triangle' }
      },
      {
        selector: 'edge',
        style: {
          'width': 2,
          'line-color': '#475569',
          'target-arrow-color': '#475569',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'label': 'data(label)',
          'font-size': '9px',
          'color': '#94a3b8',
          'text-background-color': '#0f172a',
          'text-background-opacity': 0.7,
          'text-background-padding': '2px'
        }
      }
    ],

    layout: {
      name: 'breadthfirst',
      directed: true,
      padding: 30,
      spacingFactor: 1.2
    }
  });

  // Handle Node Click Inspection
  cy.on('tap', 'node', function(evt) {
    const node = evt.target;
    const detailsBox = document.getElementById('graph-node-details');
    if (detailsBox) {
      detailsBox.innerHTML = `
        <div class="p-3 bg-dark text-white rounded border border-secondary">
          <div class="d-flex align-items-center justify-content-between mb-2">
            <span class="badge bg-primary text-uppercase">${node.data('type')} Node</span>
            <span class="badge bg-danger">Risk: ${node.data('risk') || 'High'}</span>
          </div>
          <h6 class="text-info font-monospace mb-1">${node.data('label')}</h6>
          <small class="text-muted">Entity ID: ${node.data('id')}</small>
        </div>
      `;
    }
  });
}
