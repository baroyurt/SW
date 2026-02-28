// index_fiber_bridge_patch.js (güncellendi)
// Fiber bridge UI patch - rack-scoped switch list + küçük uyumluluk düzeltmeleri

(function () {
  if (window.__fiber_bridge_patch_installed) return;
  window.__fiber_bridge_patch_installed = true;

  // Helper to create modal overlay
  function createModal(html) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay active';
    overlay.style.zIndex = 2000;
    overlay.innerHTML = `
      <div class="modal" style="max-width:720px;">
        ${html}
      </div>
    `;
    document.body.appendChild(overlay);
    // close on clicking X or outside
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) overlay.remove();
    });
    overlay.querySelectorAll('.modal-close').forEach(btn => btn.addEventListener('click', () => overlay.remove()));
    return overlay;
  }

  // Build switch options (only fiber ports) - now supports rackId filter
  function buildSwitchOptions(selectedSwitchId, rackId = null) {
    const sel = document.createElement('select');
    sel.className = 'form-control';
    sel.id = 'fb-switch-select';
    sel.innerHTML = '<option value="">Switch seçin</option>';
    if (!Array.isArray(switches)) return sel;
    switches.forEach(sw => {
      // if rackId provided, filter by rack
      if (rackId !== null && rackId !== undefined && String(sw.rack_id) !== String(rackId)) return;
      const opt = document.createElement('option');
      opt.value = sw.id;
      opt.textContent = `${sw.name} (${sw.ports} port)`;
      opt.dataset.ports = sw.ports;
      if (String(sw.id) === String(selectedSwitchId)) opt.selected = true;
      sel.appendChild(opt);
    });
    // If after filtering none found, show helpful option
    if (sel.options.length === 1) {
      sel.innerHTML = '<option value="">Bu rack\'te switch yok</option>';
      sel.disabled = true;
    }
    return sel;
  }

  // Build fiber panel options
  function buildFiberPanelOptions(selectedPanelId) {
    const sel = document.createElement('select');
    sel.className = 'form-control';
    sel.id = 'fb-panel-select';
    sel.innerHTML = '<option value="">Fiber panel seçin</option>';
    if (!Array.isArray(fiberPanels)) return sel;
    fiberPanels.forEach(fp => {
      const opt = document.createElement('option');
      opt.value = fp.id;
      const rackName = (racks.find(r=>r.id==fp.rack_id)||{}).name || '';
      opt.textContent = `${fp.panel_letter} • ${fp.total_fibers}f • ${rackName}`;
      opt.dataset.max = fp.total_fibers;
      if (String(fp.id) === String(selectedPanelId)) opt.selected = true;
      sel.appendChild(opt);
    });
    return sel;
  }

  // Build panel port select
  function buildPanelPortSelect(max) {
    const sel = document.createElement('select');
    sel.className = 'form-control';
    sel.id = 'fb-panel-port';
    sel.innerHTML = '<option value="">Port seçin</option>';
    for (let i = 1; i <= (parseInt(max)||0); i++) {
      const o = document.createElement('option'); o.value = i; o.textContent = `Port ${i}`; sel.appendChild(o);
    }
    return sel;
  }

  // Build switch port select (fiber ports only)
  function buildSwitchPortSelect(sw) {
    const sel = document.createElement('select');
    sel.className = 'form-control';
    sel.id = 'fb-switch-port';
    sel.innerHTML = '<option value="">Port seçin</option>';
    if (!sw) return sel;
    const ports = parseInt(sw.ports) || 48;
    const fiberStart = Math.max(1, ports - 3); // last 4 ports
    for (let p = fiberStart; p <= ports; p++) {
      const o = document.createElement('option'); o.value = p; o.textContent = `Port ${p} (Fiber)`; sel.appendChild(o);
    }
    return sel;
  }

  // POST helper
  async function postJson(url, data) {
    const res = await fetch(url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(data)
    });
    const text = await res.text();
    try { return JSON.parse(text); } catch(e) { throw new Error('Sunucudan geçersiz JSON: ' + text); }
  }

  // Disconnect helper
  async function disconnectFiber(panelId, portNumber) {
    showLoading();
    try {
      const resp = await postJson('disconnectPanelPort.php', {
        panelId: parseInt(panelId),
        panelType: 'fiber',
        portNumber: parseInt(portNumber)
      });
      if (resp.success) {
        showToast('Fiber bağlantısı kesildi', 'success');
        await loadData();
      } else {
        throw new Error(resp.error || resp.message || 'Disconnect failed');
      }
    } catch (err) {
      console.error(err);
      showToast('Disconnect hata: ' + err.message, 'error');
    } finally {
      hideLoading();
    }
  }

  // Main modal for editing fiber port
  async function openFiberEditModal(panelId, portNumber) {
    // get panel object for display (and rack filter)
    const panel = (Array.isArray(fiberPanels) ? fiberPanels.find(p=>String(p.id)===String(panelId)) : null) || {panel_letter: panelId, rack_id: null};
    const panelRackId = panel ? panel.rack_id : null;
    const title = `Fiber Panel ${panel.panel_letter || panelId} - Port ${portNumber}`;

    const html = `
      <div class="modal-header">
        <h3 class="modal-title">${escapeHtml(title)}</h3>
        <button class="modal-close">&times;</button>
      </div>
      <div style="padding:10px;">
        <div style="margin-bottom:12px;">
          <strong>İşlem</strong>
          <div style="display:flex; gap:8px; margin-top:8px;">
            <button class="btn btn-primary" id="fb-action-panel">Panel ↔ Panel</button>
            <button class="btn btn-primary" id="fb-action-switch">Panel ↔ Switch</button>
            <button class="btn btn-danger" id="fb-action-disconnect">Bağlantıyı Kes</button>
          </div>
        </div>

        <div id="fb-action-area" style="margin-top:12px;"></div>

        <div style="display:flex; gap:10px; margin-top:18px; justify-content:flex-end;">
          <button class="btn btn-secondary modal-close">Kapat</button>
          <button class="btn btn-success" id="fb-save-btn">Kaydet</button>
        </div>
      </div>
    `;

    const overlay = createModal(html);
    const area = overlay.querySelector('#fb-action-area');
    const saveBtn = overlay.querySelector('#fb-save-btn');
    const btnPanel = overlay.querySelector('#fb-action-panel');
    const btnSwitch = overlay.querySelector('#fb-action-switch');
    const btnDisconnect = overlay.querySelector('#fb-action-disconnect');

    // Choose default UI: if there are other panels -> panel-panel else panel-switch
    const hasOtherPanels = Array.isArray(fiberPanels) && fiberPanels.filter(p=>String(p.id)!==String(panelId)).length > 0;
    if (hasOtherPanels) {
      btnPanel.classList.add('btn-primary'); btnSwitch.classList.remove('btn-primary');
      renderPanelToPanelUI(area, panelId);
    } else {
      btnSwitch.classList.add('btn-primary'); btnPanel.classList.remove('btn-primary');
      renderPanelToSwitchUI(area, panelRackId); // pass rack filter for switch UI
    }

    // wire action buttons
    btnPanel.addEventListener('click', () => { btnPanel.classList.add('btn-primary'); btnSwitch.classList.remove('btn-primary'); renderPanelToPanelUI(area, panelId); });
    btnSwitch.addEventListener('click', () => { btnSwitch.classList.add('btn-primary'); btnPanel.classList.remove('btn-primary'); renderPanelToSwitchUI(area, panelRackId); });
    btnDisconnect.addEventListener('click', async () => {
      if (!confirm('Bu fiber portundaki bağlantıyı kesmek istediğinize emin misiniz?')) return;
      try {
        await disconnectFiber(panelId, portNumber);
        overlay.remove();
      } catch (e) {
        console.error(e);
      }
    });

    // Save handler
    saveBtn.addEventListener('click', async () => {
      const panelSelect = area.querySelector('#fb-panel-select');
      const switchSelect = area.querySelector('#fb-switch-select');

      let payload = { user: 'ui', side_a: { type: 'fiber_port', panel_id: parseInt(panelId), port: parseInt(portNumber) }, side_b: null };

      if (panelSelect) {
        const targetPanelId = panelSelect.value;
        const targetPort = area.querySelector('#fb-panel-port')?.value;
        if (!targetPanelId || !targetPort) { showToast('Hedef panel ve port seçin', 'warning'); return; }
        payload.side_b = { type: 'fiber_port', panel_id: parseInt(targetPanelId), port: parseInt(targetPort) };
      } else if (switchSelect) {
        const swId = switchSelect.value;
        const swPort = area.querySelector('#fb-switch-port')?.value;
        if (!swId || !swPort) { showToast('Hedef switch ve port seçin', 'warning'); return; }
        payload.side_b = { type: 'switch', id: parseInt(swId), port: parseInt(swPort) };
      } else {
        showToast('Hedef seçimi bulunamadı', 'error'); return;
      }

      showLoading();
      try {
        const res = await postJson('saveFiberPortConnection.php', payload);
        if (!res || !res.success) throw new Error(res && (res.message || res.error) ? (res.message || res.error) : 'Bilinmeyen hata');
        showToast('Kayıt başarılı', 'success');
        overlay.remove();
        await loadData();
      } catch (err) {
        console.error(err);
        showToast('Kaydetme hatası: ' + err.message, 'error');
      } finally {
        hideLoading();
      }
    });

    // Renderers
    function renderPanelToPanelUI(container, sourcePanelId) {
      container.innerHTML = '';
      const label = document.createElement('div'); label.style.marginBottom='8px'; label.innerHTML = '<strong>Hedef Fiber Panel</strong>';
      container.appendChild(label);
      const sel = buildFiberPanelOptions();
      Array.from(sel.options).forEach(o => { if (o.value === String(sourcePanelId)) o.remove(); });
      container.appendChild(sel);

      const portHolder = document.createElement('div'); portHolder.style.marginTop='8px';
      portHolder.innerHTML = '<strong>Hedef Port</strong><div id="fb-panel-port-wrap" style="margin-top:6px"></div>';
      container.appendChild(portHolder);

      sel.addEventListener('change', function() {
        if (!this.value) {
          document.getElementById('fb-panel-port-wrap').innerHTML = '';
          return;
        }
        const max = this.options[this.selectedIndex].dataset.max || 0;
        const portSel = buildPanelPortSelect(max);
        const wrap = document.getElementById('fb-panel-port-wrap');
        wrap.innerHTML = '';
        wrap.appendChild(portSel);
      });
    }

    function renderPanelToSwitchUI(container, rackIdForFilter = null) {
      container.innerHTML = '';
      const label = document.createElement('div'); label.style.marginBottom='8px'; label.innerHTML = '<strong>Hedef Switch (fiber port seçin)</strong>';
      container.appendChild(label);
      // pass rackId so switch list is scoped
      const swSel = buildSwitchOptions(null, rackIdForFilter);
      container.appendChild(swSel);

      const portWrap = document.createElement('div'); portWrap.style.marginTop='8px'; portWrap.innerHTML = '<div id="fb-switch-port-wrap"></div>';
      container.appendChild(portWrap);

      swSel.addEventListener('change', function() {
        const sw = switches.find(s => String(s.id) === String(this.value));
        const portWrapInner = document.getElementById('fb-switch-port-wrap');
        portWrapInner.innerHTML = '';
        if (!sw) return;
        const portSel = buildSwitchPortSelect(sw);
        portWrapInner.appendChild(portSel);
      });
    }
  } // end openFiberEditModal

  // Exported function used by UI
  window.editFiberPort = function(panelId, portNumber) {
    try {
      openFiberEditModal(panelId, portNumber);
    } catch (e) {
      console.error('openFiberEditModal error', e);
      showToast('Modal açma hatası: ' + e.message, 'error');
    }
  };

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/[&<>"'`]/g, function (s) {
        return {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '`': '&#96;'
        }[s];
    });
  }

  console.log('Fiber bridge UI patch installed (editFiberPort overridden, rack-scoped switch list).');

})();