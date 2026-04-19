<?php
/**
 * Rack QR Diagram – Mobile-first drill-down page
 *
 * URL patterns:
 *   rack_qr.php            → list of all racks, each with QR code
 *   rack_qr.php?rack_id=N  → auto-opens that rack
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$auth = new Auth($conn);
$auth->requireLogin();
// Release PHP session lock immediately – this page only reads session data.
session_write_close();

header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

$initRackId = isset($_GET['rack_id']) ? (int)$_GET['rack_id'] : 0;

$proto   = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$baseUrl = $proto . '://' . $_SERVER['HTTP_HOST'] . strtok($_SERVER['REQUEST_URI'], '?');
?>
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>Raf Kabini</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0f172a;--card:#1e293b;--bdr:#334155;
  --txt:#e2e8f0;--muted:#94a3b8;
  --blue:#3b82f6;--bl:rgba(59,130,246,.15);
  --green:#10b981;--gl:rgba(16,185,129,.15);
  --amber:#f59e0b;--al:rgba(245,158,11,.15);
  --red:#ef4444;--rl:rgba(239,68,68,.15);
  --violet:#8b5cf6;--vl:rgba(139,92,246,.15);
  --r:12px;--rs:8px;
}
html,body{background:var(--bg);color:var(--txt);font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}

/* Header */
.hdr{position:sticky;top:0;z-index:200;background:rgba(15,23,42,.96);backdrop-filter:blur(12px);
  border-bottom:1px solid var(--bdr);display:flex;align-items:center;gap:10px;padding:11px 14px}
.back-btn{display:none;width:36px;height:36px;border-radius:var(--rs);background:var(--bl);
  border:1px solid rgba(59,130,246,.3);color:#93c5fd;cursor:pointer;font-size:.95rem;
  align-items:center;justify-content:center;flex-shrink:0;-webkit-tap-highlight-color:transparent}
.back-btn.v{display:flex}
.htitles{flex:1;min-width:0}
.htitles h1{font-size:.95rem;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.htitles p{font-size:11px;color:var(--muted);margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.admin-lnk{display:flex;align-items:center;gap:5px;background:rgba(30,41,59,.8);border:1px solid var(--bdr);
  color:var(--muted);padding:6px 10px;border-radius:var(--rs);font-size:11px;text-decoration:none;flex-shrink:0}

/* Screens */
.scr{display:none;padding:14px;max-width:760px;margin:0 auto}.scr.on{display:block}

/* Rack list */
.rack-list{display:flex;flex-direction:column;gap:10px}
.rack-card{background:var(--card);border:1px solid var(--bdr);border-radius:var(--r);overflow:hidden;
  -webkit-tap-highlight-color:transparent}
.rch{display:flex;align-items:center;gap:11px;padding:13px 14px;cursor:pointer}
.rch:active,.item-row:active{filter:brightness(1.12)}
.ric{width:38px;height:38px;border-radius:var(--rs);background:var(--bl);border:1px solid rgba(59,130,246,.3);
  display:flex;align-items:center;justify-content:center;color:#93c5fd;font-size:1rem;flex-shrink:0}
.rname{font-weight:700;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rloc{font-size:11px;color:var(--muted);margin-top:2px;display:flex;flex-wrap:wrap;gap:4px;align-items:center}
.chv{color:var(--muted);font-size:12px;flex-shrink:0}
/* QR strip */
.qrs{border-top:1px solid var(--bdr);padding:10px 14px;display:flex;align-items:center;gap:12px;background:transparent}
.qrbox{background:#fff;padding:5px;border-radius:5px;flex-shrink:0;line-height:0}
.qrlbl{font-size:13px;color:var(--fg);font-weight:700;word-break:break-word;flex:1;line-height:1.4}

/* Item rows */
.sec-lbl{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.7px;
  color:var(--muted);padding:9px 2px 5px}
.il{display:flex;flex-direction:column;gap:7px}
.item-row{background:var(--card);border:1px solid var(--bdr);border-radius:var(--rs);
  display:flex;flex-direction:column;gap:0;padding:10px 12px;cursor:pointer;-webkit-tap-highlight-color:transparent}
.item-hdr{display:flex;align-items:center;gap:11px}
.item-dots{margin-top:7px;line-height:1}
.item-row.sw{border-left:3px solid var(--blue)}
.item-row.pp{border-left:3px solid var(--amber)}
.item-row.fp{border-left:3px solid var(--green)}
.item-row.rd{border-left:3px solid var(--violet)}
.ii{width:34px;height:34px;border-radius:var(--rs);display:flex;align-items:center;justify-content:center;font-size:.95rem;flex-shrink:0}
.sw .ii{background:var(--bl);color:#93c5fd}.pp .ii{background:var(--al);color:#fcd34d}.fp .ii{background:var(--gl);color:#6ee7b7}.rd .ii{background:var(--vl);color:#c4b5fd}
.iname{font-weight:600;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.isub{font-size:11px;color:var(--muted);margin-top:2px}
.sdot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.d-on{background:var(--green);box-shadow:0 0 4px var(--green)}.d-off{background:var(--red)}.d-unk{background:var(--muted)}

/* Port grid */
.pgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(60px,1fr));gap:7px;margin-bottom:14px}
.prt{aspect-ratio:1;border-radius:var(--rs);display:flex;flex-direction:column;align-items:center;justify-content:center;
  gap:2px;cursor:pointer;border:2px solid transparent;-webkit-tap-highlight-color:transparent;padding:4px;position:relative}
.prt:active{filter:brightness(1.35)}
.p-act{background:var(--gl);border-color:rgba(16,185,129,.5);color:#6ee7b7}
.p-off{background:rgba(51,65,85,.3);border-color:rgba(51,65,85,.5);color:#475569}
.p-pan{background:var(--bl);border-color:rgba(59,130,246,.5);color:#93c5fd}
.pnum{font-size:12px;font-weight:800}
.pdev{font-size:8px;text-align:center;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%;padding:0 1px}
.pbadge{position:absolute;bottom:2px;right:2px;background:var(--amber);color:#000;
  font-size:7px;font-weight:900;padding:1px 3px;border-radius:3px;line-height:1.3}

/* Panel table */
.ptbl{width:100%;border-collapse:collapse;font-size:12px}
.ptbl th{background:rgba(15,23,42,.6);color:var(--muted);padding:7px 9px;text-align:left;
  font-size:10px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--bdr)}
.ptbl td{padding:7px 9px;border-bottom:1px solid rgba(51,65,85,.3);vertical-align:middle}
.ptbl tr:last-child td{border-bottom:none}
.mono{font-family:monospace;font-size:11px;color:#38bdf8}

/* Cable drawer */
.dbg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:299}
.cdrawer{position:fixed;bottom:0;left:0;right:0;z-index:300;transform:translateY(100%);
  transition:transform .3s ease;background:rgba(13,19,34,.98);backdrop-filter:blur(16px);
  border-top:1px solid var(--bdr);border-radius:22px 22px 0 0;padding:0 14px 32px;max-height:70vh;overflow-y:auto}
.cdrawer.open{transform:translateY(0)}
.dhandle{width:38px;height:4px;background:var(--bdr);border-radius:2px;margin:11px auto 12px;cursor:pointer}
.drow{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.dtitle{font-weight:700;font-size:14px;color:#c4b5fd;display:flex;align-items:center;gap:7px}
.dclose{width:30px;height:30px;border-radius:var(--rs);background:var(--rl);border:1px solid rgba(239,68,68,.3);
  color:#fca5a5;cursor:pointer;font-size:.85rem;display:flex;align-items:center;justify-content:center}
.cstep{display:flex;align-items:flex-start;gap:9px;background:var(--vl);border:1px solid rgba(139,92,246,.3);
  border-radius:var(--rs);padding:11px 13px;margin-bottom:7px}
.csi{font-size:1.1rem;flex-shrink:0;margin-top:1px}
.csl{font-weight:700;font-size:13px}.css{font-size:11px;color:var(--muted);margin-top:2px}
.carrow{text-align:center;font-size:18px;color:var(--violet);margin:2px 0}
.nopath{color:var(--muted);font-size:12px;padding:8px 0}

/* Tags */
.tag{display:inline-flex;align-items:center;gap:3px;padding:2px 7px;border-radius:7px;font-size:11px;font-weight:600}
.tb{background:var(--bl);color:#93c5fd;border:1px solid rgba(59,130,246,.3)}
.ta{background:var(--al);color:#fcd34d;border:1px solid rgba(245,158,11,.3)}
.tg{background:var(--gl);color:#6ee7b7;border:1px solid rgba(16,185,129,.3)}
.tm{background:rgba(51,65,85,.3);color:var(--muted);border:1px solid var(--bdr)}

/* Misc */
.empty{text-align:center;padding:44px 20px;color:var(--muted)}.empty i{font-size:2.8rem;display:block;margin-bottom:10px;opacity:.35}
.spin{text-align:center;padding:44px 20px;color:var(--muted)}.spin i{font-size:1.8rem;display:block;margin-bottom:8px}

@media(max-width:360px){.pgrid{grid-template-columns:repeat(auto-fill,minmax(50px,1fr))}}
@media print{
  .hdr,.cdrawer,.dbg,.print-bar{display:none!important}
  body{background:#fff;color:#000;margin:0;padding:0}
  .scr#s-racks{display:block!important;padding:6px}
  .rack-list{display:grid!important;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:4px}
  .rack-card{background:#fff!important;border:1px solid #ccc;break-inside:avoid;page-break-inside:avoid}
  .rack-card.print-hide{display:none!important}
  /* Show rack name header; hide only interactive elements (chevron + checkbox) */
  .chv,.rack-sel-cb{display:none!important}
  .rch{padding:5px 8px!important;background:transparent!important;cursor:default!important}
  .rname{color:#000!important;font-size:11px!important;font-weight:700!important;text-transform:uppercase}
  /* Hide text label beside QR (name already shown in header above) */
  .qrlbl{display:none!important}
  .qrs{padding:4px 6px!important;border-top:none!important;background:transparent!important;justify-content:center!important}
  .qrbox img,.qrbox canvas{width:100px!important;height:100px!important}
  .item-row{background:#fff;border:1px solid #ccc}
}
.print-bar{display:flex;gap:8px;padding:10px 14px;background:rgba(15,23,42,.7);border-bottom:1px solid var(--bdr);flex-wrap:wrap;align-items:center;}
.pbtn{display:inline-flex;align-items:center;gap:5px;padding:6px 12px;border-radius:var(--rs);border:1px solid;cursor:pointer;font-size:12px;font-weight:600;}
.pbtn-all{background:var(--bl);border-color:rgba(59,130,246,.4);color:#93c5fd;}
.pbtn-sel{background:var(--gl);border-color:rgba(16,185,129,.4);color:#6ee7b7;}
.pbtn-print{background:rgba(245,158,11,.15);border-color:rgba(245,158,11,.4);color:#fcd34d;}
.pbtn-cancel{background:var(--rl);border-color:rgba(239,68,68,.3);color:#fca5a5;}
.sel-hint{font-size:11px;color:var(--muted);margin-left:4px;}
.rack-sel-cb{display:none;width:18px;height:18px;margin-right:6px;cursor:pointer;flex-shrink:0;}
.select-mode .rack-sel-cb{display:block;}
</style>
</head>
<body>

<header class="hdr" id="hdr">
  <button class="back-btn" id="bbtn" onclick="goBack()"><i class="fas fa-arrow-left"></i></button>
  <div class="htitles">
    <h1 id="htitle">Raf Kabinleri</h1>
    <p id="hsub">Bir kabine dokunun</p>
  </div>
</header>

<!-- Screen 1: All Racks -->
<div class="scr on" id="s-racks">
  <div id="print-bar-wrap"></div>
  <div class="rack-list" id="rack-list">
    <div class="spin"><i class="fas fa-spinner fa-spin"></i><p>Yükleniyor...</p></div>
  </div>
</div>

<!-- Screen 2: Rack Detail (switches + panels) -->
<div class="scr" id="s-rack"><div id="rack-det"></div></div>

<!-- Screen 3: Switch Ports -->
<div class="scr" id="s-ports"><div id="ports-wrap"></div></div>

<!-- Screen 4: Panel Ports -->
<div class="scr" id="s-panel"><div id="panel-wrap"></div></div>

<!-- Screen 5: Hub SW Ports -->
<div class="scr" id="s-hubsw"><div id="hubsw-wrap"></div></div>

<!-- Cable Path Drawer -->
<div class="dbg" id="dbg" onclick="closeDr()"></div>
<div class="cdrawer" id="cdr">
  <div class="dhandle" onclick="closeDr()"></div>
  <div class="drow">
    <div class="dtitle"><i class="fas fa-route"></i> Fiziksel Kablo Yolu</div>
    <button class="dclose" onclick="closeDr()"><i class="fas fa-times"></i></button>
  </div>
  <div id="drbody"></div>
</div>

<script>
const INIT_RACK = <?php echo json_encode($initRackId); ?>;
const BASE_URL  = <?php echo json_encode($baseUrl); ?>;
let D = null, nav = [], qrOk = {}, curRack = null, curSw = null, curPanel = null, curPanelType = null, curHubSw = null;

// ─── QR single-rack mode ──────────────────────────────────────────────────
// When opened via ?rack_id=N (QR scan): store in sessionStorage so that
// page refresh stays on the same rack, then wipe the query string so the
// browser address bar looks clean.  On subsequent loads (refresh) the
// stored id is read from sessionStorage instead of the URL.
const STORED_KEY = 'qr_rack_id';
let qrRackId = INIT_RACK || 0;
if (INIT_RACK) {
  sessionStorage.setItem(STORED_KEY, INIT_RACK);
  history.replaceState({}, '', window.location.pathname);
} else {
  const stored = parseInt(sessionStorage.getItem(STORED_KEY) || '0', 10);
  if (stored) qrRackId = stored;
}

document.addEventListener('DOMContentLoaded', async () => {
  try {
    const r = await fetch('../api/getData.php');
    D = await r.json();
    if (!D.success) throw new Error(D.error||'API error');
  } catch(e) {
    D = {racks:[],switches:[],ports:{},patch_panels:[],patch_ports:{},fiber_panels:[],fiber_ports:{},rack_devices:[]};
    document.getElementById('rack-list').innerHTML = '<div class="empty"><i class="fas fa-exclamation-triangle"></i><p>Veri yüklenemedi</p></div>';
    return;
  }
  if (qrRackId) {
    // QR / single-rack mode: show only that rack, no list, no back to list
    buildSingleRack(qrRackId);
    openRack(qrRackId, true);
    showScr('s-rack');
  } else {
    buildRacks();
  }
});

/* ─── IP masking ──────────────────────────────────── */
function maskIp(ip) { return ip ? '***' : ''; }


function showScr(id) {
  document.querySelectorAll('.scr').forEach(s => s.classList.remove('on'));
  document.getElementById(id).classList.add('on');
}
function push(id) {
  const cur = document.querySelector('.scr.on');
  if (cur) nav.push(cur.id);
  showScr(id);
  document.getElementById('bbtn').classList.toggle('v', nav.length > 0);
}
function goBack() {
  closeDr();
  if (!nav.length) return;
  const p = nav.pop();
  // In QR single-rack mode never navigate back to the full rack list
  if (qrRackId && p === 's-racks') { nav.length = 0; document.getElementById('bbtn').classList.remove('v'); return; }
  showScr(p);
  document.getElementById('bbtn').classList.toggle('v', nav.length > 0);
  if      (p==='s-racks')  sh('Raf Kabinleri','Bir kabine dokunun');
  else if (p==='s-rack')   { const rk=rk_(curRack); if(rk) sh(rk.name,rk.location||''); }
  else if (p==='s-ports')  { const sw=sw_(curSw);   if(sw) sh(sw.name,(sw.ip?'*** \u00b7 ':'')+' Portlar'); }
  else if (p==='s-hubsw')  { const rd=rd_(curHubSw); if(rd) sh(rd.name,'Hub SW Port G\u00f6r\u00fcn\u00fcm\u00fc'); }
  else if (p==='s-panel')  {
    const pp=(curPanelType==='patch'?(D.patch_panels||[]):(D.fiber_panels||[])).find(x=>x.id==curPanel);
    if(pp) sh((curPanelType==='patch'?'Patch Panel':'Fiber Panel')+' '+pp.panel_letter,'Ba\u011flant\u0131 Portlar\u0131');
  }
}
function sh(t,s){ document.getElementById('htitle').textContent=t; document.getElementById('hsub').textContent=s||''; }
function rk_(id){ return (D.racks||[]).find(r=>r.id==id); }
function sw_(id){ return (D.switches||[]).find(s=>s.id==id); }
function rd_(id){ return (D.rack_devices||[]).find(d=>d.id==id); }
function e(s){ return (s||'').toString().replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }

/* ─── Screen 1: Rack List ─────────────────────────── */
function buildRacks() {
  const racks = D.racks||[];
  const el    = document.getElementById('rack-list');
  if (!racks.length) { el.innerHTML='<div class="empty"><i class="fas fa-server"></i><p>Rack bulunamad\u0131</p></div>'; return; }
  el.innerHTML = '';
  racks.forEach(rk => {
    const c = document.createElement('div');
    c.className='rack-card';
    c.dataset.rackId=rk.id;
    c.innerHTML=`<div class="rch" onclick="onRackClick(event,${rk.id})">
        <input type="checkbox" class="rack-sel-cb" data-rack-id="${rk.id}" onclick="event.stopPropagation()">
        <div style="flex:1;min-width:0;padding:4px 0;">
          <div class="rname">${e(rk.name)}</div>
        </div>
        <i class="fas fa-chevron-right chv"></i>
      </div>
      <div class="qrs">
        <div class="qrbox" id="qr-${rk.id}"></div>
        <div class="qrlbl" id="qu-${rk.id}"></div>
      </div>`;
    el.appendChild(c);
    setTimeout(()=>mkQr(rk.id, rk.name), 80);
  });
  // Build print toolbar
  const pb = document.getElementById('print-bar-wrap');
  pb.innerHTML = `<div class="print-bar" id="print-bar">
    <button class="pbtn pbtn-all" onclick="printAll()"><i class="fas fa-print"></i> Toplu Yazdır</button>
    <button class="pbtn pbtn-sel" id="btn-sel-mode" onclick="enterSelectMode()"><i class="fas fa-check-square"></i> Seçmeli Yazdır</button>
    <div id="sel-mode-actions" style="display:none;align-items:center;gap:6px;flex-wrap:wrap;">
      <button class="pbtn pbtn-print" onclick="printSelected()"><i class="fas fa-print"></i> Seçilileri Yazdır</button>
      <button class="pbtn pbtn-cancel" onclick="exitSelectMode()"><i class="fas fa-times"></i> İptal</button>
      <span class="sel-hint" id="sel-count">0 seçili</span>
    </div>
  </div>`;
}

/* ─── Single-rack view (QR mode) ─────────────────── */
function buildSingleRack(id) {
  // In QR mode the s-racks screen shows only the one scanned rack.
  const rk = rk_(id);
  const el = document.getElementById('rack-list');
  if (!rk) { el.innerHTML='<div class="empty"><i class="fas fa-exclamation-triangle"></i><p>Kabin bulunamad\u0131</p></div>'; return; }
  el.innerHTML = '';
  const c = document.createElement('div');
  c.className = 'rack-card';
  c.dataset.rackId = rk.id;
  c.innerHTML = `<div class="rch" style="cursor:default;">
      <div style="flex:1;min-width:0;padding:4px 0;">
        <div class="rname">${e(rk.name)}</div>
      </div>
    </div>
    <div class="qrs">
      <div class="qrbox" id="qr-${rk.id}"></div>
      <div class="qrlbl" id="qu-${rk.id}"></div>
    </div>`;
  el.appendChild(c);
  setTimeout(()=>mkQr(rk.id, rk.name), 80);
  // No print toolbar in single-rack / QR mode
  document.getElementById('print-bar-wrap').innerHTML = '';
}
function onRackClick(ev, id) {
  const list = document.getElementById('rack-list');
  if (list.classList.contains('select-mode')) {
    const cb = ev.currentTarget.querySelector('.rack-sel-cb');
    if (cb) { cb.checked = !cb.checked; updateSelCount(); }
    return;
  }
  openRack(id);
}
function enterSelectMode() {
  document.getElementById('rack-list').classList.add('select-mode');
  document.getElementById('btn-sel-mode').style.display='none';
  document.getElementById('sel-mode-actions').style.display='flex';
  updateSelCount();
}
function exitSelectMode() {
  document.getElementById('rack-list').classList.remove('select-mode');
  document.getElementById('rack-list').querySelectorAll('.rack-sel-cb').forEach(cb=>cb.checked=false);
  document.getElementById('btn-sel-mode').style.display='';
  document.getElementById('sel-mode-actions').style.display='none';
}
function updateSelCount() {
  const n = document.getElementById('rack-list').querySelectorAll('.rack-sel-cb:checked').length;
  document.getElementById('sel-count').textContent = n + ' se\u00e7ili';
}
function printAll() {
  document.querySelectorAll('.rack-card').forEach(c=>c.classList.remove('print-hide'));
  window.print();
}
function printSelected() {
  const sel = new Set();
  document.getElementById('rack-list').querySelectorAll('.rack-sel-cb:checked').forEach(cb=>sel.add(cb.dataset.rackId));
  document.querySelectorAll('.rack-card').forEach(c=>{
    c.classList.toggle('print-hide', !sel.has(c.dataset.rackId));
  });
  window.print();
  document.querySelectorAll('.rack-card').forEach(c=>c.classList.remove('print-hide'));
}
function mkQr(id, name) {
  if (qrOk[id]) return;
  const url=BASE_URL+'?rack_id='+id;
  const b=document.getElementById('qr-'+id), l=document.getElementById('qu-'+id);
  if (!b) return;
  try { new QRCode(b,{text:url,width:80,height:80,colorDark:'#000',colorLight:'#fff',correctLevel:QRCode.CorrectLevel.M}); if(l)l.textContent=name||url; qrOk[id]=true; } catch(ex){ console.warn('QR generation failed for rack '+id+':', ex); }
}

/* ─── Screen 2: Rack Detail ───────────────────────── */
function openRack(id, skipNav) {
  curRack=id;
  const rk=rk_(id); if(!rk) return;
  sh(rk.name, rk.location||'Raf Kabini');

  const sws=(D.switches||[]).filter(s=>s.rack_id==id);
  const pps=(D.patch_panels||[]).filter(p=>p.rack_id==id);
  const fps=(D.fiber_panels||[]).filter(f=>f.rack_id==id);
  const rds=(D.rack_devices||[]).filter(d=>d.rack_id==id);

  // Combine all items and sort by physical slot (position_in_rack)
  const combined=[
    ...sws.map(sw=>({type:'sw',  data:sw, pos:parseInt(sw.position_in_rack)||999})),
    ...pps.map(pp=>({type:'pp',  data:pp, pos:parseInt(pp.position_in_rack)||999})),
    ...fps.map(fp=>({type:'fp',  data:fp, pos:parseInt(fp.position_in_rack)||999})),
    ...rds.map(rd=>({type:'rd',  data:rd, pos:parseInt(rd.position_in_rack)||999}))
  ].sort((a,b)=>a.pos-b.pos);

  let h='<div class="il">';
  combined.forEach(item=>{
    if(item.type==='sw'){
      const sw=item.data;
      const on=(sw.snmp_status||sw.status||'')==='online';
      const pts=D.ports&&D.ports[sw.id]?D.ports[sw.id]:[];
      const act=pts.filter(p=>p.is_active).length;
      const dc=on?'d-on':(sw.status?'d-off':'d-unk');
      const swMaxD=Math.min(sw.ports||pts.length||24,48);
      const swDots=Array.from({length:swMaxD},(_,i)=>{const p=pts.find(x=>x.port===(i+1));const u=p&&p.is_active;return `<span style="display:inline-block;width:6px;height:6px;border-radius:1px;margin:2px;background:${u?'#10b981':'#1e3a2f'};"></span>`;}).join('');
      h+=`<div class="item-row sw" onclick="openSw(${sw.id})">
        <div class="item-hdr">
          <div class="ii"><i class="fas fa-network-wired"></i></div>
          <div style="flex:1;min-width:0;"><div class="iname">${e(sw.name)}</div>
          <div class="isub">${sw.ip?'<span class="mono">***</span> &nbsp;&middot;&nbsp; ':''}${act}/${sw.ports||0} aktif</div></div>
          <div class="sdot ${dc}"></div><i class="fas fa-chevron-right" style="color:var(--muted);font-size:11px;margin-left:6px;"></i>
        </div>
        <div class="item-dots">${swDots}</div></div>`;
    } else if(item.type==='pp'){
      const pp=item.data;
      const pl=D.patch_ports&&D.patch_ports[pp.id]?D.patch_ports[pp.id]:[];
      // Count ports connected to a switch OR to a rack_device via connection_details
      const cn=pl.filter(p=>{
        if(p.connected_switch_id) return true;
        if(!p.connection_details) return false;
        try{const cd=typeof p.connection_details==='string'?JSON.parse(p.connection_details):p.connection_details;return cd&&cd.rack_device_id;}catch(ex){return false;}
      }).length;
      const ppMaxD=Math.min(pp.total_ports||24,48);
      const ppDots=Array.from({length:ppMaxD},(_,i)=>{const p=pl.find(x=>parseInt(x.port_number)===(i+1));const u=p&&(p.status==='active'||p.connected_switch_id||(p.connection_details&&p.connection_details!=='null'));return `<span style="display:inline-block;width:6px;height:6px;border-radius:1px;margin:2px;background:${u?'#10b981':'#374151'};"></span>`;}).join('');
      h+=`<div class="item-row pp" onclick="openPanel('patch',${pp.id})">
        <div class="item-hdr">
          <div class="ii"><i class="fas fa-th-large"></i></div>
          <div style="flex:1;min-width:0;"><div class="iname">Panel ${e(pp.panel_letter)}</div>
          <div class="isub">${cn} ba\u011fl\u0131 / ${pp.total_ports||24} port</div></div>
          <i class="fas fa-chevron-right" style="color:var(--muted);font-size:11px;margin-left:auto;"></i>
        </div>
        <div class="item-dots">${ppDots}</div></div>`;
    } else if(item.type==='fp'){
      const fp=item.data;
      const pl=D.fiber_ports&&D.fiber_ports[fp.id]?D.fiber_ports[fp.id]:[];
      const cn=pl.filter(p=>p.connected_switch_id||p.connected_fiber_panel_id||(p.connection_details&&p.connection_details!=='null')).length;
      const fpMaxD=Math.min(fp.total_fibers||24,48);
      const fpDots=Array.from({length:fpMaxD},(_,i)=>{const p=pl.find(x=>parseInt(x.port_number)===(i+1));const u=p&&(p.status==='active'||p.connected_switch_id||p.connected_fiber_panel_id||(p.connection_details&&p.connection_details!=='null'));return `<span style="display:inline-block;width:6px;height:6px;border-radius:1px;margin:2px;background:${u?'#10b981':'#374151'};"></span>`;}).join('');
      h+=`<div class="item-row fp" onclick="openPanel('fiber',${fp.id})">
        <div class="item-hdr">
          <div class="ii"><i class="fas fa-satellite-dish"></i></div>
          <div style="flex:1;min-width:0;"><div class="iname">Fiber Panel ${e(fp.panel_letter)}</div>
          <div class="isub">${cn} ba\u011fl\u0131 / ${fp.total_fibers||24} fiber</div></div>
          <i class="fas fa-chevron-right" style="color:var(--muted);font-size:11px;margin-left:auto;"></i>
        </div>
        <div class="item-dots">${fpDots}</div></div>`;
    } else {
      // rack_device (hub_sw or server)
      const rd=item.data;
      const isHub=rd.device_type==='hub_sw';
      const rdIcon=isHub?'fa-sitemap':'fa-server';
      const rdLabel=isHub?'Hub SW':'Server';
      const totalPorts=(rd.ports||0)+(rd.fiber_ports||0);
      const portSub=[];
      if(rd.ports>0)       portSub.push(rd.ports+'P');
      if(rd.fiber_ports>0) portSub.push(rd.fiber_ports+'FP');
      const portSubStr=portSub.length?portSub.join(' / '):'';
      const unitSize=parseInt(rd.unit_size)||1;
      const unitBadge=unitSize>1?` <span style="font-size:9px;background:var(--violet);color:#fff;border-radius:3px;padding:1px 4px;">${unitSize}U</span>`:'';
      // Build port-dot strip: green dots for ports connected to this hub via patch panel ports.
      const connectedPorts=new Set();
      Object.values(D.patch_ports||{}).forEach(panelPorts=>{
        (panelPorts||[]).forEach(pp=>{
          if(!pp.connection_details) return;
          try{
            const cd=typeof pp.connection_details==='string'?JSON.parse(pp.connection_details):pp.connection_details;
            if(cd&&parseInt(cd.rack_device_id)===parseInt(rd.id)&&cd.rack_device_port) connectedPorts.add(parseInt(cd.rack_device_port));
          }catch(ex){}
        });
      });
      const rdDots=totalPorts>0?Array.from({length:Math.min(totalPorts,48)},(_,i)=>{
        const pIdx=i+1;
        const isFiber=i>=(rd.ports||0);
        const isConn=connectedPorts.has(pIdx);
        const bg=isConn?'#10b981':(isFiber?'#164e63':'#374151');
        return `<span style="display:inline-block;width:6px;height:6px;border-radius:1px;margin:2px;background:${bg};"></span>`;
      }).join(''):'';
      const hasPortsQr = ((rd.ports||0) + (rd.fiber_ports||0)) > 0;
      const clickAction=hasPortsQr?`onclick="openHubSw(${rd.id})"`:'' ;
      const chevron=hasPortsQr?`<i class="fas fa-chevron-right" style="color:var(--muted);font-size:11px;margin-left:6px;"></i>`:'';
      h+=`<div class="item-row rd" ${clickAction} style="${hasPortsQr?'cursor:pointer':''}">
        <div class="item-hdr">
          <div class="ii"><i class="fas ${rdIcon}"></i></div>
          <div style="flex:1;min-width:0;"><div class="iname">${e(rd.name)}${unitBadge}</div>
          <div class="isub">${rdLabel}${portSubStr?' &nbsp;&middot;&nbsp; '+portSubStr:''}${rd.notes?' &nbsp;&middot;&nbsp; '+e(rd.notes.substring(0,30)):''}</div></div>
          ${chevron}
        </div>
        ${rdDots?`<div class="item-dots">${rdDots}</div>`:''}
      </div>`;
    }
  });
  if (!combined.length) h+='<div class="empty"><i class="fas fa-box-open"></i><p>Bu rack bo\u015f</p></div>';
  h+='</div>';
  document.getElementById('rack-det').innerHTML=h;
  if (!skipNav) push('s-rack');
}

/* ─── Screen 3: Switch Ports ──────────────────────── */
function openSw(id) {
  curSw=id;
  const sw=sw_(id); if(!sw) return;
  sh(sw.name,(sw.ip?'*** \u00b7 ':'')+' Port G\u00f6r\u00fcn\u00fcm\u00fc');
  const pts=D.ports&&D.ports[id]?D.ports[id]:[];
  const tot=sw.ports||pts.length||0;
  const act=pts.filter(p=>p.is_active).length;
  const wp =pts.filter(p=>p.connected_panel_id).length;
  let h=`<div style="display:flex;gap:7px;flex-wrap:wrap;margin-bottom:12px;">
    <span class="tag tg"><i class="fas fa-check-circle"></i> ${act} Aktif</span>
    <span class="tag tb"><i class="fas fa-link"></i> ${wp} Panel</span>
    <span class="tag tm">${tot} Port</span>
  </div>
  <p style="font-size:11px;color:var(--muted);margin-bottom:10px;"><i class="fas fa-hand-pointer"></i> Porta dokun \u2192 kablo yolu</p>
  <div class="pgrid">`;
  for(let i=1;i<=tot;i++){
    const p=pts.find(x=>x.port===i)||null;
    const has=p&&p.connected_panel_id, ac=p&&p.is_active;
    const cls=has?'prt p-pan':(ac?'prt p-act':'prt p-off');
    const dev=p&&p.device?p.device.substring(0,7):'';
    const badge=has?`<span class="pbadge">${e(p.connected_panel_letter||'?')}</span>`:'';
    h+=`<div class="${cls}" onclick="showPath(${id},${i})"><span class="pnum">${i}</span>${dev?'<span class="pdev">'+e(dev)+'</span>':''}${badge}</div>`;
  }
  h+='</div>';
  document.getElementById('ports-wrap').innerHTML=h;
  push('s-ports');
}

/* ─── Screen 5: Hub SW Ports ──────────────────────── */
function openHubSw(id) {
  curHubSw = id;
  const rd = rd_(id); if (!rd) return;
  sh(rd.name, 'Hub SW \u00b7 ' + ((rd.ports||0)+(rd.fiber_ports||0)) + ' Port');

  // Collect all patch_port rows that connect to this hub SW device.
  // Keyed by rack_device_port number so we can display info per hub port.
  const portMap = {}; // portNum -> {panelLetter, panelId, portNumber, port object}
  Object.values(D.patch_ports||{}).forEach(panelPorts=>{
    (panelPorts||[]).forEach(pp=>{
      if (!pp.connection_details) return;
      try {
        const cd = typeof pp.connection_details==='string' ? JSON.parse(pp.connection_details) : pp.connection_details;
        if (cd && parseInt(cd.rack_device_id) === parseInt(rd.id) && cd.rack_device_port) {
          const portNum = parseInt(cd.rack_device_port);
          portMap[portNum] = { pp, cd };
        }
      } catch(ex){}
    });
  });

  // Build a lookup for direct connections (hub_sw_port_connections)
  const directMap = {}; // portNum -> connection row
  (D.hub_sw_port_connections||[]).filter(c => parseInt(c.rack_device_id) === parseInt(rd.id)).forEach(c => {
    directMap[parseInt(c.port_number)] = c;
  });

  const tot = (rd.ports || 0) + (rd.fiber_ports || 0);
  const cn  = Object.keys(portMap).length + Object.keys(directMap).filter(k => !portMap[k]).length;
  let h = `<div style="display:flex;gap:7px;flex-wrap:wrap;margin-bottom:12px;">
    <span class="tag" style="background:var(--vl);color:#c4b5fd;border:1px solid rgba(139,92,246,.3);"><i class="fas fa-sitemap"></i> Hub SW</span>
    <span class="tag tg"><i class="fas fa-link"></i> ${cn} Ba\u011fl\u0131</span>
    <span class="tag tm">${tot} Port</span>
  </div>
  <p style="font-size:11px;color:var(--muted);margin-bottom:10px;"><i class="fas fa-hand-pointer"></i> Porta dokun \u2192 ba\u011flant\u0131 bilgisi</p>
  <div class="pgrid">`;
  for (let i = 1; i <= tot; i++) {
    const info   = portMap[i] || null;
    const dirCon = directMap[i] || null;
    const isCn   = !!(info || dirCon);
    let cls = 'prt p-off';
    if (info)   cls = 'prt p-pan';
    else if (dirCon) cls = 'prt p-act'; // direct connection: active green
    // Show panel letter (patch) or truncated device name (direct)
    let panelLbl = '';
    if (info) {
      const panel = (D.patch_panels||[]).find(x => x.id == info.pp.panel_id);
      panelLbl = panel ? panel.panel_letter : '';
    } else if (dirCon && dirCon.device_name) {
      panelLbl = dirCon.device_name.substring(0, 5);
    }
    const badge = isCn ? `<span class="pbadge">${e(panelLbl||'?')}</span>` : '';
    h += `<div class="${cls}" onclick="showHubSwPortPath(${id},${i})"><span class="pnum">${i}</span>${badge}</div>`;
  }
  h += '</div>';
  document.getElementById('hubsw-wrap').innerHTML = h;
  push('s-hubsw');
}

/* ─── Screen 4: Panel Port Grid ───────────────────── */
function openPanel(type,id){
  curPanel=id; curPanelType=type;
  const pl=type==='patch'?(D.patch_panels||[]):(D.fiber_panels||[]);
  const panel=pl.find(p=>p.id==id); if(!panel) return;
  const tn=type==='patch'?'Patch Panel':'Fiber Panel';
  const totalPorts=type==='patch'?(panel.total_ports||24):(panel.total_fibers||24);
  const pm=type==='patch'?(D.patch_ports||{}):(D.fiber_ports||{});
  const pts=pm[id]||[];
  // Count ports connected to switch OR to a rack_device (hub_sw) via connection_details
  const cn=pts.filter(p=>{
    if(p.connected_switch_id) return true;
    if(type==='fiber'&&p.connected_fiber_panel_id) return true;
    if(!p.connection_details) return false;
    try{const cd=typeof p.connection_details==='string'?JSON.parse(p.connection_details):p.connection_details;return cd&&cd.rack_device_id;}catch(ex){return false;}
  }).length;
  sh(tn+' '+panel.panel_letter, cn+' ba\u011fl\u0131 / '+totalPorts+' port');
  let h=`<div style="display:flex;gap:7px;flex-wrap:wrap;margin-bottom:12px;">
    <span class="tag ta"><i class="fas fa-link"></i> ${cn} Ba\u011fl\u0131</span>
    <span class="tag tm">${totalPorts} Port</span>
  </div>
  <p style="font-size:11px;color:var(--muted);margin-bottom:10px;"><i class="fas fa-hand-pointer"></i> Porta dokun \u2192 ba\u011flant\u0131 bilgisi</p>
  <div class="pgrid">`;
  for(let i=1;i<=totalPorts;i++){
    const p=pts.find(x=>parseInt(x.port_number)===i)||null;
    const isCdConn = p&&p.connection_details ? (()=>{try{const cd=typeof p.connection_details==='string'?JSON.parse(p.connection_details):p.connection_details;return cd&&cd.rack_device_id;}catch(ex){return false;}})() : false;
    const isCn = p && (p.connected_switch_id || (type==='fiber' && p.connected_fiber_panel_id) || isCdConn);
    const cls = isCn ? 'prt p-pan' : 'prt p-off';
    let lbl = '';
    if (p && p.connected_switch_name) { lbl = p.connected_switch_name.substring(0,7); }
    else if (p && p.connected_switch_id) { lbl = 'SW'+p.connected_switch_id; }
    else if (isCdConn) {
      try{const cd=typeof p.connection_details==='string'?JSON.parse(p.connection_details):p.connection_details;
        const rdDev=rd_(cd.rack_device_id); lbl=(rdDev?rdDev.name:(cd.device_name||'')).substring(0,7);}catch(ex){}
    }
    if (!lbl && p && p.label) lbl = p.label.substring(0,7);
    h+=`<div class="${cls}" onclick="showPanelPath('${type}',${id},${i})"><span class="pnum">${i}</span>${lbl?'<span class="pdev">'+e(lbl)+'</span>':''}</div>`;
  }
  h+='</div>';
  document.getElementById('panel-wrap').innerHTML=h;
  push('s-panel');
}

/* ─── Panel Cable Path Drawer ─────────────────────── */
function showPanelPath(type,panelId,portNum){
  const pm=type==='patch'?(D.patch_ports||{}):(D.fiber_ports||{});
  const pts=pm[panelId]||[];
  const port=pts.find(x=>parseInt(x.port_number)===portNum)||null;
  const pl=type==='patch'?(D.patch_panels||[]):(D.fiber_panels||[]);
  const panel=pl.find(p=>p.id==panelId);
  const tn=type==='patch'?'Patch Panel':'Fiber Panel';
  const ic=type==='fiber'?'fa-satellite-dish':'fa-th-large';
  const ic2=type==='fiber'?'#6ee7b7':'#fcd34d';
  const lbl=port&&port.label?(' \u2013 '+port.label):'';

  let h=`<div class="cstep"><span class="csi"><i class="fas ${ic}" style="color:${ic2};"></i></span>
    <div><div class="csl">${tn} <strong>${e(panel?panel.panel_letter:'?')}</strong> \u2014 Port ${portNum}${e(lbl)}</div>
    <div class="css">${panel&&panel.rack_name?'Rack: '+e(panel.rack_name):(panel&&panel.rack_id?'Rack #'+panel.rack_id:'')}</div></div></div>`;

  // Determine connection type: switch, fiber-fiber, or rack_device (hub_sw)
  let hasCd = false, cdObj = null;
  if (port && port.connection_details) {
    try { cdObj = typeof port.connection_details==='string'?JSON.parse(port.connection_details):port.connection_details; hasCd=cdObj&&!!cdObj.rack_device_id; } catch(ex){}
  }

  if (!port || (!port.connected_switch_id && !port.connected_fiber_panel_id && !hasCd)) {
    h+='<p class="nopath"><i class="fas fa-ban"></i> Bu port bo\u015f veya ba\u011fl\u0131 de\u011fil.</p>';
  } else if(port.connected_switch_id){
    const ts=sw_(port.connected_switch_id);
    const swPort=port.connected_switch_port||'?';
    h+=`<div class="carrow"><i class="fas fa-long-arrow-alt-down"></i></div>
      <div class="cstep"><span class="csi"><i class="fas fa-network-wired" style="color:#93c5fd;"></i></span>
      <div><div class="csl">${e(ts?ts.name:(port.connected_switch_name||'Switch'))} \u2014 Port ${swPort}</div>
      <div class="css">${ts&&ts.ip?'***':'Switch ba\u011flant\u0131s\u0131'}</div></div></div>`;
    // Show device connected to that switch port
    if(ts){
      const swPorts=(D.ports&&D.ports[ts.id])||[];
      const swp=swPorts.find(x=>x.port==swPort);
      if(swp&&(swp.device||swp.ip)){
        const _c0=swp.connections&&swp.connections.length>0?swp.connections[0]:null;
        const _cn=_c0&&_c0.device&&!/^Cihaz\s*\d*$/i.test(_c0.device.trim())?_c0.device.trim():null;
        const devLabel=_cn||swp.hub_name||swp.device||swp.ip||'Cihaz';
        const devSub=[swp.type&&swp.type!=='BO\u015e'?swp.type:'',swp.ip||'',swp.mac||''].filter(Boolean).join(' \u00b7 ');
        h+=`<div class="carrow"><i class="fas fa-long-arrow-alt-down"></i></div>
          <div class="cstep"><span class="csi"><i class="fas fa-desktop" style="color:#a78bfa;"></i></span>
          <div><div class="csl">${e(devLabel)}</div>
          <div class="css">${e(devSub)}</div></div></div>`;
      }
    }
  } else if(hasCd){
    // Patch port connected to rack_device (Hub SW)
    const rdDev=rd_(cdObj.rack_device_id);
    const rdName=rdDev?rdDev.name:(cdObj.device_name||'Hub SW');
    const rdPort=cdObj.rack_device_port?(' \u2014 Port '+cdObj.rack_device_port):'';
    h+=`<div class="carrow"><i class="fas fa-long-arrow-alt-down"></i></div>
      <div class="cstep"><span class="csi"><i class="fas fa-sitemap" style="color:#c4b5fd;"></i></span>
      <div><div class="csl">${e(rdName)}${rdPort}</div>
      <div class="css">Hub SW</div></div></div>`;
  } else if(type==='fiber'&&port.connected_fiber_panel_id){
    const peerPanel=(D.fiber_panels||[]).find(fp=>fp.id==port.connected_fiber_panel_id);
    const peerRack=peerPanel?((D.racks||[]).find(r=>r.id==peerPanel.rack_id)):null;
    h+=`<div class="carrow"><i class="fas fa-long-arrow-alt-down"></i></div>
      <div class="cstep"><span class="csi"><i class="fas fa-satellite-dish" style="color:#6ee7b7;"></i></span>
      <div><div class="csl">Fiber Panel <strong>${e(peerPanel?peerPanel.panel_letter:'?')}</strong> \u2014 Port ${port.connected_fiber_panel_port||'?'}</div>
      <div class="css">${peerRack?'Rack: '+e(peerRack.name):'K\u00f6pr\u00fc ba\u011flant\u0131s\u0131'}</div></div></div>`;
  }
  document.getElementById('drbody').innerHTML=h;
  document.getElementById('cdr').classList.add('open');
  document.getElementById('dbg').style.display='block';
}

/* ─── Hub SW Port Path Drawer ─────────────────────── */
function showHubSwPortPath(rdId, portNum) {
  const rd = rd_(rdId);
  let h = `<div class="cstep"><span class="csi"><i class="fas fa-sitemap" style="color:#c4b5fd;"></i></span>
    <div><div class="csl">${e(rd?rd.name:'Hub SW')} \u2014 Port ${portNum}</div>
    <div class="css">Hub SW</div></div></div>`;

  // Find patch panel port that connects to this hub SW port
  let found = null;
  Object.values(D.patch_ports||{}).forEach(panelPorts=>{
    if (found) return;
    (panelPorts||[]).forEach(pp=>{
      if (found) return;
      if (!pp.connection_details) return;
      try {
        const cd = typeof pp.connection_details==='string' ? JSON.parse(pp.connection_details) : pp.connection_details;
        if (cd && parseInt(cd.rack_device_id)===parseInt(rdId) && parseInt(cd.rack_device_port)===portNum) {
          found = { pp, cd };
        }
      } catch(ex){}
    });
  });

  // Also look for a direct connection saved in hub_sw_port_connections
  const directConn = (D.hub_sw_port_connections||[]).find(c =>
    parseInt(c.rack_device_id) === parseInt(rdId) && parseInt(c.port_number) === portNum
  ) || null;

  if (!found && !directConn) {
    h += '<p class="nopath"><i class="fas fa-ban"></i> Bu port bo\u015f veya ba\u011fl\u0131 de\u011fil.</p>';
  } else {
    if (found) {
      const panel = (D.patch_panels||[]).find(x=>x.id==found.pp.panel_id);
      const rk = panel ? (D.racks||[]).find(r=>r.id==panel.rack_id) : null;
      h += `<div class="carrow"><i class="fas fa-long-arrow-alt-down"></i></div>
        <div class="cstep"><span class="csi"><i class="fas fa-th-large" style="color:#fcd34d;"></i></span>
        <div><div class="csl">Patch Panel <strong>${e(panel?panel.panel_letter:'?')}</strong> \u2014 Port ${found.pp.port_number}</div>
        <div class="css">${rk?'Rack: '+e(rk.name):(panel&&panel.rack_id?'Rack #'+panel.rack_id:'Panel ba\u011flant\u0131s\u0131')}</div></div></div>`;
    }
    if (directConn) {
      h += `<div class="carrow"><i class="fas fa-long-arrow-alt-down"></i></div>
        <div class="cstep"><span class="csi"><i class="fas fa-desktop" style="color:#a78bfa;"></i></span>
        <div><div class="csl">${e(directConn.device_name||'Cihaz')}</div>
        <div class="css">${directConn.notes?e(directConn.notes):'Direkt Ba\u011flant\u0131'}</div></div></div>`;
    }
  }
  document.getElementById('drbody').innerHTML = h;
  document.getElementById('cdr').classList.add('open');
  document.getElementById('dbg').style.display = 'block';
}

/* ─── Cable Path Drawer ───────────────────────────── */
function showPath(swId,pn){
  const pts=D.ports&&D.ports[swId]?D.ports[swId]:[];
  const port=pts.find(p=>p.port===pn);
  const sw=sw_(swId);
  // Show device/IP in step 1 subtitle only when there is no panel (direct connection);
  // when there is a panel the device will appear as a dedicated 3rd step.
  const hasPanelConn = port&&port.connected_panel_id;
  const step1sub = hasPanelConn ? '' : (port&&port.device?e(port.device)+' '+(port.ip?'\u00b7 '+e(port.ip):''):'');
  let h=`<div class="cstep"><span class="csi"><i class="fas fa-network-wired" style="color:#93c5fd;"></i></span>
    <div><div class="csl">${e(sw?sw.name:'Switch')} \u2014 Port ${pn}</div>
    <div class="css">${step1sub}</div></div></div>`;
  if(!port||(!port.is_active&&!port.connected_panel_id)){
    h+='<p class="nopath"><i class="fas fa-ban"></i> Bu port bo\u015f veya ba\u011fl\u0131 de\u011fil.</p>';
  } else if(port.connected_panel_id){
    const pl=port.connected_panel_letter||'?', pp=port.connected_panel_port||'?', pr=port.connected_panel_rack||'', pt=port.panel_type||'patch';
    const ic=pt==='fiber'?'fa-satellite-dish':'fa-th-large', ic2=pt==='fiber'?'#6ee7b7':'#fcd34d', tn=pt==='fiber'?'Fiber Panel':'Patch Panel';
    h+=`<div class="carrow"><i class="fas fa-long-arrow-alt-down"></i></div>
      <div class="cstep"><span class="csi"><i class="fas ${ic}" style="color:${ic2};"></i></span>
      <div><div class="csl">${tn} <strong>${e(pl)}</strong> \u2014 Port ${pp}</div>
      <div class="css">${pr?'Rack: '+e(pr):'Panel ba\u011flant\u0131s\u0131'}</div></div></div>`;
    // Try other-end switch
    if(pt==='patch'){
      const ppanel=(D.patch_panels||[]).find(x=>x.id==port.connected_panel_id);
      if(ppanel){
        const ppl=(D.patch_ports&&D.patch_ports[ppanel.id])||[];
        const pp2=ppl.find(x=>x.port_number==port.connected_panel_port);
        if(pp2&&pp2.connected_switch_id&&pp2.connected_switch_id!=swId){
          const ts=sw_(pp2.connected_switch_id);
          if(ts){
            h+=`<div class="carrow"><i class="fas fa-long-arrow-alt-down"></i></div>
              <div class="cstep"><span class="csi"><i class="fas fa-network-wired" style="color:#93c5fd;"></i></span>
              <div><div class="csl">${e(ts.name)} \u2014 Port ${pp2.connected_switch_port||'?'}</div>
              <div class="css">${ts.ip?'***':'Hedef Switch'}</div></div></div>`;
          }
        }
      }
    }
    // Add endpoint device step when device info is available
    if(port.device||port.ip){
      const _c0=port.connections&&port.connections.length>0?port.connections[0]:null;
      const _cn=_c0&&_c0.device&&!/^Cihaz\s*\d*$/i.test(_c0.device.trim())?_c0.device.trim():null;
      const devLabel=_cn||port.hub_name||port.device||port.ip||'Cihaz';
      const devSub=[port.type&&port.type!=='BO\u015e'?port.type:'',port.ip||'',port.mac||''].filter(Boolean).join(' \u00b7 ');
      h+=`<div class="carrow"><i class="fas fa-long-arrow-alt-down"></i></div>
        <div class="cstep"><span class="csi"><i class="fas fa-desktop" style="color:#a78bfa;"></i></span>
        <div><div class="csl">${e(devLabel)}</div>
        <div class="css">${e(devSub)}</div></div></div>`;
    }
  } else if(port.snmp_port_alias){
    h+=`<div class="carrow"><i class="fas fa-long-arrow-alt-down"></i></div>
      <div class="cstep"><span class="csi"><i class="fas fa-tag" style="color:#c4b5fd;"></i></span>
      <div><div class="csl">${e(port.snmp_port_alias)}</div><div class="css">SNMP Port Alias</div></div></div>`;
  } else {
    h+=`<p class="nopath"><i class="fas fa-check-circle" style="color:var(--green);"></i> Direkt ba\u011flant\u0131 \u2014 ${e(port.device||port.ip||'Bilinmiyor')}</p>`;
  }
  document.getElementById('drbody').innerHTML=h;
  document.getElementById('cdr').classList.add('open');
  document.getElementById('dbg').style.display='block';
}
function closeDr(){ document.getElementById('cdr').classList.remove('open'); document.getElementById('dbg').style.display='none'; }
</script>
</body>
</html>
