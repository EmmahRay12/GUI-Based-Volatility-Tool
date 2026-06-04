#!/usr/bin/env python3
"""
MiniVol Web UI Server
Run: python minivol_web.py
Then open: http://localhost:5000
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, jsonify, render_template_string, send_file, abort
import threading
import json
import io

from minivol import (
    SystemInfo, ProcessList, ProcessTree,
    NetworkScan, DllList, MalwareDetector,
    ReportGenerator, VERSION, timestamp
)

app = Flask(__name__)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>MiniVol — Memory Forensics Tool</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=JetBrains+Mono:wght@300;400;700&display=swap');

  :root {
    --bg:        #050a0e;
    --bg2:       #0a1118;
    --bg3:       #0d1822;
    --panel:     #0f1e2d;
    --border:    #1a3a52;
    --accent:    #00d4ff;
    --accent2:   #00ff88;
    --danger:    #ff4444;
    --warn:      #ffaa00;
    --muted:     #3a6080;
    --text:      #c8e6f7;
    --text2:     #7ab5d4;
    --green:     #00ff88;
    --cyan:      #00d4ff;
    --glow:      0 0 20px rgba(0,212,255,0.3);
    --glow-g:    0 0 20px rgba(0,255,136,0.3);
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Scanline effect */
  body::before {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,0,0,0.03) 2px,
      rgba(0,0,0,0.03) 4px
    );
    pointer-events: none;
    z-index: 9999;
  }

  /* TOPBAR */
  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 32px;
    height: 64px;
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 100;
  }
  .logo {
    font-family: 'Orbitron', monospace;
    font-size: 22px;
    font-weight: 900;
    color: var(--accent);
    letter-spacing: 4px;
    text-shadow: var(--glow);
  }
  .logo span { color: var(--accent2); }
  .topbar-meta {
    display: flex;
    gap: 24px;
    font-size: 11px;
    color: var(--text2);
  }
  .topbar-meta .badge {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 10px;
    color: var(--accent);
  }
  .live-dot {
    display: inline-block;
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--green);
    margin-right: 6px;
    box-shadow: 0 0 8px var(--green);
    animation: pulse 1.5s infinite;
  }
  @keyframes pulse {
    0%,100% { opacity:1; } 50% { opacity:0.3; }
  }

  /* LAYOUT */
  .layout { display: flex; height: calc(100vh - 64px); }

  /* SIDEBAR */
  .sidebar {
    width: 220px;
    min-width: 220px;
    background: var(--bg2);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    padding: 20px 0;
  }
  .sidebar-title {
    font-family: 'Orbitron', monospace;
    font-size: 9px;
    letter-spacing: 3px;
    color: var(--muted);
    padding: 0 20px 16px;
    text-transform: uppercase;
  }
  .nav-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 20px;
    cursor: pointer;
    border-left: 3px solid transparent;
    font-size: 12px;
    color: var(--text2);
    transition: all 0.2s;
    text-transform: uppercase;
    letter-spacing: 1px;
    user-select: none;
  }
  .nav-item:hover {
    background: rgba(0,212,255,0.05);
    color: var(--accent);
    border-left-color: var(--accent);
  }
  .nav-item.active {
    background: rgba(0,212,255,0.08);
    color: var(--accent);
    border-left-color: var(--accent);
  }
  .nav-item .icon { font-size: 16px; width: 20px; text-align: center; }

  /* MAIN */
  .main {
    flex: 1;
    overflow-y: auto;
    padding: 28px 32px;
    background: var(--bg);
  }

  /* PAGE HEADER */
  .page-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    margin-bottom: 24px;
  }
  .page-title {
    font-family: 'Orbitron', monospace;
    font-size: 18px;
    font-weight: 700;
    color: var(--accent);
    text-shadow: var(--glow);
    letter-spacing: 2px;
  }
  .page-sub {
    font-size: 11px;
    color: var(--muted);
    margin-top: 4px;
    font-family: 'Share Tech Mono', monospace;
  }
  .btn {
    background: transparent;
    border: 1px solid var(--accent);
    color: var(--accent);
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    padding: 8px 18px;
    border-radius: 4px;
    cursor: pointer;
    letter-spacing: 1px;
    text-transform: uppercase;
    transition: all 0.2s;
  }
  .btn:hover {
    background: rgba(0,212,255,0.1);
    box-shadow: var(--glow);
  }
  .btn.danger { border-color: var(--danger); color: var(--danger); }
  .btn.danger:hover { background: rgba(255,68,68,0.1); }
  .btn.success { border-color: var(--green); color: var(--green); }
  .btn.success:hover { background: rgba(0,255,136,0.1); }

  /* STAT CARDS */
  .stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
  }
  .stat-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    position: relative;
    overflow: hidden;
  }
  .stat-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--accent), transparent);
  }
  .stat-card.danger::before { background: linear-gradient(90deg, var(--danger), transparent); }
  .stat-card.warn::before { background: linear-gradient(90deg, var(--warn), transparent); }
  .stat-card.green::before { background: linear-gradient(90deg, var(--green), transparent); }
  .stat-label {
    font-size: 9px;
    letter-spacing: 2px;
    color: var(--muted);
    text-transform: uppercase;
    margin-bottom: 8px;
    font-family: 'Orbitron', monospace;
  }
  .stat-value {
    font-size: 28px;
    font-weight: 700;
    color: var(--accent);
    font-family: 'Orbitron', monospace;
  }
  .stat-card.danger .stat-value { color: var(--danger); }
  .stat-card.warn .stat-value { color: var(--warn); }
  .stat-card.green .stat-value { color: var(--green); }
  .stat-detail { font-size: 11px; color: var(--text2); margin-top: 4px; }

  /* TABLE */
  .table-wrap {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }
  .table-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    background: var(--bg3);
  }
  .table-title {
    font-family: 'Orbitron', monospace;
    font-size: 11px;
    letter-spacing: 2px;
    color: var(--accent);
  }
  .search-box {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 6px 12px;
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    width: 220px;
    outline: none;
    transition: border 0.2s;
  }
  .search-box:focus { border-color: var(--accent); }
  .search-box::placeholder { color: var(--muted); }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  thead th {
    background: var(--bg3);
    color: var(--muted);
    font-size: 9px;
    letter-spacing: 2px;
    text-transform: uppercase;
    padding: 10px 14px;
    text-align: left;
    font-family: 'Orbitron', monospace;
    border-bottom: 1px solid var(--border);
  }
  tbody tr {
    border-bottom: 1px solid rgba(26,58,82,0.5);
    transition: background 0.1s;
  }
  tbody tr:hover { background: rgba(0,212,255,0.04); }
  tbody tr.suspicious { background: rgba(255,68,68,0.05); }
  tbody tr.suspicious:hover { background: rgba(255,68,68,0.1); }
  td {
    padding: 9px 14px;
    color: var(--text);
    font-size: 11px;
    max-width: 250px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .badge-flag {
    display: inline-block;
    background: rgba(255,68,68,0.15);
    border: 1px solid rgba(255,68,68,0.4);
    color: var(--danger);
    border-radius: 3px;
    padding: 1px 6px;
    font-size: 9px;
    letter-spacing: 1px;
    margin: 1px;
  }
  .badge-ok {
    color: var(--green);
    font-size: 10px;
  }
  .badge-status {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 10px;
    letter-spacing: 1px;
  }
  .status-running { background: rgba(0,255,136,0.1); color: var(--green); border: 1px solid rgba(0,255,136,0.3); }
  .status-sleeping { background: rgba(0,212,255,0.1); color: var(--cyan); border: 1px solid rgba(0,212,255,0.3); }
  .status-zombie { background: rgba(255,68,68,0.1); color: var(--danger); border: 1px solid rgba(255,68,68,0.3); }
  .status-other { background: rgba(255,170,0,0.1); color: var(--warn); border: 1px solid rgba(255,170,0,0.3); }

  /* MEMORY BAR */
  .mem-bar-wrap { display: flex; align-items: center; gap: 8px; }
  .mem-bar-bg {
    flex: 1; height: 4px; background: var(--bg);
    border-radius: 2px; overflow: hidden;
  }
  .mem-bar-fill {
    height: 100%;
    border-radius: 2px;
    transition: width 0.3s;
  }

  /* TREE */
  .tree-node {
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    color: var(--text);
    padding: 2px 0;
    display: block;
  }
  .tree-node.suspicious { color: var(--danger); }
  .tree-connector { color: var(--muted); }
  .tree-pid { color: var(--accent); font-size: 10px; }
  .tree-mem { color: var(--text2); font-size: 10px; }

  /* LOADING */
  .loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 60px;
    color: var(--muted);
    font-size: 13px;
    gap: 16px;
  }
  .spinner {
    width: 32px; height: 32px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* TERMINAL BLOCK */
  .terminal {
    background: #020810;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    line-height: 1.8;
    color: var(--text2);
    white-space: pre-wrap;
    word-break: break-all;
  }
  .terminal .t-green { color: var(--green); }
  .terminal .t-cyan { color: var(--cyan); }
  .terminal .t-red { color: var(--danger); }
  .terminal .t-warn { color: var(--warn); }
  .terminal .t-dim { color: var(--muted); }

  /* RISK BADGE */
  .risk-badge {
    display: inline-block;
    font-family: 'Orbitron', monospace;
    font-size: 13px;
    font-weight: 700;
    padding: 6px 18px;
    border-radius: 4px;
    letter-spacing: 2px;
  }
  .risk-HIGH { background: rgba(255,68,68,0.15); color: var(--danger); border: 1px solid var(--danger); }
  .risk-MEDIUM { background: rgba(255,170,0,0.15); color: var(--warn); border: 1px solid var(--warn); }
  .risk-LOW { background: rgba(255,170,0,0.08); color: var(--warn); border: 1px solid rgba(255,170,0,0.4); }
  .risk-CLEAN { background: rgba(0,255,136,0.08); color: var(--green); border: 1px solid rgba(0,255,136,0.4); }

  /* Section */
  .section { margin-bottom: 24px; }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--muted); border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--accent); }

  .hidden { display: none !important; }
</style>
</head>
<body>

<div class="topbar">
  <div class="logo">MINI<span>VOL</span></div>
  <div class="topbar-meta">
    <span><span class="live-dot"></span>LIVE ANALYSIS</span>
    <span class="badge">v{{ version }}</span>
    <span class="badge" id="ts">⏱ Loading...</span>
  </div>
</div>

<div class="layout">
  <nav class="sidebar">
    <div class="sidebar-title">Navigation</div>
    <div class="nav-item active" data-page="dashboard" onclick="navigate('dashboard')">
      <span class="icon">⬡</span> Dashboard
    </div>
    <div class="nav-item" data-page="pslist" onclick="navigate('pslist')">
      <span class="icon">⚙</span> Processes
    </div>
    <div class="nav-item" data-page="pstree" onclick="navigate('pstree')">
      <span class="icon">🌳</span> Proc Tree
    </div>
    <div class="nav-item" data-page="netscan" onclick="navigate('netscan')">
      <span class="icon">⬡</span> Network
    </div>
    <div class="nav-item" data-page="dlllist" onclick="navigate('dlllist')">
      <span class="icon">📦</span> DLL List
    </div>
    <div class="nav-item" data-page="malfind" onclick="navigate('malfind')">
      <span class="icon">🎯</span> MalFind
    </div>
    <div class="nav-item" data-page="report" onclick="navigate('report')">
      <span class="icon">📄</span> Report
    </div>
  </nav>

  <main class="main" id="main">
    <div class="loading"><div class="spinner"></div>Initializing MiniVol...</div>
  </main>
</div>

<script>
let cache = {};
let currentPage = '';

function navigate(page) {
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page);
  });
  currentPage = page;
  renderPage(page);
}

async function fetchData(endpoint) {
  if (cache[endpoint]) return cache[endpoint];
  const res = await fetch('/api/' + endpoint);
  const data = await res.json();
  cache[endpoint] = data;
  return data;
}

function setLoading() {
  document.getElementById('main').innerHTML =
    '<div class="loading"><div class="spinner"></div>Analyzing system memory...</div>';
}

function statusBadge(status) {
  if (!status) return '';
  const s = status.toLowerCase();
  if (s === 'running') return `<span class="badge-status status-running">${status}</span>`;
  if (s === 'sleeping' || s === 'idle') return `<span class="badge-status status-sleeping">${status}</span>`;
  if (s === 'zombie') return `<span class="badge-status status-zombie">${status}</span>`;
  return `<span class="badge-status status-other">${status}</span>`;
}

function memBar(pct) {
  const color = pct > 80 ? '#ff4444' : pct > 50 ? '#ffaa00' : '#00ff88';
  return `<div class="mem-bar-wrap">
    <div class="mem-bar-bg"><div class="mem-bar-fill" style="width:${Math.min(pct,100)}%;background:${color}"></div></div>
    <span style="font-size:10px;color:${color};min-width:38px">${pct}%</span>
  </div>`;
}

// ── DASHBOARD ──────────────────────────────────────
async function renderDashboard() {
  setLoading();
  const [sysData, procData, netData] = await Promise.all([
    fetchData('info'), fetchData('pslist'), fetchData('netscan')
  ]);
  const sys = sysData.data;
  const procs = procData.data;
  const nets = netData.data;
  const susProcs = procs.filter(p => p.suspicious).length;
  const susNets = nets.filter(n => n.suspicious).length;
  const ram = sys.memory;

  document.getElementById('main').innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">DASHBOARD</div>
        <div class="page-sub">${sys.hostname} · ${sys.os} · ${sys.architecture}</div>
      </div>
      <button class="btn" onclick="invalidateCache()">↺ Refresh</button>
    </div>
    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-label">Total RAM</div>
        <div class="stat-value">${(sys.memory.total/(1024**3)).toFixed(1)}</div>
        <div class="stat-detail">GB · ${ram.used_fmt} used (${ram.percent}%)</div>
      </div>
      <div class="stat-card ${susProcs>0?'danger':'green'}">
        <div class="stat-label">Suspicious Procs</div>
        <div class="stat-value">${susProcs}</div>
        <div class="stat-detail">out of ${procs.length} total</div>
      </div>
      <div class="stat-card ${susNets>0?'danger':'green'}">
        <div class="stat-label">Suspicious Conns</div>
        <div class="stat-value">${susNets}</div>
        <div class="stat-detail">out of ${nets.length} total</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">System Uptime</div>
        <div class="stat-value" style="font-size:16px;margin-top:4px">${sys.uptime}</div>
        <div class="stat-detail">Boot: ${sys.boot_time}</div>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">
      <div class="section">
        <div class="table-wrap">
          <div class="table-toolbar"><span class="table-title">TOP PROCESSES BY MEMORY</span></div>
          <table>
            <thead><tr><th>PID</th><th>Name</th><th>Memory</th><th>Threads</th></tr></thead>
            <tbody>
              ${[...procs].sort((a,b)=>b.memory_percent-a.memory_percent).slice(0,10).map(p=>`
              <tr class="${p.suspicious?'suspicious':''}">
                <td style="color:var(--accent)">${p.pid}</td>
                <td>${p.name}${p.suspicious?' <span style="color:var(--danger)">⚠</span>':''}</td>
                <td>${memBar(p.memory_percent)}</td>
                <td style="color:var(--text2)">${p.threads}</td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>
      <div class="section">
        <div class="table-wrap">
          <div class="table-toolbar"><span class="table-title">RECENT NETWORK CONNECTIONS</span></div>
          <table>
            <thead><tr><th>PID</th><th>Process</th><th>Remote</th><th>Status</th></tr></thead>
            <tbody>
              ${nets.filter(n=>n.status==='ESTABLISHED').slice(0,10).map(n=>`
              <tr class="${n.suspicious?'suspicious':''}">
                <td style="color:var(--accent)">${n.pid}</td>
                <td>${n.process}</td>
                <td style="font-size:10px;color:var(--text2)">${n.remote}</td>
                <td>${statusBadge(n.status)}</td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

// ── PSLIST ─────────────────────────────────────────
async function renderPslist() {
  setLoading();
  const d = await fetchData('pslist');
  const procs = d.data;
  let filter = '';

  const render = () => {
    const filtered = filter
      ? procs.filter(p =>
          p.name.toLowerCase().includes(filter) ||
          String(p.pid).includes(filter) ||
          p.username.toLowerCase().includes(filter))
      : procs;

    const rows = filtered.map(p => `
      <tr class="${p.suspicious?'suspicious':''}">
        <td style="color:var(--accent);font-weight:700">${p.pid}</td>
        <td style="color:var(--text2)">${p.ppid}</td>
        <td>${p.name}${p.suspicious?' <span style="color:var(--danger)">⚠</span>':''}</td>
        <td>${statusBadge(p.status)}</td>
        <td style="color:var(--text2)">${p.threads}</td>
        <td>${memBar(p.memory_percent)}</td>
        <td style="font-size:10px;color:var(--text2)">${p.username}</td>
        <td>${p.flags.map(f=>`<span class="badge-flag">${f}</span>`).join('')||'<span class="badge-ok">✓</span>'}</td>
      </tr>`).join('');

    document.getElementById('proc-tbody').innerHTML = rows;
    document.getElementById('proc-count').textContent = `${filtered.length} / ${procs.length} processes`;
  };

  document.getElementById('main').innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">PROCESS LIST (pslist)</div>
        <div class="page-sub" id="proc-count">${procs.length} processes</div>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <input class="search-box" placeholder="Filter by name / PID / user..." id="proc-search"/>
        <button class="btn" onclick="invalidateCache();navigate('pslist')">↺</button>
      </div>
    </div>
    <div class="table-wrap">
      <div class="table-toolbar">
        <span class="table-title">RUNNING PROCESSES</span>
        <span style="font-size:11px;color:var(--danger)">⚠ ${procs.filter(p=>p.suspicious).length} suspicious</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>PID</th><th>PPID</th><th>Name</th><th>Status</th>
            <th>Threads</th><th>Memory</th><th>User</th><th>Flags</th>
          </tr>
        </thead>
        <tbody id="proc-tbody"></tbody>
      </table>
    </div>`;
  render();
  document.getElementById('proc-search').addEventListener('input', e => {
    filter = e.target.value.toLowerCase();
    render();
  });
}

// ── PSTREE ─────────────────────────────────────────
async function renderPstree() {
  setLoading();
  const d = await fetchData('pstree');

  function buildTree(node, prefix, isLast) {
    const connector = isLast ? '└── ' : '├── ';
    const sus = node.suspicious;
    const color = sus ? 'var(--danger)' : 'var(--green)';
    let html = `<span class="tree-node ${sus?'suspicious':''}">
      <span class="tree-connector">${prefix}${connector}</span>
      <span style="color:${color}">${node.name}</span>
      <span class="tree-pid"> [${node.pid}]</span>
      <span class="tree-mem"> ${node.status} ${node.mem_pct}%</span>
      ${sus?'<span style="color:var(--danger)"> ⚠</span>':''}
    </span>`;
    if (node.children && node.children.length) {
      const ext = prefix + (isLast ? '    ' : '│   ');
      node.children.forEach((child, i) => {
        html += buildTree(child, ext, i === node.children.length - 1);
      });
    }
    return html;
  }

  const treeHtml = d.data.map((root, i) =>
    buildTree(root, '', i === d.data.length - 1)
  ).join('');

  document.getElementById('main').innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">PROCESS TREE (pstree)</div>
        <div class="page-sub">Parent ↔ Child hierarchy</div>
      </div>
      <button class="btn" onclick="invalidateCache();navigate('pstree')">↺ Refresh</button>
    </div>
    <div class="terminal">${treeHtml}</div>`;
}

// ── NETSCAN ────────────────────────────────────────
async function renderNetscan() {
  setLoading();
  const d = await fetchData('netscan');
  const conns = d.data;
  let filter = '';

  const render = () => {
    const filtered = filter
      ? conns.filter(c =>
          c.process.toLowerCase().includes(filter) ||
          c.local.includes(filter) ||
          c.remote.includes(filter) ||
          c.status.toLowerCase().includes(filter))
      : conns;

    document.getElementById('net-tbody').innerHTML = filtered.map(c => `
      <tr class="${c.suspicious?'suspicious':''}">
        <td style="color:var(--accent)">${c.pid}</td>
        <td>${c.process}</td>
        <td style="font-family:'Share Tech Mono',monospace;font-size:11px">${c.local}</td>
        <td style="font-family:'Share Tech Mono',monospace;font-size:11px;color:${c.suspicious?'var(--danger)':'var(--text2)'}">${c.remote}</td>
        <td>${statusBadge(c.status)}</td>
        <td style="color:var(--text2)">${c.type}</td>
        <td>${c.flags.map(f=>`<span class="badge-flag">${f}</span>`).join('')||'<span class="badge-ok">✓</span>'}</td>
      </tr>`).join('');
    document.getElementById('net-count').textContent = `${filtered.length} / ${conns.length} connections`;
  };

  document.getElementById('main').innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">NETWORK SCAN (netscan)</div>
        <div class="page-sub" id="net-count">${conns.length} connections</div>
      </div>
      <div style="display:flex;gap:10px">
        <input class="search-box" placeholder="Filter..." id="net-search"/>
        <button class="btn" onclick="invalidateCache();navigate('netscan')">↺</button>
      </div>
    </div>
    <div class="table-wrap">
      <div class="table-toolbar">
        <span class="table-title">ACTIVE CONNECTIONS</span>
        <span style="font-size:11px;color:var(--danger)">⚠ ${conns.filter(c=>c.suspicious).length} suspicious</span>
      </div>
      <table>
        <thead>
          <tr><th>PID</th><th>Process</th><th>Local</th><th>Remote</th><th>Status</th><th>Proto</th><th>Flags</th></tr>
        </thead>
        <tbody id="net-tbody"></tbody>
      </table>
    </div>`;
  render();
  document.getElementById('net-search').addEventListener('input', e => {
    filter = e.target.value.toLowerCase();
    render();
  });
}

// ── DLLLIST ────────────────────────────────────────
async function renderDlllist() {
  setLoading();
  const d = await fetchData('dlllist');
  const data = d.data;

  document.getElementById('main').innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">DLL / MODULE LIST (dlllist)</div>
        <div class="page-sub">${data.length} processes with modules</div>
      </div>
      <button class="btn" onclick="invalidateCache();navigate('dlllist')">↺ Refresh</button>
    </div>
    <div class="section">
      ${data.map(proc => `
      <div class="table-wrap" style="margin-bottom:16px">
        <div class="table-toolbar">
          <span class="table-title">PID ${proc.pid} — ${proc.name}</span>
          <span style="font-size:11px;color:var(--text2)">${proc.module_count} modules</span>
        </div>
        <table>
          <thead><tr><th>Path</th><th>Size</th></tr></thead>
          <tbody>
            ${proc.modules.slice(0,15).map(dll => {
              const sus = dll.path.toLowerCase().includes('temp') || dll.path.toLowerCase().includes('tmp');
              return `<tr class="${sus?'suspicious':''}">
                <td style="font-family:'Share Tech Mono',monospace;font-size:10px;${sus?'color:var(--warn)':''}">${dll.path}</td>
                <td style="color:var(--text2)">${dll.size}</td>
              </tr>`;
            }).join('')}
            ${proc.modules.length > 15 ? `<tr><td colspan="2" style="color:var(--muted);font-size:10px">... and ${proc.modules.length-15} more modules</td></tr>` : ''}
          </tbody>
        </table>
      </div>`).join('')}
    </div>`;
}

// ── MALFIND ────────────────────────────────────────
async function renderMalfind() {
  setLoading();
  const d = await fetchData('malfind');
  const r = d.data;

  const sectionHtml = (title, icon, items, fields) => {
    if (!items.length) return `
      <div class="table-wrap" style="margin-bottom:16px">
        <div class="table-toolbar"><span class="table-title">${icon} ${title}</span></div>
        <div style="padding:20px;color:var(--green);font-size:12px">✓ None detected — clean</div>
      </div>`;
    return `
      <div class="table-wrap" style="margin-bottom:16px">
        <div class="table-toolbar">
          <span class="table-title">${icon} ${title}</span>
          <span style="color:var(--danger);font-size:12px">${items.length} found</span>
        </div>
        <table>
          <thead><tr>${fields.map(f=>`<th>${f}</th>`).join('')}</tr></thead>
          <tbody>
            ${items.slice(0,20).map(item=>`<tr class="suspicious"><td>${
              fields.map(f=>{
                const v = item[f.toLowerCase().replace(/ /g,'_')]||item[f]||'N/A';
                return Array.isArray(v) ? v.map(x=>`<span class="badge-flag">${x}</span>`).join('') : v;
              }).join('</td><td>')
            }</td></tr>`).join('')}
          </tbody>
        </table>
      </div>`;
  };

  document.getElementById('main').innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">MALWARE DETECTION (malfind)</div>
        <div class="page-sub">Heuristic analysis · ${r.analysis_time}</div>
      </div>
      <div>
        <span class="risk-badge risk-${r.risk_level}">${r.risk_level}</span>
      </div>
    </div>
    <div class="stat-grid" style="margin-bottom:20px">
      <div class="stat-card ${r.suspicious_processes.length>0?'danger':'green'}">
        <div class="stat-label">Suspicious Procs</div>
        <div class="stat-value">${r.suspicious_processes.length}</div>
      </div>
      <div class="stat-card ${r.suspicious_connections.length>0?'danger':'green'}">
        <div class="stat-label">Suspicious Conns</div>
        <div class="stat-value">${r.suspicious_connections.length}</div>
      </div>
      <div class="stat-card ${r.orphan_processes.length>0?'warn':'green'}">
        <div class="stat-label">Orphan Procs</div>
        <div class="stat-value">${r.orphan_processes.length}</div>
      </div>
      <div class="stat-card ${r.temp_executables.length>0?'warn':'green'}">
        <div class="stat-label">Temp Executables</div>
        <div class="stat-value">${r.temp_executables.length}</div>
      </div>
    </div>
    ${sectionHtml('Suspicious Processes','⚠',r.suspicious_processes,['pid','name','reason','exe'])}
    ${sectionHtml('Orphan Processes','👻',r.orphan_processes,['pid','name','claimed_ppid'])}
    ${sectionHtml('Executables in Temp/AppData','📁',r.temp_executables,['pid','name','exe'])}
    ${sectionHtml('Multiple Instance Anomalies','🔁',r.multiple_instance_anomalies,['name','count','pid','note'])}
    ${sectionHtml('Suspicious Network Connections','🌐',r.suspicious_connections,['pid','process','local','remote','flags'])}
  `;
}

// ── REPORT ────────────────────────────────────────
async function renderReport() {
  document.getElementById('main').innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">REPORT GENERATION</div>
        <div class="page-sub">Export forensic data</div>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;max-width:700px">
      <div class="stat-card" style="cursor:pointer" onclick="downloadReport('json')">
        <div class="stat-label">JSON Report</div>
        <div style="font-size:40px;margin:12px 0">{ }</div>
        <div class="stat-detail">Structured forensic data<br>Machine-readable format</div>
        <button class="btn success" style="margin-top:16px;width:100%">Download JSON</button>
      </div>
      <div class="stat-card" style="cursor:pointer" onclick="downloadReport('txt')">
        <div class="stat-label">Text Report</div>
        <div style="font-size:40px;margin:12px 0">📄</div>
        <div class="stat-detail">Human-readable format<br>Easy to review</div>
        <button class="btn" style="margin-top:16px;width:100%">Download TXT</button>
      </div>
      <div class="stat-card" style="cursor:pointer" onclick="downloadReport('csv')">
        <div class="stat-label">CSV Report</div>
        <div style="font-size:40px;margin:12px 0">⬡</div>
        <div class="stat-detail">Process list as CSV<br>Import into Excel/Sheets</div>
        <button class="btn" style="margin-top:16px;width:100%">Download CSV</button>
      </div>
    </div>
    <div id="report-status" style="margin-top:20px"></div>`;
}

async function downloadReport(fmt) {
  document.getElementById('report-status').innerHTML =
    '<div class="loading" style="padding:20px"><div class="spinner"></div>Generating report...</div>';
  try {
    const res = await fetch('/api/report?format=' + fmt);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = res.headers.get('Content-Disposition')?.split('filename=')[1] || `minivol_report.${fmt}`;
    a.click();
    URL.revokeObjectURL(url);
    document.getElementById('report-status').innerHTML =
      '<div style="color:var(--green);padding:12px;font-size:13px">✓ Report downloaded successfully</div>';
  } catch(e) {
    document.getElementById('report-status').innerHTML =
      `<div style="color:var(--danger);padding:12px;font-size:13px">✗ Error: ${e.message}</div>`;
  }
}

function invalidateCache() { cache = {}; }

function updateTimestamp() {
  const el = document.getElementById('ts');
  if(el) el.textContent = '⏱ ' + new Date().toLocaleTimeString();
}

async function renderPage(page) {
  const renderers = {
    dashboard: renderDashboard,
    pslist: renderPslist,
    pstree: renderPstree,
    netscan: renderNetscan,
    dlllist: renderDlllist,
    malfind: renderMalfind,
    report: renderReport,
  };
  if(renderers[page]) await renderers[page]();
}

// Boot
setInterval(updateTimestamp, 1000);
updateTimestamp();
navigate('dashboard');
</script>
</body>
</html>
"""

# ─── API ROUTES ───────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE, version=VERSION)

@app.route("/api/info")
def api_info():
    return jsonify({"ok": True, "data": SystemInfo.collect()})

@app.route("/api/pslist")
def api_pslist():
    return jsonify({"ok": True, "data": ProcessList.collect()})

@app.route("/api/pstree")
def api_pstree():
    all_procs, children = ProcessTree.build()

    def build_node(pid):
        p = all_procs.get(pid)
        if not p:
            return None
        sus = any(s in p["name"].lower() for s in SUSPICIOUS_NAMES)
        node = {
            "pid": p["pid"],
            "ppid": p["ppid"],
            "name": p["name"],
            "status": p["status"],
            "mem_pct": p["mem_pct"],
            "suspicious": sus,
            "children": [],
        }
        for child_pid in sorted(children.get(pid, [])):
            child = build_node(child_pid)
            if child:
                node["children"].append(child)
        return node

    roots = [pid for pid, p in all_procs.items()
             if p["ppid"] not in all_procs or p["ppid"] == 0]
    tree = [build_node(pid) for pid in sorted(set(roots)) if build_node(pid)]
    return jsonify({"ok": True, "data": tree})

@app.route("/api/netscan")
def api_netscan():
    return jsonify({"ok": True, "data": NetworkScan.collect()})

@app.route("/api/dlllist")
def api_dlllist():
    data = DllList.collect()
    filtered = [d for d in data if d["modules"]]
    return jsonify({"ok": True, "data": filtered})

@app.route("/api/malfind")
def api_malfind():
    report = MalwareDetector.analyze()

    total = (
        len(report["suspicious_processes"]) * 3 +
        len(report["suspicious_connections"]) * 5 +
        len(report["orphan_processes"]) * 2 +
        len(report["temp_executables"]) * 4 +
        len(report["multiple_instance_anomalies"]) * 6
    )
    report["risk_score"] = total
    report["risk_level"] = ("HIGH" if total > 20 else
                            "MEDIUM" if total > 8 else
                            "LOW" if total > 0 else "CLEAN")
    return jsonify({"ok": True, "data": report})

@app.route("/api/report")
def api_report():
    from flask import request, send_file, Response
    fmt = request.args.get("format", "json")
    import tempfile, os as _os

    with tempfile.TemporaryDirectory() as tmpdir:
        saved = ReportGenerator.save(fmt=fmt, output_dir=tmpdir)
        if not saved:
            return jsonify({"ok": False, "error": "Report generation failed"}), 500

        fname = _os.path.basename(saved)
        mime = {
            "json": "application/json",
            "txt": "text/plain",
            "csv": "text/csv",
        }.get(fmt, "application/octet-stream")

        with open(saved, "rb") as f:
            data = f.read()

    return Response(
        data,
        mimetype=mime,
        headers={"Content-Disposition": f"attachment; filename={fname}"}
    )


if __name__ == "__main__":
    print(f"""
  ╔══════════════════════════════════════════╗
  ║   MiniVol Web UI — v{VERSION}              ║
  ║   http://localhost:5000                  ║
  ╚══════════════════════════════════════════╝
""")
    app.run(host="0.0.0.0", port=5000, debug=False)
