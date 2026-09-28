from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from .hub import Hub
from .safety import SafetyPolicy
from .service import ObservationService


DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KANSOKU v0.10.0</title>
<style>
:root { color-scheme: dark; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
* { box-sizing: border-box; }
body { margin: 0; background: #0b1020; color: #e8eefc; }
header { padding: 20px 28px; border-bottom: 1px solid #27304a; display:flex; gap:18px; align-items:center; flex-wrap:wrap; }
h1 { font-size: 22px; margin: 0; letter-spacing:.04em; }
main { padding: 22px 28px 40px; max-width: 1500px; margin:auto; }
.controls { display:flex; gap:10px; align-items:center; margin-bottom:18px; flex-wrap:wrap; }
select, button { padding:8px 10px; border-radius:8px; border:1px solid #3a4665; background:#151d32; color:#e8eefc; }
button, .run-link { cursor:pointer; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:14px; margin-bottom:18px; }
.card { background:#121a2e; border:1px solid #27304a; border-radius:12px; padding:16px; box-shadow:0 8px 20px rgba(0,0,0,.18); }
.card h2 { font-size:13px; color:#9eb0d5; margin:0 0 10px; text-transform:uppercase; letter-spacing:.08em; }
.value { font-size:28px; font-weight:700; overflow-wrap:anywhere; }
.small-value { font-size:18px; font-weight:650; overflow-wrap:anywhere; }
.state-NORMAL, .outcome-VERIFIED { color:#75e6a4; }
.state-WARNING, .outcome-WAITING_APPROVAL { color:#ffd166; }
.state-DEGRADED, .outcome-INCONCLUSIVE, .outcome-DRY_RUN { color:#ff9f43; }
.state-CRITICAL, .outcome-FAILED, .outcome-REJECTED { color:#ff6b6b; }
.outcome-ROLLED_BACK { color:#c6a0ff; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th, td { text-align:left; padding:9px 8px; border-bottom:1px solid #27304a; vertical-align:top; }
th { color:#9eb0d5; position:sticky; top:0; background:#121a2e; }
section { margin-top:18px; }
.table-wrap { overflow:auto; max-height:390px; }
.muted { color:#8390ad; } code { white-space:pre-wrap; overflow-wrap:anywhere; }
.error { color:#ff8585; } .success { color:#75e6a4; }
.charts { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:14px; }
.chart { height:180px; width:100%; background:#0d1427; border-radius:8px; }
.chart-empty { display:flex; height:180px; align-items:center; justify-content:center; color:#8390ad; background:#0d1427; border-radius:8px; }
.evidence { font-size:12px; margin-top:10px; max-height:80px; overflow:auto; }
.badge { display:inline-block; padding:3px 7px; margin:2px 4px 2px 0; border:1px solid #3a4665; border-radius:999px; font-size:11px; color:#b9c7e6; }
dialog { width:min(900px,92vw); max-height:82vh; background:#121a2e; color:#e8eefc; border:1px solid #3a4665; border-radius:12px; }
dialog::backdrop { background:rgba(0,0,0,.72); }
pre { overflow:auto; max-height:62vh; background:#0b1020; padding:14px; border-radius:8px; }
.dialog-head { display:flex; justify-content:space-between; align-items:center; gap:10px; }
</style>
</head>
<body>
<header><h1>KANSOKU v0.10.0 Dashboard</h1><span class="muted">Observation, configuration correlation, and reviewable network change recommendations</span></header>
<main>
<div class="controls"><label for="target">Target</label><select id="target"></select><button id="refresh">Refresh</button><span id="status" class="muted"></span></div>
<div class="grid">
  <div class="card"><h2>Operational State</h2><div id="state" class="value">—</div><div id="reason" class="muted"></div><div id="evidence" class="evidence"></div></div>
  <div class="card"><h2>RTT</h2><div id="rtt" class="value">—</div></div>
  <div class="card"><h2>Packet Loss</h2><div id="loss" class="value">—</div></div>
  <div class="card"><h2>Throughput</h2><div id="throughput" class="value">—</div><div id="ratio" class="muted"></div></div>
  <div class="card"><h2>Latest Capture</h2><div id="capture-packets" class="value">—</div><div id="capture-detail" class="muted"></div></div>
  <div class="card"><h2>Unique Flows</h2><div id="capture-flows" class="value">—</div><div id="capture-privacy" class="muted"></div></div>
  <div class="card"><h2>Network Devices</h2><div id="network-device-count" class="value">—</div><div id="network-device-detail" class="muted"></div></div>
  <div class="card"><h2>Flow Assessments</h2><div id="assessment-count" class="value">—</div><div id="assessment-detail" class="muted"></div></div>
  <div class="card"><h2>Recommendations</h2><div id="recommendation-count" class="value">—</div><div id="recommendation-detail" class="muted"></div></div>
  <div class="card"><h2>Lab Remediations</h2><div id="remediation-count" class="value">—</div><div id="remediation-detail" class="muted"></div></div>
  <div class="card"><h2>Target Profile</h2><div id="profile" class="small-value">—</div><div id="profile-detail" class="muted"></div></div>
  <div class="card"><h2>Observation Plan</h2><div id="plan" class="small-value">—</div><div id="plan-detail" class="muted"></div></div>
  <div class="card"><h2>Safety Policy</h2><div id="policy" class="small-value">—</div><div id="policy-detail" class="muted"></div></div>
  <div class="card"><h2>Controller Outcome</h2><div id="controller" class="small-value">—</div><div id="controller-detail" class="muted"></div></div>
  <div class="card"><h2>Managed Target</h2><div id="managed-target" class="small-value">Not registered</div><div id="managed-target-detail" class="muted"></div></div>
  <div class="card"><h2>Scheduler</h2><div id="scheduler" class="small-value">—</div><div id="scheduler-detail" class="muted"></div></div>
</div>
<section class="card"><h2>Fleet / Persistent Service</h2><div class="table-wrap"><table><thead><tr><th>Target</th><th>Enabled</th><th>State</th><th>Due</th><th>Interval</th><th>Latest cycle</th><th>Next due</th></tr></thead><tbody id="fleet"></tbody></table></div></section>
<section class="card"><h2>Remote Agents / Ingest</h2><div class="table-wrap"><table><thead><tr><th>Agent</th><th>Enabled</th><th>Capabilities</th><th>Last seen</th><th>Heartbeat</th><th>Queue</th><th>Latest batch</th></tr></thead><tbody id="remote-agents"></tbody></table></div></section>
<section class="charts">
  <div class="card"><h2>RTT history</h2><div id="chart-rtt"></div></div>
  <div class="card"><h2>Packet-loss history</h2><div id="chart-loss"></div></div>
  <div class="card"><h2>Throughput history</h2><div id="chart-throughput"></div></div>
</section>
<section class="card"><h2>Network State Inventory</h2><div class="table-wrap"><table><thead><tr><th>Device</th><th>Type</th><th>Platform</th><th>Interfaces</th><th>Routes</th><th>Policy rules</th><th>Latest snapshot</th></tr></thead><tbody id="network-devices"></tbody></table></div></section>
<section class="card"><h2>Flow-to-Configuration Assessments</h2><div class="table-wrap"><table><thead><tr><th>Time</th><th>Flow</th><th>Ingress</th><th>Route</th><th>Policy</th><th>VLAN</th><th>Verdict</th><th>Reason</th></tr></thead><tbody id="assessments"></tbody></table></div></section>
<section class="card"><h2>Configuration Recommendations</h2><div class="table-wrap"><table><thead><tr><th>Time</th><th>Rank</th><th>Category</th><th>Device</th><th>Risk</th><th>Simulation</th><th>Summary</th><th>ID</th></tr></thead><tbody id="recommendations"></tbody></table></div></section>
<section class="card"><h2>Cross-Layer Evidence Graphs</h2><div class="table-wrap"><table><thead><tr><th>Time</th><th>Assessment</th><th>Coverage</th><th>Nodes</th><th>Edges</th><th>Graph ID</th></tr></thead><tbody id="evidence-graphs"></tbody></table></div></section>
<section class="card"><h2>Guarded Virtual-Lab Remediation</h2><div class="table-wrap"><table><thead><tr><th>Time</th><th>Category</th><th>Device</th><th>Status</th><th>Approval</th><th>Verification</th><th>Rollback</th><th>Execution ID</th></tr></thead><tbody id="remediations"></tbody></table></div></section>
<section class="card"><h2>Packet Capture Sessions</h2><div class="table-wrap"><table><thead><tr><th>Local time</th><th>Interface</th><th>Filter</th><th>Privacy</th><th>Packets</th><th>Flows</th><th>Size</th><th>Scope</th><th>Capture ID</th></tr></thead><tbody id="captures"></tbody></table></div></section>
<section class="card"><h2>Top Aggregated Flows</h2><div class="table-wrap"><table><thead><tr><th>Protocol</th><th>Source</th><th>Destination</th><th>VLAN</th><th>Packets</th><th>Wire bytes</th><th>Last seen</th></tr></thead><tbody id="flows"></tbody></table></div></section>
<section class="card"><h2>Latest Observations</h2><div class="table-wrap"><table><thead><tr><th>Local time</th><th>Metric</th><th>Value</th><th>Method</th><th>Source</th></tr></thead><tbody id="observations"></tbody></table></div></section>
<section class="card"><h2>Safe Action Lifecycle</h2><div class="table-wrap"><table><thead><tr><th>Local time</th><th>Action</th><th>Outcome</th><th>Guard</th><th>Approval</th><th>Verification</th><th>Message</th></tr></thead><tbody id="lifecycle"></tbody></table></div></section>
<section class="card"><h2>Action Proposals</h2><div class="table-wrap"><table><thead><tr><th>Local time</th><th>Action</th><th>Risk</th><th>Expected effect</th><th>ID</th></tr></thead><tbody id="proposals"></tbody></table></div></section>
<section class="card"><h2>Collection Runs / Raw Evidence</h2><div class="table-wrap"><table><thead><tr><th>Local time</th><th>Agent</th><th>Return</th><th>Command</th><th>Run ID</th></tr></thead><tbody id="runs"></tbody></table></div></section>
</main>
<dialog id="run-dialog"><div class="dialog-head"><h2>Collection Run Evidence</h2><button id="close-dialog">Close</button></div><pre id="run-json"></pre></dialog>
<script>
const targetEl = document.getElementById('target');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const localTime = value => value ? new Date(value).toLocaleString() : '—';
function metricValue(metrics, name, unit) { const m=metrics[name]; return m ? `${Number(m.value).toFixed(Math.abs(m.value) < 10 ? 3 : 2)} ${unit || m.unit}` : '—'; }
function chart(containerId, series, unit) {
  const el=document.getElementById(containerId);
  if(!series || !series.length){el.innerHTML='<div class="chart-empty">No samples</div>'; return;}
  const w=560,h=180,p=28;
  const values=series.map(x=>Number(x.value)); let min=Math.min(...values),max=Math.max(...values);
  min=Math.max(0,min);
  if(min===max){max+=Math.max(1,Math.abs(max)*.05);}
  const span=Math.max(.000001,max-min);
  const points=values.map((v,i)=>{const x=p+(i/(Math.max(1,values.length-1)))*(w-2*p); const y=h-p-((v-min)/span)*(h-2*p); return `${x.toFixed(1)},${y.toFixed(1)}`;}).join(' ');
  const latest=values[values.length-1];
  el.innerHTML=`<svg class="chart" viewBox="0 0 ${w} ${h}" role="img"><line x1="${p}" y1="${p}" x2="${p}" y2="${h-p}" stroke="#425173"/><line x1="${p}" y1="${h-p}" x2="${w-p}" y2="${h-p}" stroke="#425173"/><polyline fill="none" stroke="#7eb6ff" stroke-width="3" points="${points}"/><text x="${p+5}" y="${p+14}" fill="#9eb0d5" font-size="12">max ${max.toFixed(2)} ${unit}</text><text x="${p+5}" y="${h-p-7}" fill="#9eb0d5" font-size="12">min ${min.toFixed(2)} ${unit}</text><text x="${w-p-120}" y="${p+14}" fill="#e8eefc" font-size="13">latest ${latest.toFixed(2)} ${unit}</text></svg>`;
}
async function loadTargets(){
  const data = await fetch('/api/targets').then(r=>r.json());
  const previous = targetEl.value;
  targetEl.innerHTML = data.targets.map(t=>`<option value="${esc(t)}">${esc(t)}</option>`).join('');
  if (data.targets.includes(previous)) targetEl.value=previous;
}
async function showRun(runId){
  const response=await fetch(`/api/runs/${encodeURIComponent(runId)}`);
  const data=await response.json();
  document.getElementById('run-json').textContent=JSON.stringify(data,null,2);
  document.getElementById('run-dialog').showModal();
}
async function refreshFleet(){
  try {
    const data=await fetch('/api/fleet').then(r=>r.json());
    document.getElementById('fleet').innerHTML=(data.fleet || []).map(x=>{
      const t=x.target || {}, d=x.due || {}, st=x.state || {}, c=x.latest_cycle || {};
      return `<tr><td>${esc(t.name || t.target)}<br><span class="muted">${esc(t.target)}</span></td><td class="${t.enabled ? 'success':'muted'}">${t.enabled ? 'yes':'no'}</td><td class="state-${esc(st.state || '')}">${esc(st.state || 'UNKNOWN')}</td><td>${d.due ? 'due':'waiting'}</td><td>${esc(d.interval_sec)}s</td><td class="${c.status === 'FAILED' ? 'error':'success'}">${esc(c.status || '—')}</td><td>${esc(localTime(d.next_due_at))}</td></tr>`;
    }).join('');
  } catch(e) { /* target snapshot remains usable */ }
}
async function refreshRemoteAgents(){
  try {
    const data=await fetch('/api/agents').then(r=>r.json());
    document.getElementById('remote-agents').innerHTML=(data.agents || []).map(x=>{
      const a=x.agent || {}, h=x.latest_heartbeat || {}, b=x.latest_batch || {};
      return `<tr><td>${esc(a.name || a.agent_id)}<br><span class="muted">${esc(a.agent_id)}</span></td><td class="${a.enabled ? 'success':'error'}">${a.enabled ? 'yes':'no'}</td><td>${esc((a.capabilities || []).join(', ') || '—')}</td><td>${esc(localTime(a.last_seen_at))}</td><td class="${h.status === 'ONLINE' ? 'success':'muted'}">${esc(h.status || '—')}</td><td>${esc(h.queue_depth ?? '—')}</td><td>${esc(b.status || '—')}<br><span class="muted">obs=${esc(b.observation_count ?? 0)}, cap=${esc(b.capture_count ?? 0)}, flow=${esc(b.flow_count ?? 0)}<br>${esc(localTime(b.received_at))}</span></td></tr>`;
    }).join('');
  } catch(e) { /* remote agent table is supplemental */ }
}
async function refreshNetwork(){
  try {
    const data=await fetch('/api/network').then(r=>r.json());
    const devices=data.devices || [];
    document.getElementById('network-device-count').textContent=devices.length;
    document.getElementById('network-device-detail').textContent=`${data.summary.interfaces} interfaces; ${data.summary.routes} routes; ${data.summary.policies} policy rules`;
    document.getElementById('network-devices').innerHTML=devices.map(d=>`<tr><td><code>${esc(d.device_id)}</code><br>${esc(d.name)}</td><td>${esc(d.device_type)}</td><td>${esc(d.platform)}</td><td>${esc(d.counts.interfaces)}</td><td>${esc(d.counts.routes)}</td><td>${esc(d.counts.policies)}</td><td>${esc(localTime(d.latest_snapshot?.finished_at))}</td></tr>`).join('');
  } catch(e) {
    document.getElementById('network-device-detail').textContent=`Error: ${e}`;
  }
}
async function refresh(){
  const target=targetEl.value; if(!target) return;
  document.getElementById('status').textContent='Updating…';
  try {
    const data=await fetch(`/api/snapshot?target=${encodeURIComponent(target)}&limit=100`).then(r=>r.json());
    const st=data.state || {};
    const stateEl=document.getElementById('state'); stateEl.textContent=st.state || 'UNKNOWN'; stateEl.className=`value state-${st.state || ''}`;
    document.getElementById('reason').textContent=st.reason || 'No state estimate yet';
    document.getElementById('evidence').innerHTML=(data.evidence || []).map(o=>`<span class="badge" title="${esc(o.observation_id)}">${esc(o.metric)}=${esc(o.value)} ${esc(o.unit)}</span>`).join('');
    document.getElementById('rtt').textContent=metricValue(data.latest_metrics,'rtt_ms','ms');
    document.getElementById('loss').textContent=metricValue(data.latest_metrics,'packet_loss_pct','%');
    document.getElementById('throughput').textContent=metricValue(data.latest_metrics,'throughput_mbps','Mbps');
    const latestCapture=(data.captures || [])[0];
    document.getElementById('capture-packets').textContent=latestCapture ? `${latestCapture.packet_count} packets` : '—';
    document.getElementById('capture-detail').textContent=latestCapture ? `${Number(latestCapture.wire_bytes || 0).toLocaleString()} wire bytes; ${localTime(latestCapture.finished_at)}` : 'No capture metadata';
    document.getElementById('capture-flows').textContent=latestCapture ? `${latestCapture.flow_count} flows` : '—';
    document.getElementById('capture-privacy').textContent=latestCapture ? `${latestCapture.privacy_mode}; ${latestCapture.storage_scope}` : '';
    const ratio=st.features && st.features.throughput_ratio; document.getElementById('ratio').textContent=ratio == null ? '' : `${(ratio*100).toFixed(1)}% of configured reference`;
    const profile=data.profile;
    document.getElementById('profile').textContent=profile ? profile.name : 'Absolute fallback';
    document.getElementById('profile-detail').textContent=profile ? `expected=${profile.expected_bandwidth_mbps ?? '—'} Mbps, baseline=${profile.baseline_throughput_mbps ?? '—'} Mbps` : 'No target profile configured';
    const plan=data.observation_plan;
    document.getElementById('plan').textContent=plan ? `${plan.interval_sec} seconds` : '30 seconds';
    document.getElementById('plan-detail').textContent=plan ? `${plan.mode}: ${plan.reason}` : 'Default plan';
    const policy=data.safety_policy;
    document.getElementById('policy').textContent=policy ? policy.name : 'Built-in default';
    document.getElementById('policy-detail').textContent=policy ? `target=${policy.target}; system changes=${policy.allow_system_changes ? 'allowed' : 'disabled'}; min interval=${policy.minimum_observation_interval_sec}s` : '';
    const txn=(data.control_transactions || [])[0];
    const controllerEl=document.getElementById('controller'); controllerEl.textContent=txn ? txn.outcome : 'No transaction'; controllerEl.className=`small-value outcome-${txn ? txn.outcome : ''}`;
    document.getElementById('controller-detail').textContent=txn ? txn.message : 'No proposal has been processed by the safe controller';
    const managed=data.managed_target;
    document.getElementById('managed-target').textContent=managed ? managed.name : 'Not registered';
    document.getElementById('managed-target-detail').textContent=managed ? `${managed.enabled ? 'enabled':'disabled'}; ping=${managed.ping_enabled}; iperf3=${managed.iperf3_enabled}` : 'Use kansoku target set to register this target';
    const due=data.scheduler_due || {};
    const latestCycle=(data.scheduler_cycles || [])[0];
    document.getElementById('scheduler').textContent=latestCycle ? latestCycle.status : (managed ? 'No cycle yet':'Not managed');
    document.getElementById('scheduler-detail').textContent=managed ? `${due.due ? 'due now':'next '+localTime(due.next_due_at)}; interval=${due.interval_sec ?? '—'}s` : '';
    document.getElementById('captures').innerHTML=(data.captures || []).map(c=>`<tr><td>${esc(localTime(c.finished_at))}</td><td>${esc(c.interface)}</td><td><code>${esc(c.bpf_filter || '—')}</code></td><td>${esc(c.privacy_mode)}</td><td>${esc(c.packet_count)}</td><td>${esc(c.flow_count)}</td><td>${esc(Number(c.file_size || 0).toLocaleString())}</td><td>${esc(c.storage_scope)}</td><td><code>${esc(c.capture_id)}</code></td></tr>`).join('');
    document.getElementById('flows').innerHTML=(data.flows || []).map(f=>`<tr><td>${esc(f.protocol)}</td><td><code>${esc(f.src_ip)}${f.src_port == null ? '' : ':'+f.src_port}</code></td><td><code>${esc(f.dst_ip)}${f.dst_port == null ? '' : ':'+f.dst_port}</code></td><td>${esc(f.vlan_id ?? '—')}</td><td>${esc(f.packets)}</td><td>${esc(Number(f.wire_bytes || 0).toLocaleString())}</td><td>${esc(localTime(f.last_seen))}</td></tr>`).join('');
    const assessments=data.flow_assessments || []; const verdicts={}; assessments.forEach(a=>verdicts[a.verdict]=(verdicts[a.verdict]||0)+1);
    document.getElementById('assessment-count').textContent=assessments.length;
    document.getElementById('assessment-detail').textContent=Object.entries(verdicts).map(([k,v])=>`${k}=${v}`).join('; ') || 'Run network correlate to assess captured flows';
    document.getElementById('assessments').innerHTML=assessments.map(a=>`<tr><td>${esc(localTime(a.timestamp))}</td><td><code>${esc(a.flow_id)}</code></td><td><code>${esc(a.ingress_device_id)}</code></td><td>${esc(a.route_status)}</td><td>${esc(a.policy_status)}</td><td>${esc(a.vlan_status)}</td><td class="outcome-${esc(a.verdict==='ALLOW'?'VERIFIED':a.verdict==='DENY'?'FAILED':'INCONCLUSIVE')}">${esc(a.verdict)}</td><td>${esc(a.reason)}</td></tr>`).join('');
    const recommendations=data.configuration_recommendations || []; const recCats={}; recommendations.forEach(r=>recCats[r.category]=(recCats[r.category]||0)+1);
    document.getElementById('recommendation-count').textContent=recommendations.length;
    document.getElementById('recommendation-detail').textContent=Object.entries(recCats).map(([k,v])=>`${k}=${v}`).join('; ') || 'Run recommend candidates for an abnormal assessment';
    document.getElementById('recommendations').innerHTML=recommendations.map(r=>`<tr><td>${esc(localTime(r.generated_at))}</td><td>${esc(r.metadata?.ranking?.rank ?? '—')}<br><span class="muted">${r.metadata?.ranking?.score != null ? Number(r.metadata.ranking.score).toFixed(3) : ''}</span></td><td>${esc(r.category)}</td><td><code>${esc(r.device_id)}</code><br><span class="muted">${esc(r.platform)}</span></td><td>${esc(r.risk_level)}</td><td class="outcome-${esc(r.simulation_status==='PASSED'?'VERIFIED':r.simulation_status==='FAILED'?'FAILED':'INCONCLUSIVE')}">${esc(r.simulation_status)} → ${esc(r.simulated_verdict || '—')}</td><td>${esc(r.summary)}</td><td><code>${esc(r.recommendation_id)}</code></td></tr>`).join('');
    const graphs=data.evidence_graphs || [];
    document.getElementById('evidence-graphs').innerHTML=graphs.map(g=>`<tr><td>${esc(localTime(g.generated_at))}</td><td><code>${esc(g.assessment_id)}</code></td><td>${Number(g.metadata?.evidence_coverage ?? 0).toFixed(2)}</td><td>${esc((g.nodes || []).length)}</td><td>${esc((g.edges || []).length)}</td><td><code>${esc(g.graph_id)}</code></td></tr>`).join('');
    const remediations=data.remediation_executions || []; const remStatuses={}; remediations.forEach(r=>remStatuses[r.status]=(remStatuses[r.status]||0)+1);
    document.getElementById('remediation-count').textContent=remediations.length;
    document.getElementById('remediation-detail').textContent=Object.entries(remStatuses).map(([k,v])=>`${k}=${v}`).join('; ') || 'Virtual-lab execution only';
    document.getElementById('remediations').innerHTML=remediations.map(r=>`<tr><td>${esc(localTime(r.started_at))}</td><td>${esc(r.category)}</td><td><code>${esc(r.device_id)}</code></td><td class="outcome-${esc(r.status)}">${esc(r.status)}</td><td>${esc(r.approved_by)}</td><td>${r.verification?.passed ? 'PASS' : '—'}</td><td>${r.rollback_verification?.passed ? 'PASS' : (r.status==='VERIFIED' ? 'kept' : '—')}</td><td><code>${esc(r.execution_id)}</code></td></tr>`).join('');
    document.getElementById('observations').innerHTML=data.observations.map(o=>`<tr><td>${esc(localTime(o.timestamp))}</td><td>${esc(o.metric)}</td><td>${esc(o.value)} ${esc(o.unit)}</td><td>${esc(o.method)}</td><td>${esc(o.source)}</td></tr>`).join('');
    document.getElementById('lifecycle').innerHTML=(data.action_lifecycle || []).map(x=>`<tr><td>${esc(localTime(x.timestamp))}</td><td>${esc(x.action)}</td><td class="outcome-${esc(x.outcome)}">${esc(x.outcome)}</td><td>${esc(x.guard_status || '—')}</td><td>${esc(x.approval_status || '—')}</td><td>${esc(x.verification_status || '—')}</td><td>${esc(x.message)}</td></tr>`).join('');
    document.getElementById('proposals').innerHTML=data.proposals.map(p=>`<tr><td>${esc(localTime(p.timestamp))}</td><td>${esc(p.action)}</td><td>${esc(p.risk_level)}</td><td>${esc(p.expected_effect)}</td><td><code>${esc(p.proposal_id)}</code></td></tr>`).join('');
    document.getElementById('runs').innerHTML=data.runs.map(r=>`<tr><td>${esc(localTime(r.started_at))}</td><td>${esc(r.agent)}</td><td class="${r.returncode ? 'error':'success'}">${esc(r.returncode)}</td><td><code>${esc(r.command.join(' '))}</code></td><td><button class="run-link" data-run="${esc(r.run_id)}">${esc(r.run_id)}</button></td></tr>`).join('');
    document.querySelectorAll('.run-link').forEach(b=>b.onclick=()=>showRun(b.dataset.run));
    chart('chart-rtt',data.series.rtt_ms,'ms'); chart('chart-loss',data.series.packet_loss_pct,'%'); chart('chart-throughput',data.series.throughput_mbps,'Mbps');
    await refreshFleet();
    await refreshRemoteAgents();
    await refreshNetwork();
    document.getElementById('status').textContent=`Updated ${new Date().toLocaleTimeString()}`;
  } catch(e) { document.getElementById('status').textContent=`Error: ${e}`; }
}
document.getElementById('refresh').onclick=refresh; targetEl.onchange=refresh;
document.getElementById('close-dialog').onclick=()=>document.getElementById('run-dialog').close();
(async()=>{await loadTargets(); await refreshFleet(); await refreshRemoteAgents(); await refreshNetwork(); await refresh(); setInterval(refresh,5000);})();
</script>
</body></html>"""


def build_snapshot(hub: Hub, target: str, limit: int = 100) -> Dict[str, Any]:
    observations = hub.list_observations(limit=limit, target=target)
    latest_metrics: Dict[str, Dict[str, Any]] = {}
    for obs in observations:  # newest first
        if obs.metric not in latest_metrics:
            latest_metrics[obs.metric] = obs.to_dict()

    state = hub.latest_state(target)
    evidence_ids = set(state.evidence if state else [])
    evidence = [obs.to_dict() for obs in observations if obs.observation_id in evidence_ids]
    runs = hub.list_collection_runs(limit=min(limit, 50), target=target)
    proposals = hub.list_proposals(limit=20, target=target)
    profile = hub.get_target_profile(target)
    plan = hub.get_observation_plan(target)
    policy = hub.get_safety_policy(target) or SafetyPolicy()
    transactions = hub.list_control_transactions(limit=20, target=target)
    managed_target = hub.get_managed_target(target)
    scheduler_cycles = hub.list_scheduler_cycles(limit=20, target=target)
    scheduler_due = (
        ObservationService(hub).due_status(managed_target).to_dict()
        if managed_target
        else None
    )
    captures = hub.list_capture_sessions(limit=20, target=target)
    flows = hub.list_flow_records(limit=50, target=target)
    flow_assessments = hub.list_flow_assessments(limit=100, target=target)
    configuration_recommendations = hub.list_configuration_recommendations(limit=100, target=target)
    assessment_ids = {item.assessment_id for item in flow_assessments}
    evidence_graphs = [
        item for item in hub.list_evidence_graphs(limit=200)
        if item.assessment_id in assessment_ids
    ][:100]
    recommendation_ids = {item.recommendation_id for item in configuration_recommendations}
    remediation_executions = [
        item for item in hub.list_remediation_executions(limit=200)
        if item.recommendation_id in recommendation_ids
    ][:100]

    action_lifecycle = []
    proposals_by_id = {proposal.proposal_id: proposal for proposal in proposals}
    for transaction in transactions:
        proposal = proposals_by_id.get(transaction.proposal_id) or hub.get_proposal(
            transaction.proposal_id
        )
        decision = (
            hub.get_guard_decision(transaction.guard_decision_id)
            if transaction.guard_decision_id
            else None
        )
        approval = (
            hub.get_approval(transaction.approval_id)
            if transaction.approval_id
            else None
        )
        verification = (
            hub.get_verification(transaction.verification_id)
            if transaction.verification_id
            else None
        )
        action_lifecycle.append(
            {
                **transaction.to_dict(),
                "action": proposal.action if proposal else "unknown",
                "risk_level": proposal.risk_level if proposal else None,
                "guard_status": decision.status if decision else None,
                "approval_status": approval.status if approval else None,
                "approval_actor": approval.actor if approval else None,
                "verification_status": verification.status if verification else None,
                "verification_reason": verification.reason if verification else None,
            }
        )

    series: Dict[str, list[Dict[str, Any]]] = {}
    for metric in ("rtt_ms", "packet_loss_pct", "throughput_mbps"):
        metric_rows = [obs.to_dict() for obs in reversed(observations) if obs.metric == metric]
        series[metric] = metric_rows[-50:]

    return {
        "target": target,
        "state": state.to_dict() if state else None,
        "profile": profile.to_dict() if profile else None,
        "observation_plan": plan.to_dict() if plan else None,
        "safety_policy": policy.to_dict(),
        "latest_metrics": latest_metrics,
        "series": series,
        "evidence": evidence,
        "observations": [obs.to_dict() for obs in observations],
        "runs": [run.to_dict() for run in runs],
        "proposals": [proposal.to_dict() for proposal in proposals],
        "control_transactions": [transaction.to_dict() for transaction in transactions],
        "action_lifecycle": action_lifecycle,
        "managed_target": managed_target.to_dict() if managed_target else None,
        "scheduler_cycles": [cycle.to_dict() for cycle in scheduler_cycles],
        "scheduler_due": scheduler_due,
        "captures": [item.to_dict() for item in captures],
        "flows": [item.to_dict() for item in flows],
        "flow_assessments": [item.to_dict() for item in flow_assessments],
        "configuration_recommendations": [item.to_dict() for item in configuration_recommendations],
        "evidence_graphs": [item.to_dict() for item in evidence_graphs],
        "remediation_executions": [item.to_dict() for item in remediation_executions],
    }


def make_handler(hub: Hub):
    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "KANSOKU/0.10"

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            if parsed.path == "/":
                self._send(DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            if parsed.path == "/api/targets":
                configured = [p.target for p in hub.list_target_profiles()]
                policy_targets = [p.target for p in hub.list_safety_policies() if p.target != "*"]
                managed_targets = [p.target for p in hub.list_managed_targets()]
                targets = list(dict.fromkeys(hub.list_targets() + managed_targets + configured + policy_targets))
                self._json({"targets": targets})
                return
            if parsed.path == "/api/fleet":
                service = ObservationService(hub, owner_id="dashboard-read-only")
                lease = hub.get_scheduler_lease(ObservationService.LEASE_NAME)
                self._json({
                    "fleet": service.fleet_status(),
                    "lease": lease.to_dict() if lease else None,
                })
                return
            if parsed.path == "/api/agents":
                rows = []
                for agent in hub.list_remote_agents(limit=200):
                    heartbeat = hub.latest_agent_heartbeat(agent.agent_id)
                    batches = hub.list_ingest_receipts(limit=1, agent_id=agent.agent_id)
                    rows.append({
                        "agent": agent.to_dict(),
                        "latest_heartbeat": heartbeat.to_dict() if heartbeat else None,
                        "latest_batch": batches[0].to_dict() if batches else None,
                    })
                self._json({"agents": rows})
                return
            if parsed.path == "/api/network":
                devices = []
                total_interfaces = total_routes = total_policies = 0
                for device in hub.list_network_devices(limit=500):
                    interfaces = hub.list_network_interfaces(device_id=device.device_id, limit=10_000)
                    routes = hub.list_network_routes(device_id=device.device_id, limit=20_000)
                    policies = hub.list_network_policies(device_id=device.device_id, limit=20_000)
                    snapshots = hub.list_network_snapshots(device_id=device.device_id, limit=1)
                    total_interfaces += len(interfaces)
                    total_routes += len(routes)
                    total_policies += len(policies)
                    devices.append({
                        **device.to_dict(),
                        "counts": {"interfaces": len(interfaces), "routes": len(routes), "policies": len(policies)},
                        "latest_snapshot": snapshots[0].to_dict() if snapshots else None,
                    })
                self._json({
                    "devices": devices,
                    "summary": {
                        "devices": len(devices), "interfaces": total_interfaces,
                        "routes": total_routes, "policies": total_policies,
                    },
                    "links": [item.to_dict() for item in hub.list_network_links(limit=10_000)],
                    "vlans": [item.to_dict() for item in hub.list_network_vlans(limit=10_000)],
                })
                return
            if parsed.path == "/api/snapshot":
                target = (query.get("target") or [""])[0]
                if not target:
                    self._json({"error": "target is required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                try:
                    limit = max(1, min(500, int((query.get("limit") or ["100"])[0])))
                except ValueError:
                    limit = 100
                self._json(build_snapshot(hub, target, limit=limit))
                return
            if parsed.path.startswith("/api/recommendations/"):
                recommendation_id = parsed.path.rsplit("/", 1)[-1]
                recommendation = hub.get_configuration_recommendation(recommendation_id)
                if recommendation:
                    self._json(recommendation.to_dict())
                else:
                    self._json({"error": "recommendation not found"}, status=HTTPStatus.NOT_FOUND)
                return
            if parsed.path.startswith("/api/captures/"):
                capture_id = parsed.path.rsplit("/", 1)[-1]
                session = hub.get_capture_session(capture_id)
                if session:
                    self._json({
                        "capture": session.to_dict(),
                        "flows": [item.to_dict() for item in hub.list_flow_records(capture_id=capture_id, limit=500)],
                    })
                else:
                    self._json({"error": "capture not found"}, status=HTTPStatus.NOT_FOUND)
                return
            if parsed.path.startswith("/api/runs/"):
                run_id = parsed.path.rsplit("/", 1)[-1]
                run = hub.get_collection_run(run_id)
                if run:
                    self._json(run.to_dict())
                else:
                    self._json({"error": "run not found"}, status=HTTPStatus.NOT_FOUND)
                return
            self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def _json(self, payload: Dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._send(body, "application/json; charset=utf-8", status=status)

        def _send(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
            self.send_response(status.value)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return DashboardHandler


def serve_dashboard(hub: Hub, host: str = "127.0.0.1", port: int = 8080) -> None:
    server = ThreadingHTTPServer((host, port), make_handler(hub))
    print(f"KANSOKU dashboard: http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
