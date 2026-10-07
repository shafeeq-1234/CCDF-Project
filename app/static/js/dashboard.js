async function fetchJSON(u){ const r=await fetch(u); return r.json(); }
let charts=[];
function mkChart(id, type, data, label){
  const el=document.getElementById(id); if(!el) return;
  const colors=['#38bdf8','#f472b6','#a78bfa','#facc15','#34d399','#fb7185','#94a3b8','#f97316'];
  charts.push(new Chart(el,{type, data:{labels:data.labels, datasets:[{label:label||'', data:data.values, backgroundColor:colors}]},
    options:{responsive:true, plugins:{legend:{labels:{color:'#dbe4f0'}}}, scales:type==='bar'?{x:{ticks:{color:'#94a3b8'}},y:{ticks:{color:'#94a3b8'}}}:{}}}));
}
async function loadDashboard(){
  const d=await fetchJSON('/api/dashboard');
  document.getElementById('s-cases').textContent=d.stats.total_cases;
  document.getElementById('s-files').textContent=d.stats.total_files;
  document.getElementById('s-susp').textContent=d.stats.suspicious;
  document.getElementById('s-high').textContent=d.stats.high_critical;
  document.getElementById('s-ver').textContent=d.stats.verified;
  document.getElementById('s-mis').textContent=d.stats.mismatch;
  document.getElementById('s-cust').textContent=d.stats.custody_events;
  mkChart('ch-types','doughnut',d.file_types,'files');
  mkChart('ch-susp','bar',d.suspicion,'files');
  mkChart('ch-int','pie',d.integrity,'files');
  mkChart('ch-size','bar',d.sizes,'files');
  mkChart('ch-time','line',d.timeline,'files analysed');
  const s=await fetchJSON('/api/analysis/suspicious?min_score=25');
  const tb=document.querySelector('#tbl-susp tbody'); tb.innerHTML='';
  s.slice(0,20).forEach(x=>{ const tr=document.createElement('tr');
    tr.innerHTML=`<td><a href="/evidence/${x.id}">${x.relative_path}</a></td><td>${x.score}</td><td>${x.level}</td><td class="small">${x.reasons.join('; ')}</td>`;
    tb.appendChild(tr); });
  if(!s.length) tb.innerHTML='<tr><td colspan=4>No potentially suspicious files.</td></tr>';
}
loadDashboard();
