async function loadFileAnalysis(id){
  const r=await fetch('/api/evidence/'+id); const f=await r.json();
  const w=document.getElementById('wrap');
  if(f.error){ w.innerHTML='<div class="alert alert-danger">'+f.error+'</div>'; return; }
  const lvlColor=f.suspicion_level=='CRITICAL'?'danger':f.suspicion_level=='HIGH'?'warning':f.suspicion_level=='MEDIUM'?'info':'success';
  w.innerHTML=`
  <div class="row g-3">
   <div class="col-md-6"><div class="card"><div class="card-header">File Information</div><div class="card-body">
    <p><b>Filename:</b> ${f.filename}<br><b>Path:</b> <small>${f.relative_path}</small><br>
    <b>Size:</b> ${f.size} bytes<br><b>Extension:</b> ${f.extension}<br><b>MIME:</b> ${f.mime_type}<br>
    <b>Detected type:</b> ${f.signature} (${f.detected_type}) · match=${f.signature_match}<br>
    <b>Created:</b> ${f.file_created||''}<br><b>Modified:</b> ${f.file_modified||''}<br><b>Hidden:</b> ${f.hidden}</p>
    <button class="btn btn-sm btn-success" onclick="verifyNow(${f.id})">✔ Verify Integrity</button>
    <span id="vout" class="ms-2 small"></span>
   </div></div></div>
   <div class="col-md-6"><div class="card"><div class="card-header">Hashes (SHA-256 primary)</div><div class="card-body">
    <div><b>MD5:</b><div class="hash">${f.hashes.md5}</div></div>
    <div><b>SHA-1:</b><div class="hash">${f.hashes.sha1}</div></div>
    <div><b>SHA-256:</b><div class="hash text-info">${f.hashes.sha256}</div></div>
    <p class="small text-secondary mt-2">SHA-256 is used as the primary integrity verification mechanism.</p>
   </div></div></div>
   <div class="col-md-6"><div class="card"><div class="card-header">Metadata</div><div class="card-body table-responsive">
    <table class="table table-sm"><thead><tr><th>Property</th><th>Value</th></tr></thead><tbody>
    ${Object.entries(f.metadata||{}).map(([k,v])=>`<tr><td>${k}</td><td class="small">${String(v).slice(0,300)}</td></tr>`).join('')||'<tr><td colspan=2>No metadata</td></tr>'}
    </tbody></table></div></div></div>
   <div class="col-md-6"><div class="card"><div class="card-header">Forensic Analysis</div><div class="card-body">
    <h4><span class="badge bg-${lvlColor}">${f.suspicion_level} ${f.suspicion_score}/100</span></h4>
    <p class="small text-warning">Potentially suspicious — heuristic score only, file never executed.</p>
    <ul>${(f.reasons||[]).map(x=>`<li>${x}</li>`).join('')||'<li>No indicators</li>'}</ul>
    <hr><b>Integrity:</b> <span class="badge bg-${f.integrity.status=='VERIFIED'?'success':'danger'}">${f.integrity.status}</span>
    <div class="small hash">orig: ${f.integrity.original_sha256}<br>curr: ${f.integrity.current_sha256}</div>
   </div></div></div>
  </div>`;
}
async function verifyNow(id){
  const r=await fetch('/api/evidence/'+id+'/verify',{method:'POST'}); const j=await r.json();
  document.getElementById('vout').textContent=`${j.status}: ${j.error||''}`;
  loadFileAnalysis(id);
}
async function loadSuspiciousTable(){
  const r=await fetch('/api/analysis/suspicious?min_score=0'); const j=await r.json();
  document.getElementById('wrap').innerHTML=`<div class="card"><div class="card-header">All analysed files by suspicion</div>
  <div class="card-body table-responsive"><table class="table table-sm table-striped"><thead><tr><th>File</th><th>Score</th><th>Level</th><th>Reasons</th></tr></thead>
  <tbody>${j.map(x=>`<tr><td><a href="/evidence/${x.id}">${x.relative_path}</a></td><td>${x.score}</td><td>${x.level}</td><td class="small">${x.reasons.join('; ')}</td></tr>`).join('')}</tbody></table></div></div>`;
}
