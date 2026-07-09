"""Tablero de Reclutamiento de operadores."""
import os
import json
import hmac
import time
import base64
import hashlib
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import db

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("reclutamiento")

PORT = int(os.environ.get("PORT", "10000"))
_NIVEL = {"RH": 1, "Reclutador": 1, "Administrador": 3}


def _secret():
    return db.get_secret().encode("utf-8")


def _firmar_sesion(usuario, nombre, rol):
    exp = str(int(time.time()) + 86400 * 7)
    payload = "|".join([usuario, nombre, rol, exp])
    p64 = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")
    sig = hmac.new(_secret(), p64.encode("ascii"), hashlib.sha256).hexdigest()[:32]
    return p64 + "." + sig


def _leer_sesion(cookie):
    if not cookie:
        return None
    try:
        p64, sig = cookie.split(".", 1)
        esperado = hmac.new(_secret(), p64.encode("ascii"),
                            hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig, esperado):
            return None
        usuario, nombre, rol, exp = base64.urlsafe_b64decode(
            p64.encode("ascii")).decode("utf-8").split("|")
        if int(exp) < int(time.time()):
            return None
        return {"usuario": usuario, "nombre": nombre, "rol": rol}
    except Exception:
        return None


def _puede(rol, minimo):
    return _NIVEL.get(rol, 0) >= _NIVEL.get(minimo, 99)


LOGIN_HTML = """<!doctype html><html lang=es><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Reclutamiento - Acceso</title>
<style>
 body{font-family:system-ui,Segoe UI,Arial;background:#0f172a;color:#e2e8f0;
   display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
 .box{background:#1e293b;padding:32px;border-radius:14px;width:320px;box-shadow:0 10px 40px rgba(0,0,0,.4)}
 h1{font-size:18px;margin:0 0 4px} p{color:#94a3b8;font-size:13px;margin:0 0 18px}
 input{width:100%;box-sizing:border-box;padding:10px;margin:6px 0;border-radius:8px;
   border:1px solid #334155;background:#0f172a;color:#e2e8f0}
 button{width:100%;padding:11px;margin-top:10px;border:0;border-radius:8px;
   background:#2563eb;color:#fff;font-weight:600;cursor:pointer}
 .err{color:#f87171;font-size:13px;min-height:18px}
</style></head><body>
<div class=box>
 <h1>Tablero de Reclutamiento</h1>
 <p>Control de operadores - Cryogenics y TNIR</p>
 <input id=usuario placeholder=Usuario autocomplete=username>
 <input id=password type=password placeholder=Contrasena autocomplete=current-password>
 <div class=err id=err></div>
 <button onclick=entrar()>Entrar</button>
</div>
<script>
async function entrar(){
 var u=document.getElementById('usuario').value.trim();
 var p=document.getElementById('password').value;
 var r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({usuario:u,password:p})});
 var j=await r.json();
 if(j.ok){ location.href='/'; } else { document.getElementById('err').textContent=j.error||'Acceso incorrecto'; }
}
document.getElementById('password').addEventListener('keydown',function(e){ if(e.key==='Enter') entrar(); });
</script></body></html>"""


def app_html():
    return APP_HTML


APP_HTML = """<!doctype html><html lang=es><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Tablero de Reclutamiento</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
 :root{--bg:#f1f5f9;--card:#fff;--ink:#0f172a;--mut:#64748b;--bd:#e2e8f0;
   --blue:#2563eb;--green:#16a34a;--amber:#f59e0b;--red:#dc2626;--purple:#7c3aed}
 *{box-sizing:border-box}
 body{font-family:system-ui,Segoe UI,Arial;background:var(--bg);color:var(--ink);margin:0}
 header{background:#0f172a;color:#fff;padding:10px 18px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
 header h1{font-size:17px;margin:0}
 .tabs{display:flex;gap:6px;margin-left:8px}
 .tabs button{background:#1e293b;color:#cbd5e1;border:0;padding:8px 14px;border-radius:8px;cursor:pointer;font-weight:600}
 .tabs button.on{background:var(--blue);color:#fff}
 .sp{flex:1}
 .ub{font-size:13px;color:#cbd5e1}
 .ub a{color:#93c5fd;cursor:pointer;margin-left:10px}
 main{padding:18px;max-width:1280px;margin:0 auto}
 .card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:16px;margin-bottom:16px}
 .card h2{font-size:15px;margin:0 0 12px}
 .grid{display:grid;gap:12px}
 .kpis{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
 .kpi{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px}
 .kpi .v{font-size:26px;font-weight:700}
 .kpi .l{font-size:12px;color:var(--mut);margin-top:2px}
 .nec{grid-template-columns:repeat(auto-fit,minmax(220px,1fr))}
 .nec .n{font-size:34px;font-weight:800;color:var(--red)}
 .nec .ok{color:var(--green)}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th,td{padding:7px 8px;border-bottom:1px solid var(--bd);text-align:left;vertical-align:top}
 th{color:var(--mut);font-weight:600;font-size:12px}
 .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
 input,select,textarea{padding:8px;border:1px solid var(--bd);border-radius:8px;background:#fff;color:var(--ink);font-size:13px}
 button.b{background:var(--blue);color:#fff;border:0;border-radius:8px;padding:8px 12px;cursor:pointer;font-weight:600}
 button.g{background:var(--green)} button.r{background:var(--red)} button.s{background:#64748b}
 .pill{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:700;color:#fff}
 .muted{color:var(--mut)}
 .chartbox{height:280px}
 .two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
 @media(max-width:820px){.two{grid-template-columns:1fr}}
 .hide{display:none}
 .scroll{max-height:420px;overflow:auto}
 .flexcards{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}
</style></head><body>
<header>
 <h1>&#128203; Tablero de Reclutamiento</h1>
 <div class=tabs>
  <button id=tabFlujo class=on onclick="showTab('flujo')">Pipeline reclutamiento</button>
  <button id=tabCond onclick="showTab('cond')">Conductores activos</button>
  <button id=tabDash onclick="showTab('dash')">Dashboard KPI</button>
  <button id=tabFlujoAdm onclick="showTab('flujoAdm')">Pipeline administrativo</button>
  <button id=tabDashAdm onclick="showTab('dashAdm')">Dashboard administrativo</button>
 </div>
 <span class=sp></span>
 <select id=fEmpresa onchange="recargar()"><option value="">Todas las empresas</option></select>
 <span class=ub id=userBox></span>
 <span class=ub><a onclick="abrirUsuarios()" class="perm-admin">Usuarios</a><a onclick="salir()">Salir</a></span>
</header>
<main>
 <div id=viewFlujo><div class="row" style="margin:6px 0 12px;gap:6px;align-items:center;flex-wrap:wrap"><span class=muted style="font-size:13px">Periodo:</span><button class="b s perBtn" data-d="15" onclick="setPeriodo(15)">15 dias</button><button class="b s perBtn" data-d="30" onclick="setPeriodo(30)">30 dias</button><button class="b s perBtn" data-d="60" onclick="setPeriodo(60)">60 dias</button><button class="b s perBtn" data-d="" onclick="setPeriodo(0)" style="background:#2563eb;color:#fff">Todos</button></div>
  <div class=card id=necCardWrap>
   <h2>Necesidad de reclutamiento por empresa</h2>
   <div class="grid nec" id=necCards></div>
  </div>
  <div class=card id=admReqWrap style="display:none">
   <h2>Requerimientos de personal administrativo</h2>
   <div class="row perm-recluta" style="margin-bottom:10px">
    <input id=apPuesto placeholder="Puesto (ej. Mecanico A)" style="min-width:200px">
    <input id=apReq type=number value="1" style="width:90px" title="Requeridos">
    <button class="b g" onclick="admReqSet()">Agregar / actualizar</button>
   </div>
   <div class="grid nec" id=admReqCards></div>
  </div>
  <div class=card>
   <h2>Alta de candidato</h2>
   <div class=row>
    <select id=cEmpresa></select>
    <input id=cNombre placeholder="Nombre del candidato" style="min-width:200px">
    <input id=cTel placeholder="Telefono">
    <select id=cOrigen></select>
    <input id=cPuesto placeholder="Puesto (opcional)" style="min-width:150px">
    <input id=cNotas placeholder="Notas (opcional)" style="min-width:160px">
    <button class="b g perm-recluta" onclick="candAdd()">Agregar candidato</button>
   </div>
  </div>
  <div class=card>
   <h2 id=tituloPipeline>Pipeline de candidatos</h2>
   <div class=scroll>
    <table id=tblCand><thead><tr>
     <th class=sorth data-k="candidato" onclick="sortCand('candidato')" style="cursor:pointer;user-select:none">Candidato<span class=ar></span></th><th class=sorth data-k="telefono" onclick="sortCand('telefono')" style="cursor:pointer;user-select:none">Telefono<span class=ar></span></th><th class=sorth data-k="empresa" onclick="sortCand('empresa')" style="cursor:pointer;user-select:none">Empresa<span class=ar></span></th><th class=sorth data-k="origen" onclick="sortCand('origen')" style="cursor:pointer;user-select:none">Origen<span class=ar></span></th><th>Puesto</th>
     <th class=sorth data-k="status" onclick="sortCand('status')" style="cursor:pointer;user-select:none">Status<span class=ar></span></th><th class=sorth data-k="dias" onclick="sortCand('dias')" style="cursor:pointer;user-select:none">Dias<span class=ar></span></th><th class=sorth data-k="diascontr" onclick="sortCand('diascontr')" style="cursor:pointer;user-select:none">Dias a contratacion<span class=ar></span></th><th>Acciones</th></tr></thead>
     <tbody id=candBody></tbody></table>
   </div>
  </div>
 </div>

 <!-- ===================== CONDUCTORES ===================== -->
 <div id=viewCond class=hide>
  <div class="grid kpis" id=condCounts></div>
  <div class=card>
   <h2>Conductores activos</h2>
   <div class="row perm-rh" style="margin-bottom:10px">
    <select id=dEmpresa></select>
    <input id=dNombre placeholder="Nombre del conductor" style="min-width:200px">
    <input id=dTel placeholder="Telefono">
    <button class="b g" onclick="condAdd()">Dar de alta conductor</button>
   </div>
   <input id=condFilter type=search oninput="filtrarCond()" placeholder="Buscar operador por nombre, telefono o empresa..." style="margin-bottom:10px;width:100%;max-width:420px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px">
   <div class=scroll>
    <table id=tblCond><thead><tr>
     <th>Conductor</th><th>Telefono</th><th>Empresa</th><th>Acciones</th></tr></thead>
     <tbody id=condBody></tbody></table>
   </div>
  </div>
  <div class=card>
   <h2>Historico de bajas</h2>
   <div class=scroll>
    <table id=tblBajas><thead><tr>
     <th>Conductor</th><th>Empresa</th><th>Motivo de baja</th><th>Fecha baja</th><th>Acciones</th></tr></thead>
     <tbody id=bajasBody></tbody></table>
   </div>
  </div>
 </div>
 <div id=viewDash class=hide><div class="row" style="margin:6px 0 12px;gap:6px;align-items:center;flex-wrap:wrap"><span class=muted style="font-size:13px">Periodo:</span><button class="b s perBtn" data-d="15" onclick="setPeriodo(15)">15 dias</button><button class="b s perBtn" data-d="30" onclick="setPeriodo(30)">30 dias</button><button class="b s perBtn" data-d="60" onclick="setPeriodo(60)">60 dias</button><button class="b s perBtn" data-d="" onclick="setPeriodo(0)" style="background:#2563eb;color:#fff">Todos</button></div>
  <div class="grid kpis" id=kpiCards></div>
  <div class=two>
   <div class=card><h2>Embudo de reclutamiento</h2><div class=chartbox><canvas id=chEmbudo></canvas></div></div>
   <div class=card><h2>Origen del reclutamiento</h2><div class=chartbox><canvas id=chOrigen></canvas></div></div>
  </div>
  <div class=two>
   <div class=card><h2>Motivos de rechazo de candidatos</h2><div class=chartbox><canvas id=chRech></canvas></div></div>
   <div class=card id=cardBaja><h2>Motivos de baja de conductores</h2><div class=chartbox><canvas id=chBaja></canvas></div></div>
  </div>
 </div>
 <div id=modalUsr style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:99;align-items:center;justify-content:center">
  <div style="background:#fff;color:#0f172a;max-width:560px;width:92%;max-height:90vh;overflow:auto;border-radius:12px;padding:18px">
   <h3 style="margin:0 0 10px">Usuarios y accesos</h3>
   <div class=row style="margin-bottom:10px">
    <input id=uUser placeholder=Usuario><input id=uNom placeholder=Nombre>
    <select id=uRol></select><input id=uPass placeholder=Contrasena>
    <button class="b g" onclick="usrAdd()">Crear</button>
   </div>
   <table><thead><tr><th>Usuario</th><th>Nombre</th><th>Rol</th><th></th></tr></thead><tbody id=usrBody></tbody></table>
   <div style="text-align:right;margin-top:12px"><button class="b s" onclick="cerrarUsuarios()">Cerrar</button></div>
  </div>
 </div>
</main>
<script>
var ME=null, CAT=null, _ch={}, TIPO='conductor';
function aplicarTipoUI(){
 var adm=(TIPO==='administrativo');
 var nec=document.getElementById('necCardWrap'); if(nec) nec.style.display=adm?'none':'';
 var ar=document.getElementById('admReqWrap'); if(ar) ar.style.display=adm?'':'none';
 var hb=document.getElementById('cardBaja'); if(hb) hb.style.display=adm?'none':'';
 var t1=document.getElementById('tituloPipeline'); if(t1) t1.textContent=adm?'Pipeline de candidatos administrativos':'Pipeline de candidatos';
 if(adm) cargarPlantillaAdm();
}
function _esc(s){var d=document.createElement('div');d.textContent=(s==null?'':s);return d.innerHTML;}
function _niv(r){return ({'RH':1,'Reclutador':1,'Administrador':3})[r]||0;}
var COLORS=['#2563eb','#16a34a','#f59e0b','#dc2626','#7c3aed','#0891b2','#db2777','#65a30d','#475569'];
var STATUS_COLOR={'Contactado':'#64748b','Entrevista operaciones':'#0891b2','Documentos recibidos':'#6366f1',
  'Documentos validados':'#7c3aed','Citado':'#f59e0b','Contratado':'#16a34a','Rechazado':'#dc2626'};
async function boot(){
 try{ ME=await (await fetch('/api/me',{cache:'no-store'})).json(); }catch(e){}
 if(!ME||!ME.usuario){ location.href='/login'; return; }
 CAT=await (await fetch('/api/catalogos',{cache:'no-store'})).json();
 document.getElementById('userBox').textContent='\\uD83D\\uDC64 '+ME.nombre+' ('+ME.rol+')';
 fillSel('fEmpresa', CAT.empresas, true);
 fillSel('cEmpresa', CAT.empresas);
 fillSel('dEmpresa', CAT.empresas);
 fillSel('cOrigen', CAT.origenes);
 fillSel('uRol', CAT.roles);
 permisos();
 recargar();
}
function fillSel(id, arr, conTodas){
 var s=document.getElementById(id); if(!s) return;
 var keep = (id==='fEmpresa');
 s.innerHTML = (keep?'<option value="">Todas las empresas</option>':'') + arr.map(function(x){return '<option>'+_esc(x)+'</option>';}).join('');
}
function permisos(){
 var n=_niv(ME.rol);
 document.querySelectorAll('.perm-admin').forEach(function(e){e.style.display=(n>=3?'':'none');});
 document.querySelectorAll('.perm-recluta').forEach(function(e){e.style.display=((ME.rol==='Reclutador'||n>=3)?'':'none');});
 document.querySelectorAll('.perm-rh').forEach(function(e){e.style.display=((ME.rol==='RH'||ME.rol==='Reclutador'||n>=3)?'':'none');});
}
function showTab(w){
 var isFlujo=(w==='flujo'||w==='flujoAdm'), isDash=(w==='dash'||w==='dashAdm');
 document.getElementById('viewFlujo').classList.toggle('hide', !isFlujo);
 document.getElementById('viewCond').classList.toggle('hide', w!=='cond');
 document.getElementById('viewDash').classList.toggle('hide', !isDash);
 document.getElementById('tabFlujo').classList.toggle('on', w==='flujo');
 document.getElementById('tabCond').classList.toggle('on', w==='cond');
 document.getElementById('tabDash').classList.toggle('on', w==='dash');
 document.getElementById('tabFlujoAdm').classList.toggle('on', w==='flujoAdm');
 document.getElementById('tabDashAdm').classList.toggle('on', w==='dashAdm');
 if(isFlujo){ TIPO=(w==='flujoAdm')?'administrativo':'conductor'; aplicarTipoUI(); cargarPlantilla(); cargarCand(); }
 if(w==='cond') cargarCond();
 if(isDash){ TIPO=(w==='dashAdm')?'administrativo':'conductor'; aplicarTipoUI(); cargarDash(); }
}
function emp(){ return document.getElementById('fEmpresa').value; }
async function recargar(){ await cargarPlantilla(); await cargarCand(); await cargarCond();
 if(!document.getElementById('viewDash').classList.contains('hide')) cargarDash(); }
async function salir(){ await fetch('/api/logout',{method:'POST'}); location.href='/login'; }
async function cargarPlantilla(){
 var pl=await (await fetch('/api/plantilla',{cache:'no-store'})).json();
 var admin=_niv(ME.rol)>=3;
 document.getElementById('necCards').innerHTML = pl.map(function(p){
  var cls = p.necesidad>0?'n':'n ok';
  var edit = admin? '<div class=row style="margin-top:8px">'
     +'<input type=number style="width:90px" id="req_'+p.empresa+'" value="'+p.requerida+'" title="Requerida">'
     +'<input type=number style="width:90px;background:#f1f5f9;color:#64748b" id="act_'+p.empresa+'" value="'+p.actual+'" title="Activos (automatico)" readonly>'
     +'<button class="b" onclick="plantSet(\\''+p.empresa+'\\')">Guardar</button></div>':'';
  return '<div class=kpi><div style="font-weight:700;font-size:15px">'+_esc(p.empresa)+'</div>'
   +'<div class="'+cls+'">'+p.necesidad+'</div>'
   +'<div class=l>Necesidad &nbsp; (Requerida '+p.requerida+' &minus; Activos '+p.actual+')</div>'
   +edit+'</div>';
 }).join('');
}
async function plantSet(e){
 var req=document.getElementById('req_'+e).value, act=document.getElementById('act_'+e).value;
 await fetch('/api/plantilla/set',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({empresa:e,requerida:req,actual:act})});
 cargarPlantilla();
}
async function cargarPlantillaAdm(){
 var pl=await (await fetch('/api/plantilla_adm',{cache:'no-store'})).json();
 var puede=(ME.rol==='Reclutador'||_niv(ME.rol)>=3);
 var el=document.getElementById('admReqCards'); if(!el) return;
 el.innerHTML = (pl||[]).map(function(p){
  var cls=p.necesidad>0?'n':'n ok';
  var del=puede?'<button class="b r" style="padding:3px 8px;margin-top:8px" onclick="admReqDel(\''+encodeURIComponent(p.puesto)+'\')">Eliminar</button>':'';
  return '<div class=kpi><div style="font-weight:700;font-size:15px">'+_esc(p.puesto)+'</div>'
   +'<div class="'+cls+'">'+p.necesidad+'</div>'
   +'<div class=l>Necesidad &nbsp; (Requeridos '+p.requerida+' &minus; Contratados '+p.actual+')</div>'+del+'</div>';
 }).join('') || '<div class=muted>Sin requerimientos. Agrega un puesto arriba.</div>';
}
async function admReqSet(){
 var pu=document.getElementById('apPuesto').value.trim(), req=document.getElementById('apReq').value||0;
 if(!pu){ alert('Escribe el puesto.'); return; }
 var r=await fetch('/api/plantilla_adm/set',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({puesto:pu,requerida:req})});
 var j=await r.json(); if(!j.ok){ alert(j.error||'No se pudo.'); return; }
 document.getElementById('apPuesto').value=''; document.getElementById('apReq').value='1';
 cargarPlantillaAdm();
}
async function admReqDel(pu){ if(!confirm('Eliminar el requerimiento?'))return;
 await fetch('/api/plantilla_adm/del',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({puesto:decodeURIComponent(pu)})}); cargarPlantillaAdm(); }
async function candAdd(){
 var b={empresa:document.getElementById('cEmpresa').value,nombre:document.getElementById('cNombre').value.trim(),
   telefono:document.getElementById('cTel').value.trim(),origen:document.getElementById('cOrigen').value,
   notas:document.getElementById('cNotas').value.trim(),tipo:TIPO,puesto:(document.getElementById('cPuesto')?document.getElementById('cPuesto').value.trim():'')};
 if(!b.nombre||!b.telefono){ alert('Captura nombre y telefono.'); return; }
 var r=await fetch('/api/candidatos/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
 var j=await r.json(); if(!j.ok){ alert('No se pudo (requiere rol Reclutador).'); return; }
 document.getElementById('cNombre').value='';document.getElementById('cTel').value='';document.getElementById('cNotas').value='';var _cp=document.getElementById('cPuesto');if(_cp)_cp.value='';
 cargarCand();
}
function candKeyVal(c,k){
 if(k=="candidato") return (c.nombre||"").toLowerCase();
 if(k=="telefono") return (c.telefono||"").toLowerCase();
 if(k=="empresa") return (c.empresa||"").toLowerCase();
 if(k=="origen") return (c.origen||"").toLowerCase();
 if(k=="status") return (c.status||"").toLowerCase();
 if(k=="dias"){ var f=(c.status=="Contratado"&&c.fecha_contratado)?c.fecha_contratado:null; var v=_dias(c.creado,f); return (v==null?Number.POSITIVE_INFINITY:v); }
 if(k=="diascontr"){ var v=(c.fecha_contratado)?_dias(c.creado,c.fecha_contratado):null; return (v==null?Number.POSITIVE_INFINITY:v); }
 return "";
}
async function sortCand(k){
 var s=window._CANDSORT||{key:null,dir:1};
 if(s.key===k) s.dir=-s.dir; else { s.key=k; s.dir=1; }
 window._CANDSORT=s;
 await cargarCand();
 document.querySelectorAll("#tblCand thead .ar").forEach(function(e){e.textContent="";});
 var el=document.querySelector('#tblCand thead th[data-k="'+k+'"] .ar');
 if(el) el.textContent = s.dir>0?" \u25B2":" \u25BC";
}
window._PERIODO='';
function _qs(){ var p=[]; var e=emp(); if(e) p.push('empresa='+encodeURIComponent(e)); if(window._PERIODO) p.push('dias='+window._PERIODO); if(TIPO) p.push('tipo='+encodeURIComponent(TIPO)); return p.length?('?'+p.join('&')):''; }
function setPeriodo(d){ window._PERIODO=(d||'')+''; var key=(d||'')+''; document.querySelectorAll('.perBtn').forEach(function(b){ var on=(b.getAttribute('data-d')===key); b.style.background=on?'#2563eb':''; b.style.color=on?'#fff':''; }); cargarCand(); if(!document.getElementById('viewDash').classList.contains('hide')) cargarDash(); }
async function cargarCand(){
 var q=_qs();
 var arr=await (await fetch('/api/candidatos'+q,{cache:'no-store'})).json();
 window._CANDS=arr;
 if(window._CANDSORT && window._CANDSORT.key){ var _s=window._CANDSORT;
  arr=arr.slice().sort(function(a,b){ var va=candKeyVal(a,_s.key), vb=candKeyVal(b,_s.key);
   var r=(typeof va=="number"&&typeof vb=="number")?(va-vb):String(va).localeCompare(String(vb)); return r*_s.dir; }); }
 var puede=(ME.rol==='Reclutador'||_niv(ME.rol)>=3), admin=_niv(ME.rol)>=3;
 document.getElementById('candBody').innerHTML = arr.map(function(c){
  var col=STATUS_COLOR[c.status]||'#64748b';
  var dias=_dias(c.creado, (c.status==='Contratado'&&c.fecha_contratado)?c.fecha_contratado:null);
  var diasContr=(c.fecha_contratado)?_dias(c.creado, c.fecha_contratado):null;
  var pill='<span class=pill style="background:'+col+'">'+_esc(c.status)+'</span>';
  if(c.status==='Rechazado'&&c.motivo_rechazo) pill+=' <span class=muted style="font-size:11px">'+_esc(c.motivo_rechazo)+'</span>';
  var acc='';
  if(puede){
   acc='<select onchange="candStatus('+c.id+',this)" style="font-size:12px">'
     +CAT.statuses.map(function(s){return '<option'+(s===c.status?' selected':'')+'>'+_esc(s)+'</option>';}).join('')+'</select>';
  }
  if(puede) acc+=' <button class="b s" style="padding:4px 8px" onclick="candNota('+c.id+')" title="Editar observacion">&#9998;</button>';
  if(admin) acc+=' <button class="b r" style="padding:4px 8px" onclick="candDel('+c.id+')">&#10005;</button>';
  return '<tr><td><b>'+_esc(c.nombre)+'</b>'+(c.notas?'<div class=muted style="font-size:11px">'+_esc(c.notas)+(c.notas_actualizado?' <span style="color:#94a3b8">(ed. '+String(c.notas_actualizado).slice(0,16).replace('T',' ')+')</span>':'')+'</div>':'')+'</td>'
   +'<td>'+_esc(c.telefono||'')+'</td><td>'+_esc(c.empresa)+'</td><td>'+_esc(c.origen||'')+'</td><td>'+_esc(c.puesto||'')+'</td>'
   +'<td>'+pill+'</td><td>'+(dias==null?'-':dias)+'</td><td>'+(diasContr==null?'—':diasContr)+'</td><td style="white-space:nowrap">'+acc+'</td></tr>';
 }).join('') || '<tr><td colspan=9 class=muted>Sin candidatos aun.</td></tr>';
}
async function candStatus(id, sel){
 var status=sel.value, motivo=null;
 if(status==='Rechazado'){
  motivo=prompt('Motivo de rechazo:\\n'+CAT.motivos_rechazo.map(function(m,i){return (i+1)+') '+m;}).join('\\n')+'\\n\\nEscribe el numero o el texto:');
  if(motivo==null){ cargarCand(); return; }
  var n=parseInt(motivo,10); if(!isNaN(n)&&CAT.motivos_rechazo[n-1]) motivo=CAT.motivos_rechazo[n-1];
 }
 await fetch('/api/candidatos/status',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({id:id,status:status,motivo_rechazo:motivo})});
 if(status==='Contratado' && TIPO==='conductor'){
  var cc=(window._CANDS||[]).find(function(x){return x.id==id;});
  if(cc && confirm('El candidato '+cc.nombre+' paso a Contratado. Agregarlo a conductores activos de '+cc.empresa+'?')){
   var rr=await fetch('/api/conductores/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({empresa:cc.empresa, nombre:cc.nombre, telefono:cc.telefono||''})});
   var jj=await rr.json();
   if(jj&&jj.ok){ alert(cc.nombre+' agregado a conductores activos.'); } else { alert((jj&&jj.error)||'No se pudo agregar (quiza ya existe).'); }
  }
 }
 cargarCand();
}
window.candNota=function(id){
 var c=(window._CANDS||[]).find(function(x){return x.id==id;});
 var actual=c?(c.notas||''):'';
 var nota=prompt('Ultima observacion del candidato:', actual);
 if(nota===null) return;
 fetch('/api/candidatos/editar',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id, notas:nota})}).then(function(r){return r.json();}).then(function(j){ if(j&&j.ok===false){alert(j.error||'No se pudo (requiere rol Reclutador).');} cargarCand(); });
};
async function candDel(id){ if(!confirm('Eliminar candidato?'))return;
 await fetch('/api/candidatos/del',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})}); cargarCand(); }
async function condAdd(){
 var b={empresa:document.getElementById('dEmpresa').value,nombre:document.getElementById('dNombre').value.trim(),
   telefono:document.getElementById('dTel').value.trim()};
 if(!b.nombre){ alert('Captura el nombre.'); return; }
 var r=await fetch('/api/conductores/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
 var j=await r.json(); if(!j.ok){ alert('No se pudo (requiere rol RH).'); return; }
 document.getElementById('dNombre').value='';document.getElementById('dTel').value='';
 cargarCond();
}
function filtrarCond(){
 var f=document.getElementById("condFilter"); if(!f) return;
 var q=(f.value||"").toLowerCase().trim();
 var rows=document.querySelectorAll("#condBody tr");
 rows.forEach(function(tr){ var t=(tr.textContent||"").toLowerCase(); tr.style.display=(!q||t.indexOf(q)>=0)?"":"none"; });
}
async function cargarCond(){
 var q=_qs();
 var arr=await (await fetch('/api/conductores'+q,{cache:'no-store'})).json();
 window._CONDS=arr;
 var rh=(ME.rol==='RH'||ME.rol==='Reclutador'||_niv(ME.rol)>=3), admin=_niv(ME.rol)>=3;
 var activos=(arr||[]).filter(function(c){return c.activo;});
 var bajas=(arr||[]).filter(function(c){return !c.activo;});
 document.getElementById('condBody').innerHTML = activos.map(function(c){
  var acc='';
  if(rh) acc='<button class="b r" style="padding:4px 8px" onclick="condBaja('+c.id+')">Dar de baja</button>';
  if(rh) acc+=' <button class="b s" style="padding:4px 8px" onclick="condCambiar('+c.id+')">Cambiar compania</button>';
  if(admin) acc+=' <button class="b r" style="padding:4px 8px" onclick="condDel('+c.id+')">&#10005;</button>';
  return '<tr><td><b>'+_esc(c.nombre)+'</b></td><td>'+_esc(c.telefono||'')+'</td><td>'+_esc(c.empresa)+'</td><td style="white-space:nowrap">'+acc+'</td></tr>';
 }).join('') || '<tr><td colspan=4 class=muted>Sin conductores activos.</td></tr>';
 filtrarCond();
 document.getElementById('bajasBody').innerHTML = bajas.map(function(c){
  var acc='';
  if(rh) acc='<button class="b s" style="padding:4px 8px" onclick="condReact('+c.id+')">Reactivar</button>';
  if(admin) acc+=' <button class="b r" style="padding:4px 8px" onclick="condDel('+c.id+')">&#10005;</button>';
  var fb=(c.fecha_baja||'').slice(0,10);
  return '<tr><td>'+_esc(c.nombre)+'</td><td>'+_esc(c.empresa)+'</td><td>'+_esc(c.motivo_baja||'')+'</td><td>'+_esc(fb)+'</td><td style="white-space:nowrap">'+acc+'</td></tr>';
 }).join('') || '<tr><td colspan=5 class=muted>Sin bajas registradas.</td></tr>';
 try{
  var all=await (await fetch('/api/conductores',{cache:'no-store'})).json();
  var allAct=(all||[]).filter(function(c){return c.activo;});
  var total=allAct.length;
  var nC=allAct.filter(function(c){return c.empresa==='Cryogenics';}).length;
  var nT=allAct.filter(function(c){return c.empresa==='TNIR';}).length;
  function pct(n){return total? Math.round(n/total*100):0;}
  document.getElementById('condCounts').innerHTML =
    '<div class=kpi><div class=v style="color:#0891b2">'+nC+' <span style="font-size:15px;color:#64748b">('+pct(nC)+'%)</span></div><div class=l>Activos Cryogenics</div></div>'
   +'<div class=kpi><div class=v style="color:#2563eb">'+nT+' <span style="font-size:15px;color:#64748b">('+pct(nT)+'%)</span></div><div class=l>Activos TNIR</div></div>';
 }catch(e){}
}
async function condBaja(id){
 var motivo=prompt('Motivo de baja:\\n'+CAT.motivos_baja.map(function(m,i){return (i+1)+') '+m;}).join('\\n')+'\\n\\nEscribe el numero o el texto:');
 if(motivo==null) return;
 var n=parseInt(motivo,10); if(!isNaN(n)&&CAT.motivos_baja[n-1]) motivo=CAT.motivos_baja[n-1];
 await fetch('/api/conductores/baja',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,motivo:motivo})});
 cargarCond();
}
async function condReact(id){ await fetch('/api/conductores/reactivar',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})}); cargarCond(); }
async function condCambiar(id){
 var c=(window._CONDS||[]).find(function(x){return x.id==id;});
 var actual=c?c.empresa:''; var destino=(actual==='Cryogenics')?'TNIR':'Cryogenics';
 if(!confirm('Cambiar a '+(c?c.nombre:'este conductor')+' de '+actual+' a '+destino+'?')) return;
 var r=await fetch('/api/conductores/cambiar_empresa',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})});
 var j=await r.json(); if(!j.ok){ alert(j.error||'No se pudo.'); return; }
 cargarCond(); cargarPlantilla();
}
async function condDel(id){ if(!confirm('Eliminar conductor del padron?'))return;
 await fetch('/api/conductores/del',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})}); cargarCond(); }
async function cargarDash(){
 var q=_qs();
 var s=await (await fetch('/api/stats'+q,{cache:'no-store'})).json();
 var tc=(s.tiempo_conversion_dias==null?'-':s.tiempo_conversion_dias+' d');
 var bp=s.baja_principal?(s.baja_principal.motivo+' ('+s.baja_principal.n+')'):'-';
 var cards=[
  ['Candidatos contactados', s.contactados, '#2563eb'],
  ['Tasa de conversion', s.tasa_conversion+'%', '#16a34a'],
  ['Tiempo de conversion', tc, '#7c3aed'],
  ['Contratados', s.contratados, '#16a34a'],
  ['En proceso', s.en_proceso, '#f59e0b'],
  ['Rechazados', s.rechazados, '#dc2626']
 ];
 if(TIPO==='conductor'){ cards.push(['Conductores activos', s.conductores_activos, '#0891b2']); cards.push(['Bajas', s.bajas_total, '#dc2626']); cards.push(['Motivo principal de baja', bp, '#475569']); }
 document.getElementById('kpiCards').innerHTML = cards.map(function(c){
  return '<div class=kpi><div class=v style="color:'+c[2]+'">'+_esc(c[1])+'</div><div class=l>'+_esc(c[0])+'</div></div>';
 }).join('');
 barChart('chEmbudo', s.embudo.map(function(x){return x.status;}).concat(['Rechazado']), s.embudo.map(function(x){return x.n;}).concat([s.rechazados]), s.embudo.map(function(){return '#2563eb';}).concat(['#dc2626']));
 dough('chOrigen', s.origenes);
 dough('chRech', s.rechazos_motivos);
 barChart('chBaja', Object.keys(s.bajas_motivos), Object.values(s.bajas_motivos), '#dc2626');
}
function _destroy(id){ if(_ch[id]){ _ch[id].destroy(); delete _ch[id]; } }
function barChart(id, labels, data, color){
 var cv=document.getElementById(id); if(!cv) return; _destroy(id);
 _ch[id]=new Chart(cv,{type:'bar',data:{labels:labels,datasets:[{data:data,backgroundColor:color}]},
  options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
   scales:{y:{beginAtZero:true,ticks:{precision:0}}}}});
}
function dough(id, obj){
 var cv=document.getElementById(id); if(!cv) return; _destroy(id);
 var labels=Object.keys(obj), data=Object.values(obj);
 _ch[id]=new Chart(cv,{type:'doughnut',data:{labels:labels,datasets:[{data:data,backgroundColor:COLORS}]},
  options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{boxWidth:12,font:{size:11}}}}}});
}
async function abrirUsuarios(){ document.getElementById('modalUsr').style.display='flex'; cargarUsuarios(); }
function cerrarUsuarios(){ document.getElementById('modalUsr').style.display='none'; }
async function cargarUsuarios(){
 var arr=await (await fetch('/api/usuarios',{cache:'no-store'})).json();
 document.getElementById('usrBody').innerHTML=(arr||[]).map(function(u){
  return '<tr><td>'+_esc(u.usuario)+'</td><td>'+_esc(u.nombre)+'</td><td>'+_esc(u.rol)+'</td>'
   +'<td><button class="b r" style="padding:3px 7px" onclick="usrDel(\\''+u.usuario+'\\')">&#10005;</button></td></tr>';
 }).join('');
}
async function usrAdd(){
 var b={usuario:document.getElementById('uUser').value.trim(),nombre:document.getElementById('uNom').value.trim(),
   rol:document.getElementById('uRol').value,password:document.getElementById('uPass').value};
 if(!b.usuario||!b.password){ alert('Usuario y contrasena requeridos.'); return; }
 var r=await fetch('/api/usuarios/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
 var j=await r.json(); if(!j.ok){ alert(j.error||'No se pudo crear.'); return; }
 document.getElementById('uUser').value='';document.getElementById('uNom').value='';document.getElementById('uPass').value='';
 cargarUsuarios();
}
async function usrDel(u){ if(!confirm('Eliminar usuario '+u+'?'))return;
 await fetch('/api/usuarios/del',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({usuario:u})}); cargarUsuarios(); }
function _dias(a,b){ try{ var da=new Date(a); var db=b?new Date(b):new Date();
  return Math.max(0, Math.round((db-da)/86400000)); }catch(e){ return null; } }
boot();
</script><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/gridstack@10.3.1/dist/gridstack.min.css">
<style>
.grid-stack-item-content{overflow:auto}
.grid-stack-item-content>.card{height:100%;margin:0;box-sizing:border-box}
body.gs-edit .gs-handle{cursor:move}
#gridbar{position:fixed;left:14px;bottom:14px;z-index:60;display:none;gap:8px}
#gridbar button{font:600 13px system-ui;padding:8px 12px;border-radius:8px;border:1px solid #cbd5e1;background:#fff;color:#0f172a;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.18)}
#gridbar button.act{background:#16a34a;color:#fff;border-color:#16a34a}
</style>
<script src="https://cdn.jsdelivr.net/npm/gridstack@10.3.1/dist/gridstack-all.js"></script>
<script>
(function(){var grid=null,done=false,editing=false;function gridify(){try{if(typeof GridStack==="undefined")return;var tab=document.getElementById("viewDash");if(!tab||tab.offsetParent===null||tab.querySelector(".grid-stack"))return;var cards=[].slice.call(tab.querySelectorAll(".card"));if(!cards.length)return;function slug(s){return (s||"").toLowerCase().normalize("NFD").replace(/[^a-z0-9]+/g,"-").replace(/(^-|-$)/g,"").slice(0,28);}var used={};var meta=cards.map(function(c,i){var head=c.querySelector("h1,h2,h3,h4");var id=slug(head?head.textContent:"")||("card-"+i);if(used[id])id=id+"-"+i;used[id]=1;var ratio=c.offsetWidth/(tab.clientWidth||1240);var w=Math.min(12,Math.max(3,Math.round(ratio*12)));var h=Math.max(2,Math.ceil((c.offsetHeight+16)/80));return {c:c,id:id,w:w,h:h,head:head};});var gridEl=document.createElement("div");gridEl.className="grid-stack";meta.forEach(function(m){var item=document.createElement("div");item.className="grid-stack-item";item.setAttribute("gs-w",m.w);item.setAttribute("gs-h",m.h);item.setAttribute("gs-id",m.id);var content=document.createElement("div");content.className="grid-stack-item-content";if(m.head)m.head.classList.add("gs-handle");content.appendChild(m.c);item.appendChild(content);gridEl.appendChild(item);});var kpis=tab.querySelector(".kpis");[].slice.call(tab.children).forEach(function(ch){if(ch===kpis||ch.tagName==="FOOTER"||ch.classList.contains("grid-stack"))return;if(ch.classList.contains("card")||ch.classList.contains("two")||ch.classList.contains("grid2")||ch.classList.contains("grid3")||!ch.querySelector(".card"))ch.remove();});if(kpis&&kpis.parentElement===tab)kpis.after(gridEl);else tab.insertBefore(gridEl,tab.firstChild);grid=GridStack.init({column:12,cellHeight:80,margin:8,float:false,disableDrag:true,disableResize:true,handle:".gs-handle"},gridEl);try{var saved=JSON.parse(localStorage.getItem("recl_grid_v1")||"null");if(saved&&saved.length){saved.forEach(function(n){var el=gridEl.querySelector('[gs-id="'+n.id+'"]');if(el)grid.update(el,{x:n.x,y:n.y,w:n.w,h:n.h});});}}catch(e){}grid.on("change",function(){try{localStorage.setItem("recl_grid_v1",JSON.stringify(grid.save(false)));}catch(e){}});grid.on("resizestop",function(ev,el){try{var cv=el.querySelector("canvas");if(cv&&window.Chart&&Chart.getChart){var ch=Chart.getChart(cv);if(ch)ch.resize();}}catch(e){}});var bar=document.createElement("div");bar.id="gridbar";var bE=document.createElement("button");bE.textContent="Editar acomodo";var bR=document.createElement("button");bR.textContent="Restablecer";bar.appendChild(bE);bar.appendChild(bR);document.body.appendChild(bar);bE.onclick=function(){editing=!editing;grid.enableMove(editing);grid.enableResize(editing);document.body.classList.toggle("gs-edit",editing);bE.classList.toggle("act",editing);bE.textContent=editing?"Listo":"Editar acomodo";};bR.onclick=function(){try{localStorage.removeItem("recl_grid_v1");}catch(e){}location.reload();};done=true;}catch(e){}}setInterval(function(){try{if(!done)gridify();var bar=document.getElementById("gridbar");var vd=document.getElementById("viewDash");if(bar&&vd)bar.style.display=(vd.offsetParent!==null)?"flex":"none";}catch(e){}},600);})();
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _cookie_sesion(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith("recl_sess="):
                return part[len("recl_sess="):]
        return None

    def _usuario(self):
        return _leer_sesion(self._cookie_sesion())

    def _send(self, code, body, ctype="application/json; charset=utf-8", cookie=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        qs = {}
        if "?" in self.path:
            for kv in self.path.split("?", 1)[1].split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    from urllib.parse import unquote_plus
                    qs[k] = unquote_plus(v)
        u = self._usuario()
        if path == "/login":
            return self._send(200, LOGIN_HTML, "text/html; charset=utf-8")
        if path == "/":
            if not u:
                return self._send(200, LOGIN_HTML, "text/html; charset=utf-8")
            return self._send(200, app_html(), "text/html; charset=utf-8")
        if path == "/api/me":
            return self._json(u or {})
        if path == "/api/catalogos":
            return self._json({"empresas": db.EMPRESAS, "statuses": db.STATUSES,
                               "motivos_rechazo": db.MOTIVOS_RECHAZO,
                               "origenes": db.ORIGENES, "motivos_baja": db.MOTIVOS_BAJA,
                               "roles": db.ROLES})
        if not u:
            return self._json({"error": "no autorizado"}, 401)
        if path == "/api/plantilla":
            return self._json(db.plantilla_list())
        if path == "/api/plantilla_adm":
            return self._json(db.plantilla_adm_list())
        if path == "/api/candidatos":
            return self._json(db.candidatos_list(qs.get("empresa"), qs.get("dias"), qs.get("tipo")))
        if path == "/api/conductores":
            return self._json(db.conductores_list(qs.get("empresa")))
        if path == "/api/stats":
            return self._json(db.stats(qs.get("empresa"), qs.get("dias"), qs.get("tipo")))
        if path == "/api/usuarios":
            if not _puede(u["rol"], "Administrador"):
                return self._json({"error": "solo admin"}, 403)
            return self._json(db.usuarios_list())
        return self._json({"error": "no encontrado"}, 404)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        data = self._body()
        if path == "/api/login":
            r = db.usuario_login(str(data.get("usuario", "")).strip(),
                                 str(data.get("password", "")))
            if not r:
                return self._json({"ok": False, "error": "Usuario o contrasena incorrectos"})
            cookie = ("recl_sess=" + _firmar_sesion(r["usuario"], r["nombre"], r["rol"]) +
                      "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + str(86400 * 7))
            return self._send(200, json.dumps({"ok": True}),
                              "application/json; charset=utf-8", cookie)
        if path == "/api/logout":
            return self._send(200, json.dumps({"ok": True}),
                              "application/json; charset=utf-8",
                              "recl_sess=; Path=/; Max-Age=0")
        u = self._usuario()
        if not u:
            return self._json({"ok": False, "error": "no autorizado"}, 401)
        rol = u["rol"]

        def reclutador():
            return rol == "Reclutador" or _puede(rol, "Administrador")

        def rh():
            return rol == "RH" or _puede(rol, "Administrador")

        if path == "/api/plantilla/set":
            if not _puede(rol, "Administrador"):
                return self._json({"ok": False, "error": "solo admin"}, 403)
            db.plantilla_set(data.get("empresa"), data.get("requerida") or 0,
                             data.get("actual") or 0)
            return self._json({"ok": True})
        if path == "/api/plantilla_adm/set":
            if not (reclutador() or _puede(rol, "Administrador")):
                return self._json({"ok": False, "error": "solo reclutador/admin"}, 403)
            db.plantilla_adm_set(data.get("puesto"), data.get("requerida") or 0)
            return self._json({"ok": True})
        if path == "/api/plantilla_adm/del":
            if not (reclutador() or _puede(rol, "Administrador")):
                return self._json({"ok": False, "error": "solo reclutador/admin"}, 403)
            db.plantilla_adm_del(data.get("puesto"))
            return self._json({"ok": True})
        if path == "/api/candidatos/add":
            if not reclutador():
                return self._json({"ok": False, "error": "solo reclutador"}, 403)
            emp = data.get("empresa")
            if emp not in db.EMPRESAS:
                return self._json({"ok": False, "error": "empresa invalida"})
            db.candidato_add(emp, str(data.get("nombre", "")).strip(),
                             str(data.get("telefono", "")).strip(),
                             data.get("origen") or "", u["nombre"],
                             str(data.get("notas", "")).strip(),
                             data.get("tipo") or "conductor",
                             str(data.get("puesto", "")).strip())
            return self._json({"ok": True})
        if path == "/api/candidatos/status":
            if not reclutador():
                return self._json({"ok": False, "error": "solo reclutador"}, 403)
            ok = db.candidato_status(data.get("id"), data.get("status"),
                                     data.get("motivo_rechazo"), u["nombre"])
            return self._json({"ok": bool(ok)})
        if path == "/api/candidatos/editar":
            if not reclutador():
                return self._json({"ok": False, "error": "solo reclutador"}, 403)
            return self._json({"ok": bool(db.candidato_editar(data.get("id"), data))})
        if path == "/api/candidatos/del":
            if not _puede(rol, "Administrador"):
                return self._json({"ok": False, "error": "solo admin"}, 403)
            db.candidato_del(data.get("id"))
            return self._json({"ok": True})
        if path == "/api/conductores/add":
            if not (rh() or reclutador()):
                return self._json({"ok": False, "error": "solo RH"}, 403)
            emp = data.get("empresa")
            if emp not in db.EMPRESAS:
                return self._json({"ok": False, "error": "empresa invalida"})
            _cid = db.conductor_add(emp, str(data.get("nombre", "")).strip(),
                             str(data.get("telefono", "")).strip())
            if _cid is None:
                return self._json({"ok": False, "error": "ese conductor ya esta en la lista de activos"})
            return self._json({"ok": True})
        if path == "/api/conductores/baja":
            if not (rh() or reclutador()):
                return self._json({"ok": False, "error": "solo RH"}, 403)
            db.conductor_baja(data.get("id"), data.get("motivo") or "No especifico")
            return self._json({"ok": True})
        if path == "/api/conductores/reactivar":
            if not (rh() or reclutador()):
                return self._json({"ok": False, "error": "solo RH"}, 403)
            db.conductor_reactivar(data.get("id"))
            return self._json({"ok": True})
        if path == "/api/conductores/cambiar_empresa":
            if not (rh() or reclutador()):
                return self._json({"ok": False, "error": "solo RH"}, 403)
            _ne = db.conductor_cambiar_empresa(data.get("id"))
            if _ne is None:
                return self._json({"ok": False, "error": "no encontrado"})
            return self._json({"ok": True, "empresa": _ne})
        if path == "/api/conductores/del":
            if not _puede(rol, "Administrador"):
                return self._json({"ok": False, "error": "solo admin"}, 403)
            db.conductor_del(data.get("id"))
            return self._json({"ok": True})
        if path == "/api/usuarios/add":
            if not _puede(rol, "Administrador"):
                return self._json({"ok": False, "error": "solo admin"}, 403)
            usuario = str(data.get("usuario", "")).strip()
            if db.usuario_existe(usuario):
                return self._json({"ok": False, "error": "ese usuario ya existe"})
            if data.get("rol") not in db.ROLES:
                return self._json({"ok": False, "error": "rol invalido"})
            db.usuario_add(usuario, str(data.get("nombre", "")).strip() or usuario,
                           data.get("rol"), str(data.get("password", "")))
            return self._json({"ok": True})
        if path == "/api/usuarios/del":
            if not _puede(rol, "Administrador"):
                return self._json({"ok": False, "error": "solo admin"}, 403)
            db.usuario_del(data.get("usuario"))
            return self._json({"ok": True})
        return self._json({"ok": False, "error": "no encontrado"}, 404)


def main():
    db.init()
    log.info("Reclutamiento escuchando en puerto %s", PORT)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
X
