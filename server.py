"""Tablero de Reclutamiento de operadores."""
import os
import json
import hmac
import time
import base64
import hashlib
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from datetime import datetime

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
 <p>Control de operadores - Cryogenics, TNIR y Rasch Logistics</p>
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
<script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-datalabels@2.2.0/dist/chartjs-plugin-datalabels.min.js"></script>
<script>
(function(){
  if(!window.Chart || !window.ChartDataLabels) return;
  Chart.register(window.ChartDataLabels);
  Chart.defaults.set('plugins.datalabels', {
    display: function(c){ var t=c.chart.config.type; return (t==='bar'||t==='doughnut'||t==='pie'); },
    color: function(c){ if(c.chart.config.type!=='bar') return '#ffffff'; return (c.chart.data.datasets.length>1)?'#ffffff':'#334155'; },
    font: { weight: 'bold', size: 11 },
    anchor: function(c){ if(c.chart.config.type!=='bar') return 'center'; return (c.chart.data.datasets.length>1)?'center':'end'; },
    align: function(c){ if(c.chart.config.type!=='bar') return 'center'; return (c.chart.data.datasets.length>1)?'center':'end'; },
    clamp: true,
    formatter: function(value, ctx){
      var t=ctx.chart.config.type;
      if(t==='doughnut' || t==='pie'){
        var dsx=ctx.chart.data.datasets[ctx.datasetIndex] || {};
        var arr=dsx.data || [];
        var total=arr.reduce(function(a,b){return a+(Number(b)||0);},0);
        var v=Number(value)||0;
        if(!total || v<=0) return '';
        var pct=v/total*100;
        return pct<4 ? '' : Math.round(pct)+'%';
      }
      var n=Number(value);
      return (!n) ? '' : n;
    }
  });
})();
</script>
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
 /* La lista de conductores es la mas larga del tablero y se recorria en una
    ventanita de 420 px. Se le da casi toda la altura de la pantalla para que el
    scroll sea corto; el encabezado se queda fijo al desplazarse. */
 .scroll.alto{max-height:72vh}
 .scroll.alto thead th{position:sticky;top:0;background:#f1f5f9;z-index:1}
 /* Semaforo de las evaluaciones del periodo de prueba. */
 .ev{width:30px;height:28px;margin-right:4px;border-radius:7px;border:1px solid #cbd5e1;
     background:#f8fafc;color:#64748b;font-weight:700;cursor:pointer;font-size:13px}
 .ev:disabled{cursor:not-allowed;opacity:.55}
 .ev.pendiente{background:#f97316;border-color:#ea580c;color:#fff}
 .ev.rojo{background:#dc2626;border-color:#b91c1c;color:#fff}
 .ev.amarillo{background:#facc15;border-color:#eab308;color:#422006}
 .ev.verde{background:#16a34a;border-color:#15803d;color:#fff}
 .fcontrat{border:1px solid #cbd5e1;border-radius:6px;padding:3px 6px;font:inherit;width:140px}
 .toggle{border:1px solid #cbd5e1;background:#fff;color:#334155;border-radius:999px;
         padding:6px 14px;cursor:pointer;font:inherit;font-size:13px}
 .toggle.on{background:#1d4ed8;border-color:#1d4ed8;color:#fff;font-weight:600}
 .dias{font-size:11px;color:#64748b;display:block}
 .crit td{vertical-align:top;font-size:13px}
 .crit .op{display:block;cursor:pointer;padding:2px 0}
 .crit .op input{margin-right:5px}
 .califbox{font-size:26px;font-weight:800;padding:8px 14px;border-radius:10px;display:inline-block}
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
 <div id=viewFlujo><div class="row" style="margin:6px 0 12px;gap:6px;align-items:center;flex-wrap:wrap"><span class=muted style="font-size:13px">Periodo:</span><button class="b s perBtn" data-d="15" onclick="setPeriodo(15)">15 dias</button><button class="b s perBtn" data-d="30" onclick="setPeriodo(30)">30 dias</button><button class="b s perBtn" data-d="60" onclick="setPeriodo(60)">60 dias</button><button class="b s perBtn" data-d="" onclick="setPeriodo(0)" style="background:#2563eb;color:#fff">Todos</button><span class="muted" style="font-size:13px;margin-left:10px">o rango:</span><input type="date" class="fDesde" style="font-size:12px;padding:3px 6px"><span class="muted" style="font-size:12px">a</span><input type="date" class="fHasta" style="font-size:12px;padding:3px 6px"><button class="b s" onclick="setRango(this)">Aplicar</button><button class="b s" onclick="limpiarRango()">Limpiar</button></div>
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
   <div class=row style="margin-bottom:10px;gap:8px;align-items:center;flex-wrap:wrap">
    <input id=condFilter type=search oninput="filtrarCond()" placeholder="Buscar operador por nombre, telefono o empresa..." style="flex:1 1 280px;max-width:420px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px">
    <button id=btnPrueba class=toggle onclick="togglePrueba()"
     title="Deja solo a los que siguen dentro del periodo de prueba (menos de 90 dias), que son a los que hay que evaluar antes de decidir su contrato definitivo">&#9201; Solo periodo de prueba</button>
    <button id=btnUrgente class="toggle on" onclick="toggleUrgente()"
     title="Sube los que ya tienen una evaluacion vencida, el mas atrasado primero">&#8593; Pendientes de evaluar primero</button>
    <span id=condCuenta class=muted style="font-size:12px"></span>
   </div>
   <div class="scroll alto">
    <table id=tblCond><thead><tr>
     <th class=sorth onclick="sortTabla('tblCond',0,this)" style="cursor:pointer;user-select:none">Conductor<span class=ar></span></th><th class=sorth onclick="sortTabla('tblCond',1,this)" style="cursor:pointer;user-select:none">Telefono<span class=ar></span></th><th class=sorth onclick="sortTabla('tblCond',2,this)" style="cursor:pointer;user-select:none">Empresa<span class=ar></span></th><th class=sorth onclick="sortTabla('tblCond',3,this)" style="cursor:pointer;user-select:none">Fecha contratacion<span class=ar></span></th><th title="Tres evaluaciones durante el periodo de prueba, a los 25, 55 y 85 dias. Naranja = ya vencio y falta hacerla.">Evaluaciones de prueba</th><th>Acciones</th></tr></thead>
     <tbody id=condBody></tbody></table>
   </div>
   <div class=muted style="margin-top:8px;font-size:12px">
    Evaluaciones a los <b>25</b>, <b>55</b> y <b>85</b> dias &mdash; cinco antes de cada corte, para decidir el contrato con margen.
    <span class="ev pendiente" style="cursor:default">1</span> pendiente &middot;
    <span class="ev rojo" style="cursor:default">2</span> 0-49 &middot;
    <span class="ev amarillo" style="cursor:default">2</span> 50-69 &middot;
    <span class="ev verde" style="cursor:default">3</span> 70 o mas, listo para contrato definitivo.
   </div>
  </div>
  <div class=card>
   <h2>Historico de bajas</h2>
   <input id=bajasFilter type=search oninput="filtrarBajas()" placeholder="Buscar operador por nombre, empresa o motivo..." style="margin-bottom:10px;width:100%;max-width:420px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px">
   <div class=scroll>
    <table id=tblBajas><thead><tr>
     <th class=sorth onclick="sortTabla('tblBajas',0,this)" style="cursor:pointer;user-select:none">Conductor<span class=ar></span></th><th class=sorth onclick="sortTabla('tblBajas',1,this)" style="cursor:pointer;user-select:none">Empresa<span class=ar></span></th><th class=sorth onclick="sortTabla('tblBajas',2,this)" style="cursor:pointer;user-select:none">Motivo de baja<span class=ar></span></th><th class=sorth onclick="sortTabla('tblBajas',3,this)" style="cursor:pointer;user-select:none">Fecha baja<span class=ar></span></th><th>Acciones</th></tr></thead>
     <tbody id=bajasBody></tbody></table>
   </div>
  </div>
 </div>
 <div id=viewDash class=hide><div class="row" style="margin:6px 0 12px;gap:6px;align-items:center;flex-wrap:wrap"><span class=muted style="font-size:13px">Periodo:</span><button class="b s perBtn" data-d="15" onclick="setPeriodo(15)">15 dias</button><button class="b s perBtn" data-d="30" onclick="setPeriodo(30)">30 dias</button><button class="b s perBtn" data-d="60" onclick="setPeriodo(60)">60 dias</button><button class="b s perBtn" data-d="" onclick="setPeriodo(0)" style="background:#2563eb;color:#fff">Todos</button><span class="muted" style="font-size:13px;margin-left:10px">o rango:</span><input type="date" class="fDesde" style="font-size:12px;padding:3px 6px"><span class="muted" style="font-size:12px">a</span><input type="date" class="fHasta" style="font-size:12px;padding:3px 6px"><button class="b s" onclick="setRango(this)">Aplicar</button><button class="b s" onclick="limpiarRango()">Limpiar</button></div>
  <div class="grid kpis" id=kpiCards></div>
  <div class=two>
   <div class=card><h2>Embudo de reclutamiento</h2><div class=chartbox><canvas id=chEmbudo></canvas></div></div>
   <div class=card><h2>Origen del reclutamiento</h2><div class=chartbox><canvas id=chOrigen></canvas></div></div>
  </div>
  <div class=two>
   <div class=card><h2>Motivos de rechazo de candidatos</h2><div class=chartbox><canvas id=chRech></canvas></div></div>
   <div class=card id=cardBaja><h2>Motivos de baja de conductores</h2><div class=chartbox><canvas id=chBaja></canvas></div></div>
  </div>
  <div class=two id=rowOps>
   <div class=card><h2>Operadores contratados por semana</h2><div class=chartbox><canvas id=chOpSem></canvas></div></div>
   <div class=card><h2>Operadores contratados por reclutador</h2><div class=chartbox><canvas id=chOpRecl></canvas></div></div>
  </div>
 </div>
 <div id=modalEval style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:99;align-items:center;justify-content:center">
  <div style="background:#fff;color:#0f172a;max-width:820px;width:94%;max-height:92vh;overflow:auto;border-radius:12px;padding:18px">
   <h3 style="margin:0" id=evTitulo></h3>
   <div class=muted style="font-size:12px;margin:2px 0 12px" id=evSub></div>
   <div class=row style="margin-bottom:10px;gap:8px;flex-wrap:wrap">
    <input id=evJefe placeholder="Jefe inmediato" style="min-width:190px">
    <input id=evBase placeholder="Base">
    <input id=evPuesto placeholder="Puesto">
    <input id=evFecha type=date title="Fecha de realizacion">
   </div>
   <table style="width:100%;border-collapse:collapse" class=crit>
    <thead><tr><th style="text-align:left">Tema a evaluar</th><th style="text-align:left">Peso</th><th style="text-align:left">Puntaje</th></tr></thead>
    <tbody id=evCrit></tbody>
   </table>
   <div style="display:flex;align-items:center;gap:14px;margin:14px 0;flex-wrap:wrap">
    <span class=muted>Porcentaje de desempeno:</span>
    <span id=evCalif class=califbox>0%</span>
    <span id=evVeredicto style="font-weight:600"></span>
   </div>
   <label class=muted style="font-size:12px">Retroalimentacion sobre aspectos positivos</label>
   <textarea id=evPos rows=3 style="width:100%;margin-bottom:10px"></textarea>
   <label class=muted style="font-size:12px">Retroalimentacion sobre areas a desarrollar y compromisos</label>
   <textarea id=evAreas rows=3 style="width:100%"></textarea>
   <div style="text-align:right;margin-top:12px">
    <span id=evSoloLectura class=muted style="display:none;margin-right:10px;font-size:12px">Solo lectura: la captura el jefe de operaciones o RH.</span>
    <button class="b s" onclick="cerrarEval()">Cerrar</button>
    <button class="b g" id=evGuardar onclick="guardarEval()">Guardar evaluacion</button>
   </div>
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
  var del=puede?'<button class="b r" style="padding:3px 8px;margin-top:8px" onclick="admReqDel(\\''+encodeURIComponent(p.puesto)+'\\')">Eliminar</button>':'';
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
function _qs(){ var p=[]; var e=emp(); if(e) p.push('empresa='+encodeURIComponent(e)); if(window._DESDE||window._HASTA){ if(window._DESDE) p.push('desde='+window._DESDE); if(window._HASTA) p.push('hasta='+window._HASTA); } else if(window._PERIODO){ p.push('dias='+window._PERIODO); } if(TIPO) p.push('tipo='+encodeURIComponent(TIPO)); return p.length?('?'+p.join('&')):''; }
function setRango(btn){ var row=btn.closest('.row')||btn.parentNode; var d=(row.querySelector('.fDesde')||{}).value||''; var h=(row.querySelector('.fHasta')||{}).value||''; if(!d && !h) return; window._DESDE=d; window._HASTA=h; window._PERIODO=''; document.querySelectorAll('.fDesde').forEach(function(x){ x.value=d; }); document.querySelectorAll('.fHasta').forEach(function(x){ x.value=h; }); document.querySelectorAll('.perBtn').forEach(function(b){ b.style.background=''; b.style.color=''; }); cargarCand(); if(!document.getElementById('viewDash').classList.contains('hide')) cargarDash(); }
function limpiarRango(){ window._DESDE=''; window._HASTA=''; document.querySelectorAll('.fDesde').forEach(function(x){ x.value=''; }); document.querySelectorAll('.fHasta').forEach(function(x){ x.value=''; }); setPeriodo(0); }
function setPeriodo(d){ window._PERIODO=(d||'')+''; window._DESDE=''; window._HASTA=''; document.querySelectorAll('.fDesde').forEach(function(x){ x.value=''; }); document.querySelectorAll('.fHasta').forEach(function(x){ x.value=''; }); var key=(d||'')+''; document.querySelectorAll('.perBtn').forEach(function(b){ var on=(b.getAttribute('data-d')===key); b.style.background=on?'#2563eb':''; b.style.color=on?'#fff':''; }); cargarCand(); if(!document.getElementById('viewDash').classList.contains('hide')) cargarDash(); }
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
function sortTabla(tblId,colIdx,th){
 var tbl=document.getElementById(tblId); if(!tbl||!tbl.tBodies[0]) return;
 var tb=tbl.tBodies[0];
 var same=(tbl.getAttribute('data-sc')==String(colIdx));
 var dir=(same && tbl.getAttribute('data-sd')=='asc')?'desc':'asc';
 tbl.setAttribute('data-sc',String(colIdx)); tbl.setAttribute('data-sd',dir);
 var rows=[].slice.call(tb.rows).filter(function(r){return r.cells.length>colIdx;});
 rows.sort(function(a,b){
  var x=(a.cells[colIdx].textContent||'').trim();
  var y=(b.cells[colIdx].textContent||'').trim();
  var c=x.localeCompare(y,'es',{numeric:true,sensitivity:'base'});
  return dir=='asc'?c:-c;
 });
 rows.forEach(function(r){tb.appendChild(r);});
 var hs=th.parentNode.children; for(var i=0;i<hs.length;i++){var a=hs[i].querySelector('.ar'); if(a) a.textContent='';}
 var ar=th.querySelector('.ar'); if(ar) ar.textContent=dir=='asc'?' ▲':' ▼';
}
function filtrarBajas(){
 var f=document.getElementById('bajasFilter'); if(!f) return;
 var q=(f.value||'').toLowerCase().trim();
 var rows=document.querySelectorAll('#bajasBody tr');
 rows.forEach(function(tr){var t=(tr.textContent||'').toLowerCase(); tr.style.display=(!q||t.indexOf(q)>=0)?'':'none';});
}
function filtrarCond(){
 var f=document.getElementById("condFilter"); if(!f) return;
 var q=(f.value||"").toLowerCase().trim();
 var rows=document.querySelectorAll("#condBody tr");
 rows.forEach(function(tr){ var t=(tr.textContent||"").toLowerCase(); tr.style.display=(!q||t.indexOf(q)>=0)?"":"none"; });
}
/* Los tres botones del periodo de prueba, con su color.
   Gris: todavia no cumple ese mes, no hay nada que pedir. Naranja: ya vencio y
   falta hacerla. Rojo/amarillo/verde: ya esta hecha, con su calificacion. */
function botonesEval(c){
 var est=(c.prueba&&c.prueba.evaluaciones)||[];
 if(!est.length) return '';
 var puede=(ME.rol==='Jefe de operaciones'||ME.rol==='RH'||_niv(ME.rol)>=3);
 return est.map(function(e){
  var clase='ev '+(e.estado==='hecha'?e.color:(e.estado==='pendiente'?'pendiente':''));
  var tip;
  var dias=(c.prueba||{}).dias;
  if(e.estado==='hecha') tip='Evaluacion '+e.numero+' (dia '+e.dia+'): '+e.porcentaje+'% el '+(e.fecha||'');
  else if(e.estado==='pendiente') tip='Evaluacion '+e.numero+' PENDIENTE desde el dia '+e.dia
   +(dias!=null?' (lleva '+(dias-e.dia)+' dias de atraso)':'');
  else if(e.estado==='fuera_de_plazo') tip='Evaluacion '+e.numero+' (dia '+e.dia+'): no se hizo y el periodo de prueba ya cerro';
  else if(e.estado==='sin_fecha') tip='Falta capturar la fecha de contratacion';
  else tip='Evaluacion '+e.numero+': se pide a los '+e.dia+' dias'
   +(dias!=null?' (faltan '+(e.dia-dias)+')':'');
  // Se puede abrir siempre para consultarla; el boton de guardar es el que
  // respeta el rol. Asi RH lee la evaluacion del jefe sin poder alterarla.
  return '<button class="'+clase+'" title="'+_esc(tip)+'" onclick="abrirEval('+c.id+','+e.numero+')">'+e.numero+'</button>';
 }).join('');
}

async function condFecha(id, valor){
 var r=await fetch('/api/conductores/fecha_contratacion',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,fecha:valor||''})});
 var j=await r.json();
 if(!j.ok){ alert(j.error||'No se pudo guardar la fecha'); }
 // Se espera al refresco: sin esto la tabla podia quedar un instante con la fecha
 // vieja y los botones del color anterior, justo despues de capturarla.
 await cargarCond();
}

var _EVAL={cid:null,num:null};

async function abrirEval(cid, num){
 var c=(window._CONDS||[]).filter(function(x){return x.id===cid;})[0]||{};
 _EVAL={cid:cid,num:num};
 var prev=await (await fetch('/api/evaluacion?conductor_id='+cid+'&numero='+num,{cache:'no-store'})).json();
 var puntos=(prev&&prev.puntos)||{};
 var puede=(ME.rol==='Jefe de operaciones'||ME.rol==='RH'||_niv(ME.rol)>=3);
 var crit=(CAT&&CAT.criterios)||[];
 var tema='';
 var filas=crit.map(function(k){
  var cab = (k.tema!==tema) ? '<tr><td colspan=3 style="background:#f1f5f9;font-weight:700;padding:6px 8px">'+_esc(k.tema)+'</td></tr>' : '';
  tema=k.tema;
  // Los temas sin punto medio no lo ofrecen: el formato dice "-" y poner la
  // opcion invitaria a calificar algo que el papel no permite.
  var ops=[[0,k.n0],[3,k.n3],[5,k.n5]].filter(function(o){return o[1];}).map(function(o){
   var sel=(String(puntos[k.clave])===String(o[0]))?' checked':'';
   return '<label class=op><input type=radio name="pt_'+k.clave+'" value="'+o[0]+'"'+sel+(puede?'':' disabled')+' onchange="calcEval()"> <b>'+o[0]+'</b> &mdash; '+_esc(o[1])+'</label>';
  }).join('');
  return cab+'<tr><td style="padding:6px 8px"><b>'+_esc(k.sub)+'</b></td>'
   +'<td style="padding:6px 8px;white-space:nowrap" class=muted>'+Math.round(k.peso*100)+'%</td>'
   +'<td style="padding:6px 8px">'+ops+'</td></tr>';
 }).join('');
 document.getElementById('evTitulo').textContent='Evaluacion '+num+' de '+((CAT&&CAT.evaluaciones)||3)+' \u2014 '+(c.nombre||'');
 document.getElementById('evSub').textContent='F-RRHH-09 Feedback Operadores \u00b7 '+(c.empresa||'')+' \u00b7 contratado el '+((c.fecha_contratacion||'').slice(0,10)||'(sin capturar)');
 document.getElementById('evCrit').innerHTML=filas;
 document.getElementById('evJefe').value=(prev&&prev.jefe)||'';
 document.getElementById('evBase').value=(prev&&prev.base)||'';
 document.getElementById('evPuesto').value=(prev&&prev.puesto)||'Operador';
 document.getElementById('evFecha').value=(prev&&prev.fecha)||new Date().toISOString().slice(0,10);
 document.getElementById('evPos').value=(prev&&prev.positivos)||'';
 document.getElementById('evAreas').value=(prev&&prev.areas)||'';
 ['evJefe','evBase','evPuesto','evFecha','evPos','evAreas'].forEach(function(id){document.getElementById(id).disabled=!puede;});
 document.getElementById('evGuardar').style.display=puede?'':'none';
 document.getElementById('evSoloLectura').style.display=puede?'none':'';
 calcEval();
 document.getElementById('modalEval').style.display='flex';
}

function cerrarEval(){ document.getElementById('modalEval').style.display='none'; }

/* El porcentaje se calcula mientras se contesta, con la misma formula del
   servidor: quien evalua ve de inmediato en que color va a quedar. */
function calcEval(){
 var crit=(CAT&&CAT.criterios)||[], total=0;
 crit.forEach(function(k){
  var el=document.querySelector('input[name="pt_'+k.clave+'"]:checked');
  if(!el) return;
  var f={'0':0,'3':0.5,'5':1}[el.value]||0;
  total+=f*k.peso;
 });
 var pct=Math.round(total*1000)/10;
 var color=(pct<50)?'rojo':((pct<70)?'amarillo':'verde');
 var caja=document.getElementById('evCalif');
 caja.className='califbox ev '+color;
 caja.textContent=pct+'%';
 document.getElementById('evVeredicto').textContent =
  (pct>=70)?'Luz verde para contrato definitivo.'
          :((pct>=50)?'Desempeno medio: requiere seguimiento.'
                    :'Desempeno bajo.');
}

async function guardarEval(){
 var crit=(CAT&&CAT.criterios)||[], puntos={}, faltan=0;
 crit.forEach(function(k){
  var el=document.querySelector('input[name="pt_'+k.clave+'"]:checked');
  if(el) puntos[k.clave]=parseInt(el.value,10); else faltan++;
 });
 if(faltan && !confirm('Faltan '+faltan+' tema(s) por calificar. Lo que no se califica cuenta como 0 y baja el porcentaje. Guardar asi?')) return;
 var b={conductor_id:_EVAL.cid, numero:_EVAL.num, puntos:puntos,
        jefe:document.getElementById('evJefe').value,
        base:document.getElementById('evBase').value,
        puesto:document.getElementById('evPuesto').value,
        fecha:document.getElementById('evFecha').value,
        positivos:document.getElementById('evPos').value,
        areas:document.getElementById('evAreas').value};
 var r=await fetch('/api/evaluacion/guardar',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
 var j=await r.json();
 if(!j.ok){ alert(j.error||'No se pudo guardar'); return; }
 cerrarEval();
 await cargarCond();
 alert('Evaluacion '+_EVAL.num+' guardada: '+j.porcentaje+'%');
}

/* Dos interruptores sobre la misma lista: uno acota a quien le toca evaluacion y
   otro sube a los que ya la deben. El orden por urgencia viene prendido porque es
   para lo que se mira esta pantalla. */
var SOLO_PRUEBA=false, URGENTE_PRIMERO=true;

function togglePrueba(){ SOLO_PRUEBA=!SOLO_PRUEBA;
 document.getElementById('btnPrueba').classList.toggle('on', SOLO_PRUEBA); pintarCond(); }
function toggleUrgente(){ URGENTE_PRIMERO=!URGENTE_PRIMERO;
 document.getElementById('btnUrgente').classList.toggle('on', URGENTE_PRIMERO); pintarCond(); }

/* Quien entra en el filtro: solo los que siguen DENTRO del periodo de prueba.
   Pasados los 90 dias ya tienen contrato definitivo y no hay evaluacion que
   aplicarles; esta pantalla es para decidir antes de ese corte, no despues. */
function _enPrueba(c){
 return !!(c.prueba||{}).en_prueba;
}

/* Que tan urgente es: dias transcurridos desde el corte mas viejo sin atender.
   Mientras mas atrasado, mas arriba. Los que no deben nada van despues, y entre
   ellos primero el que tiene el corte mas cerca. */
function _urgencia(c){
 var p=c.prueba||{}, evs=p.evaluaciones||[], dias=p.dias;
 if(dias==null) return -1e6;                       // sin fecha: no se puede saber
 var atraso=null, proximo=null;
 evs.forEach(function(e){
  if(e.estado==='pendiente'){ var a=dias-e.dia; if(atraso===null||a>atraso) atraso=a; }
  else if(e.estado==='futura'){ var f=e.dia-dias; if(proximo===null||f<proximo) proximo=f; }
  // `fuera_de_plazo` no suma urgencia: el periodo cerro y ya no hay que hacer nada.
 });
 if(atraso!==null) return 1000+atraso;             // vencidas: el mas atrasado arriba
 if(proximo!==null) return 100-proximo;            // por vencer: el mas cercano arriba
 return -1;                                        // todas hechas
}

async function cargarCond(){
 var q=_qs();
 var arr=await (await fetch('/api/conductores'+q,{cache:'no-store'})).json();
 window._CONDS=arr;
 pintarCond();
 try{
  var all=await (await fetch('/api/conductores',{cache:'no-store'})).json();
  var allAct=(all||[]).filter(function(c){return c.activo;});
  var total=allAct.length;
  var nC=allAct.filter(function(c){return c.empresa==='Cryogenics';}).length;
  var nT=allAct.filter(function(c){return c.empresa==='TNIR';}).length;
 var nR=allAct.filter(function(c){return c.empresa==='Rasch Logistics';}).length;
  function pct(n){return total? Math.round(n/total*100):0;}
  document.getElementById('condCounts').innerHTML =
    '<div class=kpi><div class=v style="color:#0891b2">'+nC+' <span style="font-size:15px;color:#64748b">('+pct(nC)+'%)</span></div><div class=l>Activos Cryogenics</div></div>'
   +'<div class=kpi><div class=v style="color:#2563eb">'+nT+' <span style="font-size:15px;color:#64748b">('+pct(nT)+'%)</span></div><div class=l>Activos TNIR</div></div>'
 +'<div class=kpi><div class=v style="color:#059669">'+nR+' <span style="font-size:15px;color:#64748b">('+pct(nR)+'%)</span></div><div class=l>Activos Rasch Logistics</div></div>';
 }catch(e){}
}

function pintarCond(){
 var arr=window._CONDS||[];
 var rh=(ME.rol==='RH'||ME.rol==='Reclutador'||_niv(ME.rol)>=3), admin=_niv(ME.rol)>=3;
 var activos=(arr||[]).filter(function(c){return c.activo;});
 var bajas=(arr||[]).filter(function(c){return !c.activo;});
 var total=activos.length;
 if(SOLO_PRUEBA) activos=activos.filter(_enPrueba);
 if(URGENTE_PRIMERO) activos=activos.slice().sort(function(a,b){
  var d=_urgencia(b)-_urgencia(a);
  return d||((a.nombre||'')<(b.nombre||'')?-1:1);
 });
 var pend=activos.filter(function(c){return (c.prueba||{}).pendientes;}).length;
 var cuenta=document.getElementById('condCuenta');
 if(cuenta) cuenta.textContent = (SOLO_PRUEBA?(activos.length+' de '+total+' conductores'):(total+' conductores'))
   + (pend?(' \u00b7 '+pend+' con evaluacion pendiente'):'');
 document.getElementById('condBody').innerHTML = activos.map(function(c){
  var acc='';
  if(rh) acc='<button class="b r" style="padding:4px 8px" onclick="condBaja('+c.id+')">Dar de baja</button>';
  if(rh) acc+=' <button class="b s" style="padding:4px 8px" onclick="condCambiar('+c.id+')">Cambiar compania</button>';
  if(admin) acc+=' <button class="b r" style="padding:4px 8px" onclick="condDel('+c.id+')">&#10005;</button>';
  var fc=(c.fecha_contratacion||'').slice(0,10);
  var dias=(c.prueba||{}).dias;
  // Los dias transcurridos van junto a la fecha: los cortes son 25/55/85 dias, y
  // sin ese numero a la vista hay que sacar la cuenta de cabeza para entender el
  // color de los botones.
  var leyenda = (dias==null) ? ''
   : '<span class=dias>'+dias+' dias'+((c.prueba||{}).en_prueba?' \u00b7 en prueba':' \u00b7 contrato definitivo')+'</span>';
  var celdaFecha = rh
   ? '<input type=date class=fcontrat value="'+_esc(fc)+'" onchange="condFecha('+c.id+',this.value)">'+leyenda
   : ((_esc(fc)||'<span class=muted>sin capturar</span>')+leyenda);
  return '<tr><td><b>'+_esc(c.nombre)+'</b></td><td>'+_esc(c.telefono||'')+'</td><td>'+_esc(c.empresa)+'</td>'
   +'<td style="white-space:nowrap">'+celdaFecha+'</td>'
   +'<td style="white-space:nowrap">'+botonesEval(c)+'</td>'
   +'<td style="white-space:nowrap">'+acc+'</td></tr>';
 }).join('') || '<tr><td colspan=6 class=muted>Sin conductores activos.</td></tr>';
 filtrarCond();
 document.getElementById('bajasBody').innerHTML = bajas.map(function(c){
  var acc='';
  if(rh) acc='<button class="b s" style="padding:4px 8px" onclick="condReact('+c.id+')">Reactivar</button>';
  if(admin) acc+=' <button class="b r" style="padding:4px 8px" onclick="condDel('+c.id+')">&#10005;</button>';
  var fb=(c.fecha_baja||'').slice(0,10);
  return '<tr><td>'+_esc(c.nombre)+'</td><td>'+_esc(c.empresa)+'</td><td>'+_esc(c.motivo_baja||'')+'</td><td>'+_esc(fb)+'</td><td style="white-space:nowrap">'+acc+'</td></tr>';
 }).join('') || '<tr><td colspan=5 class=muted>Sin bajas registradas.</td></tr>';
 filtrarBajas();
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
 var actual=c?c.empresa:''; var _emps=(window.CAT&&CAT.empresas)||['Cryogenics','TNIR','Rasch Logistics'];var _ix=_emps.indexOf(actual);var destino=_emps[(_ix+1)%_emps.length]||_emps[0];
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
 if(TIPO==='conductor'){ cards.push(['Conductores activos', s.conductores_activos, '#0891b2']); cards.push(['Rotacion de personal', (s.rotacion!=null?s.rotacion:0)+'%', '#f59e0b']); cards.push(['Bajas', s.bajas_total, '#dc2626']); cards.push(['Motivo principal de baja', bp, '#475569']); }
 document.getElementById('kpiCards').innerHTML = cards.map(function(c){
  return '<div class=kpi><div class=v style="color:'+c[2]+'">'+_esc(c[1])+'</div><div class=l>'+_esc(c[0])+'</div></div>';
 }).join('');
 barChart('chEmbudo', s.embudo.map(function(x){return x.status;}).concat(['Rechazado']), s.embudo.map(function(x){return x.n;}).concat([s.rechazados]), s.embudo.map(function(){return '#2563eb';}).concat(['#dc2626']));
 dough('chOrigen', s.origenes);
 dough('chRech', s.rechazos_motivos);
 barChart('chBaja', Object.keys(s.bajas_motivos), Object.values(s.bajas_motivos), '#dc2626');
 var rowOps=document.getElementById('rowOps'); if(rowOps) rowOps.style.display=(TIPO==='conductor')?'':'none';
 if(TIPO==='conductor'){
  var _os=s.op_semana||{labels:[],empresas:[],series:{}};
  var _lsem=(_os.labels||[]).map(function(d){var p=(d||'').split('-');return p.length===3?(p[2]+'/'+p[1]):d;});
  stackBar('chOpSem', _lsem, _os.empresas||[], _os.series||{});
  var _or=s.op_reclutador||{labels:[],empresas:[],series:{}};
  stackBar('chOpRecl', _or.labels||[], _or.empresas||[], _or.series||{});
 }
}
function _destroy(id){ if(_ch[id]){ _ch[id].destroy(); delete _ch[id]; } }
var _dlPlugin={id:"dl",afterDatasetsDraw:function(chart){
 var ctx=chart.ctx; ctx.save(); ctx.textAlign="center"; ctx.font="bold 11px sans-serif";
 var tot=[];
 chart.data.datasets.forEach(function(ds,di){
  var meta=chart.getDatasetMeta(di);
  meta.data.forEach(function(bar,i){
   var val=(ds.data[i]||0); tot[i]=(tot[i]||0)+val;
   if(val>0){ ctx.fillStyle="#fff"; ctx.textBaseline="middle"; var mid=(bar.base!=null)?(bar.y+bar.base)/2:(bar.y-8); ctx.fillText(val, bar.x, mid); }
  });
 });
 var lastMeta=chart.getDatasetMeta(chart.data.datasets.length-1);
 if(lastMeta){ ctx.fillStyle="#0f172a"; ctx.textBaseline="bottom";
  lastMeta.data.forEach(function(bar,i){ if((tot[i]||0)>0) ctx.fillText(tot[i], bar.x, bar.y-3); }); }
 ctx.restore();
}};
function stackBar(id, labels, empresas, series){
 var cv=document.getElementById(id); if(!cv) return; _destroy(id);
 var COLE={"TNIR":"#2563eb","Cryogenics":"#7c3aed","Rasch Logistics":"#059669","Sin asignar":"#94a3b8","Otra":"#f59e0b"};
 var ds=(empresas||[]).map(function(e){return {label:e,data:(series&&series[e])||[],backgroundColor:(COLE[e]||"#0891b2"),stack:"s"};});
 _ch[id]=new Chart(cv,{type:"bar",data:{labels:labels,datasets:ds},
  options:{responsive:true,maintainAspectRatio:false,layout:{padding:{top:18}},
   plugins:{legend:{display:true,position:"bottom",labels:{boxWidth:12,font:{size:11}}}},
   scales:{x:{stacked:true},y:{stacked:true,beginAtZero:true,ticks:{precision:0}}}},
  plugins:[_dlPlugin]});
}
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
                               "roles": db.ROLES,
                               "criterios": db.CRITERIOS,
                               "evaluaciones": db.EVALUACIONES})
        if not u:
            return self._json({"error": "no autorizado"}, 401)
        if path == "/api/plantilla":
            return self._json(db.plantilla_list())
        if path == "/api/plantilla_adm":
            return self._json(db.plantilla_adm_list())
        if path == "/api/candidatos":
            return self._json(db.candidatos_list(qs.get("empresa"), qs.get("dias"), qs.get("tipo"), qs.get("desde"), qs.get("hasta")))
        if path == "/api/conductores":
            return self._json(db.conductores_list(qs.get("empresa")))
        if path == "/api/evaluacion":
            try:
                cid = int(qs.get("conductor_id") or 0)
                num = int(qs.get("numero") or 0)
            except ValueError:
                return self._json({"error": "parametros invalidos"}, 400)
            return self._json(db.evaluacion_get(cid, num) or {})
        if path == "/api/stats":
            return self._json(db.stats(qs.get("empresa"), qs.get("dias"), qs.get("tipo"), qs.get("desde"), qs.get("hasta")))
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
        if path == "/api/conductores/fecha_contratacion":
            if not (rh() or reclutador()):
                return self._json({"ok": False, "error": "solo RH"}, 403)
            fecha = str(data.get("fecha") or "").strip()[:10]
            if fecha:
                try:
                    datetime.strptime(fecha, "%Y-%m-%d")
                except ValueError:
                    return self._json({"ok": False,
                                       "error": "la fecha va como AAAA-MM-DD"})
            db.conductor_fecha_contratacion(data.get("id"), fecha or None)
            return self._json({"ok": True})
        if path == "/api/evaluacion/guardar":
            # La hace el jefe de operaciones con el que trabaja el conductor; RH y
            # el administrador tambien, porque alguien tiene que poder corregirla.
            if not (rol == "Jefe de operaciones" or rh()
                    or _puede(rol, "Administrador")):
                return self._json({"ok": False,
                                   "error": "solo jefe de operaciones o RH"}, 403)
            try:
                cid = int(data.get("conductor_id") or 0)
                num = int(data.get("numero") or 0)
            except (TypeError, ValueError):
                return self._json({"ok": False, "error": "datos invalidos"})
            if num not in range(1, db.EVALUACIONES + 1):
                return self._json({"ok": False,
                                   "error": f"la evaluacion va de 1 a {db.EVALUACIONES}"})
            porcentaje = db.evaluacion_guardar(
                cid, num, data.get("puntos") or {},
                jefe=str(data.get("jefe") or "").strip(),
                base=str(data.get("base") or "").strip(),
                puesto=str(data.get("puesto") or "").strip(),
                positivos=str(data.get("positivos") or "").strip(),
                areas=str(data.get("areas") or "").strip(),
                fecha=str(data.get("fecha") or "").strip()[:10] or None,
                autor=u.get("nombre") or u.get("usuario") or "")
            if porcentaje is None:
                return self._json({"ok": False, "error": "no se pudo guardar"})
            return self._json({"ok": True, "porcentaje": porcentaje,
                               "color": db.color_calificacion(porcentaje)})
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
