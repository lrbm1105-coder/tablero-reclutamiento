"""Capa de datos del tablero de Reclutamiento."""
import os
import hmac
import base64
import hashlib
import secrets
from datetime import datetime, timezone

DATABASE_URL = os.environ.get("DATABASE_URL")
IS_PG = bool(DATABASE_URL)

if IS_PG:
    import psycopg2
    PH = "%s"
else:
    import sqlite3
    PH = "?"
    _SQLITE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reclutamiento.db")

EMPRESAS = ["Cryogenics", "TNIR"]
STATUSES = ["Contactado", "Entrevista operaciones", "Documentos recibidos",
            "Documentos validados", "Citado", "Contratado", "Rechazado"]
STATUS_CONVERSION = "Contratado"
STATUS_RECHAZO = "Rechazado"
MOTIVOS_RECHAZO = ["Rechazado por operaciones", "Falta de experiencia",
                   "Rechazado por RH", "Rechazado por salud",
                   "Documentacion incompleta", "No se presento"]
ORIGENES = ["Gerencia", "Osvaldo", "Elena", "Recomendado"]
MOTIVOS_BAJA = ["Falta de viajes", "Inconformidad con sueldo",
                "Problema con despachadores", "Problemas con gerencia",
                "Problemas personales", "Problema con cliente",
                "No especifico", "Bajo rendimiento", "Indisciplina"]
ROLES = ["Administrador", "Reclutador", "RH"]


def _conn():
    if IS_PG:
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(_SQLITE)


def _run(q, params=(), fetch=None):
    c = _conn()
    cur = c.cursor()
    try:
        cur.execute(q, params)
        if fetch == "one":
            r = cur.fetchone()
        elif fetch == "all":
            r = cur.fetchall()
        else:
            r = None
        c.commit()
        return r
    finally:
        cur.close()
        c.close()


def _dicts(rows, cols):
    return [dict(zip(cols, r)) for r in (rows or [])]


def _ahora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _nuevo_id():
    return int(datetime.now().timestamp() * 1000)


def init():
    _run("""CREATE TABLE IF NOT EXISTS recl_usuarios(
        id BIGINT PRIMARY KEY, usuario TEXT UNIQUE, nombre TEXT, rol TEXT,
        pass_hash TEXT, salt TEXT)""")
    _run("""CREATE TABLE IF NOT EXISTS recl_plantilla(
        empresa TEXT PRIMARY KEY, requerida INTEGER DEFAULT 0,
        actual INTEGER DEFAULT 0)""")
    _run("""CREATE TABLE IF NOT EXISTS recl_candidatos(
        id BIGINT PRIMARY KEY, empresa TEXT, nombre TEXT, telefono TEXT,
        origen TEXT, status TEXT, motivo_rechazo TEXT, reclutador TEXT,
        creado TEXT, actualizado TEXT, fecha_contratado TEXT,
        fecha_rechazo TEXT, notas TEXT, notas_actualizado TEXT)""")
    try:
        _run("ALTER TABLE recl_candidatos ADD COLUMN IF NOT EXISTS notas_actualizado TEXT")
    except Exception:
        pass
    try:
        _run("ALTER TABLE recl_candidatos ADD COLUMN IF NOT EXISTS tipo TEXT")
    except Exception:
        pass
    try:
        _run("ALTER TABLE recl_candidatos ADD COLUMN IF NOT EXISTS puesto TEXT")
    except Exception:
        pass
    _run("""CREATE TABLE IF NOT EXISTS recl_plantilla_adm(
        puesto TEXT PRIMARY KEY, requerida INTEGER DEFAULT 0)""")
    _run("""CREATE TABLE IF NOT EXISTS recl_conductores(
        id BIGINT PRIMARY KEY, empresa TEXT, nombre TEXT, telefono TEXT,
        activo INTEGER DEFAULT 1, fecha_alta TEXT, fecha_baja TEXT,
        motivo_baja TEXT)""")
    _run("""CREATE TABLE IF NOT EXISTS recl_config(
        clave TEXT PRIMARY KEY, valor TEXT)""")
    for e in EMPRESAS:
        try:
            _run(f"INSERT INTO recl_plantilla(empresa, requerida, actual) "
                 f"VALUES ({PH}, 0, 0)", (e,))
        except Exception:
            pass
    seed_admin()


def _hash_pass(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                            salt.encode("utf-8"), 100000)
    return base64.b64encode(h).decode("ascii"), salt


def _verif_pass(password, pass_hash, salt):
    h, _ = _hash_pass(password, salt)
    return hmac.compare_digest(h, pass_hash or "")


COLS_USER = ["id", "usuario", "nombre", "rol", "pass_hash", "salt"]


def usuarios_list():
    rows = _run("SELECT id, usuario, nombre, rol FROM recl_usuarios "
                "ORDER BY rol, usuario", fetch="all")
    return _dicts(rows, ["id", "usuario", "nombre", "rol"])


def usuario_existe(usuario):
    r = _run(f"SELECT 1 FROM recl_usuarios WHERE usuario = {PH}", (usuario,), "one")
    return bool(r)


def usuario_login(usuario, password):
    r = _run(f"SELECT id, usuario, nombre, rol, pass_hash, salt FROM recl_usuarios "
             f"WHERE usuario = {PH}", (usuario,), "one")
    if not r:
        return None
    d = dict(zip(COLS_USER, r))
    if _verif_pass(password, d["pass_hash"], d["salt"]):
        return {"id": d["id"], "usuario": d["usuario"],
                "nombre": d["nombre"], "rol": d["rol"]}
    return None


def usuario_add(usuario, nombre, rol, password):
    ph, salt = _hash_pass(password)
    _run(f"INSERT INTO recl_usuarios(id, usuario, nombre, rol, pass_hash, salt) "
         f"VALUES ({PH}, {PH}, {PH}, {PH}, {PH}, {PH})",
         (_nuevo_id(), usuario, nombre, rol, ph, salt))


def usuario_del(usuario):
    _run(f"DELETE FROM recl_usuarios WHERE usuario = {PH}", (usuario,))


def seed_admin():
    r = _run("SELECT COUNT(*) FROM recl_usuarios", fetch="one")
    if r and r[0] == 0:
        usuario_add("admin", "Administrador", "Administrador", "admin1234")


def get_secret():
    r = _run(f"SELECT valor FROM recl_config WHERE clave = {PH}",
             ("session_secret",), "one")
    if r and r[0]:
        return r[0]
    s = secrets.token_hex(32)
    try:
        _run(f"INSERT INTO recl_config(clave, valor) VALUES ({PH}, {PH})",
             ("session_secret", s))
    except Exception:
        _run(f"UPDATE recl_config SET valor = {PH} WHERE clave = {PH}",
             (s, "session_secret"))
    return s


def plantilla_list():
    rows = _run("SELECT empresa, requerida, actual FROM recl_plantilla "
                "ORDER BY empresa", fetch="all")
    # La base "Actual" es el conteo real de conductores activos por empresa.
    crows = _run("SELECT empresa, COUNT(*) FROM recl_conductores "
                 "WHERE activo = 1 GROUP BY empresa", fetch="all")
    activos = {}
    for ce, cn in (crows or []):
        activos[str(ce).strip().lower()] = cn
    data = []
    for e, req, act in (rows or []):
        req = req or 0
        act = activos.get(str(e).strip().lower(), 0)
        data.append({"empresa": e, "requerida": req, "actual": act,
                     "necesidad": max(req - act, 0)})
    return data


def plantilla_set(empresa, requerida, actual):
    _run(f"UPDATE recl_plantilla SET requerida = {PH}, actual = {PH} "
         f"WHERE empresa = {PH}", (int(requerida), int(actual), empresa))
    r = _run(f"SELECT 1 FROM recl_plantilla WHERE empresa = {PH}", (empresa,), "one")
    if not r:
        _run(f"INSERT INTO recl_plantilla(empresa, requerida, actual) "
             f"VALUES ({PH}, {PH}, {PH})", (empresa, int(requerida), int(actual)))


COLS_CAND = ["id", "empresa", "nombre", "telefono", "origen", "status",
             "motivo_rechazo", "reclutador", "creado", "actualizado",
             "fecha_contratado", "fecha_rechazo", "notas", "notas_actualizado",
             "tipo", "puesto"]


def candidatos_list(empresa=None, dias=None, tipo=None):
    conds, params = [], []
    if empresa and empresa in EMPRESAS:
        conds.append(f"empresa = {PH}")
        params.append(empresa)
    if tipo == "administrativo":
        conds.append("tipo = 'administrativo'")
    else:
        conds.append("(tipo IS NULL OR tipo <> 'administrativo')")
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    rows = _run(f"SELECT {', '.join(COLS_CAND)} FROM recl_candidatos"
                f"{where} ORDER BY creado DESC", tuple(params), "all")
    data = _dicts(rows, COLS_CAND)
    if dias:
        try:
            from datetime import timedelta
            _corte = (datetime.now() - timedelta(days=int(dias))).strftime("%Y-%m-%dT%H:%M:%S")
            data = [c for c in data if str(c.get("creado") or "")[:19] >= _corte]
        except Exception:
            pass
    return data


def candidato_get(cid):
    rows = _run(f"SELECT {', '.join(COLS_CAND)} FROM recl_candidatos "
                f"WHERE id = {PH}", (cid,), "all")
    d = _dicts(rows, COLS_CAND)
    return d[0] if d else None


def candidato_add(empresa, nombre, telefono, origen, reclutador, notas="", tipo="conductor", puesto=""):
    cid = _nuevo_id()
    ahora = _ahora()
    _run(f"INSERT INTO recl_candidatos(id, empresa, nombre, telefono, origen, "
         f"status, motivo_rechazo, reclutador, creado, actualizado, "
         f"fecha_contratado, fecha_rechazo, notas, tipo, puesto) "
         f"VALUES ({', '.join([PH] * 15)})",
         (cid, empresa, nombre, telefono, origen, "Contactado", None,
          reclutador, ahora, ahora, None, None, notas,
          "administrativo" if tipo == "administrativo" else "conductor", puesto))
    return cid


def candidato_status(cid, status, motivo_rechazo=None, autor=""):
    c = candidato_get(cid)
    if not c:
        return False
    ahora = _ahora()
    f_contr = c.get("fecha_contratado")
    f_rech = c.get("fecha_rechazo")
    mot = c.get("motivo_rechazo")
    if status == STATUS_CONVERSION and not f_contr:
        f_contr = ahora
    if status == STATUS_RECHAZO:
        f_rech = ahora
        mot = motivo_rechazo or mot
    else:
        mot = None
    _run(f"UPDATE recl_candidatos SET status = {PH}, motivo_rechazo = {PH}, "
         f"actualizado = {PH}, fecha_contratado = {PH}, fecha_rechazo = {PH} "
         f"WHERE id = {PH}", (status, mot, ahora, f_contr, f_rech, cid))
    return True


def candidato_editar(cid, campos):
    permitidos = ["empresa", "nombre", "telefono", "origen", "notas", "puesto"]
    sets, vals = [], []
    for k in permitidos:
        if k in campos:
            sets.append(f"{k} = {PH}")
            vals.append(campos[k])
    if not sets:
        return False
    vals.append(_ahora())
    sets.append(f"actualizado = {PH}")
    if "notas" in campos:
        sets.append(f"notas_actualizado = {PH}")
        vals.append(_ahora())
    vals.append(cid)
    _run(f"UPDATE recl_candidatos SET {', '.join(sets)} WHERE id = {PH}", tuple(vals))
    return True


def candidato_del(cid):
    _run(f"DELETE FROM recl_candidatos WHERE id = {PH}", (cid,))


COLS_COND = ["id", "empresa", "nombre", "telefono", "activo",
             "fecha_alta", "fecha_baja", "motivo_baja"]


def conductores_list(empresa=None, solo_activos=None):
    cond = []
    params = []
    if empresa and empresa in EMPRESAS:
        cond.append(f"empresa = {PH}")
        params.append(empresa)
    if solo_activos is True:
        cond.append("activo = 1")
    elif solo_activos is False:
        cond.append("activo = 0")
    where = (" WHERE " + " AND ".join(cond)) if cond else ""
    rows = _run(f"SELECT {', '.join(COLS_COND)} FROM recl_conductores{where} "
                f"ORDER BY activo DESC, nombre", tuple(params), "all")
    return _dicts(rows, COLS_COND)


def conductor_add(empresa, nombre, telefono=""):
    existe = _run(f"SELECT 1 FROM recl_conductores WHERE empresa = {PH} "
                  f"AND LOWER(nombre) = LOWER({PH}) AND activo = 1",
                  (empresa, nombre), "one")
    if existe:
        return None
    cid = _nuevo_id()
    _run(f"INSERT INTO recl_conductores(id, empresa, nombre, telefono, activo, "
         f"fecha_alta, fecha_baja, motivo_baja) "
         f"VALUES ({PH}, {PH}, {PH}, {PH}, 1, {PH}, {PH}, {PH})",
         (cid, empresa, nombre, telefono, _ahora(), None, None))
    return cid


def conductor_baja(cid, motivo):
    _run(f"UPDATE recl_conductores SET activo = 0, fecha_baja = {PH}, "
         f"motivo_baja = {PH} WHERE id = {PH}", (_ahora(), motivo, cid))


def conductor_reactivar(cid):
    _run(f"UPDATE recl_conductores SET activo = 1, fecha_baja = {PH}, "
         f"motivo_baja = {PH} WHERE id = {PH}", (None, None, cid))


def conductor_cambiar_empresa(cid):
    r = _run(f"SELECT empresa FROM recl_conductores WHERE id = {PH}", (cid,), "one")
    if not r:
        return None
    actual = (r[0] or "").strip()
    nueva = "TNIR" if actual == "Cryogenics" else "Cryogenics"
    _run(f"UPDATE recl_conductores SET empresa = {PH} WHERE id = {PH}", (nueva, cid))
    return nueva


def conductor_del(cid):
    _run(f"DELETE FROM recl_conductores WHERE id = {PH}", (cid,))


def _dias_entre(a, b):
    try:
        da = datetime.strptime(a[:19], "%Y-%m-%dT%H:%M:%S")
        dbb = datetime.strptime(b[:19], "%Y-%m-%dT%H:%M:%S")
        return (dbb - da).total_seconds() / 86400.0
    except Exception:
        return None


def plantilla_adm_list():
    rows = _run("SELECT puesto, requerida FROM recl_plantilla_adm ORDER BY puesto", fetch="all")
    crows = _run("SELECT puesto, COUNT(*) FROM recl_candidatos "
                 "WHERE tipo = 'administrativo' AND status = 'Contratado' "
                 "GROUP BY puesto", fetch="all")
    actuales = {}
    for pu, n in (crows or []):
        actuales[str(pu or "").strip().lower()] = n
    data = []
    for pu, req in (rows or []):
        req = req or 0
        act = actuales.get(str(pu or "").strip().lower(), 0)
        data.append({"puesto": pu, "requerida": req, "actual": act,
                     "necesidad": max(req - act, 0)})
    return data


def plantilla_adm_set(puesto, requerida):
    puesto = str(puesto or "").strip()
    if not puesto:
        return
    r = _run(f"SELECT 1 FROM recl_plantilla_adm WHERE puesto = {PH}", (puesto,), "one")
    if r:
        _run(f"UPDATE recl_plantilla_adm SET requerida = {PH} WHERE puesto = {PH}",
             (int(requerida), puesto))
    else:
        _run(f"INSERT INTO recl_plantilla_adm(puesto, requerida) VALUES ({PH}, {PH})",
             (puesto, int(requerida)))


def plantilla_adm_del(puesto):
    _run(f"DELETE FROM recl_plantilla_adm WHERE puesto = {PH}", (puesto,))


def stats(empresa=None, dias=None, tipo=None):
    cands = candidatos_list(empresa, dias, tipo)
    conds = conductores_list(empresa) if tipo != "administrativo" else []
    total = len(cands)
    contratados = [c for c in cands if c.get("status") == STATUS_CONVERSION
                   or c.get("fecha_contratado")]
    n_contr = len(contratados)
    rechazados = [c for c in cands if c.get("status") == STATUS_RECHAZO]
    tasa = round(n_contr / total * 100, 1) if total else 0.0
    tiempos = []
    for c in contratados:
        d = _dias_entre(c.get("creado"), c.get("fecha_contratado"))
        if d is not None and d >= 0:
            tiempos.append(d)
    tiempo_prom = round(sum(tiempos) / len(tiempos), 1) if tiempos else None
    embudo = []
    for s in STATUSES:
        if s == STATUS_RECHAZO:
            continue
        embudo.append({"status": s, "n": sum(1 for c in cands if c.get("status") == s)})
    rech_motivos = {}
    for c in rechazados:
        m = c.get("motivo_rechazo") or "Sin motivo"
        rech_motivos[m] = rech_motivos.get(m, 0) + 1
    origenes = {}
    for c in cands:
        o = c.get("origen") or "Sin origen"
        origenes[o] = origenes.get(o, 0) + 1
    bajas = [c for c in conds if not c.get("activo")]
    bajas_motivos = {}
    for c in bajas:
        m = c.get("motivo_baja") or "Sin motivo"
        bajas_motivos[m] = bajas_motivos.get(m, 0) + 1
    baja_principal = None
    if bajas_motivos:
        baja_principal = max(bajas_motivos.items(), key=lambda x: x[1])
    activos = sum(1 for c in conds if c.get("activo"))
    bajas_periodo = bajas
    if dias:
        try:
            from datetime import timedelta
            _cb = (datetime.now() - timedelta(days=int(dias))).strftime("%Y-%m-%dT%H:%M:%S")
            bajas_periodo = [c for c in bajas if str(c.get("fecha_baja") or "")[:19] >= _cb]
        except Exception:
            bajas_periodo = bajas
    n_bp = len(bajas_periodo)
    rotacion = round(n_bp / activos * 100, 1) if activos else 0.0
    return {
        "empresa": empresa or "Todas",
        "contactados": total,
        "contratados": n_contr,
        "rechazados": len(rechazados),
        "en_proceso": total - n_contr - len(rechazados),
        "tasa_conversion": tasa,
        "tiempo_conversion_dias": tiempo_prom,
        "embudo": embudo,
        "rechazos_motivos": rech_motivos,
        "origenes": origenes,
        "bajas_total": len(bajas),
        "bajas_motivos": bajas_motivos,
        "baja_principal": ({"motivo": baja_principal[0], "n": baja_principal[1]}
                           if baja_principal else None),
        "conductores_activos": activos,
        "rotacion": rotacion,
        "bajas_periodo": n_bp,
    }
