"""Capa de datos del tablero de Reclutamiento."""
import os
import json
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

EMPRESAS = ["Cryogenics", "TNIR", "Rasch Logistics"]
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
ROLES = ["Administrador", "Reclutador", "RH", "Jefe de operaciones"]

# ---------------------------------------------------------------------------
# Evaluacion de periodo de prueba (formato F-RRHH-09 Feedback Operadores TNIR)
# ---------------------------------------------------------------------------
# Tres evaluaciones, una por mes durante los tres primeros meses. Las hace el jefe
# de operaciones con el que trabaja el conductor; RH las lee para decidir el
# contrato definitivo.
#
# Cada tema se califica con 0, 3 o 5 puntos, que valen 0, 0.5 y 1.0 del peso del
# tema. Los pesos suman 1.0, asi que el total es directamente el porcentaje de
# desempeno. Dos temas (camara obstruida y aviso de colision) NO tienen punto
# medio en el formato: o hubo eventos o no los hubo.
CRITERIOS = [
    {"clave": "camara", "tema": "Habitos de manejo Samsara",
     "sub": "Camara obstruida", "peso": 0.05,
     "n0": "1 o mas eventos", "n3": None, "n5": "0 eventos"},
    {"clave": "frenados", "tema": "Habitos de manejo Samsara",
     "sub": "Frenados bruscos", "peso": 0.05,
     "n0": "4 o mas eventos", "n3": "1 a 3 eventos", "n5": "0 eventos"},
    {"clave": "colision", "tema": "Habitos de manejo Samsara",
     "sub": "Aviso probable colision", "peso": 0.05,
     "n0": "1 o mas eventos", "n3": None, "n5": "0 eventos"},
    {"clave": "movil", "tema": "Habitos de manejo Samsara",
     "sub": "Uso del movil", "peso": 0.05,
     "n0": "21 o mas eventos", "n3": "11 a 20 eventos", "n5": "0 a 10 eventos"},
    {"clave": "diesel", "tema": "Rendimiento",
     "sub": "Rendimiento del diesel", "peso": 0.40,
     "n0": "2.4 o menos", "n3": "2.5 a 2.7", "n5": "2.7 a 3"},
    {"clave": "transito", "tema": "Tiempos de transito",
     "sub": "Viajes concluidos / llegadas", "peso": 0.20,
     "n0": "Menos del 75%", "n3": "75% al 89%", "n5": "90% al 100%"},
    {"clave": "tallones", "tema": "Cuidado de unidad",
     "sub": "Tallones / banquetazos", "peso": 0.15,
     "n0": "2 o mas accidentes", "n3": "1 accidente menor", "n5": "0 accidentes"},
    {"clave": "interior", "tema": "Cuidado de unidad",
     "sub": "Cuidado de la unidad interior", "peso": 0.05,
     "n0": "0 inspecciones positivas", "n3": "1 a 2 inspecciones positivas",
     "n5": "3 inspecciones positivas"},
]
# Cuanto vale cada puntaje del formato, como fraccion del peso del tema.
FACTOR_PUNTOS = {0: 0.0, 3: 0.5, 5: 1.0}
EVALUACIONES = 3                      # una por mes de periodo de prueba


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
    _run("ALTER TABLE recl_plantilla_adm ADD COLUMN IF NOT EXISTS creado TEXT")
    try:
        _run(f"UPDATE recl_plantilla_adm SET creado = {PH} WHERE creado IS NULL",
             (_ahora(),))
    except Exception:
        pass
    _run("""CREATE TABLE IF NOT EXISTS recl_conductores(
        id BIGINT PRIMARY KEY, empresa TEXT, nombre TEXT, telefono TEXT,
        activo INTEGER DEFAULT 1, fecha_alta TEXT, fecha_baja TEXT,
        motivo_baja TEXT)""")
    # Fecha real de contratacion. NO es `fecha_alta`, que es cuando alguien capturo
    # el renglon en este tablero: el periodo de prueba se cuenta desde que entro a
    # trabajar, y para los que ya estaban en la lista hay que capturarla a mano.
    try:
        _run("ALTER TABLE recl_conductores ADD COLUMN IF NOT EXISTS fecha_contratacion TEXT")
    except Exception:
        try:
            _run("ALTER TABLE recl_conductores ADD COLUMN fecha_contratacion TEXT")
        except Exception:
            pass
    _run("""CREATE TABLE IF NOT EXISTS recl_evaluaciones(
        id BIGINT PRIMARY KEY, conductor_id BIGINT, numero INTEGER,
        fecha TEXT, jefe TEXT, base TEXT, puesto TEXT, puntos TEXT,
        porcentaje REAL, positivos TEXT, areas TEXT, creado TEXT, autor TEXT)""")
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
    reqmap = {}
    for e, req, act in (rows or []):
        reqmap[str(e).strip()] = req or 0
    data = []
    vistos = set()
    for e in EMPRESAS:
        req = reqmap.get(str(e).strip(), 0)
        act = activos.get(str(e).strip().lower(), 0)
        data.append({"empresa": e, "requerida": req, "actual": act,
                     "necesidad": max(req - act, 0)})
        vistos.add(str(e).strip())
    for e, req in reqmap.items():
        if str(e).strip() not in vistos:
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


def candidatos_list(empresa=None, dias=None, tipo=None, desde=None, hasta=None):
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
    if desde or hasta:
        d0 = str(desde)[:10] if desde else "0000-00-00"
        d1 = str(hasta)[:10] if hasta else "9999-99-99"
        data = [c for c in data if d0 <= str(c.get("creado") or "")[:10] <= d1]
    elif dias:
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
             "fecha_alta", "fecha_baja", "motivo_baja", "fecha_contratacion"]


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
    conductores = _dicts(rows, COLS_COND)
    # Las evaluaciones viajan con el conductor: la tabla pinta tres botones por
    # renglon, y pedirlas una por una serian cientos de consultas para dibujar
    # una sola pantalla.
    hechas = {}
    for fila in _run("SELECT conductor_id, numero, porcentaje, fecha "
                     "FROM recl_evaluaciones", (), "all") or []:
        hechas.setdefault(fila[0], {})[int(fila[1])] = {
            "porcentaje": fila[2], "fecha": fila[3]}
    for c in conductores:
        c["evaluaciones"] = hechas.get(c["id"], {})
        c["prueba"] = estado_prueba(c["fecha_contratacion"], c["evaluaciones"])
    return conductores


def _suma_meses(fecha, meses):
    """La misma fecha N meses despues. Si el dia no existe, cae al ultimo del mes."""
    anio = fecha.year + (fecha.month - 1 + meses) // 12
    mes = (fecha.month - 1 + meses) % 12 + 1
    dia = fecha.day
    while dia > 28:
        try:
            return fecha.replace(year=anio, month=mes, day=dia)
        except ValueError:
            dia -= 1
    return fecha.replace(year=anio, month=mes, day=dia)


def color_calificacion(porcentaje):
    """Semaforo del formato: 0-49 rojo, 50-69 amarillo, 70 o mas verde.

    El verde es el que importa: es la luz que RH necesita para contratar en
    definitiva al terminar el periodo de prueba.
    """
    if porcentaje is None:
        return ""
    if porcentaje < 50:
        return "rojo"
    if porcentaje < 70:
        return "amarillo"
    return "verde"


def estado_prueba(fecha_contratacion, evaluaciones):
    """En que va el periodo de prueba: una entrada por cada evaluacion.

    Cada evaluacion vence al cumplir ese mes desde la contratacion. Mientras no
    vence no se pide nada —pedir la de un mes que no ha pasado solo ensena a
    ignorar el color—; vencida y sin hacer se marca en naranja; hecha, toma el
    color de su calificacion.
    """
    salida = {"meses": None, "pendientes": 0, "evaluaciones": []}
    inicio = None
    if fecha_contratacion:
        try:
            inicio = datetime.strptime(str(fecha_contratacion)[:10], "%Y-%m-%d")
        except ValueError:
            inicio = None
    ahora = datetime.now(timezone.utc)
    hoy = datetime(ahora.year, ahora.month, ahora.day)
    if inicio:
        cumplidos = 0
        while cumplidos < 60 and hoy >= _suma_meses(inicio, cumplidos + 1):
            cumplidos += 1
        salida["meses"] = cumplidos
    for numero in range(1, EVALUACIONES + 1):
        hecha = ((evaluaciones or {}).get(numero)
                 or (evaluaciones or {}).get(str(numero)))
        if hecha:
            salida["evaluaciones"].append({
                "numero": numero, "estado": "hecha",
                "porcentaje": hecha.get("porcentaje"),
                "color": color_calificacion(hecha.get("porcentaje")),
                "fecha": (hecha.get("fecha") or "")[:10]})
            continue
        # Sin fecha de contratacion no se puede saber si ya vencio: se deja en
        # blanco en vez de inventar una urgencia que nadie puede atender.
        if inicio is None:
            estado = "sin_fecha"
        elif hoy >= _suma_meses(inicio, numero):
            estado = "pendiente"
            salida["pendientes"] += 1
        else:
            estado = "futura"
        salida["evaluaciones"].append({"numero": numero, "estado": estado,
                                       "porcentaje": None, "color": "",
                                       "fecha": ""})
    return salida


def conductor_fecha_contratacion(cid, fecha):
    """Captura o corrige la fecha de contratacion. Vacio la borra."""
    _run(f"UPDATE recl_conductores SET fecha_contratacion = {PH} WHERE id = {PH}",
         ((fecha or None), cid))


COLS_EVAL = ["id", "conductor_id", "numero", "fecha", "jefe", "base", "puesto",
             "puntos", "porcentaje", "positivos", "areas", "creado", "autor"]


def evaluacion_get(conductor_id, numero):
    fila = _run(f"SELECT {', '.join(COLS_EVAL)} FROM recl_evaluaciones "
                f"WHERE conductor_id = {PH} AND numero = {PH}",
                (conductor_id, int(numero)), "one")
    if not fila:
        return None
    datos = _dicts([fila], COLS_EVAL)[0]
    try:
        datos["puntos"] = json.loads(datos["puntos"] or "{}")
    except Exception:
        datos["puntos"] = {}
    return datos


def limpiar_puntos(puntos):
    """Deja solo los puntajes que el formato admite, por tema.

    Vive en UN solo lugar porque lo usan el calculo y el guardado: con la regla
    repetida, un 3 puntos en un tema que no lo tiene daba un porcentaje al
    calcularlo y otro distinto al guardarlo.
    """
    limpios = {}
    for criterio in CRITERIOS:
        valor = (puntos or {}).get(criterio["clave"])
        if valor in (None, ""):
            continue
        try:
            valor = int(valor)
        except (TypeError, ValueError):
            continue
        # Lo que no existe en papel tampoco puede entrar por el API: camara
        # obstruida y aviso de colision no tienen punto medio, o hubo eventos o no.
        if valor == 3 and not criterio["n3"]:
            continue
        if valor in FACTOR_PUNTOS:
            limpios[criterio["clave"]] = valor
    return limpios


def calcular_porcentaje(puntos):
    """Porcentaje de desempeno del formato: suma de (factor x peso), en por ciento.

    Los temas sin calificar no suman. Es lo correcto —no se puede dar por bueno lo
    que nadie reviso— y ademas se nota: una evaluacion a medias sale baja.
    """
    total = 0.0
    for criterio in CRITERIOS:
        valor = limpiar_puntos(puntos).get(criterio["clave"])
        if valor is None:
            continue
        total += FACTOR_PUNTOS.get(valor, 0.0) * criterio["peso"]
    return round(total * 100, 1)


def evaluacion_guardar(conductor_id, numero, puntos, jefe="", base="", puesto="",
                       positivos="", areas="", fecha=None, autor=""):
    """Guarda (o reemplaza) la evaluacion N de ese conductor."""
    numero = int(numero)
    if numero not in range(1, EVALUACIONES + 1):
        return None
    limpios = limpiar_puntos(puntos)
    porcentaje = calcular_porcentaje(limpios)
    previa = evaluacion_get(conductor_id, numero)
    if previa:
        _run(f"UPDATE recl_evaluaciones SET fecha = {PH}, jefe = {PH}, base = {PH}, "
             f"puesto = {PH}, puntos = {PH}, porcentaje = {PH}, positivos = {PH}, "
             f"areas = {PH}, autor = {PH} WHERE id = {PH}",
             (fecha or _ahora()[:10], jefe, base, puesto, json.dumps(limpios),
              porcentaje, positivos, areas, autor, previa["id"]))
    else:
        _run(f"INSERT INTO recl_evaluaciones(id, conductor_id, numero, fecha, jefe, "
             f"base, puesto, puntos, porcentaje, positivos, areas, creado, autor) "
             f"VALUES ({PH}, {PH}, {PH}, {PH}, {PH}, {PH}, {PH}, {PH}, {PH}, {PH}, "
             f"{PH}, {PH}, {PH})",
             (_nuevo_id(), conductor_id, numero, fecha or _ahora()[:10], jefe,
              base, puesto, json.dumps(limpios), porcentaje, positivos, areas,
              _ahora(), autor))
    return porcentaje


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
    nueva = EMPRESAS[(EMPRESAS.index(actual) + 1) % len(EMPRESAS)] if actual in EMPRESAS else EMPRESAS[0]
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
    rows = _run("SELECT puesto, requerida, creado FROM recl_plantilla_adm "
                "ORDER BY puesto", fetch="all")
    crows = _run("SELECT puesto, fecha_contratado FROM recl_candidatos "
                 "WHERE tipo = 'administrativo' AND status = 'Contratado'",
                 fetch="all")
    porpuesto = {}
    for pu, fc in (crows or []):
        porpuesto.setdefault(str(pu or "").strip().lower(), []).append(fc)
    data = []
    for pu, req, creado in (rows or []):
        req = req or 0
        fcs = porpuesto.get(str(pu or "").strip().lower(), [])
        if creado:
            # Solo cuenta contrataciones a partir de la fecha de alta del
            # requerimiento: un puesto nuevo arranca en 0.
            act = sum(1 for fc in fcs if fc and str(fc) >= str(creado))
        else:
            act = len(fcs)
        data.append({"puesto": pu, "requerida": req, "actual": act,
                     "necesidad": max(req - act, 0)})
    return data


def plantilla_adm_set(puesto, requerida):
    puesto = str(puesto or "").strip()
    if not puesto:
        return
    ahora = _ahora()
    r = _run(f"SELECT 1 FROM recl_plantilla_adm WHERE puesto = {PH}", (puesto,), "one")
    if r:
        _run(f"UPDATE recl_plantilla_adm SET requerida = {PH}, creado = {PH} "
             f"WHERE puesto = {PH}", (int(requerida), ahora, puesto))
    else:
        _run(f"INSERT INTO recl_plantilla_adm(puesto, requerida, creado) "
             f"VALUES ({PH}, {PH}, {PH})", (puesto, int(requerida), ahora))


def plantilla_adm_del(puesto):
    _run(f"DELETE FROM recl_plantilla_adm WHERE puesto = {PH}", (puesto,))


def stats(empresa=None, dias=None, tipo=None, desde=None, hasta=None):
    cands = candidatos_list(empresa, dias, tipo, desde, hasta)
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
    # Contrataciones de operadores (tipo conductor) desde el inicio,
    # divididas por empresa (TNIR / Cryogenics) para las graficas apiladas.
    import datetime as _dt
    _emp_ord = ["TNIR", "Cryogenics", "Rasch Logistics"]

    def _empk(c):
        e = str(c.get("empresa") or "").strip()
        return e if e in _emp_ord else (e or "Otra")

    _opall = candidatos_list(empresa, None, "conductor")
    _opc = [c for c in _opall if c.get("fecha_contratado")]

    def _lunes(sq):
        try:
            d = _dt.datetime.strptime(str(sq)[:10], "%Y-%m-%d").date()
        except Exception:
            return None
        return d - _dt.timedelta(days=d.weekday())

    _emps = [e for e in _emp_ord if any(_empk(c) == e for c in _opc)]
    for c in _opc:
        e = _empk(c)
        if e not in _emps:
            _emps.append(e)

    _semcnt = {}
    for c in _opc:
        m = _lunes(c.get("fecha_contratado"))
        if m:
            k = (m, _empk(c))
            _semcnt[k] = _semcnt.get(k, 0) + 1
    _labels_sem = []
    if _semcnt:
        _ws = [k[0] for k in _semcnt]
        _ini = min(_ws)
        _fin = max(_ws)
        _hoy = _dt.date.today()
        _hoy = _hoy - _dt.timedelta(days=_hoy.weekday())
        if _hoy > _fin:
            _fin = _hoy
        _cur = _ini
        while _cur <= _fin:
            _labels_sem.append(_cur)
            _cur += _dt.timedelta(days=7)
    op_semana = {
        "labels": [d.isoformat() for d in _labels_sem],
        "empresas": _emps,
        "series": {e: [_semcnt.get((d, e), 0) for d in _labels_sem]
                   for e in _emps},
    }

    _rcnt = {}
    _rtot = {}
    for c in _opc:
        rk = (str(c.get("reclutador") or "").strip() or "Sin asignar")
        k = (rk, _empk(c))
        _rcnt[k] = _rcnt.get(k, 0) + 1
        _rtot[rk] = _rtot.get(rk, 0) + 1
    _labels_recl = [k for k, _ in sorted(_rtot.items(), key=lambda x: -x[1])]
    op_reclutador = {
        "labels": _labels_recl,
        "empresas": _emps,
        "series": {e: [_rcnt.get((r, e), 0) for r in _labels_recl]
                   for e in _emps},
    }

    return {
        "empresa": empresa or "Todas",
        "op_semana": op_semana,
        "op_reclutador": op_reclutador,
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
