# Tablero de Reclutamiento de operadores

Control del flujo de reclutamiento (pipeline de candidatos) y dashboard de KPIs
para las empresas Cryogenics y TNIR.

## Despliegue en Render
1. Repo ya creado: tablero-reclutamiento.
2. Render: New > Web Service, conecta el repo.
   - Build command: pip install -r requirements.txt
   - Start command: python server.py
3. Variable de entorno DATABASE_URL = la misma cadena de Supabase de tus otros
   tableros (las tablas llevan prefijo recl_ y no chocan).
4. Usuario inicial: admin / admin1234 (Administrador). Crea los usuarios reales
   desde el boton Usuarios y cambia el admin por defecto.

Sin DATABASE_URL corre con SQLite local para pruebas.
