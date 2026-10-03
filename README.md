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

## Periodo de prueba y evaluaciones (F-RRHH-09)

Cada conductor lleva su **fecha de contratacion** (la real, no la de captura) y
**tres evaluaciones**, a los **25, 55 y 85 dias**. Van cinco dias antes de cada corte
de mes a proposito: la evaluacion no sirve para constatar lo que ya paso, sirve para
decidir el siguiente contrato, y esa decision hay que tomarla con margen.

Las hace el **jefe de operaciones** con el que trabaja el conductor; RH las lee para
decidir el contrato definitivo. **Pasados los 90 dias ya no aplican**: el operador
quedo de planta y la decision se tomo. Una evaluacion que no se hizo a tiempo queda
en gris (fuera de plazo), no en naranja — un color que pide algo imposible es el que
ensena a ignorar todos los demas.

Dos botones sobre la tabla: **Solo periodo de prueba** deja a los que siguen dentro
de los 90 dias, y **Pendientes de evaluar primero** sube a los que ya deben una, el
mas atrasado arriba.

Los tres botones de la tabla dicen en que va cada quien:

| Color | Significa |
|---|---|
| gris | todavia no llega a ese dia, o el periodo ya cerro: no hay nada que pedir |
| naranja | **ya vencio y falta hacerla** |
| rojo | 0-49 % |
| amarillo | 50-69 % |
| verde | 70 % o mas: luz verde para contrato definitivo |

Sin fecha de contratacion los tres quedan en gris: no se puede saber que vencio.

El formulario replica el formato F-RRHH-09: ocho temas, cada uno con 0, 3 o 5
puntos que valen 0, 0.5 y 1.0 de su peso. Los pesos suman 1.0, asi que el total es
directamente el porcentaje de desempeno. «Camara obstruida» y «aviso probable
colision» no tienen punto medio, igual que en el papel.

El rol **Jefe de operaciones** se crea desde el boton Usuarios. Puede entrar y
capturar evaluaciones; el alta y la baja de conductores siguen siendo de RH.

