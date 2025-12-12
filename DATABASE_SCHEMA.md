# Estructura de Bases de Datos - DigitalMX

## 1. USUARIOS.DB
Base de datos de usuarios y autenticación

### Tablas

#### usuarios
```
id              INTEGER PRIMARY KEY AUTOINCREMENT
celular         TEXT NOT NULL UNIQUE
correo          TEXT NOT NULL UNIQUE
password        TEXT NOT NULL (scrypt hash)
admin           INTEGER (0=no, 1=si)
role            INTEGER (0=usuario, 1=admin, 2=proveedor, etc)
saldo           REAL (saldo disponible)
```

**Usuarios Activos:**
- admin@admin.com (rol: admin, celular: 0000000000)

#### user_sessions
```
id              INTEGER PRIMARY KEY AUTOINCREMENT
user_id         INTEGER NOT NULL (FK -> usuarios.id)
session_id      TEXT NOT NULL UNIQUE
device_name     TEXT
ip_address      TEXT
created_at      TEXT (ISO format)
last_activity   TEXT (ISO format)
expires_at      TEXT (ISO format)
```

**Propósito:** Almacenar sesiones activas del usuario (máx 2 concurrentes)

#### archivos
```
id              INTEGER PRIMARY KEY AUTOINCREMENT
pedido_id       INTEGER NOT NULL (FK -> tramites.pedidos.id)
proveedor_id    INTEGER NOT NULL
nombre_archivo  TEXT
url_archivo     TEXT
fecha_subida    TEXT
```

#### saldos
```
id              INTEGER PRIMARY KEY AUTOINCREMENT
user_id         INTEGER NOT NULL (FK -> usuarios.id)
cantidad        REAL
concepto        TEXT
fecha           TEXT
```

---

## 2. TRAMITES.DB
Base de datos de trámites y pedidos

### Tablas

#### tramites
```
id              INTEGER PRIMARY KEY AUTOINCREMENT
tramite         TEXT NOT NULL (nombre del trámite)
precio          REAL NOT NULL
tiempo          TEXT (ej: "5-7 días")
```

**Trámites Disponibles (10):**
1. Registro de Constitución de Sociedad Mercantil - $2,500.00
2. Renovación de Licencia de Funcionamiento - $1,200.00
3. Cambio de Domicilio del Negocio - $800.00
4. Ampliación de Giro Comercial - $1,500.00
5. Disolución y Liquidación de Empresa - $3,000.00
6. Modificación de Datos Registrales - $600.00
7. Certificado de Existencia y Representación Legal - $400.00
8. Autorización de Transferencia de Acciones - $1,800.00
9. Inscripción de Apoderado - $700.00
10. Cambio de Administrador o Consejero - $900.00

#### horarios
```
id                      INTEGER PRIMARY KEY AUTOINCREMENT
tramite_id              INTEGER NOT NULL UNIQUE (FK -> tramites.id)
horario                 TEXT NOT NULL
activo                  INTEGER (0=inactivo, 1=activo)
aviso                   TEXT (mensaje de aviso)
aviso_activo            INTEGER (0=inactivo, 1=activo)
fecha_actualizacion     TEXT (ISO format)
```

**Índices:** idx_horarios_tramite_id (único)

#### pedidos
```
id                      INTEGER PRIMARY KEY AUTOINCREMENT
user_id                 INTEGER NOT NULL (FK -> usuarios.id)
estado                  INTEGER (0=Pendiente, 1=En proceso, 2=Completado, 3=Cancelado)
identificador           TEXT NOT NULL (ej: PED-1001)
tramite                 TEXT NOT NULL
fecha                   TEXT (ISO format)
precio                  REAL NOT NULL
resultado               TEXT (estado legible: "Pendiente", "En proceso", etc)
asignado_a              INTEGER (FK -> usuarios.id, NULL si no asignado)
asignado_at             TEXT (ISO format, cuándo se asignó)
correo                  TEXT (correo del usuario)
```

**Índices:**
- idx_pedidos_user_id
- idx_pedidos_estado
- idx_pedidos_identificador
- idx_pedidos_asignado_a
- idx_pedidos_correo

**Pedidos de Ejemplo (15):**
- PED-1000 a PED-1014 con diversos estados

#### procesados
```
id                      INTEGER PRIMARY KEY AUTOINCREMENT
proveedor               TEXT
identificador           TEXT
tramite                 TEXT
solicitud               TEXT
atencion                TEXT (detalles del procesamiento)
```

**Índices:**
- idx_procesados_identificador
- idx_procesados_tramite

**Registros de Ejemplo (8):**
- PROC-2000 a PROC-2007

---

## 3. CONEXIONES EN LA APLICACIÓN (app.py)

### Funciones de Conexión

#### get_db()
```python
@contextmanager
def get_db():
    """Conecta a usuarios.db"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()
```

#### get_tramites_db()
```python
@contextmanager
def get_tramites_db():
    """Conecta a tramites.db"""
    conn = sqlite3.connect(TRAMITES_DB)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()
```

### Rutas API Principales

#### POST /login
- **Entrada:** JSON {email, password}
- **Proceso:** 
  1. Valida usuario en usuarios.db
  2. Verifica límite de sesiones (máx 2)
  3. Crea registro en user_sessions
  4. Retorna session cookie
- **Salida:** {success: true, redirect: "/mis-pedidos", is_admin: true/false}

#### GET /api/horarios
- **Proceso:** Lee de tramites.db (tramites + horarios)
- **Salida:** {horarios: [{tramite_id, tramite_nombre, horario, activo, aviso, ...}]}

#### GET /mis-pedidos
- **Proceso:** Lee pedidos del usuario desde tramites.db
- **Salida:** HTML renderizado con tabla de pedidos

#### GET /api/sessions
- **Proceso:** Lista sesiones activas del usuario
- **Salida:** {sessions: [{id, device, created, expires, ...}], max_sessions: 2}

---

## 4. PROPIEDADES DE BASES DE DATOS

### Ubicación en Producción
```
/home/digitalmx/digitalmx/usuarios.db  (72 KB)
/home/digitalmx/digitalmx/tramites.db  (56 KB)
```

### Ubicación Local (Desarrollo)
```
C:\Users\Studio\Desktop\API DIGITALMX\usuarios.db
C:\Users\Studio\Desktop\API DIGITALMX\tramites.db
```

### Permisos en Servidor
```
-rw-r--r-- (644)
Propietario: digitalmx:digitalmx
```

---

## 5. SINCRONIZACIÓN

### Script de Seed (seed_db.py)
```bash
python seed_db.py
```

Genera:
- 10 trámites con datos realistas
- 10 horarios (aleatorios entre 4 opciones)
- 15 pedidos (estados variados: pendiente, en proceso, completado, cancelado)
- 8 registros procesados

### Sincronización a Producción
```bash
scp tramites.db root@165.227.7.242:/home/digitalmx/digitalmx/
scp usuarios.db root@165.227.7.242:/home/digitalmx/digitalmx/
ssh root@165.227.7.242 "chown digitalmx:digitalmx /home/digitalmx/digitalmx/*.db"
ssh root@165.227.7.242 "systemctl restart digitalmx"
```

---

## 6. VALIDACIÓN DE INTEGRIDAD

### Verificar Conexión Local
```python
import sqlite3

# Usuarios
conn = sqlite3.connect('usuarios.db')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM usuarios')
print(f"Usuarios: {c.fetchone()[0]}")
conn.close()

# Trámites
conn = sqlite3.connect('tramites.db')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM tramites')
print(f"Trámites: {c.fetchone()[0]}")
c.execute('SELECT COUNT(*) FROM pedidos')
print(f"Pedidos: {c.fetchone()[0]}")
conn.close()
```

### Verificar Conexión en Producción
```bash
ssh root@165.227.7.242 "cd /home/digitalmx/digitalmx && python3 << 'EOF'
import sqlite3
conn = sqlite3.connect('tramites.db')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM tramites')
print(f'Tramites: {c.fetchone()[0]}')
conn.close()
EOF"
```

---

## 7. NOTAS IMPORTANTES

1. **Limites de Sesión:** Máximo 2 sesiones concurrentes por usuario
2. **Rutas Protegidas:** Requieren autenticación (verifican session['user_id'])
3. **CSRF Protection:** Deshabilitado para endpoints JSON (/login)
4. **SameSite Cookies:** Lax (compatible con navegadores modernos)
5. **Sesiones Permanentes:** 1 hora de expiración
6. **Encoding:** UTF-8 en todas las bases de datos

---

Última actualización: 2025-12-12
