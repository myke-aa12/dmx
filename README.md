# API DIGITALMX

Sistema web de gestión de trámites y asignación de proveedores para Digital México.

## Características

- ✅ Autenticación y gestión de sesiones (1 hora timeout, máx 2 sesiones simultáneas)
- ✅ Gestión de usuarios (admin, proveedores, usuarios regulares)
- ✅ Sistema de pedidos y trámites
- ✅ Asignación dinámica de proveedores
- ✅ Panel administrativo con análisis de datos
- ✅ Historial de descargas con información de proveedores
- ✅ Paginación optimizada de 25 registros por página
- ✅ Subida y descarga de archivos PDF (máx 5MB)
- ✅ Protección CSRF en producción
- ✅ Rate limiting (200/día, 50/hora)
- ✅ Logging con rotación automática
- ✅ API RESTful con autenticación

## Stack Tecnológico

### Backend
- **Flask** 3.0.3 - Framework web
- **SQLite3** - Base de datos
- **Flask-SocketIO** - WebSockets en tiempo real
- **Flask-WTF** - Protección CSRF
- **Flask-Limiter** - Rate limiting
- **Python 3.x**

### Frontend
- **HTML5 / CSS3**
- **JavaScript (Vanilla)**
- **SweetAlert2** - Alertas elegantes
- **SocketIO Client** - WebSockets

### DevOps
- **Gunicorn** - Servidor WSGI
- **Nginx** - Reverse proxy
- **Systemd** - Servicio Linux

## Instalación

### Requisitos previos
- Python 3.8+
- pip
- Git

### Pasos de instalación

1. **Clonar repositorio**
   ```bash
   git clone https://github.com/tu-usuario/API-DIGITALMX.git
   cd API-DIGITALMX
   ```

2. **Crear ambiente virtual**
   ```bash
   python -m venv .venv
   # En Windows:
   .\.venv\Scripts\activate
   # En Linux/Mac:
   source .venv/bin/activate
   ```

3. **Instalar dependencias**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configurar variables de entorno**
   ```bash
   # Crear archivo .env (ver .env.example)
   cp .env.example .env
   # Editar .env con tus configuraciones
   ```

5. **Iniciar la aplicación**
   ```bash
   python app.py
   ```

   La aplicación estará disponible en `http://localhost:5000`

## Configuración

### Variables de entorno (.env)

```env
# Flask
FLASK_ENV=development
FLASK_DEBUG=false
FLASK_SECRET_KEY=tu-clave-secreta-aqui

# Bases de datos
DATABASE_PATH=usuarios.db
TRAMITES_DATABASE_PATH=tramites.db

# Rutas
UPLOAD_DIR=uploads
BACKUP_DIR=backups

# CORS
CORS_ORIGINS=http://localhost:3000

# Ambiente
API_HOST=127.0.0.1
API_PORT=5000
```

## Estructura del proyecto

```
API-DIGITALMX/
├── app.py                      # Aplicación principal
├── gunicorn_config.py          # Configuración de Gunicorn
├── nginx.conf                  # Configuración de Nginx
├── api-digitalmx.service       # Servicio Systemd
├── requirements.txt            # Dependencias Python
├── .env                        # Variables de entorno
├── .gitignore                  # Archivos a ignorar
│
├── static/                     # Archivos estáticos
│   ├── css/
│   ├── js/
│   └── images/
│
├── templates/                  # Templates HTML
│   ├── index.html              # Página principal
│   ├── login.html              # Login
│   ├── registro.html           # Registro
│   ├── pedidos.html            # Panel de pedidos
│   ├── proveedor.html          # Panel de proveedores
│   └── panel.html              # Panel administrativo
│
├── uploads/                    # Archivos subidos (usuario)
├── backups/                    # Backups de BD
├── logs/                       # Logs de aplicación
│
├── usuarios.db                 # BD de usuarios
└── tramites.db                 # BD de trámites
```

## Credenciales de prueba

**Admin:**
- Email: `admin@admin.com`
- Contraseña: `ACME0920`

**Proveedor de ejemplo:**
- Email: `proveedor1@proveedor.com`
- Contraseña: `111111`

## API Endpoints

### Autenticación
- `POST /login` - Iniciar sesión
- `POST /logout` - Cerrar sesión
- `POST /registro` - Registrar usuario

### Pedidos
- `GET /obtener_pedidos` - Obtener pedidos del usuario
- `GET /obtener_todos_pedidos` - Obtener todos los pedidos (proveedores)
- `POST /crear_pedido` - Crear nuevo pedido
- `POST /reservar_pedido` - Reservar pedido
- `POST /liberar_pedido` - Liberar pedido
- `POST /terminar_pedido` - Marcar como completado

### Archivos
- `POST /subir_archivo` - Subir archivo PDF
- `GET /descargar_archivo` - Descargar archivo

### Admin
- `POST /crear_usuario` - Crear usuario
- `GET /obtener_proveedores` - Listar proveedores
- `POST /actualizar_proveedor` - Actualizar datos de proveedor
- `POST /agregar_saldo` - Agregar saldo a usuario
- `GET /api/horarios` - Obtener horarios
- `POST /api/horarios/<id>` - Actualizar horarios

## Características de seguridad

✅ **CSRF Protection** - Activo en producción  
✅ **Rate Limiting** - Límite de requests  
✅ **Sesiones seguras** - HttpOnly, Secure cookies  
✅ **Password Hashing** - Werkzeug security  
✅ **Validación de entrada** - En todos los endpoints  
✅ **CORS restringido** - Solo orígenes permitidos  
✅ **Autenticación por sesión** - Timeout de 1 hora  
✅ **Máximo 2 sesiones** - Por usuario simultáneamente  

## Despliegue en producción

### Con Gunicorn + Nginx

1. **Instalar Gunicorn**
   ```bash
   pip install gunicorn
   ```

2. **Ejecutar con Gunicorn**
   ```bash
   gunicorn -c gunicorn_config.py app:app
   ```

3. **Configurar Nginx** (ver `nginx.conf`)

4. **Crear servicio Systemd** (ver `api-digitalmx.service`)

## Desarrollo

### Instalar dependencias de desarrollo
```bash
pip install pytest pytest-cov black flake8
```

### Ejecutar tests
```bash
pytest
```

### Linter
```bash
flake8 app.py
black app.py
```

## Logs

Los logs se almacenan en `logs/app.log` con rotación automática cada 10MB.

```bash
# Ver logs en tiempo real
tail -f logs/app.log
```

## Troubleshooting

### Error: "CSRF token missing"
- En producción, asegurate de tener `FLASK_SECRET_KEY` en `.env`
- En desarrollo, CSRF está deshabilitado por defecto

### Error: "Database locked"
- Espera unos segundos e intenta de nuevo
- Limpia `__pycache__` y bases de datos si es necesario

### Error de puerto ocupado (5000)
```bash
# Cambiar puerto en app.py o variable de entorno
# Matar proceso en puerto 5000:
# Windows:
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Linux:
lsof -i :5000
kill -9 <PID>
```

## Licencia

MIT License - Ver LICENSE.md

## Contacto

Para soporte y consultas: [Tu email aquí]

## Changelog

### v1.0.0 (Actual)
- ✅ Sistema de gestión de pedidos
- ✅ Panel administrativo funcional
- ✅ Gestión de proveedores
- ✅ Sistema de sesiones seguro
- ✅ Paginación optimizada
- ✅ Protección CSRF en producción
- ✅ Rate limiting activo
