"""
Configuración de Gunicorn para producción
Ejecutar con: gunicorn --config gunicorn_config.py app:app
"""

import multiprocessing
import os

# Configuración de socket
bind = f"0.0.0.0:{os.environ.get('PORT', 5000)}"
backlog = 2048

# Procesos Worker
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "eventlet"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
timeout = 60

# Logging
accesslog = 'logs/access.log'
errorlog = 'logs/error.log'
loglevel = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Server mechanics
daemon = False
pidfile = 'logs/gunicorn.pid'
umask = 0o022
user = None
group = None
tmp_upload_dir = None

# SSL (si está configurado en nginx)
keyfile = None
certfile = None

# Hooks
def post_fork(server, worker):
    """Después de que el proceso worker es iniciado"""
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def pre_fork(server, worker):
    """Antes de que el proceso worker sea creado"""
    pass

def pre_exec(server):
    """Antes de que se ejecute el master process"""
    server.log.info("Forked children, re-executing.")

def when_ready(server):
    """Cuando el servidor está listo para aceptar conexiones"""
    server.log.info("Server is ready. Spawning workers")

def on_exit(server):
    """Cuando el servidor está saliendo"""
    server.log.info("Server is shutting down")

# Configuración de aplicación
raw_env = [
    f"FLASK_ENV={os.environ.get('FLASK_ENV', 'production')}",
    f"FLASK_DEBUG=false"
]

# Configuración de aplicación específica
forwarded_allow_ips = '*'
secure_scheme_headers = {
    'X_FORWARDED_PROTOCOL': 'ssl',
    'X_FORWARDED_PROTO': 'https',
    'X_FORWARDED_SSL': 'on',
}
