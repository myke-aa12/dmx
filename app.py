from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
import os
from datetime import datetime, UTC
import pytz
from flask_socketio import SocketIO
import json
import uuid
import shutil
from pathlib import Path
import csv
import io
import threading
import time

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.urandom(32)

DATABASE = 'usuarios.db'
TRAMITES_DB = 'tramites.db'
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
BACKUP_DIR = os.path.join(os.path.dirname(__file__), 'backups')

Path(UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
Path(BACKUP_DIR).mkdir(parents=True, exist_ok=True)

socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

@app.before_request
def verificar_inactividad():
    """Verifica si la sesión ha estado inactiva por más de 1 hora"""
    if 'user_id' in session and 'login_time' in session:
        from datetime import timedelta
        user_id = session.get('user_id')
        login_time = datetime.fromisoformat(session['login_time'])
        tiempo_transcurrido = datetime.now(UTC) - login_time
        
        # Si han pasado más de 1 hora, cerrar sesión
        if tiempo_transcurrido > timedelta(hours=1):
            # Limpiar de BD
            with get_db() as db:
                db.execute('DELETE FROM sesiones_activas WHERE user_id = ?', (user_id,))
                db.commit()
            session.clear()
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'message': 'Sesión expirada. Inicia sesión nuevamente.'}), 401
            flash('Sesión expirada. Por favor, inicia sesión nuevamente.', 'warning')
            return redirect(url_for('index'))
        
        # Actualizar timestamp de última actividad
        session['login_time'] = datetime.now(UTC).isoformat()
        device_fingerprint = session.get('device_fingerprint')
        if device_fingerprint:
            with get_db() as db:
                ahora = datetime.now(UTC).isoformat()
                db.execute(
                    'UPDATE sesiones_activas SET ultima_actividad = ? WHERE user_id = ? AND device_fingerprint = ?',
                    (ahora, user_id, device_fingerprint)
                )
                db.commit()

def get_db():
    """Devuelve una conexión a la base de datos de usuarios"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def get_tramites_db():
    """Devuelve una conexión a la base de datos de trámites"""
    conn = sqlite3.connect(TRAMITES_DB)
    conn.row_factory = sqlite3.Row
    return conn

def get_device_fingerprint():
    """Genera un fingerprint del dispositivo basado en user-agent"""
    import hashlib
    user_agent = request.headers.get('User-Agent', 'unknown')
    return hashlib.md5(user_agent.encode()).hexdigest()

def get_client_ip():
    """Obtiene la IP del cliente"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

def limpiar_sesiones_expiradas(user_id):
    """Elimina sesiones inactivas por más de 1 hora"""
    from datetime import datetime, timedelta
    with get_db() as db:
        hace_una_hora = (datetime.now() - timedelta(hours=1)).isoformat()
        db.execute(
            'DELETE FROM sesiones_activas WHERE user_id = ? AND ultima_actividad < ?',
            (user_id, hace_una_hora)
        )
        db.commit()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.path.startswith('/api/'):
                return jsonify({'success': False, 'message': 'No autorizado. Inicia sesión.'}), 401
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'message': 'Acceso denegado. Se requiere ser administrador.'}), 403
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def emit_event(event_name, data):
    """Emite un evento SocketIO de forma segura desde rutas HTTP usando threading"""
    def emit_in_thread():
        try:
            time.sleep(0.1)  # Pequeña pausa para asegurar conexión
            socketio.emit(event_name, data, to=None, skip_sid=None)
        except Exception as e:
            print(f'Error emitiendo evento {event_name}: {e}')
    
    # Emitir en un hilo separado para no bloquear la respuesta HTTP
    thread = threading.Thread(target=emit_in_thread)
    thread.daemon = True
    thread.start()

def init_db():
    """Inicializa la base de datos de usuarios y de trámites"""
    with app.app_context():
        with get_db() as db:
            db.execute('''
                CREATE TABLE IF NOT EXISTS usuarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    celular TEXT NOT NULL UNIQUE,
                    correo TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    admin INTEGER NOT NULL DEFAULT 0,
                    role INTEGER NOT NULL DEFAULT 0,
                    saldo REAL NOT NULL DEFAULT 0
                )
            ''')
            
            db.execute('''
                CREATE TABLE IF NOT EXISTS archivos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pedido_id INTEGER NOT NULL,
                    proveedor_id INTEGER NOT NULL,
                    storage TEXT NOT NULL DEFAULT 'local',
                    key TEXT NOT NULL,
                    nombre_original TEXT,
                    mime TEXT,
                    size INTEGER,
                    creado_en TEXT
                )
            ''')
            
            db.execute('''
                CREATE TABLE IF NOT EXISTS saldos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usuario TEXT NOT NULL,
                    abono REAL NOT NULL,
                    fecha TEXT NOT NULL
                )
            ''')
            
            db.execute('''
                CREATE TABLE IF NOT EXISTS sesiones_activas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    device_fingerprint TEXT NOT NULL,
                    timestamp_creacion TEXT NOT NULL,
                    ultima_actividad TEXT NOT NULL,
                    user_agent TEXT,
                    ip_address TEXT,
                    FOREIGN KEY(user_id) REFERENCES usuarios(id)
                )
            ''')
            
            try:
                db.execute('SELECT role FROM usuarios LIMIT 1')
            except sqlite3.OperationalError:
                db.execute('ALTER TABLE usuarios ADD COLUMN role INTEGER NOT NULL DEFAULT 0')

            try:
                db.execute('SELECT saldo FROM usuarios LIMIT 1')
            except sqlite3.OperationalError:
                db.execute('ALTER TABLE usuarios ADD COLUMN saldo REAL NOT NULL DEFAULT 0')

            existing_admin = db.execute('SELECT id FROM usuarios WHERE correo = ?', ('admin@admin.com',)).fetchone()
            if not existing_admin:
                db.execute(
                    'INSERT INTO usuarios (celular, correo, password, admin, role, saldo) VALUES (?, ?, ?, 1, 1, 0)',
                    ('0000000000', 'admin@admin.com', generate_password_hash('ACME0920'))
                )
        
        with get_tramites_db() as tdb:
            tdb.execute('''
                CREATE TABLE IF NOT EXISTS tramites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tramite TEXT NOT NULL,
                    precio REAL NOT NULL,
                    tiempo TEXT NOT NULL
                )
            ''')
            
            tdb.execute('''
                CREATE TABLE IF NOT EXISTS pedidos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    estado INTEGER NOT NULL,
                    identificador TEXT NOT NULL,
                    tramite TEXT NOT NULL,
                    fecha TEXT NOT NULL,
                    precio REAL NOT NULL,
                    resultado TEXT,
                    asignado_a INTEGER DEFAULT NULL
                )
            ''')

            tdb.execute('''
                CREATE TABLE IF NOT EXISTS procesados (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    proveedor TEXT,
                    identificador TEXT,
                    tramite TEXT,
                    solicitud TEXT,
                    atencion TEXT
                )
            ''')
            
            try:
                tdb.execute('SELECT user_id FROM pedidos LIMIT 1')
            except sqlite3.OperationalError:
                tdb.execute('ALTER TABLE pedidos ADD COLUMN user_id INTEGER NOT NULL DEFAULT 0')
            
            try:
                tdb.execute('SELECT asignado_a FROM pedidos LIMIT 1')
            except sqlite3.OperationalError:
                tdb.execute('ALTER TABLE pedidos ADD COLUMN asignado_a INTEGER DEFAULT NULL')
                
            try:
                tdb.execute('SELECT asignado_at FROM pedidos LIMIT 1')
            except sqlite3.OperationalError:
                tdb.execute('ALTER TABLE pedidos ADD COLUMN asignado_at TEXT DEFAULT NULL')
            
            try:
                tdb.execute('SELECT correo FROM pedidos LIMIT 1')
            except sqlite3.OperationalError:
                tdb.execute('ALTER TABLE pedidos ADD COLUMN correo TEXT DEFAULT NULL')
            
            tdb.execute('''
                CREATE TABLE IF NOT EXISTS horarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tramite_id INTEGER NOT NULL UNIQUE,
                    horario TEXT NOT NULL,
                    activo INTEGER NOT NULL DEFAULT 1,
                    aviso TEXT,
                    aviso_activo INTEGER NOT NULL DEFAULT 0,
                    fecha_actualizacion TEXT,
                    FOREIGN KEY(tramite_id) REFERENCES tramites(id)
                )
            ''')

@app.route('/')
def index():
    """Página principal"""
    user_logged_in = 'user_id' in session
    user_email = None
    user_saldo_str = "$0.00"
    
    if user_logged_in:
        with get_db() as db:
            user = db.execute('SELECT correo, saldo FROM usuarios WHERE id = ?', (session['user_id'],)).fetchone()
            if user:
                user_email = user['correo']
                try:
                    saldo_val = float(user['saldo'] or 0)
                except Exception:
                    saldo_val = 0.0
                user_saldo_str = f"${saldo_val:,.2f}"
    
    with get_tramites_db() as tdb:
        rows = tdb.execute('SELECT id, precio, tiempo FROM tramites').fetchall()
        tramites_map = { row['id']: {'precio': row['precio'], 'tiempo': row['tiempo']} for row in rows }
        
        # Traer horarios y avisos
        horarios_rows = tdb.execute('SELECT tramite_id, horario, activo, aviso, aviso_activo FROM horarios').fetchall()
        horarios_map = {}
        for row in horarios_rows:
            horarios_map[row['tramite_id']] = {
                'horario': row['horario'] if row['activo'] else 'No disponible',
                'activo': bool(row['activo']),
                'aviso': row['aviso'],
                'aviso_activo': bool(row['aviso_activo'])
            }

    return render_template('index.html', user_logged_in=user_logged_in, user_email=user_email, user_saldo_str=user_saldo_str, tramites_map=tramites_map, horarios_map=horarios_map)

@app.route('/login_page')
def login_page():
    """Página de login dedicada"""
    if 'user_id' in session:
        return redirect(url_for('admin_usuario_panel'))
    return render_template('login.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    """Maneja el registro de nuevos usuarios"""
    if request.method == 'POST':
        celular = request.form.get('celular', '').strip()
        correo = request.form.get('correo', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if not celular or not correo or not password or not confirm_password:
            flash('Todos los campos son obligatorios', 'error')
            return render_template('registro.html')
        
        if len(celular) != 10 or not celular.isdigit():
            flash('El celular debe tener 10 dígitos', 'error')
            return render_template('registro.html')
        
        if '@' not in correo or '.' not in correo:
            flash('Correo electrónico inválido', 'error')
            return render_template('registro.html')
        
        if len(password) < 6:
            flash('La contraseña debe tener al menos 6 caracteres', 'error')
            return render_template('registro.html')
        
        if password != confirm_password:
            flash('Las contraseñas no coinciden', 'error')
            return render_template('registro.html')
        
        with get_db() as db:
            existing_user = db.execute(
                'SELECT id FROM usuarios WHERE correo = ? OR celular = ?',
                (correo, celular)
            ).fetchone()
            
            if existing_user:
                flash('El correo o celular ya están registrados', 'error')
                return render_template('registro.html')
            
            try:
                hashed_password = generate_password_hash(password)
                db.execute(
                    'INSERT INTO usuarios (celular, correo, password, saldo) VALUES (?, ?, ?, 0)',
                    (celular, correo, hashed_password)
                )
                
                flash('¡Cuenta creada exitosamente! Ahora puedes iniciar sesión', 'success')
                return redirect(url_for('index'))
            
            except sqlite3.IntegrityError:
                flash('Error al crear la cuenta. Intenta de nuevo', 'error')
                return render_template('registro.html')
    
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    return render_template('registro.html')

@app.route('/login', methods=['POST'])
def login():
    """Maneja el inicio de sesión"""
    if request.method == 'POST':
        # Aceptar tanto JSON como FormData
        if request.is_json:
            data = request.get_json() or {}
            correo = data.get('email', '').strip()
        else:
            # FormData tradicional
            correo = request.form.get('correo', '').strip()
        
        password = request.form.get('password', '') if not request.is_json else request.get_json().get('password', '')
        
        if not correo or not password:
            return jsonify({'success': False, 'message': 'Correo y contraseña son obligatorios'})
        
        with get_db() as db:
            user = db.execute(
                'SELECT id, password, admin, role FROM usuarios WHERE correo = ?',
                (correo,)
            ).fetchone()
        
        if user and check_password_hash(user['password'], password):
            user_id = user['id']
            device_fingerprint = get_device_fingerprint()
            
            # Limpiar sesiones expiradas
            limpiar_sesiones_expiradas(user_id)
            
            with get_db() as db:
                # Contar sesiones activas
                sesiones_activas = db.execute(
                    'SELECT COUNT(*) as count FROM sesiones_activas WHERE user_id = ?',
                    (user_id,)
                ).fetchone()['count']
                
                # Si hay 2 o más sesiones, eliminar la más antigua
                if sesiones_activas >= 2:
                    sesion_antigua = db.execute(
                        'SELECT id FROM sesiones_activas WHERE user_id = ? ORDER BY timestamp_creacion ASC LIMIT 1',
                        (user_id,)
                    ).fetchone()
                    if sesion_antigua:
                        db.execute('DELETE FROM sesiones_activas WHERE id = ?', (sesion_antigua['id'],))
                        db.commit()
                
                # Registrar la nueva sesión
                ahora = datetime.now(UTC).isoformat()
                db.execute(
                    '''INSERT INTO sesiones_activas 
                       (user_id, device_fingerprint, timestamp_creacion, ultima_actividad, user_agent, ip_address) 
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    (user_id, device_fingerprint, ahora, ahora, 
                     request.headers.get('User-Agent', ''), get_client_ip())
                )
                db.commit()
            
            session['user_id'] = user_id
            session['user_email'] = correo
            session['correo'] = correo
            session['role'] = int(user['role']) if user['role'] is not None else 0
            session['is_admin'] = bool(user['admin']) or (session.get('role') == 1)
            session['device_fingerprint'] = device_fingerprint
            session['login_time'] = datetime.now(UTC).isoformat()
            
            return jsonify({
                'success': True, 
                'message': '¡Inicio de sesión exitoso!', 
                'redirect': url_for('admin_usuario_panel') if session['is_admin'] else url_for('proveedor_panel'),
                'is_admin': bool(user['admin']),
                'role': session['role']
            })
        else:
            return jsonify({'success': False, 'message': 'Correo o contraseña incorrectos'})

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """Cierra la sesión del usuario"""
    user_id = session.get('user_id')
    device_fingerprint = session.get('device_fingerprint')
    
    # Eliminar sesión de la BD
    if user_id and device_fingerprint:
        with get_db() as db:
            db.execute(
                'DELETE FROM sesiones_activas WHERE user_id = ? AND device_fingerprint = ?',
                (user_id, device_fingerprint)
            )
            db.commit()
    
    session.clear()
    flash('Has cerrado sesión exitosamente', 'success')
    redirect_to = request.args.get('redirect', 'index')
    return redirect(url_for(redirect_to))

# ===== ENDPOINTS DE HORARIOS Y AVISOS =====

@app.route('/api/horarios', methods=['GET'])
@admin_required
def get_horarios():
    """Obtiene todos los horarios y avisos"""
    try:
        with get_tramites_db() as tdb:
            # Obtener todos los trámites
            tramites = tdb.execute('SELECT id, tramite FROM tramites ORDER BY id').fetchall()
            
            # Obtener horarios existentes
            horarios = tdb.execute('SELECT tramite_id, horario, activo, aviso, aviso_activo FROM horarios').fetchall()
            horarios_dict = {row['tramite_id']: {
                'horario': row['horario'],
                'activo': bool(row['activo']),
                'aviso': row['aviso'],
                'aviso_activo': bool(row['aviso_activo'])
            } for row in horarios}
            
            # Combinar datos
            result = []
            for tramite in tramites:
                tid = tramite['id']
                h = horarios_dict.get(tid, {
                    'horario': 'Todos los días de 09:00 a 18:00 Hrs',
                    'activo': True,
                    'aviso': '',
                    'aviso_activo': False
                })
                result.append({
                    'tramite_id': tid,
                    'tramite_nombre': tramite['tramite'],
                    'horario': h['horario'],
                    'activo': h['activo'],
                    'aviso': h['aviso'],
                    'aviso_activo': h['aviso_activo']
                })
            
            return jsonify({'success': True, 'horarios': result})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/horarios/<int:tramite_id>', methods=['POST'])
@admin_required
def actualizar_horario(tramite_id):
    """Actualiza horario y aviso de un trámite"""
    try:
        data = request.get_json()
        horario = data.get('horario', '').strip()
        activo = bool(data.get('activo', True))
        aviso = data.get('aviso', '').strip()
        aviso_activo = bool(data.get('aviso_activo', False))
        
        if not horario:
            return jsonify({'success': False, 'message': 'El horario es obligatorio'}), 400
        
        with get_tramites_db() as tdb:
            # Verificar si el trámite existe
            tramite = tdb.execute('SELECT id FROM tramites WHERE id = ?', (tramite_id,)).fetchone()
            if not tramite:
                return jsonify({'success': False, 'message': 'Trámite no encontrado'}), 404
            
            # Insertar o actualizar horario
            existing = tdb.execute('SELECT id FROM horarios WHERE tramite_id = ?', (tramite_id,)).fetchone()
            
            if existing:
                tdb.execute('''
                    UPDATE horarios 
                    SET horario = ?, activo = ?, aviso = ?, aviso_activo = ?, fecha_actualizacion = ?
                    WHERE tramite_id = ?
                ''', (horario, int(activo), aviso, int(aviso_activo), datetime.now().isoformat(), tramite_id))
            else:
                tdb.execute('''
                    INSERT INTO horarios (tramite_id, horario, activo, aviso, aviso_activo, fecha_actualizacion)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (tramite_id, horario, int(activo), aviso, int(aviso_activo), datetime.now().isoformat()))
            
            tdb.commit()
            return jsonify({'success': True, 'message': 'Horario actualizado correctamente'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin_usuario_panel')
@app.route('/mis-pedidos')
@login_required
def admin_usuario_panel():
    """Panel de pedidos del usuario (requiere login)"""
    with get_tramites_db() as tdb:
        tramites = tdb.execute('SELECT DISTINCT tramite FROM tramites ORDER BY tramite ASC').fetchall()
    return render_template('pedidos.html', tramites=tramites)

@app.route('/obtener_pedidos', methods=['GET'])
@login_required
def obtener_pedidos():
    """Obtiene los pedidos del usuario logueado"""
    user_id = session.get('user_id')
    
    with get_tramites_db() as tdb:
        pedidos = tdb.execute(
            'SELECT id, estado, identificador, tramite, fecha, precio, resultado FROM pedidos WHERE user_id = ? ORDER BY id DESC',
            (user_id,)
        ).fetchall()
    pedidos_list = [dict(p) for p in pedidos]
    
    return jsonify({'pedidos': pedidos_list})

@app.route('/obtener_todos_pedidos', methods=['GET'])
@login_required
def obtener_todos_pedidos():
    """Obtiene todos los pedidos (solo para proveedores)"""
    if session.get('role') != 2:
        return jsonify({'success': False, 'message': 'No autorizado'}), 403
    
    proveedor_id = session.get('user_id')
    
    with get_tramites_db() as tdb:
        pedidos = tdb.execute(
            'SELECT id, estado, identificador, tramite, fecha, precio, resultado, asignado_a, asignado_at FROM pedidos ORDER BY id DESC'
        ).fetchall()
    pedidos_list = [dict(p) for p in pedidos]
    
    return jsonify({'pedidos': pedidos_list, 'proveedor_id': proveedor_id})

@app.route('/obtener_tramites_procesados', methods=['GET'])
@login_required
def obtener_tramites_procesados():
    """Obtiene los trámites procesados del proveedor logueado desde la tabla procesados"""
    if session.get('role') != 2:
        return jsonify({'success': False, 'message': 'No autorizado'}), 403
    
    # Obtener el correo del usuario logueado (que es el proveedor)
    correo = session.get('correo')
    
    # Parámetros de paginación
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    
    with get_tramites_db() as tdb:
        # Obtener total de registros que coinciden
        total_result = tdb.execute(
            'SELECT COUNT(*) as total FROM procesados WHERE proveedor = ?',
            (correo,)
        ).fetchone()
        total = total_result['total'] if total_result else 0
        
        # Obtener los registros paginados
        procesados = tdb.execute(
            'SELECT identificador, tramite, solicitud, atencion FROM procesados WHERE proveedor = ? ORDER BY id DESC LIMIT ? OFFSET ?',
            (correo, per_page, offset)
        ).fetchall()
        
        # Obtener lista de trámites únicos para el filtro
        tramites = tdb.execute(
            'SELECT DISTINCT tramite FROM procesados WHERE proveedor = ? ORDER BY tramite ASC',
            (correo,)
        ).fetchall()
    
    procesados_list = [dict(p) for p in procesados]
    tramites_list = [dict(t)['tramite'] for t in tramites]
    
    return jsonify({
        'success': True,
        'procesados': procesados_list,
        'tramites': tramites_list,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page
    })

@app.route('/reservar_pedido', methods=['POST'])
@login_required
def reservar_pedido():
    """Reserva un pedido para un proveedor"""
    if session.get('role') != 2:
        return jsonify({'success': False, 'message': 'No autorizado'}), 403
    
    try:
        data = request.get_json()
        pedido_id = data.get('pedido_id')
        proveedor_id = session.get('user_id')
        
        if not pedido_id:
            return jsonify({'success': False, 'message': 'ID de pedido requerido'})
        
        with get_tramites_db() as tdb:
            pedido = tdb.execute(
                'SELECT id, asignado_a FROM pedidos WHERE id = ?',
                (pedido_id,)
            ).fetchone()

            if not pedido:
                return jsonify({'success': False, 'message': 'Pedido no encontrado'})

            if pedido['asignado_a'] is not None:
                return jsonify({'success': False, 'message': 'Este pedido ya fue tomado por otro proveedor'})

            now_iso = datetime.now(UTC).isoformat()
            tdb.execute(
                'UPDATE pedidos SET asignado_a = ?, asignado_at = ? WHERE id = ?',
                (proveedor_id, now_iso, pedido_id)
            )
            emit_event('pedido_actualizado', {'pedido_id': pedido_id})
        
        return jsonify({'success': True, 'message': 'Pedido reservado exitosamente'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})


@app.route('/liberar_pedido', methods=['POST'])
@login_required
def liberar_pedido():
    """Libera la reserva de un pedido por el proveedor que la tiene"""
    if session.get('role') != 2:
        return jsonify({'success': False, 'message': 'No autorizado'}), 403
    try:
        data = request.get_json()
        pedido_id = data.get('pedido_id')
        proveedor_id = session.get('user_id')
        if not pedido_id:
            return jsonify({'success': False, 'message': 'ID de pedido requerido'})
        with get_tramites_db() as tdb:
            pedido = tdb.execute('SELECT id, asignado_a FROM pedidos WHERE id = ?', (pedido_id,)).fetchone()
            if not pedido:
                return jsonify({'success': False, 'message': 'Pedido no encontrado'})
            if pedido['asignado_a'] != proveedor_id:
                return jsonify({'success': False, 'message': 'No autorizado para liberar este pedido'})
            tdb.execute('UPDATE pedidos SET asignado_a = NULL, asignado_at = NULL WHERE id = ?', (pedido_id,))
        emit_event('pedido_actualizado', {'pedido_id': pedido_id})
        return jsonify({'success': True, 'message': 'Reserva liberada'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/terminar_pedido', methods=['POST'])
@login_required
def terminar_pedido():
    """Marca un pedido como terminado (sin éxito) por el proveedor actual y guarda el motivo"""
    if session.get('role') != 2:
        return jsonify({'success': False, 'message': 'No autorizado'}), 403
    try:
        data = request.get_json()
        pedido_id = data.get('pedido_id')
        motivo = data.get('motivo', '').strip()
        proveedor_id = session.get('user_id')

        if not pedido_id:
            return jsonify({'success': False, 'message': 'ID de pedido requerido'})

        with get_tramites_db() as tdb:
            pedido = tdb.execute('SELECT id, asignado_a, user_id, precio, estado FROM pedidos WHERE id = ?', (pedido_id,)).fetchone()
            if not pedido:
                return jsonify({'success': False, 'message': 'Pedido no encontrado'})
            if pedido['asignado_a'] != proveedor_id:
                return jsonify({'success': False, 'message': 'No autorizado para terminar este pedido'})
            try:
                estado_actual = int(pedido['estado']) if pedido['estado'] is not None else 0
            except Exception:
                estado_actual = 0
            if estado_actual in (2, 3):
                return jsonify({'success': False, 'message': 'El pedido ya fue finalizado previamente'})

            user_id_pedido = int(pedido['user_id'])
            try:
                precio_pedido = float(pedido['precio'] or 0)
            except Exception:
                precio_pedido = 0.0

        with get_db() as db:
            db.execute('UPDATE usuarios SET saldo = saldo + ? WHERE id = ?', (precio_pedido, user_id_pedido))

        with get_tramites_db() as tdb:
            tdb.execute(
                'UPDATE pedidos SET estado = ?, resultado = ?, asignado_a = NULL, asignado_at = NULL WHERE id = ?',
                (3, motivo, pedido_id)
            )

        emit_event('pedido_actualizado', {'pedido_id': pedido_id})

        return jsonify({'success': True, 'message': 'Pedido marcado como sin éxito'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/crear_pedido', methods=['POST'])
@login_required
def crear_pedido():
    """Crea un nuevo pedido en la tabla pedidos"""
    try:
        data = request.get_json()
        identificador = data.get('identificador', '').strip().upper()
        tramite_id = data.get('tramite_id', '')
        user_id = session.get('user_id')
        
        if not identificador or not tramite_id:
            return jsonify({'success': False, 'message': 'Datos incompletos'})
        
        if len(identificador) != 18:
            return jsonify({'success': False, 'message': 'El CURP debe tener 18 caracteres'})
        
        with get_tramites_db() as tdb:
            tramite = tdb.execute(
                'SELECT tramite, precio FROM tramites WHERE id = ?',
                (tramite_id,)
            ).fetchone()
            
            if not tramite:
                return jsonify({'success': False, 'message': 'Trámite no encontrado'})
            
            precio_tramite = float(tramite['precio'])
        
        with get_db() as db:
            usuario = db.execute(
                'SELECT saldo FROM usuarios WHERE id = ?',
                (user_id,)
            ).fetchone()
            
            if not usuario:
                return jsonify({'success': False, 'message': 'Usuario no encontrado'})
            
            saldo_actual = float(usuario['saldo'])
            
            if saldo_actual < precio_tramite:
                return jsonify({'success': False, 'message': 'Saldo insuficiente'})
            
            nuevo_saldo = saldo_actual - precio_tramite
            db.execute(
                'UPDATE usuarios SET saldo = ? WHERE id = ?',
                (nuevo_saldo, user_id)
            )
        
        tz_mexico = pytz.timezone('America/Mexico_City')
        fecha_actual = datetime.now(tz_mexico).strftime('%d/%m/%y %H:%M')
        
        # Obtener correo del usuario logueado
        user_correo = session.get('user_email') or session.get('correo') or ''
        
        with get_tramites_db() as tdb:
            tdb.execute('''
                INSERT INTO pedidos (user_id, estado, identificador, tramite, fecha, precio, resultado, correo)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, 1, identificador, tramite['tramite'], fecha_actual, precio_tramite, None, user_correo))
        
        return jsonify({'success': True, 'message': 'Pedido creado exitosamente'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})


@app.route('/subir_archivo', methods=['POST'])
@login_required
def subir_archivo():
    """Sube un archivo PDF (<=5MB) para un pedido asignado al proveedor. Marca el pedido como éxito y guarda metadatos."""
    if session.get('role') != 2:
        return jsonify({'success': False, 'message': 'No autorizado'}), 403
    try:
        pedido_id = request.form.get('pedido_id')
        proveedor_id = session.get('user_id')
        file = request.files.get('file')
        if not pedido_id or not file:
            return jsonify({'success': False, 'message': 'Pedido ID y archivo requeridos'})

        filename_orig = file.filename or ''
        ext = os.path.splitext(filename_orig)[1].lower()
        if ext != '.pdf':
            return jsonify({'success': False, 'message': 'Solo se permiten archivos PDF'})
        file.seek(0, os.SEEK_END)
        size_bytes = file.tell()
        file.seek(0)
        if size_bytes > 5 * 1024 * 1024:
            return jsonify({'success': False, 'message': 'El archivo excede el límite de 5MB'})

        with get_tramites_db() as tdb:
            pedido = tdb.execute('SELECT id, asignado_a, resultado, estado FROM pedidos WHERE id = ?', (pedido_id,)).fetchone()
            if not pedido:
                return jsonify({'success': False, 'message': 'Pedido no encontrado'})
            if pedido['asignado_a'] != proveedor_id:
                return jsonify({'success': False, 'message': 'No autorizado para subir archivo en este pedido'})
            try:
                estado_actual = int(pedido['estado']) if pedido['estado'] is not None else 0
            except Exception:
                estado_actual = 0
            if estado_actual in (2, 3):
                return jsonify({'success': False, 'message': 'El pedido ya fue finalizado'})

        filename = f"{uuid.uuid4().hex}{ext}"
        save_path = os.path.join(UPLOAD_DIR, filename)
        file.save(save_path)

        now_iso = datetime.now(UTC).isoformat()
        with get_db() as db:
            db.execute(
                'INSERT INTO archivos (pedido_id, proveedor_id, storage, key, nombre_original, mime, size, creado_en) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (pedido_id, proveedor_id, 'local', filename, filename_orig, 'application/pdf', size_bytes, now_iso)
            )
        with get_tramites_db() as tdb:
            pedido = tdb.execute('SELECT resultado FROM pedidos WHERE id = ?', (pedido_id,)).fetchone()
            prev = pedido['resultado'] if pedido else None
            try:
                prev_obj = json.loads(prev) if prev else {}
            except Exception:
                prev_obj = {'raw': prev} if prev else {}
            files = prev_obj.get('files', [])
            files.append({'storage': 'local', 'key': filename, 'name': filename_orig, 'mime': 'application/pdf', 'size': size_bytes})
            prev_obj['files'] = files
            nueva = json.dumps(prev_obj, ensure_ascii=False)
            tdb.execute('UPDATE pedidos SET resultado = ?, estado = ?, asignado_a = NULL, asignado_at = NULL WHERE id = ?', (nueva, 2, pedido_id))

        emit_event('pedido_actualizado', {'pedido_id': int(pedido_id)})

        try:
            with get_tramites_db() as tdb:
                pedido = tdb.execute('SELECT identificador, tramite, fecha FROM pedidos WHERE id = ?', (pedido_id,)).fetchone()
            proveedor_nombre = session.get('nombre') or session.get('correo') or ''
            identificador = pedido['identificador'] if pedido else ''
            tramite = pedido['tramite'] if pedido else ''
            solicitud = pedido['fecha'] if pedido else ''
            tz_mexico = pytz.timezone('America/Mexico_City')
            atencion = datetime.now(tz_mexico).strftime('%d/%m/%Y %H:%M')
            with get_tramites_db() as tdb:
                tdb.execute(
                    'INSERT INTO procesados (proveedor, identificador, tramite, solicitud, atencion) VALUES (?, ?, ?, ?, ?)',
                    (proveedor_nombre, identificador, tramite, solicitud, atencion)
                )
        except Exception as e:
            pass
        return jsonify({'success': True, 'message': 'Archivo subido', 'url': f"/descargar_archivo?key={filename}"})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})


@app.route('/descargar_archivo')
@login_required
def descargar_archivo():
    """Descarga un archivo local por clave (key) verificando autorización por pedido."""
    key = request.args.get('key', '').strip()
    if not key:
        return jsonify({'success': False, 'message': 'Key requerida'}), 400
    with get_db() as db:
        meta = db.execute('SELECT pedido_id, nombre_original FROM archivos WHERE key = ?', (key,)).fetchone()
    if not meta:
        return jsonify({'success': False, 'message': 'Archivo no encontrado'}), 404

    pedido_id = meta['pedido_id']

    user_id = session.get('user_id')
    is_admin = session.get('is_admin')
    with get_tramites_db() as tdb:
        ped = tdb.execute('SELECT user_id, asignado_a FROM pedidos WHERE id = ?', (pedido_id,)).fetchone()
    if not ped:
        return jsonify({'success': False, 'message': 'Pedido no encontrado'}), 404
    if not (is_admin or ped['user_id'] == user_id or ped['asignado_a'] == user_id):
        return jsonify({'success': False, 'message': 'No autorizado'}), 403

    path = os.path.join(UPLOAD_DIR, key)
    if not os.path.isfile(path):
        return jsonify({'success': False, 'message': 'Archivo no disponible'}), 404
    try:
        return send_from_directory(UPLOAD_DIR, key, as_attachment=True, download_name=(meta['nombre_original'] or key))
    except TypeError:
        return send_from_directory(UPLOAD_DIR, key, as_attachment=True)

@app.route('/panel')
@admin_required
def panel_admin():
    with get_tramites_db() as tdb:
        tramites = tdb.execute('SELECT id, tramite, precio, tiempo FROM tramites ORDER BY id ASC').fetchall()
    return render_template('panel.html', tramites=tramites)

@app.route('/proveedor')
@login_required
def proveedor_panel():
    if session.get('role') != 2:
        return redirect(url_for('index'))
    with get_tramites_db() as tdb:
        tramites = tdb.execute('SELECT DISTINCT tramite FROM tramites ORDER BY tramite ASC').fetchall()
    return render_template('proveedor.html', tramites=tramites)

@app.route('/crear_usuario', methods=['POST'])
@admin_required
def crear_usuario():
    """Crear un usuario (solo admin) desde el panel"""
    try:
        data = request.get_json() if request.is_json else request.form
        celular = data.get('celular', '').strip()
        correo = data.get('correo', '').strip()
        password = data.get('password', '').strip()
        role = int(data.get('role', 0)) if data.get('role') is not None else 0

        if not celular or not correo or not password:
            return jsonify({'success': False, 'message': 'Datos incompletos'})

        if len(celular) != 10 or not celular.isdigit():
            return jsonify({'success': False, 'message': 'Celular inválido'})

        if '@' not in correo or '.' not in correo:
            return jsonify({'success': False, 'message': 'Correo inválido'})

        if len(password) < 6:
            return jsonify({'success': False, 'message': 'La contraseña debe tener al menos 6 caracteres'})

        hashed = generate_password_hash(password)
        admin_flag = 1 if role == 1 else 0
        with get_db() as db:
            existing = db.execute('SELECT id FROM usuarios WHERE correo = ? OR celular = ?', (correo, celular)).fetchone()
            if existing:
                return jsonify({'success': False, 'message': 'El correo o celular ya están registrados'})
            db.execute('INSERT INTO usuarios (celular, correo, password, admin, role, saldo) VALUES (?, ?, ?, ?, ?, ?)', (celular, correo, hashed, admin_flag, role, 0))
        return jsonify({'success': True, 'message': 'Usuario creado'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error al crear usuario'})

@app.route('/tramites/nuevo', methods=['POST'])
@admin_required
def crear_tramite():
    tramite = request.form.get('tramite', '').strip()
    precio = request.form.get('precio', '').strip()
    tiempo = request.form.get('tiempo', '').strip()

    if not tramite or not precio or not tiempo:
        return redirect(url_for('panel_admin'))

    try:
        precio_val = float(precio)
    except ValueError:
        return redirect(url_for('panel_admin'))

    with get_tramites_db() as tdb:
        tdb.execute('INSERT INTO tramites (tramite, precio, tiempo) VALUES (?, ?, ?)', (tramite, precio_val, tiempo))
    return redirect(url_for('panel_admin'))

@app.route('/tramites/<int:tramite_id>', methods=['POST'])
@admin_required
def actualizar_tramite(tramite_id):
    tramite = request.form.get('tramite', '').strip()
    precio = request.form.get('precio', '').strip()
    tiempo = request.form.get('tiempo', '').strip()

    fields = []
    values = []
    if tramite:
        fields.append('tramite = ?')
        values.append(tramite)
    if precio:
        try:
            values.append(float(precio))
            fields.append('precio = ?')
        except ValueError:
            pass
    if tiempo:
        fields.append('tiempo = ?')
        values.append(tiempo)

    if fields:
        sql = 'UPDATE tramites SET ' + ', '.join(fields) + ' WHERE id = ?'
        values.append(tramite_id)
        with get_tramites_db() as tdb:
            tdb.execute(sql, values)

    return redirect(url_for('panel_admin'))

@app.route('/verificar_sesion')
def verificar_sesion():
    """Endpoint para verificar si el usuario está logueado"""
    return jsonify({'logged_in': 'user_id' in session})

@app.route('/buscar_usuarios', methods=['POST'])
@admin_required
def buscar_usuarios():
    """Busca usuarios por correo o celular (solo admin)"""
    try:
        data = request.get_json()
        busqueda = data.get('busqueda', '').strip().lower()
        
        if not busqueda:
            return jsonify({'usuarios': []})
        
        with get_db() as db:
            usuarios = db.execute(
                'SELECT id, correo, celular, saldo FROM usuarios WHERE LOWER(correo) LIKE ? OR celular LIKE ? ORDER BY correo ASC',
                (f'%{busqueda}%', f'%{busqueda}%')
            ).fetchall()
        
        usuarios_list = [{'id': u['id'], 'correo': u['correo'], 'celular': u['celular'], 'saldo': u['saldo']} for u in usuarios]
        return jsonify({'usuarios': usuarios_list})
    except Exception as e:
        return jsonify({'usuarios': []})

@app.route('/agregar_saldo', methods=['POST'])
@admin_required
def agregar_saldo():
    """Agrega saldo a un usuario (solo admin)"""
    try:
        data = request.get_json()
        usuario_id = data.get('usuario_id')
        monto = float(data.get('monto', 0))
        set_saldo = data.get('set', False)

        if not usuario_id or (not set_saldo and monto <= 0):
            return jsonify({'success': False, 'message': 'Datos inválidos'})

        with get_db() as db:
            usuario = db.execute('SELECT id, saldo, correo FROM usuarios WHERE id = ?', (usuario_id,)).fetchone()
            if not usuario:
                return jsonify({'success': False, 'message': 'Usuario no encontrado'})

            if set_saldo:
                nuevo_saldo = monto
            else:
                nuevo_saldo = float(usuario['saldo']) + monto
            db.execute('UPDATE usuarios SET saldo = ? WHERE id = ?', (nuevo_saldo, usuario_id))
            
            # Registrar el abono en la tabla saldos
            correo_usuario = usuario['correo']
            tz_mexico = pytz.timezone('America/Mexico_City')
            fecha_registro = datetime.now(tz_mexico).strftime('%d/%m/%Y %H:%M')
            
            # Solo registrar si es un abono (monto positivo o ajuste de saldo)
            monto_registrar = monto if not set_saldo else monto
            db.execute(
                'INSERT INTO saldos (usuario, abono, fecha) VALUES (?, ?, ?)',
                (correo_usuario, monto_registrar, fecha_registro)
            )

        return jsonify({'success': True, 'message': 'Saldo actualizado' if set_saldo else 'Saldo agregado', 'nuevo_saldo': nuevo_saldo})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})


@app.route('/obtener_proveedores', methods=['GET'])
@admin_required
def obtener_proveedores():
    """Obtiene lista de proveedores registrados (role=2) - solo admin"""
    try:
        with get_db() as db:
            proveedores = db.execute(
                'SELECT id, celular, correo FROM usuarios WHERE role = 2 ORDER BY id ASC'
            ).fetchall()
        proveedores_list = [{'id': p['id'], 'celular': p['celular'], 'correo': p['correo']} for p in proveedores]
        return jsonify({'proveedores': proveedores_list})
    except Exception as e:
        return jsonify({'proveedores': []})

@app.route('/actualizar_proveedor', methods=['POST'])
@admin_required
def actualizar_proveedor():
    """Actualiza datos de un proveedor - solo admin"""
    try:
        data = request.get_json()
        proveedor_id = data.get('proveedor_id')
        celular = data.get('celular', '').strip()
        correo = data.get('correo', '').strip()
        password = data.get('password', '').strip()
        
        if not proveedor_id or not celular or not correo:
            return jsonify({'success': False, 'message': 'Datos incompletos'})
        
        if len(celular) != 10 or not celular.isdigit():
            return jsonify({'success': False, 'message': 'Celular inválido'})
        
        with get_db() as db:
            proveedor = db.execute(
                'SELECT id, role FROM usuarios WHERE id = ?',
                (proveedor_id,)
            ).fetchone()
            
            if not proveedor:
                return jsonify({'success': False, 'message': 'Proveedor no encontrado'})
            
            if proveedor['role'] != 2:
                return jsonify({'success': False, 'message': 'Este usuario no es un proveedor'})
            
            existing = db.execute(
                'SELECT id FROM usuarios WHERE (celular = ? OR correo = ?) AND id != ?',
                (celular, correo, proveedor_id)
            ).fetchone()
            
            if existing:
                return jsonify({'success': False, 'message': 'El celular o correo ya están registrados'})
            
            if password:
                hashed_password = generate_password_hash(password)
                db.execute(
                    'UPDATE usuarios SET celular = ?, correo = ?, password = ? WHERE id = ?',
                    (celular, correo, hashed_password, proveedor_id)
                )
            else:
                db.execute(
                    'UPDATE usuarios SET celular = ?, correo = ? WHERE id = ?',
                    (celular, correo, proveedor_id)
                )
        
        return jsonify({'success': True, 'message': 'Proveedor actualizado exitosamente'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/obtener_saldo', methods=['GET'])
@login_required
def obtener_saldo():
    """Obtiene el saldo actual del usuario logueado formateado como moneda"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'success': False, 'saldo': '$0.00', 'message': 'No hay usuario logueado'})
        
        with get_db() as db:
            usuario = db.execute('SELECT saldo FROM usuarios WHERE id = ?', (user_id,)).fetchone()
            
            if not usuario:
                return jsonify({'success': False, 'saldo': '$0.00', 'message': 'Usuario no encontrado'})
            
            try:
                saldo_val = float(usuario['saldo'] or 0)
            except Exception:
                saldo_val = 0.0
            
            saldo_str = f"${saldo_val:,.2f}"
            return jsonify({'success': True, 'saldo': saldo_str, 'saldo_raw': saldo_val})
    except Exception as e:
        return jsonify({'success': False, 'saldo': '$0.00', 'message': f'Error: {str(e)}'})


@app.route('/admin/backup')
@admin_required
def backup_dbs():
    """Crea un backup de las bases de datos y lo devuelve como un zip sin guardar."""
    try:
        import zipfile
        
        # Crear ZIP en memoria
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            if os.path.exists(DATABASE):
                zf.write(DATABASE, os.path.basename(DATABASE))
            if os.path.exists(TRAMITES_DB):
                zf.write(TRAMITES_DB, os.path.basename(TRAMITES_DB))
        
        zip_buffer.seek(0)
        backup_filename = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        
        return send_file(
            zip_buffer,
            mimetype='application/zip',
            as_attachment=True,
            download_name=backup_filename
        )
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error al crear backup: {str(e)}'}), 500

@app.route('/api/pedidos', methods=['GET'])
@admin_required
def api_pedidos():
    """API endpoint para obtener los pedidos con paginación y filtros."""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('search', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()
    status = request.args.get('status', '').strip()

    params = []
    base_query = "FROM pedidos"
    where_clauses = []

    if search:
        where_clauses.append("(identificador LIKE ? OR tramite LIKE ? OR correo LIKE ?)")
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

    if status:
        try:
            status_int = int(status)
            where_clauses.append("estado = ?")
            params.append(status_int)
        except Exception:
            pass

    if date_from:
        formatted_date_from = datetime.strptime(date_from, '%Y-%m-%d').strftime('%y-%m-%d')
        where_clauses.append("SUBSTR(fecha, 7, 2) || '-' || SUBSTR(fecha, 4, 2) || '-' || SUBSTR(fecha, 1, 2) >= ?")
        params.append(formatted_date_from)
    if date_to:
        formatted_date_to = datetime.strptime(date_to, '%Y-%m-%d').strftime('%y-%m-%d')
        where_clauses.append("SUBSTR(fecha, 7, 2) || '-' || SUBSTR(fecha, 4, 2) || '-' || SUBSTR(fecha, 1, 2) <= ?")
        params.append(formatted_date_to)

    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)

    with get_tramites_db() as tdb:
        count_query = "SELECT COUNT(*) " + base_query
        total_records = tdb.execute(count_query, params).fetchone()[0]
        total_pages = (total_records + per_page - 1) // per_page

        offset = (page - 1) * per_page
        data_query = "SELECT * " + base_query + " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        pedidos = tdb.execute(data_query, params).fetchall()

    pedidos_list = [dict(p) for p in pedidos]

    return jsonify({
        'pedidos': pedidos_list,
        'page': page,
        'total_pages': total_pages,
        'total_records': total_records
    })


@app.route('/api/saldos', methods=['GET'])
@admin_required
def api_saldos():
    """API endpoint para obtener los saldos con paginación y filtros."""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('search', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()

    params = []
    base_query = "FROM saldos"
    where_clauses = []

    if search:
        where_clauses.append("usuario LIKE ?")
        params.append(f'%{search}%')

    if date_from:
        # Convertir fecha de YYYY-MM-DD a DD/MM/YYYY para comparar
        try:
            formatted_date_from = datetime.strptime(date_from, '%Y-%m-%d').strftime('%d/%m/%Y')
            where_clauses.append("DATE(SUBSTR(fecha, 7, 4) || '-' || SUBSTR(fecha, 4, 2) || '-' || SUBSTR(fecha, 1, 2)) >= ?")
            params.append(formatted_date_from)
        except:
            pass

    if date_to:
        try:
            formatted_date_to = datetime.strptime(date_to, '%Y-%m-%d').strftime('%d/%m/%Y')
            where_clauses.append("DATE(SUBSTR(fecha, 7, 4) || '-' || SUBSTR(fecha, 4, 2) || '-' || SUBSTR(fecha, 1, 2)) <= ?")
            params.append(formatted_date_to)
        except:
            pass

    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)

    with get_db() as db:
        count_query = "SELECT COUNT(*) " + base_query
        total_records = db.execute(count_query, params).fetchone()[0]
        total_pages = (total_records + per_page - 1) // per_page

        offset = (page - 1) * per_page
        data_query = "SELECT * " + base_query + " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        saldos = db.execute(data_query, params).fetchall()

    saldos_list = [dict(s) for s in saldos]

    return jsonify({
        'saldos': saldos_list,
        'page': page,
        'total_pages': total_pages,
        'total_records': total_records
    })


@app.route('/api/saldos/delete', methods=['POST'])
@admin_required
def delete_saldos():
    """Elimina registros de saldos por IDs."""
    try:
        data = request.get_json()
        ids = data.get('ids', [])
        
        if not ids or not isinstance(ids, list):
            return jsonify({'success': False, 'message': 'Se requiere una lista de IDs.'}), 400

        with get_db() as db:
            placeholders = ','.join(['?'] * len(ids))
            db.execute(f"DELETE FROM saldos WHERE id IN ({placeholders})", ids)
            db.commit()

        return jsonify({'success': True, 'message': f'{len(ids)} registros eliminados.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@app.route('/api/saldos/delete-filtered', methods=['POST'])
@admin_required
def delete_saldos_filtered():
    """Elimina registros de saldos que coinciden con los filtros."""
    try:
        data = request.get_json()
        search = data.get('search', '').strip()
        date_from = data.get('date_from', '').strip()
        date_to = data.get('date_to', '').strip()

        params = []
        where_clauses = []

        if search:
            where_clauses.append("usuario LIKE ?")
            params.append(f'%{search}%')

        if date_from:
            try:
                formatted_date_from = datetime.strptime(date_from, '%Y-%m-%d').strftime('%d/%m/%Y')
                where_clauses.append("DATE(SUBSTR(fecha, 7, 4) || '-' || SUBSTR(fecha, 4, 2) || '-' || SUBSTR(fecha, 1, 2)) >= ?")
                params.append(formatted_date_from)
            except:
                pass

        if date_to:
            try:
                formatted_date_to = datetime.strptime(date_to, '%Y-%m-%d').strftime('%d/%m/%Y')
                where_clauses.append("DATE(SUBSTR(fecha, 7, 4) || '-' || SUBSTR(fecha, 4, 2) || '-' || SUBSTR(fecha, 1, 2)) <= ?")
                params.append(formatted_date_to)
            except:
                pass

        if not where_clauses:
            return jsonify({'success': False, 'message': 'Se requieren filtros para eliminar.'}), 400

        where_sql = " WHERE " + " AND ".join(where_clauses)

        with get_db() as db:
            # Contar cuántos serán eliminados
            count_query = "SELECT COUNT(*) FROM saldos" + where_sql
            count = db.execute(count_query, params).fetchone()[0]
            
            # Eliminar
            delete_query = "DELETE FROM saldos" + where_sql
            db.execute(delete_query, params)
            db.commit()

        return jsonify({'success': True, 'message': f'{count} registros eliminados.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@app.route('/export/saldos/csv')
@admin_required
def export_saldos_csv():
    """Exporta los saldos filtrados a un archivo CSV."""
    search = request.args.get('search', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()

    params = []
    base_query = "FROM saldos"
    where_clauses = []

    if search:
        where_clauses.append("usuario LIKE ?")
        params.append(f'%{search}%')

    if date_from:
        try:
            formatted_date_from = datetime.strptime(date_from, '%Y-%m-%d').strftime('%d/%m/%Y')
            where_clauses.append("DATE(SUBSTR(fecha, 7, 4) || '-' || SUBSTR(fecha, 4, 2) || '-' || SUBSTR(fecha, 1, 2)) >= ?")
            params.append(formatted_date_from)
        except:
            pass

    if date_to:
        try:
            formatted_date_to = datetime.strptime(date_to, '%Y-%m-%d').strftime('%d/%m/%Y')
            where_clauses.append("DATE(SUBSTR(fecha, 7, 4) || '-' || SUBSTR(fecha, 4, 2) || '-' || SUBSTR(fecha, 1, 2)) <= ?")
            params.append(formatted_date_to)
        except:
            pass

    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)

    data_query = "SELECT * " + base_query + " ORDER BY id DESC"

    with get_db() as db:
        saldos = db.execute(data_query, params).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)

    if not saldos:
        writer.writerow(['No hay datos para exportar con los filtros seleccionados.'])
    else:
        headers = ['ID', 'Usuario', 'Abono', 'Fecha']
        writer.writerow(headers)
        for row in saldos:
            writer.writerow([row['id'], row['usuario'], f"{row['abono']:.2f}", row['fecha']])

    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f"saldos_{datetime.now().strftime('%Y%m%d')}.csv"
    )


@app.route('/export/csv')
@admin_required
def export_csv():
    """Exporta los pedidos filtrados a un archivo CSV."""
    search = request.args.get('search', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()

    params = []
    
    base_query = "FROM pedidos"
    where_clauses = []

    if search:
        where_clauses.append("(identificador LIKE ? OR tramite LIKE ? OR correo LIKE ?)")
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

    if date_from:
        try:
            formatted_date_from = datetime.strptime(date_from, '%Y-%m-%d').strftime('%y-%m-%d')
            where_clauses.append("SUBSTR(fecha, 7, 2) || '-' || SUBSTR(fecha, 4, 2) || '-' || SUBSTR(fecha, 1, 2) >= ?")
            params.append(formatted_date_from)
        except ValueError:
            pass
    if date_to:
        try:
            formatted_date_to = datetime.strptime(date_to, '%Y-%m-%d').strftime('%y-%m-%d')
            where_clauses.append("SUBSTR(fecha, 7, 2) || '-' || SUBSTR(fecha, 4, 2) || '-' || SUBSTR(fecha, 1, 2) <= ?")
            params.append(formatted_date_to)
        except ValueError:
            pass

    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)
    
    data_query = "SELECT * " + base_query + " ORDER BY id DESC"

    with get_tramites_db() as tdb:
        pedidos = tdb.execute(data_query, params).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    
    if not pedidos:
        writer.writerow(['No hay datos para exportar con los filtros seleccionados.'])
    else:
        headers = pedidos[0].keys()
        writer.writerow(headers)
        for row in pedidos:
            writer.writerow(row)

    output.seek(0)
    
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f"pedidos_{datetime.now().strftime('%Y%m%d')}.csv"
    )

@app.route('/api/pedidos/delete-filtered', methods=['POST'])
@admin_required
def delete_filtered_pedidos():
    """Elimina los pedidos que coinciden con los filtros de búsqueda."""

    try:
        data = request.get_json()
        ids = data.get('ids')
        search = data.get('search', '').strip()
        date_from = data.get('date_from', '').strip()
        date_to = data.get('date_to', '').strip()
        status = data.get('status', '').strip()

        pedidos_a_eliminar = []
        pedido_ids = []

        with get_tramites_db() as tdb:
            if ids and isinstance(ids, list) and len(ids) > 0:
                placeholders = ','.join(['?'] * len(ids))
                select_query = f"SELECT id, resultado FROM pedidos WHERE id IN ({placeholders})"
                pedidos_a_eliminar = tdb.execute(select_query, ids).fetchall()
                pedido_ids = [p['id'] for p in pedidos_a_eliminar]
            else:
                params = []
                where_clauses = []
                if search:
                    where_clauses.append("(identificador LIKE ? OR tramite LIKE ?)")
                    params.extend([f'%{search}%', f'%{search}%'])
                if status:
                    try:
                        status_int = int(status)
                        where_clauses.append("estado = ?")
                        params.append(status_int)
                    except Exception:
                        pass
                if date_from:
                    try:
                        formatted_date_from = datetime.strptime(date_from, '%Y-%m-%d').strftime('%y-%m-%d')
                        where_clauses.append("SUBSTR(fecha, 7, 2) || '-' || SUBSTR(fecha, 4, 2) || '-' || SUBSTR(fecha, 1, 2) >= ?")
                        params.append(formatted_date_from)
                    except ValueError: pass
                if date_to:
                    try:
                        formatted_date_to = datetime.strptime(date_to, '%Y-%m-%d').strftime('%y-%m-%d')
                        where_clauses.append("SUBSTR(fecha, 7, 2) || '-' || SUBSTR(fecha, 4, 2) || '-' || SUBSTR(fecha, 1, 2) <= ?")
                        params.append(formatted_date_to)
                    except ValueError: pass
                if not where_clauses:
                    return jsonify({'success': False, 'message': 'Se requieren filtros o IDs para eliminar.'}), 400
                where_sql = " WHERE " + " AND ".join(where_clauses)
                select_query = "SELECT id, resultado FROM pedidos" + where_sql
                pedidos_a_eliminar = tdb.execute(select_query, params).fetchall()
                pedido_ids = [p['id'] for p in pedidos_a_eliminar]

            for pedido in pedidos_a_eliminar:
                if not pedido['resultado']:
                    continue
                try:
                    resultado_json = json.loads(pedido['resultado'])
                    if 'files' in resultado_json and isinstance(resultado_json['files'], list):
                        for file_meta in resultado_json['files']:
                            if 'key' in file_meta:
                                file_path = os.path.join(UPLOAD_DIR, file_meta['key'])
                                if os.path.exists(file_path):
                                    os.remove(file_path)
                except (json.JSONDecodeError, TypeError):
                    continue
            if pedido_ids:
                placeholders = ','.join(['?'] * len(pedido_ids))
                with get_db() as db:
                    db.execute(f"DELETE FROM archivos WHERE pedido_id IN ({placeholders})", pedido_ids)
                delete_query = f"DELETE FROM pedidos WHERE id IN ({placeholders})" if ids else "DELETE FROM pedidos" + where_sql
                cursor = tdb.cursor()
                if ids:
                    cursor.execute(delete_query, ids)
                else:
                    cursor.execute(delete_query, params)
                rows_deleted = cursor.rowcount
                tdb.commit()
            else:
                rows_deleted = 0
        return jsonify({'success': True, 'message': f'{rows_deleted} pedidos eliminados.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500




@app.route('/archivos/eliminar', methods=['POST'])
@admin_required
def eliminar_archivos():
    try:
        data = request.get_json()
        ids = data.get('ids')
        if not ids or not isinstance(ids, list):
            return jsonify({'success': False, 'message': 'Se requiere una lista de IDs.'}), 400
        with get_db() as db:
            placeholders = ','.join(['?'] * len(ids))
            archivos = db.execute(f"SELECT key FROM archivos WHERE id IN ({placeholders})", ids).fetchall()
            for archivo in archivos:
                file_path = os.path.join(UPLOAD_DIR, archivo['key'])
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception:
                        pass
            db.execute(f"DELETE FROM archivos WHERE id IN ({placeholders})", ids)
        return jsonify({'success': True, 'message': f'{len(ids)} archivos eliminados.'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error al eliminar archivos.'}), 500

@app.route('/archivos/eliminar_filtrados', methods=['POST'])
@admin_required
def eliminar_archivos_filtrados():
    try:
        data = request.get_json()
        filtro = data.get('filtro', {})
        where_clauses = []
        params = []
        if 'pedido_id' in filtro:
            where_clauses.append('pedido_id = ?')
            params.append(filtro['pedido_id'])
        if 'proveedor_id' in filtro:
            where_clauses.append('proveedor_id = ?')
            params.append(filtro['proveedor_id'])
        if not where_clauses:
            return jsonify({'success': False, 'message': 'Se requiere al menos un filtro.'}), 400
        where_sql = ' WHERE ' + ' AND '.join(where_clauses)
        with get_db() as db:
            archivos = db.execute(f"SELECT key FROM archivos{where_sql}", params).fetchall()
            for archivo in archivos:
                file_path = os.path.join(UPLOAD_DIR, archivo['key'])
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception:
                        pass
            db.execute(f"DELETE FROM archivos{where_sql}", params)
        return jsonify({'success': True, 'message': f'{len(archivos)} archivos eliminados.'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error al eliminar archivos filtrados.'}), 500

# ========== USUARIOS ENDPOINTS ==========
@app.route('/obtener_usuarios', methods=['GET'])
@admin_required
def obtener_usuarios():
    """Obtiene lista de usuarios paginada"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        offset = (page - 1) * per_page
        
        with get_db() as db:
            total = db.execute('SELECT COUNT(*) as total FROM usuarios').fetchone()['total']
            usuarios = db.execute(
                'SELECT id, celular, correo, password, saldo FROM usuarios ORDER BY id DESC LIMIT ? OFFSET ?',
                (per_page, offset)
            ).fetchall()
        
        usuarios_list = [dict(u) for u in usuarios]
        total_pages = (total + per_page - 1) // per_page
        
        return jsonify({
            'success': True,
            'usuarios': usuarios_list,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/usuarios/<int:usuario_id>/actualizar_password', methods=['POST'])
@admin_required
def actualizar_usuario_password(usuario_id):
    """Actualiza la contraseña de un usuario"""
    try:
        data = request.get_json()
        nueva_password = data.get('nueva_password', '').strip()
        
        if not nueva_password or len(nueva_password) < 4:
            return jsonify({'success': False, 'message': 'La contraseña debe tener al menos 4 caracteres.'}), 400
        
        password_hash = generate_password_hash(nueva_password)
        
        with get_db() as db:
            db.execute('UPDATE usuarios SET password = ? WHERE id = ?', (password_hash, usuario_id))
            db.commit()
        
        return jsonify({'success': True, 'message': 'Contraseña actualizada correctamente.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/usuarios/<int:usuario_id>/eliminar', methods=['POST'])
@admin_required
def eliminar_usuario(usuario_id):
    """Elimina un usuario"""
    try:
        # Prevenir eliminación del admin logueado
        if usuario_id == session.get('user_id'):
            return jsonify({'success': False, 'message': 'No puedes eliminar tu propia cuenta.'}), 400
        
        with get_db() as db:
            db.execute('DELETE FROM usuarios WHERE id = ?', (usuario_id,))
            db.commit()
        
        return jsonify({'success': True, 'message': 'Usuario eliminado correctamente.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ========== ENDPOINTS PARA TRÁMITES PROCESADOS EN ADMIN ==========

@app.route('/api/tramites_procesados', methods=['GET'])
@admin_required
def api_tramites_procesados():
    """Obtiene todos los trámites procesados con filtros y paginación"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()
    per_page = 20
    offset = (page - 1) * per_page
    
    try:
        with get_tramites_db() as tdb:
            # Construir consulta base
            query = 'SELECT id, proveedor, identificador, tramite, solicitud, atencion FROM procesados WHERE 1=1'
            params = []
            
            # Filtros opcionales
            if search:
                query += ' AND (identificador LIKE ? OR tramite LIKE ?)'
                params.extend([f'%{search}%', f'%{search}%'])
            
            if date_from:
                # Convertir la fecha del frontend (YYYY-MM-DD) al formato de la BD (DD/MM/YY)
                from_parts = date_from.split('-')
                db_date_from = f'{from_parts[2]}/{from_parts[1]}/{from_parts[0][2:]}'
                query += ' AND SUBSTR(solicitud, 1, 8) >= ?'
                params.append(db_date_from)
            
            if date_to:
                # Convertir la fecha del frontend (YYYY-MM-DD) al formato de la BD (DD/MM/YY)
                to_parts = date_to.split('-')
                db_date_to = f'{to_parts[2]}/{to_parts[1]}/{to_parts[0][2:]}'
                query += ' AND SUBSTR(solicitud, 1, 8) <= ?'
                params.append(db_date_to)
            
            # Obtener total (con los mismos parámetros de filtro)
            count_query = 'SELECT COUNT(*) as total FROM procesados WHERE 1=1'
            count_params = []
            
            if search:
                count_query += ' AND (identificador LIKE ? OR tramite LIKE ?)'
                count_params.extend([f'%{search}%', f'%{search}%'])
            
            if date_from:
                from_parts = date_from.split('-')
                db_date_from = f'{from_parts[2]}/{from_parts[1]}/{from_parts[0][2:]}'
                count_query += ' AND SUBSTR(solicitud, 1, 8) >= ?'
                count_params.append(db_date_from)
            
            if date_to:
                to_parts = date_to.split('-')
                db_date_to = f'{to_parts[2]}/{to_parts[1]}/{to_parts[0][2:]}'
                count_query += ' AND SUBSTR(solicitud, 1, 8) <= ?'
                count_params.append(db_date_to)
            
            total = tdb.execute(count_query, count_params).fetchone()['total']
            
            # Obtener datos paginados
            query += ' ORDER BY solicitud DESC LIMIT ? OFFSET ?'
            params.extend([per_page, offset])
            
            procesados = tdb.execute(query, params).fetchall()
            procesados_list = [dict(p) for p in procesados]
            
            total_pages = (total + per_page - 1) // per_page
            
            return jsonify({
                'success': True,
                'procesados': procesados_list,
                'total': total,
                'page': page,
                'per_page': per_page,
                'total_pages': total_pages
            })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/tramites_procesados/eliminar_seleccionados', methods=['POST'])
@admin_required
def eliminar_tramites_seleccionados():
    """Elimina los trámites procesados seleccionados"""
    data = request.get_json()
    ids = data.get('ids', [])
    
    if not ids:
        return jsonify({'success': False, 'message': 'No hay registros para eliminar'}), 400
    
    try:
        with get_tramites_db() as tdb:
            placeholders = ','.join('?' * len(ids))
            tdb.execute(f'DELETE FROM procesados WHERE id IN ({placeholders})', ids)
            tdb.commit()
        
        return jsonify({'success': True, 'message': f'{len(ids)} trámite(s) eliminado(s) correctamente'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/tramites_procesados/eliminar_filtrados', methods=['POST'])
@admin_required
def eliminar_tramites_filtrados():
    """Elimina los trámites procesados que coinciden con los filtros"""
    data = request.get_json()
    search = data.get('search', '').strip()
    date_from = data.get('date_from', '').strip()
    date_to = data.get('date_to', '').strip()
    
    try:
        with get_tramites_db() as tdb:
            query = 'DELETE FROM procesados WHERE 1=1'
            params = []
            
            if search:
                query += ' AND (identificador LIKE ? OR tramite LIKE ?)'
                params.extend([f'%{search}%', f'%{search}%'])
            
            if date_from:
                from_parts = date_from.split('-')
                db_date_from = f'{from_parts[2]}/{from_parts[1]}/{from_parts[0][2:]}'
                query += ' AND SUBSTR(solicitud, 1, 8) >= ?'
                params.append(db_date_from)
            
            if date_to:
                to_parts = date_to.split('-')
                db_date_to = f'{to_parts[2]}/{to_parts[1]}/{to_parts[0][2:]}'
                query += ' AND SUBSTR(solicitud, 1, 8) <= ?'
                params.append(db_date_to)
            
            cursor = tdb.execute(query, params)
            tdb.commit()
            
            return jsonify({'success': True, 'message': f'{cursor.rowcount} trámite(s) eliminado(s) correctamente'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/tramites_procesados/exportar_csv', methods=['GET'])
@admin_required
def exportar_tramites_csv():
    """Exporta los trámites procesados filtrados a CSV"""
    search = request.args.get('search', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()
    
    try:
        with get_tramites_db() as tdb:
            query = 'SELECT proveedor, identificador, tramite, solicitud, atencion FROM procesados WHERE 1=1'
            params = []
            
            if search:
                query += ' AND (identificador LIKE ? OR tramite LIKE ?)'
                params.extend([f'%{search}%', f'%{search}%'])
            
            if date_from:
                from_parts = date_from.split('-')
                db_date_from = f'{from_parts[2]}/{from_parts[1]}/{from_parts[0][2:]}'
                query += ' AND SUBSTR(solicitud, 1, 8) >= ?'
                params.append(db_date_from)
            
            if date_to:
                to_parts = date_to.split('-')
                db_date_to = f'{to_parts[2]}/{to_parts[1]}/{to_parts[0][2:]}'
                query += ' AND SUBSTR(solicitud, 1, 8) <= ?'
                params.append(db_date_to)
            
            query += ' ORDER BY solicitud DESC'
            
            procesados = tdb.execute(query, params).fetchall()
            
            # Crear CSV
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Proveedor', 'Identificador', 'Trámite', 'Solicitud', 'Atención'])
            
            for p in procesados:
                writer.writerow([p['proveedor'], p['identificador'], p['tramite'], p['solicitud'], p['atencion']])
            
            output.seek(0)
            
            return send_file(
                io.BytesIO(output.getvalue().encode('utf-8')),
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'tramites_procesados_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            )
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/tramites_procesados/respaldar_db', methods=['POST'])
@admin_required
def respaldar_tramites_db():
    """Respalda la base de datos de trámites y la envía para descargar"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f'tramites_{timestamp}.db'
        
        # Leer el archivo en memoria y enviarlo
        with open(TRAMITES_DB, 'rb') as f:
            file_content = f.read()
        
        return send_file(
            io.BytesIO(file_content),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=backup_filename
        )
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/backups/<filename>', methods=['GET'])
def descargar_backup(filename):
    """Descarga un archivo de respaldo"""
    try:
        backup_path = os.path.join(BACKUP_DIR, filename)
        if os.path.exists(backup_path):
            return send_file(backup_path, as_attachment=True, download_name=filename)
        else:
            return jsonify({'success': False, 'message': 'Archivo no encontrado'}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    init_db()
    app.run(port=5000, debug=True)

