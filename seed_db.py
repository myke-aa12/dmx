#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para agregar datos realistas a las bases de datos
"""

import sqlite3
import os
from datetime import datetime, timedelta
import random

def seed_databases():
    tramites_db = 'tramites.db'
    usuarios_db = 'usuarios.db'
    
    print("=" * 70)
    print("SEMBRANDO DATOS REALISTAS EN BASES DE DATOS")
    print("=" * 70)
    
    # ============ TRAMITES.DB ============
    conn_tramites = sqlite3.connect(tramites_db)
    cursor_tramites = conn_tramites.cursor()
    
    # 1. Insertar trámites realistas
    print("\n[1] Insertando trámites...")
    tramites = [
        ('Registro de Constitución de Sociedad Mercantil', 2500.00, '5-7 días'),
        ('Renovación de Licencia de Funcionamiento', 1200.00, '3-5 días'),
        ('Cambio de Domicilio del Negocio', 800.00, '2-3 días'),
        ('Ampliación de Giro Comercial', 1500.00, '4-6 días'),
        ('Disolución y Liquidación de Empresa', 3000.00, '7-10 días'),
        ('Modificación de Datos Registrales', 600.00, '1-2 días'),
        ('Certificado de Existencia y Representación Legal', 400.00, '1 día'),
        ('Autorización de Transferencia de Acciones', 1800.00, '5-7 días'),
        ('Inscripción de Apoderado', 700.00, '2-3 días'),
        ('Cambio de Administrador o Consejero', 900.00, '3-4 días'),
    ]
    
    cursor_tramites.execute("DELETE FROM tramites")
    for tramite, precio, tiempo in tramites:
        cursor_tramites.execute(
            "INSERT INTO tramites (tramite, precio, tiempo) VALUES (?, ?, ?)",
            (tramite, precio, tiempo)
        )
        print(f"   - {tramite} (${precio:,.2f})")
    
    conn_tramites.commit()
    
    # 2. Insertar horarios para cada trámite
    print("\n[2] Insertando horarios...")
    cursor_tramites.execute("SELECT id FROM tramites")
    tramite_ids = [row[0] for row in cursor_tramites.fetchall()]
    
    cursor_tramites.execute("DELETE FROM horarios")
    horarios_data = [
        'Lunes a Viernes: 09:00 - 13:00 y 14:00 - 18:00',
        'Martes y Jueves: 10:00 - 17:00',
        'Lunes a Viernes: 09:00 - 18:00',
        'Lunes a Viernes: 08:00 - 16:00',
    ]
    
    for tramite_id in tramite_ids:
        horario = random.choice(horarios_data)
        cursor_tramites.execute(
            """INSERT INTO horarios 
               (tramite_id, horario, activo, aviso, aviso_activo, fecha_actualizacion) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            (tramite_id, horario, 1, 'Trámite disponible', 0, datetime.now().isoformat())
        )
        print(f"   - Trámite {tramite_id}: {horario}")
    
    conn_tramites.commit()
    
    # 3. Insertar pedidos
    print("\n[3] Insertando pedidos...")
    cursor_tramites.execute("DELETE FROM pedidos")
    
    estados = ['Pendiente', 'En proceso', 'Completado', 'Cancelado']
    
    base_date = datetime.now()
    for i in range(15):
        user_id = 1  # Usuario admin
        estado = i % 4  # 0=Pendiente, 1=En proceso, 2=Completado, 3=Cancelado
        identificador = f'PED-{1000 + i}'
        tramite_idx = i % len(tramites)
        tramite_nombre = tramites[tramite_idx][0]
        precio = tramites[tramite_idx][1]
        fecha = (base_date - timedelta(days=random.randint(0, 30))).isoformat()
        resultado = estados[estado]
        asignado_a = random.choice([1, None]) if estado > 0 else None
        asignado_at = (datetime.now() - timedelta(days=random.randint(0, 20))).isoformat() if asignado_a else None
        correo = 'admin@admin.com'
        
        cursor_tramites.execute(
            """INSERT INTO pedidos 
               (user_id, estado, identificador, tramite, fecha, precio, resultado, asignado_a, asignado_at, correo) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, estado, identificador, tramite_nombre, fecha, precio, resultado, asignado_a, asignado_at, correo)
        )
        print(f"   - {identificador}: {tramite_nombre[:30]}... ({resultado})")
    
    conn_tramites.commit()
    
    # 4. Insertar procesados
    print("\n[4] Insertando registros procesados...")
    cursor_tramites.execute("DELETE FROM procesados")
    
    for i in range(8):
        proveedor = f'Proveedor {chr(65 + (i % 5))}'
        identificador = f'PROC-{2000 + i}'
        tramite_nombre = tramites[i % len(tramites)][0]
        solicitud = f'Solicitud de {tramite_nombre.split()[0]}'
        atencion = f'Se procesó exitosamente el {(datetime.now() - timedelta(days=random.randint(0, 15))).strftime("%Y-%m-%d")}'
        
        cursor_tramites.execute(
            """INSERT INTO procesados 
               (proveedor, identificador, tramite, solicitud, atencion) 
               VALUES (?, ?, ?, ?, ?)""",
            (proveedor, identificador, tramite_nombre, solicitud, atencion)
        )
        print(f"   - {identificador}: {tramite_nombre[:30]}...")
    
    conn_tramites.commit()
    conn_tramites.close()
    
    # ============ USUARIOS.DB ============
    conn_usuarios = sqlite3.connect(usuarios_db)
    cursor_usuarios = conn_usuarios.cursor()
    
    # Ya existe el usuario admin, podemos agregar más usuarios si es necesario
    print("\n[5] Verificando usuarios en usuarios.db...")
    cursor_usuarios.execute("SELECT COUNT(*) FROM usuarios")
    count = cursor_usuarios.fetchone()[0]
    print(f"   - Total de usuarios: {count}")
    
    cursor_usuarios.execute("SELECT correo, admin FROM usuarios")
    users = cursor_usuarios.fetchall()
    for correo, admin in users:
        user_type = "Administrador" if admin else "Usuario Regular"
        print(f"     • {correo} ({user_type})")
    
    # Agregar saldos si no existen
    print("\n[6] Verificando saldos...")
    cursor_usuarios.execute("SELECT COUNT(*) FROM saldos")
    saldo_count = cursor_usuarios.fetchone()[0]
    print(f"   - Total de registros de saldo: {saldo_count}")
    
    # Agregar archivos si no existen
    print("\n[7] Verificando archivos...")
    cursor_usuarios.execute("SELECT COUNT(*) FROM archivos")
    archivo_count = cursor_usuarios.fetchone()[0]
    print(f"   - Total de archivos: {archivo_count}")
    
    conn_usuarios.close()
    
    print("\n" + "=" * 70)
    print("DATOS REALISTAS AGREGADOS EXITOSAMENTE")
    print("=" * 70)
    
    # Verificación final
    conn_tramites = sqlite3.connect(tramites_db)
    cursor_tramites = conn_tramites.cursor()
    
    print("\nRESUMEN FINAL:")
    
    cursor_tramites.execute("SELECT COUNT(*) FROM tramites")
    count = cursor_tramites.fetchone()[0]
    print(f"  - Trámites: {count}")
    
    cursor_tramites.execute("SELECT COUNT(*) FROM horarios")
    count = cursor_tramites.fetchone()[0]
    print(f"  - Horarios: {count}")
    
    cursor_tramites.execute("SELECT COUNT(*) FROM pedidos")
    count = cursor_tramites.fetchone()[0]
    print(f"  - Pedidos: {count}")
    
    cursor_tramites.execute("SELECT COUNT(*) FROM procesados")
    count = cursor_tramites.fetchone()[0]
    print(f"  - Procesados: {count}")
    
    conn_tramites.close()
    
    print("\n✓ Bases de datos sincronizadas correctamente")

if __name__ == '__main__':
    seed_databases()
