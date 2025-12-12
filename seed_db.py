#!/usr/bin/env python3
"""
Script para agregar datos de prueba a las bases de datos
"""

import sqlite3
import os
from datetime import datetime

def seed_databases():
    tramites_db = 'tramites.db'
    
    print("=" * 70)
    print("SEMBRANDO DATOS DE PRUEBA EN BASES DE DATOS")
    print("=" * 70)
    
    # Conectar a tramites.db
    conn = sqlite3.connect(tramites_db)
    cursor = conn.cursor()
    
    # Insertar trámites de ejemplo
    print("\n[1] Insertando trámites...")
    tramites = [
        ('Registro de Empresa', 1500.00, 5),
        ('Renovacion de Licencia', 800.00, 3),
        ('Cambio de Domicilio', 600.00, 2),
        ('Ampliacion de Giro', 1200.00, 4),
        ('Disolucion de Empresa', 2000.00, 7),
        ('Modificacion de Datos', 400.00, 1),
    ]
    
    cursor.execute("DELETE FROM tramites")  # Limpiar primero
    for tramite, precio, tiempo in tramites:
        cursor.execute(
            "INSERT INTO tramites (tramite, precio, tiempo) VALUES (?, ?, ?)",
            (tramite, precio, tiempo)
        )
        print(f"   - {tramite} (${precio}, {tiempo} dias)")
    
    conn.commit()
    
    # Insertar horarios para cada trámite
    print("\n[2] Insertando horarios...")
    cursor.execute("SELECT id FROM tramites")
    tramite_ids = [row[0] for row in cursor.fetchall()]
    
    cursor.execute("DELETE FROM horarios")  # Limpiar primero
    for tramite_id in tramite_ids:
        cursor.execute(
            """INSERT INTO horarios 
               (tramite_id, horario, activo, aviso, aviso_activo, fecha_actualizacion) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            (tramite_id, 'Lunes a Viernes: 09:00 - 18:00', 1, 'Tramite en proceso', 1, datetime.now().isoformat())
        )
        print(f"   - Horario para trámite {tramite_id}")
    
    conn.commit()
    
    # Insertar algunos pedidos de ejemplo
    print("\n[3] Insertando pedidos de ejemplo...")
    cursor.execute("DELETE FROM pedidos")  # Limpiar primero
    
    pedidos = [
        (1, 0, 'PED-001', 'Registro de Empresa', datetime.now().isoformat(), 1500.00, 'Pendiente', None, None, 'admin@admin.com'),
        (1, 1, 'PED-002', 'Renovacion de Licencia', datetime.now().isoformat(), 800.00, 'En proceso', 1, None, 'admin@admin.com'),
        (1, 2, 'PED-003', 'Cambio de Domicilio', datetime.now().isoformat(), 600.00, 'Completado', 1, datetime.now().isoformat(), 'admin@admin.com'),
    ]
    
    for user_id, estado, identificador, tramite, fecha, precio, resultado, asignado_a, asignado_at, correo in pedidos:
        cursor.execute(
            """INSERT INTO pedidos 
               (user_id, estado, identificador, tramite, fecha, precio, resultado, asignado_a, asignado_at, correo) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, estado, identificador, tramite, fecha, precio, resultado, asignado_a, asignado_at, correo)
        )
        print(f"   - {identificador}: {tramite} (Estado: {resultado})")
    
    conn.commit()
    conn.close()
    
    print("\n" + "=" * 70)
    print("DATOS DE PRUEBA AGREGADOS EXITOSAMENTE")
    print("=" * 70)
    
    # Verificar
    conn = sqlite3.connect(tramites_db)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM tramites")
    count = cursor.fetchone()[0]
    print(f"\nTotal de trámites: {count}")
    
    cursor.execute("SELECT COUNT(*) FROM horarios")
    count = cursor.fetchone()[0]
    print(f"Total de horarios: {count}")
    
    cursor.execute("SELECT COUNT(*) FROM pedidos")
    count = cursor.fetchone()[0]
    print(f"Total de pedidos: {count}")
    
    conn.close()

if __name__ == '__main__':
    seed_databases()
