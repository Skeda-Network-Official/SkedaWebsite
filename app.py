import os
import json
import time
import uuid
import secrets
from datetime import date
from functools import wraps
from pathlib import Path

import requests
from flask import Flask, request, jsonify, session, redirect, send_from_directory, abort
from dotenv import load_dotenv

# El .env vive en config/.env, no en la raíz del proyecto ni en node_modules/.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(dotenv_path=Path(BASE_DIR) / 'config' / '.env')

DISCORD_CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID')
DISCORD_CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET')
DISCORD_REDIRECT_URI = os.environ.get('DISCORD_REDIRECT_URI')
DISCORD_BOT_TOKEN = os.environ.get('DISCORD_BOT_TOKEN')
DISCORD_GUILD_ID = os.environ.get('DISCORD_GUILD_ID')
DISCORD_REQUIRED_ROLE_ID = os.environ.get('DISCORD_REQUIRED_ROLE_ID')
SECRET_KEY = os.environ.get('SECRET_KEY')
COOKIE_SECURE = os.environ.get('COOKIE_SECURE', 'false').lower() == 'true'
PORT = int(os.environ.get('PORT', 3000))

# Comprobación temprana: si falta algo esencial, avisa claramente en consola en vez
# de fallar de forma confusa más adelante.
REQUERIDAS = {
    'DISCORD_CLIENT_ID': DISCORD_CLIENT_ID,
    'DISCORD_CLIENT_SECRET': DISCORD_CLIENT_SECRET,
    'DISCORD_REDIRECT_URI': DISCORD_REDIRECT_URI,
    'DISCORD_BOT_TOKEN': DISCORD_BOT_TOKEN,
    'DISCORD_GUILD_ID': DISCORD_GUILD_ID,
    'DISCORD_REQUIRED_ROLE_ID': DISCORD_REQUIRED_ROLE_ID,
    'SECRET_KEY': SECRET_KEY,
}
faltantes = [k for k, v in REQUERIDAS.items() if not v]
if faltantes:
    raise SystemExit(
        'Faltan variables de entorno en .env: ' + ', '.join(faltantes) +
        '\nCopia .env.example como .env y rellénalo antes de arrancar el servidor.'
    )

PUBLIC_DIR = BASE_DIR
NOTICIAS_FILE = os.path.join(BASE_DIR, 'data', 'noticias.json')

# Carpeta donde viven las páginas de error personalizadas (404.html, y las que
# se añadan en el futuro: 403.html, 500.html, etc.). Nunca se sirve por URL
# directa; solo la usan internamente los @app.errorhandler de más abajo.
ERRORS_DIR = os.path.join(BASE_DIR, 'errors')

# Carpetas/archivos que NUNCA deben poder pedirse por HTTP, aunque vivan
# junto a los .html (código fuente, dependencias, datos internos, etc.).
RUTAS_BLOQUEADAS = ('node_modules', 'data', 'config', 'Markdown', '.env', '.git',
                     'app.py', 'requirements.txt', '.gitignore', 'LICENSE',
                     '__pycache__', 'venv', '.venv', 'errors')

app = Flask(__name__, static_folder=None)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,  # 8 horas
)


# ===================== Páginas de error personalizadas =====================

@app.errorhandler(404)
def pagina_no_encontrada(error):
    return send_from_directory(ERRORS_DIR, '404.html'), 404


@app.errorhandler(500)
def error_interno(error):
    app.logger.error('Error 500: %s', error)
    return send_from_directory(ERRORS_DIR, '500.html'), 500


@app.errorhandler(403)
def acceso_prohibido(error):
    return send_from_directory(ERRORS_DIR, '403.html'), 403


@app.errorhandler(400)
def peticion_incorrecta(error):
    return send_from_directory(ERRORS_DIR, '400.html'), 400


@app.errorhandler(405)
def metodo_no_permitido(error):
    return send_from_directory(ERRORS_DIR, '405.html'), 405


# Para añadir otro código de error en el futuro, añade errors/<código>.html
# y un handler igual que los de arriba, cambiando el número en
# @app.errorhandler(...) y en el nombre del archivo.


# ===================== Utilidades de noticias =====================

def leer_noticias():
    try:
        with open(NOTICIAS_FILE, 'r', encoding='utf-8') as f:
            datos = json.load(f)
        return datos if isinstance(datos, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def guardar_noticias(noticias):
    with open(NOTICIAS_FILE, 'w', encoding='utf-8') as f:
        json.dump(noticias, f, ensure_ascii=False, indent=2)


def generar_id():
    return f'n_{int(time.time() * 1000)}_{uuid.uuid4().hex[:6]}'


# ===================== Middleware de autenticación =====================

def requiere_sesion(vista):
    @wraps(vista)
    def envoltura(*args, **kwargs):
        if session.get('autenticado'):
            return vista(*args, **kwargs)
        if request.path.startswith('/api/'):
            return jsonify({'error': 'No autenticado'}), 401
        return redirect('/admin/login.html')
    return envoltura


# ===================== Rutas de login con Discord =====================

@app.route('/auth/discord/login')
def discord_login():
    params = {
        'client_id': DISCORD_CLIENT_ID,
        'redirect_uri': DISCORD_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'identify email guilds',
        'prompt': 'consent',
    }
    query = '&'.join(f'{k}={requests.utils.quote(str(v))}' for k, v in params.items())
    return redirect(f'https://discord.com/api/oauth2/authorize?{query}')


@app.route('/auth/discord/callback')
def discord_callback():
    code = request.args.get('code')
    if not code:
        return redirect('/admin/login.html?error=sin_codigo')

    try:
        # 1. Intercambiar el code por un access_token de Discord.
        token_res = requests.post(
            'https://discord.com/api/oauth2/token',
            data={
                'client_id': DISCORD_CLIENT_ID,
                'client_secret': DISCORD_CLIENT_SECRET,
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': DISCORD_REDIRECT_URI,
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=10,
        )
        token_res.raise_for_status()
        access_token = token_res.json()['access_token']

        # 2. Obtener el usuario autenticado.
        user_res = requests.get(
            'https://discord.com/api/users/@me',
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10,
        )
        user_res.raise_for_status()
        usuario = user_res.json()

        # 3. Comprobar sus roles en el servidor de Discord, usando el BOT token.
        miembro_res = requests.get(
            f'https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{usuario["id"]}',
            headers={'Authorization': f'Bot {DISCORD_BOT_TOKEN}'},
            timeout=10,
        )

        if miembro_res.status_code == 404:
            return redirect('/admin/login.html?error=no_estas_en_el_servidor')
        miembro_res.raise_for_status()

        miembro = miembro_res.json()
        tiene_rol = DISCORD_REQUIRED_ROLE_ID in miembro.get('roles', [])

        if not tiene_rol:
            return redirect('/admin/login.html?error=sin_permiso')

        # 4. Todo correcto: creamos la sesión.
        session.permanent = True
        session['autenticado'] = True
        session['discord_user'] = {'id': usuario['id'], 'username': usuario['username']}
        return redirect('/admin/panel.html')

    except requests.RequestException as err:
        app.logger.error('Error en el login de Discord: %s', err)
        return redirect('/admin/login.html?error=fallo_interno')


@app.route('/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect('/admin/login.html')


@app.route('/api/sesion')
def api_sesion():
    return jsonify({
        'autenticado': bool(session.get('autenticado')),
        'usuario': session.get('discord_user'),
    })


# --- SOLO PARA PROBAR el 500. Borrar esta ruta cuando termines de probar. ---
@app.route('/test-500')
def forzar_error():
    raise Exception("Prueba del error 500")
# --- FIN DEL BLOQUE DE PRUEBA ---


# ===================== API pública de noticias (solo lectura) =====================

@app.route('/api/noticias', methods=['GET'])
def api_listar_noticias():
    return jsonify(leer_noticias())


# ===================== API protegida (requiere sesión + rol) =====================

@app.route('/api/noticias', methods=['POST'])
@requiere_sesion
def api_crear_noticia():
    datos = request.get_json(silent=True) or {}
    titulo = (datos.get('titulo') or '').strip()
    contenido = (datos.get('contenido') or '').strip()
    if not titulo or not contenido:
        return jsonify({'error': 'Título y contenido son obligatorios'}), 400

    noticias = leer_noticias()
    noticias.append({
        'id': generar_id(),
        'titulo': titulo,
        'contenido': contenido,
        'fecha': date.today().isoformat(),
    })
    guardar_noticias(noticias)
    return jsonify({'ok': True})


@app.route('/api/noticias/<id_noticia>', methods=['PUT'])
@requiere_sesion
def api_editar_noticia(id_noticia):
    datos = request.get_json(silent=True) or {}
    titulo = (datos.get('titulo') or '').strip()
    contenido = (datos.get('contenido') or '').strip()
    if not titulo or not contenido:
        return jsonify({'error': 'Título y contenido son obligatorios'}), 400

    noticias = leer_noticias()
    encontrada = False
    for n in noticias:
        if n['id'] == id_noticia:
            n['titulo'] = titulo
            n['contenido'] = contenido
            encontrada = True
            break
    if not encontrada:
        return jsonify({'error': 'No encontrada'}), 404

    guardar_noticias(noticias)
    return jsonify({'ok': True})


@app.route('/api/noticias/<id_noticia>', methods=['DELETE'])
@requiere_sesion
def api_borrar_noticia(id_noticia):
    noticias = leer_noticias()
    noticias = [n for n in noticias if n['id'] != id_noticia]
    guardar_noticias(noticias)
    return jsonify({'ok': True})


# ===================== Archivos estáticos =====================

# El panel de administración exige sesión antes de servir el HTML.
@app.route('/admin/panel.html')
@requiere_sesion
def admin_panel():
    return send_from_directory(os.path.join(PUBLIC_DIR, 'admin'), 'panel.html')


@app.route('/', defaults={'ruta': 'index.html'})
@app.route('/<path:ruta>')
def archivos_publicos(ruta):
    primer_segmento = ruta.split('/', 1)[0]
    if primer_segmento in RUTAS_BLOQUEADAS or ruta in RUTAS_BLOQUEADAS:
        abort(404)
    return send_from_directory(PUBLIC_DIR, ruta)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)
