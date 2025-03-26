from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
from dotenv import load_dotenv
import psycopg2
import psycopg2.extras  # Adicionando import necessário para DictCursor
import secrets
import datetime
import logging
import time
import random
import string
import json
import hashlib

load_dotenv()

# Configuração de Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],  # Adicionado OPTIONS
        "allow_headers": ["Content-Type", "Authorization", "Access-Control-Allow-Origin"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

# Configuração do PostgreSQL para Render
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

CHAVES_VALIDAS = []

port = int(os.environ.get("PORT", 5000))

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

# Corrigir a função authenticate_admin
def authenticate_admin(username, password, hwid):
    try:
        # Obter conexão
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificar se usuário existe e é admin
        cur.execute("""
            SELECT is_admin 
            FROM users 
            WHERE username = %s 
            AND password = %s 
            AND hwid = %s
        """, (username, password, hwid))
        
        result = cur.fetchone()
        
        # Fechar cursor e conexão
        cur.close()
        conn.close()
        
        return bool(result and result[0])  # Retorna True se encontrou e é admin
        
    except Exception as e:
        logging.error(f"Erro na autenticação de admin: {str(e)}")
        return False

@app.before_request
def start_timer():
    request.start_time = time.time()

@app.after_request
def log_response_time(response):
    duration = time.time() - getattr(request, 'start_time', time.time())
    logging.info(f"Resposta enviada: {response.status} em {duration:.2f} segundos")
    return response

@app.before_request
def log_request_info():
    logging.info(f"Requisição recebida: {request.method} {request.url}")
    logging.info(f"Headers: {dict(request.headers)}")
    logging.info(f"Body: {request.get_data(as_text=True)}")

@app.before_request
def verify_content_type():
    if request.method == "POST":
        if not request.is_json:
            return jsonify({
                "success": False,
                "message": "Content-Type deve ser application/json"
            }), 415

@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({"status": "ok", "message": "Servidor online!"})

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    logging.debug(f"Iniciando geração de key por: {request.json.get('generatedBy')}")
    try:
        data = request.get_json()
        generated_by = data.get('generatedBy')
        quantidade = data.get('quantidade', 1)
        duracao_dias = data.get('duracao_dias', 30)  # Pegando a duração dos dias

        logging.info(f"Tentativa de gerar key por: {generated_by} com duração de {duracao_dias} dias")

        try:
            conn = psycopg2.connect(DATABASE_URL)
            cur = conn.cursor()
            
            # Verifica se é admin
            cur.execute("""
                SELECT is_admin FROM users 
                WHERE username = %s
            """, (generated_by,))
            
            result = cur.fetchone()
            if not result or not result[0]:
                return jsonify({
                    "success": False,
                    "message": "Apenas administradores podem gerar keys"
                }), 403

            # Gera nova key
            key = f"MGSP-{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}"
            
            # Calcula a data de expiração baseada na duração informada
            expiration_date = datetime.datetime.now() + datetime.timedelta(days=duracao_dias)

            # Salva no banco incluindo a duração em dias
            cur.execute("""
                INSERT INTO keys (key_value, expiration_date, generated_by, duration_days)
                VALUES (%s, %s, %s, %s)
                RETURNING key_value, duration_days
            """, (key, expiration_date, generated_by, duracao_dias))
            
            key_data = cur.fetchone()
            conn.commit()

            logging.info(f"Key gerada com sucesso: {key} - Duração: {duracao_dias} dias")

            return jsonify({
                "success": True,
                "key": key,
                "duration_days": duracao_dias,
                "expiration_date": expiration_date.strftime("%d/%m/%Y")
            }), 201

        except Exception as e:
            conn.rollback()
            logging.error(f"Erro ao gerar key: {str(e)}")
            return jsonify({
                "success": False,
                "message": "Erro ao gerar key"
            }), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    except Exception as e:
        logging.error(f"Erro no endpoint generate_keys: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Erro interno: {str(e)}"
        }), 500

@app.route('/generate_custom_key', methods=['POST'])
def generate_custom_key():
    try:
        data = request.get_json()
        logging.info(f"Dados recebidos: {data}")
        
        key_value = data.get('key_value')  # Formato personalizado da key
        duracao_dias = int(data.get('duracao_dias', 0))
        generated_by = data.get('generatedBy')
        is_mod_key = data.get('is_mod_key', False)

        # Validações
        if not key_value or duracao_dias <= 0 or not generated_by:
            return jsonify({
                "success": False, 
                "message": "Dados inválidos. Verifique os campos."
            }), 400

        conn = get_db_connection()
        cur = conn.cursor()

        # Verifica se é admin
        cur.execute("""
            SELECT is_admin FROM users 
            WHERE username = %s
        """, (generated_by,))
        
        result = cur.fetchone()
        if not result or not result[0]:
            return jsonify({
                "success": False,
                "message": "Apenas administradores podem gerar keys"
            }), 403

        # Verifica se a key já existe
        cur.execute("SELECT key_value FROM keys WHERE key_value = %s", (key_value,))
        if cur.fetchone():
            return jsonify({
                "success": False,
                "message": "Esta key já existe!"
            }), 400

        expiration_date = datetime.datetime.now() + datetime.timedelta(days=duracao_dias)

        # Usa diretamente o key_value fornecido (sem prefixo MGSP-)
        cur.execute("""
            INSERT INTO keys (
                key_value, 
                expiration_date, 
                generated_by, 
                duration_days,
                is_used,
                is_admin_key,
                created_at
            ) VALUES (%s, %s, %s, %s, FALSE, %s, NOW())
            RETURNING key_value, expiration_date, duration_days
        """, (key_value, expiration_date, generated_by, duracao_dias, is_mod_key))

        key_data = cur.fetchone()
        conn.commit()

        if key_data:
            key_value, exp_date, duration = key_data
            return jsonify({
                "success": True,
                "key": key_value,  # Retorna a key exatamente como foi fornecida
                "duration_days": duration,
                "expiration_date": exp_date.strftime("%d/%m/%Y"),
                "is_mod_key": is_mod_key
            }), 201
        else:
            raise Exception("Falha ao gerar key personalizada")

    except Exception as e:
        logging.error(f"Erro ao gerar key personalizada: {str(e)}")
        if 'conn' in locals():
            conn.rollback()
        return jsonify({
            "success": False,
            "message": f"Erro ao gerar key personalizada: {str(e)}"
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    key = data.get('key')
    hwid = data.get('hwid')
    vmid = data.get('vmid')
    
    # Verificações de dados
    if not username or not password or not email or not key or not hwid:
        return jsonify({"success": False, "message": "Dados incompletos"})
    
    # Verificação da chave
    conn = get_db_connection()
    # Usar DictCursor para acessar os resultados como dicionário
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT * FROM keys WHERE key_value = %s AND is_used = false", [key])
    key_record = cur.fetchone()
    
    if not key_record:
        cur.close()
        conn.close()
        return jsonify({"success": False, "message": "Chave inválida ou já utilizada"})
    
    # Verificar usuário existente
    cur.execute("SELECT * FROM users WHERE username = %s", [username])
    if cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({"success": False, "message": "Nome de usuário já existe"})
    
    # Obter data de expiração da chave
    expiration_date = key_record['expiration_date']
    is_admin_key = key_record['is_admin_key']
    
    # Registrar usuário com a data de expiração da chave
    try:
        cur.execute(
            "INSERT INTO users (username, password, email, hwid, vmid, expiration_date, is_admin) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            [username, password, email, hwid, vmid, expiration_date, is_admin_key]
        )
        cur.execute("UPDATE keys SET is_used = true, used_by = %s, used_at = CURRENT_TIMESTAMP WHERE key_value = %s", 
                      [username, key])
        conn.commit()
        cur.close()
        conn.close()
        
        # Formatando a data para log
        expiry_str = "sem expiração" if not expiration_date else expiration_date.strftime("%d/%m/%Y %H:%M:%S")
        logging.info(f"Usuário {username} registrado com sucesso. Data de expiração: {expiry_str}")
        
        return jsonify({
            "success": True, 
            "message": "Registro concluído com sucesso!",
            "expirationDate": expiry_str if expiration_date else None
        })
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        logging.error(f"Erro ao registrar usuário {username}: {str(e)}")
        return jsonify({"success": False, "message": f"Erro ao registrar: {str(e)}"})

@app.route('/validate_key', methods=['POST'])
def validate_key():
    data = request.get_json()
    key = data.get('key')
    hwid = data.get('hwid')

    if not key or not hwid:
        return jsonify({"success": False, "message": "Dados incompletos fornecidos."}), 400

    try:
        conn = psycopg2.connect(DATABASE_URL)
        logging.debug("Conexão com banco de dados estabelecida")
        cur = conn.cursor()
        cur.execute("SELECT data_expiracao FROM users WHERE key_value = %s AND hwid = %s", (key, hwid))

        result = cur.fetchone()
        cur.close()
        conn.close()

        if result:
            data_expiracao_db = result[0]
            if datetime.datetime.now() <= data_expiracao_db:
                return jsonify({"success": True, "message": "Chave/Usuário válido!"})
            else:
                return jsonify({"success": False, "message": "Chave/Usuário expirado."}), 401
        else:
            return jsonify({"success": False, "message": "Usuário/Chave inválido."}), 401
    except Exception as e:
        logging.error(f"Erro ao validar chave/usuário: {e}")
        return jsonify({"success": False, "message": f"Erro ao validar chave/usuário: {e}"}), 500

# 1. Modifique a rota de login para corresponder ao client
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    hwid = data.get('hwid')
    vmid = data.get('vmid')
    
    if not username or not password:
        return jsonify({"success": False, "message": "Dados incompletos"})
    
    # Não aplicar hash na senha - usar diretamente como enviada pelo cliente
    # A senha está armazenada como texto simples no PostgreSQL
    
    # Verificar credenciais
    conn = get_db_connection()
    # Usar DictCursor para acessar os resultados como dicionário
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT * FROM users WHERE username = %s AND password = %s", [username, password])
    user = cur.fetchone()
    
    if not user:
        cur.close()
        conn.close()
        return jsonify({"success": False, "message": "Usuário ou senha incorretos"})
    
    # MODIFICADO: Verificar hwid OU vmid
    # Agora podemos acessar os campos como um dicionário
    if hwid != user['hwid'] and vmid != user['vmid'] and user['hwid'] != '0':
        cur.close()
        conn.close()
        return jsonify({"success": False, "message": "HWID incorreto. Você não pode usar esta licença neste computador."})
    
    # NOVO: Atualizar hwid se login feito por vmid
    if vmid == user['vmid'] and hwid != user['hwid'] and user['hwid'] != '0':
        try:
            cur.execute("UPDATE users SET hwid = %s WHERE username = %s", [hwid, username])
            conn.commit()
        except Exception as e:
            conn.rollback()
    
    # Extrair data de expiração
    expiration_date = user['expiration_date']
    expiration_str = None
    
    if expiration_date:
        expiration_str = int(expiration_date.timestamp())  # Converter para timestamp UNIX
    
    # Fechar recursos
    cur.close()
    conn.close()
    
    # Registrar login bem-sucedido
    logging.info(f"Login bem-sucedido para o usuário: {username}")
    
    # Login bem-sucedido
    return jsonify({
        "success": True,
        "message": "Login bem-sucedido",
        "username": user['username'],
        "isAdmin": user.get('is_admin', False),
        "expirationDate": expiration_str
    })

@app.route('/check_expiration', methods=['POST'])
def check_expiration():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        hwid = data.get('hwid')

        if not all([username, password]):
            return jsonify({"valid": False, "message": "Dados incompletos"}), 400

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Verifica usuário e admin status
        cur.execute("""
            SELECT * FROM users 
            WHERE username = %s AND password = %s
        """, (username, password))
        
        user = cur.fetchone()
        
        if not user:
            cur.close()
            conn.close()
            return jsonify({"valid": False, "message": "Usuário não encontrado"}), 404

        # Verificar se HWID corresponde (se fornecido)
        if hwid and user['hwid'] != '0' and hwid != user['hwid'] and hwid != user['vmid']:
            cur.close()
            conn.close()
            return jsonify({"valid": False, "message": "HWID não corresponde ao usuário"}), 403
            
        # Verificar status administrativo
        is_admin = user.get('is_admin', False)
        expiration_date = user.get('expiration_date')

        # Se for admin, retorna válido
        if is_admin:
            cur.close()
            conn.close()
            return jsonify({
                "valid": True,
                "isAdmin": True,
                "message": "Conta administrativa",
                "expirationDate": None  # Administradores não têm data de expiração
            }), 200

        # Se não tiver data de expiração
        if not expiration_date:
            cur.close()
            conn.close()
            return jsonify({
                "valid": False,
                "message": "Data de expiração não encontrada",
                "expirationDate": None
            }), 200  # Mudar para 200 para que o cliente ainda mostre a mensagem

        # Calcula dias restantes
        now = datetime.datetime.now()
        remaining = expiration_date - now
        is_valid = expiration_date > now
        
        # Calcula dias e horas restantes
        remaining_days = remaining.days
        remaining_hours = remaining.seconds // 3600  # Converte segundos para horas
        
        # Converter data de expiração para timestamp
        expiration_timestamp = int(expiration_date.timestamp())

        cur.close()
        conn.close()
        
        return jsonify({
            "valid": is_valid,
            "expirationDate": expiration_timestamp,
            "expirationFormatted": expiration_date.strftime("%d/%m/%Y %H:%M"),
            "remainingDays": remaining_days,
            "remainingHours": remaining_hours,
            "message": "Licença válida" if is_valid else "Licença expirada"
        }), 200

    except Exception as e:
        logging.error(f"Erro ao verificar expiração: {str(e)}")
        if 'cur' in locals() and cur:
            cur.close()
        if 'conn' in locals() and conn:
            conn.close()
            
        return jsonify({
            "valid": False,
            "message": f"Erro interno: {str(e)}"
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    try:
        # Verifica conexão com banco
        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cur:
            cur.execute('SELECT 1')
        conn.close()
        
        return jsonify({
            "status": "healthy",
            "database": "connected",
            "message": "Servidor operacional",
            "timestamp": datetime.datetime.now().isoformat(),
            "version": "1.0.0"
        }), 200
    except Exception as e:
        logging.error(f"Erro no health check: {str(e)}")
        return jsonify({
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }), 500

# Variáveis globais para armazenar as informações
current_news = "🔔 Bem-vindo ao MilGrau Spoofer"
current_version = "3.1.0"
current_download_url = "https://github.com/MilGrauSpoofer/releases"

@app.route('/check_updates', methods=['POST'])
def check_updates():
    try:
        data = request.get_json()
        client_version = data.get('version')
        
        needs_update = current_version > client_version
        
        return jsonify({
            'success': True,
            'needs_update': needs_update,
            'download_url': current_download_url if needs_update else None,
            'news': current_news
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao verificar updates: {str(e)}'
        }), 500

# Rota para atualizar as informações
@app.route('/admin/update_info', methods=['POST'])
def update_info():
    try:
        data = request.get_json()
        
        # Atualiza variáveis globais
        global current_news, current_version, current_download_url
        
        if 'news' in data:
            current_news = data['news']
        if 'version' in data:
            current_version = data['version']
        if 'download_url' in data:
            current_download_url = data['download_url']
            
        return jsonify({
            'success': True,
            'message': 'Informações atualizadas com sucesso'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao atualizar informações: {str(e)}'
        }), 500

# Corrigir a rota update_configs
@app.route('/update_configs', methods=['POST'])
def update_configs():
    try:
        data = request.json
        conn = get_db_connection()
        
        # Verificar admin
        if not authenticate_admin(
            data.get('username'),
            data.get('password'),
            data.get('hwid')
        ):
            return jsonify({
                "success": False,
                "message": "Acesso negado: usuário não é administrador"
            }), 403

        # Atualizar configs
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO configs 
                (version, discord_link, news_message, updated_by)
            VALUES 
                (%s, %s, %s, %s)
        """, (
            data.get('version'),
            data.get('discord_link'),
            data.get('news_message'),
            data.get('username')
        ))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Configurações atualizadas com sucesso"
        })

    except Exception as e:
        logging.error(f"Erro ao atualizar configs: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Erro ao atualizar configurações: {str(e)}"
        }), 500

@app.route('/get_configs', methods=['GET'])
def get_configs():
    try:
        configs = db.get_configs()
        return jsonify(configs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/')
def index():
    return jsonify({
        "name": "MG Spoofer API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": [
            "/health",
            "/api/v1/login",
            "/api/v1/register",
            "/api/v1/validate_key"
        ]
    })

@app.route('/reset_hwid', methods=['POST'])
def reset_hwid():
    """Rota para resetar o HWID de um usuário"""
    try:
        data = request.get_json()
        username = data.get('username')
        admin_username = data.get('admin')
        
        logging.info(f"Tentativa de resetar HWID para o usuário {username} por {admin_username}")
        
        # Validar dados
        if not username or not admin_username:
            return jsonify({
                "success": False, 
                "message": "Dados incompletos. Necessário informar username e admin."
            }), 400
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificar se o solicitante é admin
        cur.execute("""
            SELECT is_admin FROM users 
            WHERE username = %s
        """, (admin_username,))
        
        admin_check = cur.fetchone()
        if not admin_check or not admin_check[0]:
            cur.close()
            conn.close()
            logging.warning(f"Tentativa não autorizada de resetar HWID por {admin_username}")
            return jsonify({
                "success": False,
                "message": "Apenas administradores podem resetar HWID"
            }), 403
        
        # Verificar se o usuário existe
        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        
        if not user:
            cur.close()
            conn.close()
            return jsonify({
                "success": False,
                "message": f"Usuário {username} não encontrado"
            }), 404
        
        # Resetar o HWID
        cur.execute("UPDATE users SET hwid = NULL WHERE username = %s", (username,))
        conn.commit()
        
        logging.info(f"HWID resetado com sucesso para o usuário {username} por {admin_username}")
        
        cur.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": f"HWID do usuário {username} foi resetado com sucesso"
        })
        
    except Exception as e:
        logging.error(f"Erro ao resetar HWID: {str(e)}")
        if 'conn' in locals() and conn:
            conn.rollback()
            if 'cur' in locals() and cur:
                cur.close()
            conn.close()
            
        return jsonify({
            "success": False,
            "message": f"Erro ao resetar HWID: {str(e)}"
        }), 500

@app.route('/verify_key', methods=['POST'])
def verify_key():
    """Rota para verificar informações de uma chave"""
    try:
        data = request.get_json()
        key = data.get('key')
        
        logging.info(f"Tentativa de verificar informações da chave: {key}")
        
        # Validar dados
        if not key:
            return jsonify({
                "success": False, 
                "message": "Dados incompletos. Necessário informar a chave."
            }), 400
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificar se a chave existe
        cur.execute("""
            SELECT 
                k.key_value,
                k.expiration_date,
                k.is_used,
                k.user_id,
                u.username,
                u.hwid
            FROM 
                keys k
                LEFT JOIN users u ON k.user_id = u.id
            WHERE 
                k.key_value = %s
        """, (key,))
        
        key_info = cur.fetchone()
        
        if not key_info:
            cur.close()
            conn.close()
            return jsonify({
                "success": False,
                "message": f"Chave '{key}' não encontrada"
            }), 404
        
        key_value, expiry_date, is_used, user_id, username, hwid = key_info
        
        # Determinar status da chave
        current_date = datetime.datetime.now()
        
        if is_used and user_id:
            if expiry_date and current_date > expiry_date:
                status = "Expirado"
            else:
                status = "Ativo"
        else:
            status = "Não Ativado"
        
        # Formatação da data para exibição
        expiration_date_str = expiry_date.strftime("%d/%m/%Y") if expiry_date else "N/A"
        
        cur.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "key": key_value,
            "status": status,
            "username": username if username else "Não Associado",
            "hwid": hwid if hwid else "Não Associado",
            "expirationDate": expiration_date_str,
            "isUsed": is_used
        })
        
    except Exception as e:
        logging.error(f"Erro ao verificar chave: {str(e)}")
        if 'conn' in locals() and conn:
            if 'cur' in locals() and cur:
                cur.close()
            conn.close()
            
        return jsonify({
            "success": False,
            "message": f"Erro ao verificar chave: {str(e)}"
        }), 500

@app.route('/verify_user', methods=['POST'])
def verify_user():
    """Rota para verificar informações de um usuário"""
    try:
        data = request.get_json()
        username = data.get('username')
        admin_username = data.get('admin')
        
        logging.info(f"Tentativa de verificar informações do usuário: {username} por {admin_username}")
        
        # Validar dados
        if not username or not admin_username:
            return jsonify({
                "success": False, 
                "message": "Dados incompletos. Necessário informar o usuário e o administrador."
            }), 400
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificar se o requisitante é um administrador
        cur.execute("SELECT is_admin FROM users WHERE username = %s", (admin_username,))
        admin_check = cur.fetchone()
        
        if not admin_check or not admin_check[0]:
            cur.close()
            conn.close()
            return jsonify({
                "success": False,
                "message": "Apenas administradores podem verificar informações de usuários."
            }), 403
        
        # Verificar se o usuário existe
        cur.execute("""
            SELECT username, hwid, expiration_date, is_admin 
            FROM users 
            WHERE username = %s
        """, (username,))
        
        user_info = cur.fetchone()
        
        if not user_info:
            cur.close()
            conn.close()
            return jsonify({
                "success": False,
                "message": f"Usuário '{username}' não encontrado."
            }), 404
        
        username_db, hwid_db, expiry_date_db, is_admin_db = user_info
        
        # Define o status baseado na data de expiração e status de admin
        if is_admin_db:
            status = "Administrador"
        elif expiry_date_db and datetime.datetime.now() <= expiry_date_db:
            status = "Ativo"
        elif expiry_date_db:
            status = "Expirado"
        else:
            status = "Desconhecido"
        
        # Formato da data de expiração
        expiry_str = expiry_date_db.strftime("%d/%m/%Y") if expiry_date_db else "Não aplicável"
        
        cur.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "username": username_db,
            "status": status,
            "hwid": hwid_db if hwid_db else "Não definido",
            "expiration_date": expiry_str
        })
        
    except Exception as e:
        logging.error(f"Erro ao verificar usuário: {str(e)}")
        if 'conn' in locals() and conn:
            if 'cur' in locals() and cur:
                cur.close()
            conn.close()
            
        return jsonify({
            "success": False,
            "message": f"Erro ao verificar usuário: {str(e)}"
        }), 500

@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Erro não tratado: {str(e)}", exc_info=True)
    logging.error(f"Requisição que causou o erro: {request.method} {request.url}")
    if request.get_json():
        logging.error(f"Dados JSON recebidos: {request.get_json()}")
    return jsonify({"success": False, "message": f"Erro interno do servidor: {str(e)}"}), 500

if __name__ == '__main__':
    # Modo de desenvolvimento
    if os.environ.get('FLASK_ENV') == 'development':
        app.run(host='0.0.0.0', port=port, debug=True)
    else:
        # Modo de produção
        app.run(host='0.0.0.0', port=port)