from flask import Flask, request, jsonify
import pika
import json
import time
import random
import os
import sys
from flask_cors import CORS
import requests
from functools import wraps
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization
import base64
from redis_utils import RedisUtils
from redis.sentinel import Sentinel

load_dotenv()

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
API_AUDIENCE = os.getenv("API_AUDIENCE")
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST")
AUTH0_USERINFO_URL = os.getenv("AUTH0_USERINFO_URL")
RABBITMQ_USER = os.getenv("RABBITMQ_USER")
RABBITMQ_PASS = os.getenv("RABBITMQ_PASS")
RABBITMQ_PORT = os.getenv("RABBITMQ_PORT")

print('RABBITMQ_PASS')
print(RABBITMQ_PASS)
# Get the current script's directory
current_dir = os.path.dirname(os.path.abspath(__file__))
# Get the parent directory
parent_dir = os.path.dirname(current_dir)

redis_master = None

redis_utils = RedisUtils()

# Valores de umbral para resolver rápido y lento
threshold_fast = 50.0  # Tiempo en segundos para considerar que el worker resuelve rápido
threshold_slow = 100.0  # Tiempo en segundos para considerar que el worker resuelve lento

print("Parent Directory:", parent_dir)
sys.path.append(parent_dir)

# Function to calculate the hash using the provided number and base string
# New hash function
def enhanced_hash(data):
    hash_val = 0
    for byte in data.encode('utf-8'):
        hash_val = (hash_val * 31 + byte) % (2**32)
        hash_val ^= (hash_val << 13) | (hash_val >> 19)  # Additional bit rotation
        hash_val = (hash_val * 17) % (2**32)  # Additional multiplication with a new constant
        hash_val = ((hash_val << 5) | (hash_val >> 27)) & 0xFFFFFFFF  # Final bitwise operation
    return hash_val

# Method to process packages every minute
def process_packages():            
        # Process messages in chunks of 5
        while True:
            try:
                package = []
                for _ in range(20):
                    method_frame, header_frame, body = channel.basic_get(queue='transactions', auto_ack=False)
                    if method_frame:
                        # Add the message to the package
                        package.append(json.loads(body))
                        # Acknowledge the message
                        channel.basic_ack(delivery_tag=method_frame.delivery_tag)
                    else:
                        break  # No more messages available

                if package:
                    # Add metadata to the block package
                    tail_elements = redis_utils.get_recent_messages()
                    
                
                    last_element = redis_utils.get_latest_element()

                
                    max_random=sys.maxsize-1
                    block_id= str(random.randint(0, max_random))
                    prefix = get_prefix_from_redis()  # Obtener el prefijo actual desde Redis

                    block = {
                        "id": block_id,
                        "transactions": package,
                        "prefix": prefix,  # Placeholder for difficulty
                        "base_string_chain": "A4FC",  # hexa for the goal
                        "blockchain_content": last_element["blockchain_content"] if last_element else "[]",  # the blockchain inmutability
                        "random_num_max": max_random,
                    }
                    # Publish the package to" the 'blocks' topic exchange in RabbitMQ
                    channel.basic_publish(exchange='', routing_key='block_challenge', body=json.dumps(block))

                    print(f"Package with block ID {block_id} sent to the 'blocks' topic exchange")
                    # Increment block ID for the next package
                
                time.sleep(60)
            except Exception as e:
                print(f"[ERROR] process_packages: {e}")
                time.sleep(5)  # pequeña espera antes de seguir  

# Connect to RabbitMQ server
def connect_rabbitmq():
    while True:
        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, port=RABBITMQ_PORT, credentials=pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)))
            return connection
        except pika.exceptions.AMQPConnectionError:
            print("Fallo en la conexión, reintentando en 5 segundos...")
            time.sleep(5)

connection = connect_rabbitmq()

channel = connection.channel()
# Declare queues
channel.queue_declare(queue='transactions')
# Declare the topic exchange
#channel.exchange_declare(exchange='block_challenge', exchange_type='topic', durable=True)
channel.queue_declare(queue='block_challenge')

# --- APP side --- 
app = Flask(__name__)
CORS(app)

def inicializar_prefijo():
    if redis_utils.redis_client.get('prefix_key') is None:
        redis_master.redis_client.set('prefix_key', '0000')  # Valor inicial por defecto
        print("Prefijo inicial insertado en Redis: 0000")
    else:
        print("Prefijo ya presente en Redis:", get_prefix_from_redis())

# Endpoint to check the status of the application
@app.route('/status', methods=['GET'])
def check_status():
    return jsonify({'status': 'running'})

# Method to handle incoming transactions (READY)
@app.route('/transaction', methods=['POST'])
def receive_transaction():
    data = request.get_json()

    print(f"Transacción recibida: {data}")

    if "transaction" not in data or "signature" not in data:
        return jsonify({"error": "Missing fields transaction or fields signature"}), 400

    transaction = data["transaction"]
    signature = data["signature"]
    
    required_fields = ["user_from", "user_to", "amount"]
    if not all(field in transaction for field in required_fields):
        return jsonify({"error": "Missing fields in transaction"}), 400

    user_from = transaction["user_from"]

    if user_from == 'universal_acount':
        return jsonify({"error": "universal_account cannot be the user_from"}), 400

    # Recuperar clave pública del usuario
    public_key_json = redis_utils.redis_client.get(f"public_key:{user_from}")
    if not public_key_json:
        return jsonify({"error": "Public key not found for user"}), 400
    
    public_key = json.loads(public_key_json)
    print(public_key)

    if not verify_signature(public_key, transaction, signature):
        return jsonify({"error": "Invalid signature"}), 403

    if channel.is_open:
        channel.basic_publish(exchange='', routing_key='transactions', body=json.dumps(data))
    else:
        reconnect()
        
    return jsonify({"message": "Transaction received and queued in RabbitMQ"}), 200

def reconnect():
    global connection, channel
    while True:
        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(
                host=RABBITMQ_HOST,
                port=RABBITMQ_PORT,
                credentials=pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
            ))
            channel = connection.channel()
            channel.queue_declare(queue='transactions', durable=True)
            channel.queue_declare(queue='block_challenge', durable=True)
            print("🔁 Reconnected to RabbitMQ")
            break
        except pika.exceptions.AMQPConnectionError as e:
            print(f"🔌 Reconnection failed: {e}. Retrying in 5 seconds...")
            time.sleep(5)

# Función para agregar relleno Base64
def add_b64_padding(b64_string):
    return b64_string + '=' * (-len(b64_string) % 4)

def verify_signature(jwk, transaction, signature_b64):
    try:
        message = f"{transaction['user_from']}|{transaction['user_to']}|{transaction['amount']}"

        print(f"[DEBUG] JWK: {jwk}")
        print(f"[DEBUG] Message: {message}")
        print(f"[DEBUG] Signature (base64): {signature_b64}")

        x = int.from_bytes(base64.urlsafe_b64decode(add_b64_padding(jwk['x'])), 'big')
        y = int.from_bytes(base64.urlsafe_b64decode(add_b64_padding(jwk['y'])), 'big')
        public_numbers = EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        public_key = public_numbers.public_key(default_backend())

        encoded_message = message.encode('utf-8')
        print(f"[DEBUG] Mensaje codificado (bytes): {encoded_message}")

        signature_bytes = base64.urlsafe_b64decode(add_b64_padding(signature_b64))
        print(f"[DEBUG] Signature (raw): {signature_bytes.hex()}")

        # Convertir raw firma a DER
        r = int.from_bytes(signature_bytes[:32], 'big')
        s = int.from_bytes(signature_bytes[32:], 'big')
        der_signature = encode_dss_signature(r, s)

        public_key.verify(der_signature, encoded_message, ec.ECDSA(hashes.SHA256()))
        print("[DEBUG] Firma válida ✅")
        return True
    except Exception as e:
        print(f"[ERROR] Verificación fallida: {e}")
        return False

@app.route('/balance/<user_id>', methods=['GET'])
def get_balance(user_id):
    balance = 0

    blocks = redis_utils.redis_client.lrange('blockchain', 0, -1)

    for block in blocks:
        block_data = json.loads(block)

        recompensa = block_data.get('tx_recompensa')
        if recompensa and recompensa.get('user_to') == user_id:
            balance += float(recompensa.get('amount', 0))

        transactions = block_data.get('transactions', [])
        for tx_data in transactions:
            tx = tx_data.get('transaction', {})
            if tx.get('user_to') == user_id:
                balance += float(tx.get('amount', 0))
            if tx.get('user_from') == user_id:
                balance -= float(tx.get('amount', 0))

    return jsonify({'balance': balance})


def balance_universal():
    balance = 1_000_000

    blocks = redis_utils.redis_client.lrange('blockchain', 0, -1)

    for block in blocks:
        block_data = json.loads(block)

        recompensa = block_data.get('tx_recompensa')

        if recompensa is not None:
            balance -= float(recompensa.get('amount', 0))

    print(f'balance {balance}')
    return balance

def get_prefix_from_redis():
    prefix = redis_utils.redis_client.get('prefix_key')
    if prefix is None:
        return "00000"  # Valor por defecto si no existe
    return prefix.decode('utf-8')

@app.route('/key_exists/<user_id>', methods=['GET'])
def check_key_exists(user_id):
    # Verificar si la clave pública existe en Redis
    public_key_json = redis_utils.redis_client.get(f"public_key:{user_id}")
    
    # Responder con un JSON indicando si existe o no
    return jsonify({'exists': bool(public_key_json)}), 200

# Notificación al Pool Manager para ajustar la dificultad (prefijo)
def ajustar_prefijo_coordinador(tiempo_resolucion):
    """
    Función que ajusta la dificultad en el Coordinador en función del tiempo de resolución.
    Si la resolución es rápida, incrementa el prefijo, si es lenta, lo disminuye.
    """
    if tiempo_resolucion < threshold_fast:  # Si se resolvió rápidamente
        # Notificar al Pool Manager para aumentar el prefijo
        print("Resolución rápida, aumentando dificultad (prefijo).")
        aumentar_prefijo()
    elif tiempo_resolucion > threshold_slow:  # Si se resolvió lentamente
        # Notificar al Pool Manager para disminuir el prefijo
        print("Resolución lenta, disminuyendo dificultad (prefijo).")
        disminuir_prefijo()
    else:
        # Si está dentro de los tiempos aceptables, mantener la dificultad
        print("Resolución en tiempo normal, manteniendo dificultad (prefijo).")

def aumentar_prefijo():
    prefix = get_prefix_from_redis()  # Obtener el prefijo actual desde Redis
    prefix = "0" + prefix  # Añadir más ceros al prefijo
    redis_master.redis_client.set('prefix_key', prefix)  # Actualizar el prefijo en Redis
    print(f"Nuevo prefijo aumentado: {prefix}")

def disminuir_prefijo():
    prefix = get_prefix_from_redis()  # Obtener el prefijo actual desde Redis
    if len(prefix) > 1:
        prefix = prefix[1:]  # Eliminar un cero del prefijo
        redis_master.redis_client.set('prefix_key', prefix)  # Actualizar el prefijo en Redis
    print(f"Nuevo prefijo disminuido: {prefix}")

@app.route('/solved_task', methods=['POST'])
def receive_solved_task():
    data = request.get_json()

    if data['timeout']:
        if not redis_utils.exists_id(data['id']):
            disminuir_prefijo()
            return jsonify({'message': 'Ok, it was very difficult. Reducing the difficult...'}), 201
        else:
            return jsonify({'message': 'Discarding the package.'}), 201

    # Calcular el hash usando el número y la cadena base proporcionados
    combined_data = f"{data['number']}{data['base_string_chain']}{data['blockchain_content']}"
    calculated_hash = format(enhanced_hash(combined_data), '08x')
    timestamp = time.time()

    # Tiempo de resolución
    tiempo_resolucion = data.get("processing_time")
    print(f"Tiempo de resolución del worker: {tiempo_resolucion} segundos")

    print("--------------------------------")
    print(f"Received hash: {data['hash']}")
    print(f"Locally calculated hash: {calculated_hash}")

    if data['hash'] == calculated_hash:
        print("Data is valid")
        print("--------------------------------")

        # Verificar si el bloque ya existe en la base de datos
        if redis_utils.exists_id(data['id']):
            print("Block exists")
            return jsonify({'message': 'Block already solved by another node. Discarding...'}), 200
        else:
            print("Block does not exist, adding to the network")

            # Ajustar el prefijo basado en el tiempo de resolución
            ajustar_prefijo_coordinador(tiempo_resolucion)

            blockchain_data = f"{data['base_string_chain']}{data['hash']}"
            blockchain_content = format(enhanced_hash(blockchain_data), '08x')
            print(f"Blockchain content: {blockchain_content}")

            # Obtener el hash del último bloque almacenado en la base de datos
            try:
                previous_block = redis_utils.get_latest_element()
            except:
                previous_block = 'Null'

            if previous_block != None:
                print("--------------------------------")
                print(f"Previous block hash: {previous_block['hash']}")
                data['previous_block'] = previous_block["hash"]
                print("--------------------------------")
            else:
                print("--------------------------------")
                print(f"Previous block hash: NULL ")
                print("--------------------------------")
                data['previous_block'] = "None"

            # Añadir timestamp y el hash del bloque anterior a los datos
            data['timestamp'] = timestamp
            data['blockchain_content'] = blockchain_content
            data['tx_recompensa'] = {'nonce': data['number'],"user_to":"", 'from':"", 'amount':0}

            # Si es un usuario, enviar la recompensa
            is_user = data.get("worker_user") == "true"  # Convertir a booleano

            is_reward_block = any(tx.get("reward", False) for tx in data.get("transactions", []))

            if is_user and not is_reward_block:
                try:
                    print("Data is user")
                    user_id = data.get('user_id')
                    difficulty = len(data.get('prefix'))
                    reward_amount = 10 * difficulty  # La recompensa puede depender de la dificultad
                    message = f"Recompensa de {reward_amount} tokens para {user_id} por encontrar bloque"

                    if user_id:
                        balance = balance_universal()
                        print(f'universal_acount {balance}')
                        if balance <= 0:
                              return jsonify({'message': 'Nos fundimos :('}), 400
                        data['tx_recompensa']['from'] = "universal_acount"
                        data['tx_recompensa']['user_to'] = user_id
                        data['tx_recompensa']['amount'] = reward_amount

                    else:
                        print("No se encontró user_id para recompensa")

                except Exception as e:
                    print(f"Error al enviar recompensa: {str(e)}")

            print("------ Final Block -------")
            print(data)
            print("------ Final Block -------")

             # Guardar el bloque en Redis
            consultar_maestro()
            redis_master.post_message(message=data)

        return jsonify({'message': 'Block validated and added to the blockchain.'}), 201
    else:
        return jsonify({'message': 'Invalid hash. Discarding the package.'}), 400

@app.route('/metrics', methods=['GET'])
def get_metrics():
    workers = {
        "worker_cpu": {"cant": 0, "processing_time": 0},
        "worker_gpu": {"cant": 0, "processing_time": 0},
        "worker_user": {"cant": 0, "processing_time": 0}
    }

    blocks = redis_utils.redis_client.lrange('blockchain', 0, -1)

    for block in blocks:
        try:
            block_data = json.loads(block)
            worker_type = block_data.get("worker_type")
            timestamp = block_data.get("processing_time", 0)
            print("metric")
            print(block_data)

            if worker_type in workers:
                workers[worker_type]["cant"] += 1
                workers[worker_type]["processing_time"] += timestamp
        except json.JSONDecodeError:
            continue  # Ignorar bloques corruptos


    for worker_type, data in workers.items():
            if data["cant"] > 0:
                data["processing_time"] = data["processing_time"] / data["cant"]

    return jsonify({'data': workers}), 200

def is_token_valid(token):
    try:
        response = requests.get(
            AUTH0_USERINFO_URL,
            headers={"Authorization": f"Bearer {token}"}
        )
        return response.status_code == 200
    except Exception as e:
        print(f"Error validating token: {e}")
        return False

@app.route('/register_key', methods=['POST'])
def register_key():
    data = request.get_json()
    auth_header = request.headers.get("Authorization")
    user_id = data.get("user_id")
    public_key = data.get("public_key")

    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or malformed Authorization header"}), 401
    
    token = auth_header.replace("Bearer ", "")

    if not is_token_valid(token):
        return jsonify({"error": "Invalid or expired token"}), 401

    if not user_id or not public_key:
        return jsonify({"error": "Missing user_id or public_key"}), 400

    redis_key = f"public_key:{user_id}"
    redis_master.redis_client.set(redis_key, json.dumps(public_key))

    return jsonify({"message": "Public key registered successfully"}), 200

def create_genesis_block():
    genesis_block = {
        "id": "genesis_block",
        "hash": "00000000",  # Hash fijo o generado
        "previous_block": None,
        "blockchain_content": "",
        "timestamp": time.time(),
        "transactions": [
            {
                "user_from": "system",  # o "null"
                "user_to": "universal_account",
                "amount": 1_000_000
            }
        ]
    }

    # Agregarlo como primer bloque si aún no existe
    latest = redis_utils.get_latest_element()
    if latest is None:
        redis_master.post_message(genesis_block)
        print("🧱 Bloque génesis creado con fondos para universal_account")
    else:
        print("🧱 Ya existe un bloque, génesis no necesario")

# Cargar la clave privada de universal_account desde un archivo .pem
def load_private_key():
    private_key_path = "universal_account_private_key.pem"  # Asegúrate de usar la ruta correcta
    with open(private_key_path, "rb") as f:
        private_key_data = f.read()
    private_key = load_pem_private_key(private_key_data, password=None)
    return private_key

def sign_message(private_key, message):
    # Firmar el mensaje con la clave privada (esto genera una firma DER)
    signature_der = private_key.sign(
        message.encode('utf-8'),
        ec.ECDSA(hashes.SHA256())
    )

    # Decodificar firma DER a r|s raw
    r, s = decode_dss_signature(signature_der)
    signature_raw = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')

    # Codificar la firma raw a base64 url-safe sin padding
    signature_b64 = base64.urlsafe_b64encode(signature_raw).decode('utf-8').rstrip("=")
    return signature_b64

def register_universal_account_key():
    redis_key = "public_key:universal_account"

    # Si ya existe la clave, no hacemos nada
    if redis_utils.redis_client.get(redis_key):
        print("🔑 Clave pública de universal_account ya registrada")
        return

    # Generar par de claves
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    # Codificar x e y en Base64 URL-safe sin padding
    x = base64.urlsafe_b64encode(public_numbers.x.to_bytes(32, 'big')).decode('utf-8').rstrip("=")
    y = base64.urlsafe_b64encode(public_numbers.y.to_bytes(32, 'big')).decode('utf-8').rstrip("=")

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "ext": True,
        "key_ops": ["verify"]
    }

    # Guardar clave pública en Redis
    redis_master.redis_client.set(redis_key, json.dumps(jwk))
    print("🔐 Clave pública de universal_account registrada en Redis")

    # Guardar la clave privada en un archivo .pem
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Especifica la ruta del archivo .pem donde se almacenará la clave privada
    pem_file_path = "universal_account_private_key.pem"

    with open(pem_file_path, "wb") as pem_file:
        pem_file.write(private_key_pem)

    print(f"Clave privada guardada en {pem_file_path}")

def consultar_maestro():

    global redis_master
    
    # Lista de tuplas (host, puerto) de los Sentinels
    sentinels = [
        ('redis-sentinel-0.service-redis-sentinel.default.svc.cluster.local', 26379),
        ('redis-sentinel-1.service-redis-sentinel.default.svc.cluster.local', 26379),
        ('redis-sentinel-2.service-redis-sentinel.default.svc.cluster.local', 26379),
    ]

    # Conectar al Sentinel
    sentinel = Sentinel(sentinels, socket_timeout=0.1)

    master_address = sentinel.discover_master('mymaster')

    print(f"Master: {master_address[0]}:{master_address[1]}")

    host_master = master_address[0].split(":")[0]

    redis_master = RedisUtils(host=host_master)

# Run the process_packages method in a separate thread
import threading
process_packages_thread = threading.Thread(target=process_packages)
process_packages_thread.start()

if __name__ == '__main__':
    # 💥 Crear bloque génesis si es necesario
    create_genesis_block()

    # 💥 Generar claves del usuario génesis si es necesario
    register_universal_account_key()
    
    # 💥 Inicializar prefijo de bloques o recuperarlo de Redis
    inicializar_prefijo()

    consultar_maestro()

    app.run(host='0.0.0.0', port=8080, debug=False)
