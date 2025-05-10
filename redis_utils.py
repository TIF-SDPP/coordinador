import redis
import json
import time
import os
from dotenv import load_dotenv


class RedisUtils:
    load_dotenv()

    redis_host = os.getenv("REDIS_HOST")
    redis_password = os.getenv("REDIS_PASSWORD")
    def __init__(self, host=redis_host, port=6379, db=0, password=redis_password):
        """Initialize Redis connection with security."""
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.redis_client = None
        self.retry_interval = 10
        self._connect()

    def _connect(self):
        """Try to connect to Redis with retries."""
        while True:
            try:
                # Intentar conectarse a Redis
                self.redis_client = redis.StrictRedis(host=self.host, port=self.port, db=self.db, password=self.password)
                self.redis_client.ping()  # Verificar que Redis esté respondiendo
                print("Conexión a Redis establecida exitosamente.")
                break
            except redis.ConnectionError:
                print("Error de conexión a Redis. Reintentando en {} segundos...".format(self.retry_interval))
                time.sleep(self.retry_interval)

    def post_message(self, message, list_key='blockchain'):
        """Serialize and add a message to the beginning of a Redis list."""
        try:
            message_json = json.dumps(message)
            self.redis_client.lpush(list_key, message_json)
        except redis.RedisError as e:
            print(f"Error al publicar mensaje en Redis: {e}")
            self._connect()  # Try reconnecting and retry the operation
            self.post_message(message, list_key)

    def get_recent_messages(self, list_key='blockchain', count=10):
        """Retrieve the last 'count' messages from a Redis list."""
        try:
            messages_json = self.redis_client.lrange(list_key, 0, count - 1)
            return [json.loads(msg) for msg in messages_json]
        except redis.RedisError as e:
            print(f"Error al obtener mensajes de Redis: {e}")
            self._connect()  # Try reconnecting and retry the operation
            return self.get_recent_messages(list_key, count)

    def get_latest_element(self, list_key='blockchain'):
        """Retrieve the latest element from a Redis list."""
        try:
            latest_element_json = self.redis_client.lindex(list_key, 0)
            if latest_element_json:
                return json.loads(latest_element_json)
        except redis.RedisError as e:
            print(f"Error al obtener mensajes de Redis: {e}")
            self._connect()  # Try reconnecting and retry the operation
            return self.get_latest_element(list_key='blockchain')
    
    def exists_id(self, id, list_key='blockchain'):
        """Check if an ID exists in the list."""
        try:
            messages_json = self.redis_client.lrange(list_key, 0, -1)  # Retrieve all messages
            for msg_json in messages_json:
                msg = json.loads(msg_json)
                if 'id' in msg and msg['id'] == id:
                    return True
            return False
        except redis.RedisError as e:
            print(f"Error al obtener mensajes de Redis: {e}")
            self._connect()  # Try reconnecting and retry the operation
            return self.exists_id(id, list_key='blockchain')

# The module can be used after import by creating an instance of RedisUtils