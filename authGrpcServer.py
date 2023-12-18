import asyncio
import datetime
import hashlib
import json
import logging
from sys import argv
from concurrent import futures

import grpc
from grpc_reflection.v1alpha import reflection
import auth_pb2_grpc
import auth_pb2
import psycopg2
import jwt
import redis


JWT_SECRET = '23be4a6cb3002f3ab4d223e754ab4dd16c1979bc79cac957a1fe377e8d5746b7'
r_client = redis.Redis(host='localhost', port=6379, db=0)
_cleanup_coroutines = []

db_config = {
    'dbname': 'your_dbname',
    'user': 'your_username',
    'password': 'your_password',
    'host': 'your_host',
    'port': 'your_port'
}

refresh_cache = {}

class OAuth2Service(auth_pb2_grpc.OAuth2ServiceServicer):


    def __init__(self):
        global db_config
        self.db_connection = psycopg2.connect(**db_config)

    def __del__(self):
        self.db_connection.close()

    async def generateToken(self, request: auth_pb2.TokenRequest, context: grpc.aio.ServicerContext) -> auth_pb2.TokenResponse:

        try:
            cur = self.db_connection.cursor()
            cur.execute("""select client_secrete from admin.users where uuid = %s""", (request.client_id, ))
            _sql_data = cur.fetchone()

            if not _sql_data:
                raise Exception('No user found with provided data')

            payload_access_token = {
                "client_id": request.client_id,
                "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1),
            }

            encoded_jwt = jwt.encode(payload_access_token, JWT_SECRET, algorithm='HS256')

            if not request.refresh and r_client.hget(request.client_id, 'refresh'):

                refresh_token = r_client.hget(request.client_id, 'refresh')

            else:
                payload_refresh_token = {
                    "client_id": request.client_id
                }
                refresh_token = hashlib.sha256(json.dumps(payload_refresh_token).encode()).hexdigest()
                await r_client.hmset(request.client_id, {'jwt': encoded_jwt, 'refresh': refresh_token})
                await r_client.expire(request.client_id, 3600)

            return auth_pb2.TokenResponse(access_token=encoded_jwt, token_type='Bearer', expires_in=3600,
                                          refresh_token=refresh_token)
        except Exception as e:
            raise e


    async def validateToken(self, request: auth_pb2.TokenValidationRequest, context: grpc.aio.ServicerContext) -> auth_pb2.TokenValidationResponse:

        try:
            decoded_jwt = jwt.decode(request.access_token, JWT_SECRET, algorithms=['HS256'])
            return auth_pb2.TokenValidationResponse(user_id=json.loads(decoded_jwt)['client_id'])
        except jwt.ExpiredSignatureError:
            raise Exception('Token is expired, please regenerate it')
        except jwt.InvalidTokenError:
            raise Exception('Access token is invalid')
        except Exception as e:
            raise e



async def serve(port):
    server_options = [('grpc.max_send_message_length', 512 * 1024 * 1024),
                  ('grpc.max_receive_message_length', 512 * 1024 * 1024)]
    server = grpc.aio.server(futures.ThreadPoolExecutor(max_workers=100), options = server_options)
    auth_pb2_grpc.add_OAuth2ServiceServicer_to_server(OAuth2Service(), server)
    SERVICE_NAMES = (
        auth_pb2.DESCRIPTOR.services_by_name["DataBaseWorker"].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(SERVICE_NAMES, server)

    server.add_insecure_port(f'[::]:{port}')
    await server.start()

    async def server_graceful_shutdown():
        logging.info("Starting graceful shutdown...")
        await server.stop(5)

    _cleanup_coroutines.append(server_graceful_shutdown())
    await server.wait_for_termination()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    logging.basicConfig(level=logging.INFO)
    try:
        port = 4001
        if len(argv) > 1:
            port = argv[1]
        loop.run_until_complete(serve(port))
    except Exception as err:
        print(err)
    finally:
        loop.run_until_complete(*_cleanup_coroutines)
        loop.close()