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
        db_connection = psycopg2.connect(**db_config)
        db_cursor = db_connection.cursor()
        db_cursor.execute('select uuid, password, client_secret from admin.users')
        self.db_users = {row[0]: {'password': row[1], 'client_secret': row[2]} for row in db_cursor.fetchall()}
        del db_cursor
        db_connection.close()

    def __del__(self):
        self.db_users = {}

    async def generateToken(self, request: auth_pb2.TokenRequest, context: grpc.aio.ServicerContext) -> auth_pb2.TokenResponse:

        payload_access_token = {
            "grant_type": request.grant_type,
            "client_id": request.client_id,
            "scope": request.scope,
            "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
        }

        if not request.refresh and request.client_id in refresh_cache.keys():
            refresh_token = refresh_cache[request.client_id]
        else:
            payload_refresh_token = {
                "grant_type": request.grant_type,
                "client_id": request.client_id,
                "scope": request.scope
            }
            refresh_token = hashlib.sha256(json.dumps(payload_refresh_token).encode()).hexdigest()
            refresh_cache[request.client_id] = refresh_token

        client_secret = request.client_secret

        encoded_jwt = jwt.encode(payload_access_token, client_secret, algorithm='HS256')

        return auth_pb2.TokenResponse(access_token=encoded_jwt, token_type='Bearer', expires_in=3600, scope=request.scope, refresh_token=refresh_token)


    async def validateToken(self, request: auth_pb2.TokenValidationRequest, context: grpc.aio.ServicerContext) -> auth_pb2.TokenValidationResponse:




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