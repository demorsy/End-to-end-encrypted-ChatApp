import threading
import socket
from urllib.parse import urlparse
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, HMAC
import json
import base64
import logging

logging.basicConfig(filename='server.log', level=logging.INFO)


serverRSAprivate = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQC99S+ebJlyBL8hY4Za7PWR2zcyfvNJls20zxcZDVJ7KbAwwkuu\nSp0PJEAq3wcFfyjl0VqeLxM4GAxKgilut2Z10fwgYo4982f+UGQrlq+AI1iKbOuj\nlCMWXTyJwfelPIGZr/MiYhWP/Itrz/l1rj4b6SSwbmYfvWYzgVfgRcfHewIDAQAB\nAoGAPGPNfr0hz0jJBrFgTlnU/EjH9Iq9h6Ckxx2rRzCgDz3CoM20R7W61sx8heSf\nk9TISL/U4kMvBf9HMQzOZT9zF+cgzufPrkNqfywAyue0YqURr3zUm9jZXRB5Pz0B\nBKskPg6BCkBE03fSHRwEDHDKN4VOQhnInH1mrHFOL1KCLzkCQQDJiwuOsCmVQkVu\nNikdbbMZv0kzkXFi8vuhmGntUKqXsyf/3rheRwzEke9L6v25Mk65jaxMG+PpMEiS\no+Su9YxdAkEA8UjEaevwOv9E1rqJk1nhEnD1dLjVqk+MR4AaMzwMl9g/J4huX3qr\nUMZfjcLl14yXF48o5WxzHtC8bSQbO2MltwJATtDWczWG/XzOJByAFacZvD7nBIij\nO9vj9bzh59F89Rg100Uo+o10e8bKOvkpwevfh4bU02qwxTeBmf8H5jfWbQJAFp67\nyzJTUzSbP4Y9X5MNhq0QVeD+JvlOLWXVDviSNaoQQaSItGrLpMb0LlYXNh34DD1f\nmCKSqFDpWVIJO4gQAQJBAL4spOxGeWkngpwpAdU7t5W9vwcjttj7q4iGeikduAF4\nZZEwc1DHFFTGcspg/QUZeJkgYHhqHfwwYxGzOuK/NWY=\n-----END RSA PRIVATE KEY-----'
serverRSApublic = b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC99S+ebJlyBL8hY4Za7PWR2zcy\nfvNJls20zxcZDVJ7KbAwwkuuSp0PJEAq3wcFfyjl0VqeLxM4GAxKgilut2Z10fwg\nYo4982f+UGQrlq+AI1iKbOujlCMWXTyJwfelPIGZr/MiYhWP/Itrz/l1rj4b6SSw\nbmYfvWYzgVfgRcfHewIDAQAB\n-----END PUBLIC KEY-----'

database = {}
# Create a new socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the address and port
s.bind(('localhost', 8080))

# Listen for incoming connections
s.listen()

def sign_publickey(private_key, userpublickey):
    # Mesajı özetleme (hash)

    logging.debug('Sign public key: {}'.format(userpublickey))

    
    hashed_message = SHA256.new(userpublickey)
    


    # Dijital imza oluşturma
    rsa_private_key = RSA.import_key(private_key)
    signature = pkcs1_15.new(rsa_private_key).sign(hashed_message)
    return signature



# Function to handle a new connection in a separate thread
def handle_connection(conn, addr):


    request = conn.recv(1024)

    request_str = request.decode()
    json_request = json.loads(request_str)

    method_path = json_request["method"]

    if(method_path=="register"):
        user_publickey = json_request["publickey"]
        username = json_request["username"]
        password = json_request["password"]
        port = json_request["port"]


        if username in database:
            logging.error('Username already exists: {}'.format(username))
            json_response = {"status": "Bu kullanıcı ismi kullanılmış."}
            json_response = json.dumps(json_response)
            conn.sendall(json_response.encode())
        else:    
            signed_key = sign_publickey(serverRSAprivate,user_publickey.encode())
            database[username] = [password,signed_key,port,user_publickey]

            conn.sendall(signed_key)


    if(method_path=="login"):
        username = json_request["username"]
        password = json_request["password"]
        if username in database:
            if database[username][0] == password:
                logging.info('User logged in: {}'.format(username))
                json_response = {"status": "ok"}
                json_response = json.dumps(json_response)
                conn.sendall(json_response.encode())
            else:
                logging.error('Wrong password for user: {}'.format(username))
                json_response = {"status": "wrong password."}
                json_response = json.dumps(json_response)
                conn.sendall(json_response.encode())
        else:
            logging.error('Wrong username: {}'.format(username))
            json_response = {"status": "wrong username."}
            json_response = json.dumps(json_response)
            conn.sendall(json_response.encode())
        
    if(method_path=="requested_inf"):
        requested_username = json_request["requested_username"]
        if requested_username in database:
            requested_port = database[requested_username][2] 
            certificate_ofreceiver = database[requested_username][1]
            publickey_ofreceiver = database[requested_username][3]
            certificate_base64 = base64.b64encode(certificate_ofreceiver).decode('utf-8')

            logging.info('Requested info for user: {}'.format(requested_username))
            logging.info('Requested port for user: {}'.format(requested_port))
            logging.info('Requested certificate for user: {}'.format(certificate_base64))
            logging.info('Requested public key for user: {}'.format(publickey_ofreceiver))

            json_response = {"status": "ok", "requested_port":requested_port,
                              "requested_certificate":certificate_base64, 
                              "requested_publickeyofreceiver":publickey_ofreceiver}
            json_response = json.dumps(json_response)
            conn.sendall(json_response.encode())
        else:
            logging.error('Wrong username: {}'.format(requested_username))
            json_response = {"status": "username not found."}
            json_response = json.dumps(json_response)
            conn.sendall(json_response.encode())


    conn.close()


# Accept incoming connections in a loop
while True:
    conn, addr = s.accept()
    
    
    # Create a new thread to handle the connection
    t = threading.Thread(target=handle_connection, args=(conn, addr))
    # Start the thread
    t.start()
    
            
