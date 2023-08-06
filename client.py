import tkinter as tk
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import threading
import socket
import hashlib
import time
import hmac
import base64
import json
import sys
serverRSApublic = b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC99S+ebJlyBL8hY4Za7PWR2zcy\nfvNJls20zxcZDVJ7KbAwwkuuSp0PJEAq3wcFfyjl0VqeLxM4GAxKgilut2Z10fwg\nYo4982f+UGQrlq+AI1iKbOujlCMWXTyJwfelPIGZr/MiYhWP/Itrz/l1rj4b6SSw\nbmYfvWYzgVfgRcfHewIDAQAB\n-----END PUBLIC KEY-----'
lock = threading.Lock()
import os
import logging





if not os.path.exists("secrets"):
    os.makedirs("secrets")
if not os.path.exists("RSA_keys"):
    os.makedirs("RSA_keys")
if not os.path.exists("datas"):
    os.makedirs("datas")
if not os.path.exists("datas"):
    os.makedirs("datas")

# STEP 1 -----------------------------------------------------------------

#draw login screen
class LoginScreen(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
       
        self.master = master
        self.pack()
        self.create_widgets()
        self.on_login_success = on_login_success
        self.myRSApublic = None
        self.myRSAprivate = None
        self.serverRSApublic = b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC99S+ebJlyBL8hY4Za7PWR2zcy\nfvNJls20zxcZDVJ7KbAwwkuuSp0PJEAq3wcFfyjl0VqeLxM4GAxKgilut2Z10fwg\nYo4982f+UGQrlq+AI1iKbOujlCMWXTyJwfelPIGZr/MiYhWP/Itrz/l1rj4b6SSw\nbmYfvWYzgVfgRcfHewIDAQAB\n-----END PUBLIC KEY-----'
        self.username = None
        self.port = None

    # login screen fields and buttons
    def create_widgets(self):
        self.username_label = tk.Label(self, text="Kullanıcı Adı:")
        self.username_label.pack()
        self.username_entry = tk.Entry(self)
        self.username_entry.pack()

        self.password_label = tk.Label(self, text="Parola:")
        self.password_label.pack()
        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack()

        self.login_button = tk.Button(self, text="Giriş Yap", command=self.login_screen)
        self.login_button.pack()

        self.login_button = tk.Button(self, text="Kayıt Ol", command=self.register)
        self.login_button.pack()

    #login function to send login request to server
    def login_screen(self):
        #get username and password from entry fields
        username_t = self.username_entry.get()
        password_t = self.password_entry.get()
        password_hashed = hashlib.sha256(password_t.encode())
        #create json message to send server
        json_message = {'method' : "login",
                        'username': username_t,
                        'password': password_hashed.hexdigest()}

        log_filename = f"client_{username_t}.log"
        logging.basicConfig(filename=log_filename, level=logging.INFO)      

        #send json message to server
        if(self.login(json_message)):

            logging.info("Login successful")
            self.username = username_t
            self.port = self.generate_port_from_username(username_t)
            
            #open RSA private keys
            with open('RSA_keys/private_key{}.pem'.format(username_t), 'rb') as f:
                self.myRSAprivate = f.read()
                logging.info("Private key read ->" + str(self.myRSAprivate))
            #open RSA public keys
            with open('RSA_keys/public_key{}.pem'.format(username_t), 'rb') as f:
                self.myRSApublic = f.read()
                logging.info("Public key read ->" + str(self.myRSApublic))
            #change screen to chat screen
            self.on_login_success(self.username,self.port,self.myRSApublic, self.myRSAprivate)
        else:
            logging.info("Login failed")
        
        # Giriş doğrulama işlemleri burada yapılabilir

    def register(self):
        #get username and password from entry fields
        username_t = self.username_entry.get()
        password_t = self.password_entry.get()
        self.username = username_t 
        password_hashed = hashlib.sha256(password_t.encode())

        log_filename = f"client_{username_t}.log"
        logging.basicConfig(filename=log_filename, level=logging.INFO)    
        #create json message to send server
        port = self.generate_port_from_username(self.username)
        reg_result = self.registerServer(self.username,password_hashed.hexdigest(),self.serverRSApublic,port)
        if (reg_result):


            
            
            logging.info("Register successful")
             #change screen to chat screen
            self.on_login_success(self.username,port,self.myRSApublic, self.myRSAprivate)
        else:
            logging.info("Register failed")
            
        


    def generate_port_from_username(self,username):
        # Hash the username using SHA256
        hash_object = hashlib.sha256(username.encode())
        hash_hex = hash_object.hexdigest()

        # Convert the hash to a decimal number
        decimal_hash = int(hash_hex, 16)

        # Limit the port number within a specific range
        # The port range is from 1024 to 65535 (inclusive)
        port = decimal_hash % (65535 - 1024 + 1) + 1024

        return port


    
    def verification(self,public_key, hashed_public, server_response):
        # Verify the digital signature
        logging.info("Verification started")
        logging.info("Public key ->" + str(public_key))
        logging.info("Hashed public key ->" + str(hashed_public))
        logging.info("Server response ->" + str(server_response))

        # Import the RSA public key
        rsa_public_key = RSA.import_key(public_key)
        try:
            # Verify the signature using the PKCS#1 v1.5 padding scheme
            pkcs1_15.new(rsa_public_key).verify(hashed_public, server_response)
            verification = True
        except (ValueError, TypeError):
            verification = False

        return verification

    def registerServer(self,username,password_hashed, publickey,port):
        # Generate RSA keys
        self.myRSAprivate, self.myRSApublic = self.generate_keys_RSA()
        json_message_register = {'method' : "register",
                            'username': username,
                            'password': password_hashed,
                            'publickey': self.myRSApublic.decode(),
                            'port': port}
        
        logging.info("Register started")
        # Create a TCP/IP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect the socket to the port where the server is listening
        client_socket.connect(('localhost', 8080))
        # Convert the JSON message to a string
        json_message_register = json.dumps(json_message_register)
        # Send the JSON message to the server
        client_socket.sendall(json_message_register.encode())
        # Receive the response from the server
        response = client_socket.recv(1024)
        try:
            # Convert the response to a JSON object
            json_response = json.loads(response.decode())
            logging.info("Server response ->" + str(response))
            # Get the server's RSA public key
            server_certificate_response = json_response["certificate"]
            logging.info("Server certificate ->" + str(server_certificate_response))
            client_socket.close()
            return 0
        except:
            # Calculate the SHA256 hash of self.myRSApublic
            hashed_public = SHA256.new(self.myRSApublic)
            # Verify the digital signature using serverRSApublic, hashed_public, and response
            verfy = self.verification(serverRSApublic, hashed_public, response)
            if (verfy):
                logging.info("Verification is OK")
               
                # Write the signed data to a file
                with open("certificate_{}.bin".format(username), "wb") as file:
                    file.write(response)
                logging.info("Certificate is written to file")

                client_socket.close()
                return 1
            else:
                #error message
                logging.info("Verification is NOT OK")
                client_socket.close()
                return 0

    def login(self,message):
        # Create a TCP/IP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            #Setting the socket to connect to the server
            client_socket.connect(('localhost', 8080))
            # Convert the message to JSON format
            json_message = json.dumps(message)

            # Send the message to the server
            client_socket.sendall(json_message.encode())

            # Receive and parse the response from the server as JSON
            response = client_socket.recv(1024).decode()
            json_response = json.loads(response)

            logging.info("Server response ->" + str(response))


        finally:
            # close the socket
            client_socket.close()
            if(json_response["status"] == "ok"):
                return 1
            else:
                return 0

        
    def generate_keys_RSA(self):
        # Generate an RSA key pair with a key size of 1024 bits
        key = RSA.generate(1024)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        # Export the private key in PEM format and save it to a file
        with open('RSA_keys/private_key{}.pem'.format(self.username), 'wb') as f:
            f.write(key.export_key('PEM'))
            logging.info("Private key is written to file")
            logging.info("Private key ->" + str(private_key))

        # Export the public key in PEM format and save it to a file
        with open('RSA_keys/public_key{}.pem'.format(self.username), 'wb') as f:
            f.write(key.publickey().export_key('PEM'))
            logging.info("Public key is written to file")
            logging.info("Public key ->" + str(public_key))

        return private_key, public_key
##############################################################################################################################################

#second screen after login to chat with other users
class ChatBox(tk.Frame):
    def __init__(self, master, username, port, myRSApublic, myRSAprivate):
        super().__init__(master)
        self.master = master
        self.pack()
        self.username = username
        self.port = port
        self.myRSApublic = myRSApublic
        self.myRSAprivate = myRSAprivate
        self.create_widgets()
    #function to send message to other users    
    def create_widgets(self):
        try:  
            #load old messages from json file
            with open(("datas/{}_data.json").format(self.username), "r") as file:
                logging.info("Data file is loaded to read old messages")

                self.loaded_msg_database = json.load(file)
                self.msg_database = self.loaded_msg_database
        except:
            self.msg_database = {}
        
        self.chat_label = tk.Label(self, text="ChatBox Ekranı")
        self.chat_label.pack()

        self.chat_label2 = tk.Label(self, text="Mesaj göndermek istediğiniz kullanıcı adı")
        self.chat_label2.pack()

        self.to_who = tk.Entry(self)
        self.to_who.pack()

        self.login_button = tk.Button(self, text="Sohbete git", command=self.go_chat)
        self.login_button.pack()

        self.master.protocol("WM_DELETE_WINDOW", self.exit_program)
    
        self.listen()
        
        

    def listen(self):
        # Create a socket and bind it to the specified address and port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('localhost', self.port))
        s.listen()
        # Listen for incoming connections and handle them in a loop
        while True:
            # Accept a new connection
            conn, addr = s.accept()
            # Start a new thread to handle receiving messages from the connected client
            receive_thread = threading.Thread(target=self.receive_message, args=(conn, addr), daemon=True)
            receive_thread.start()
    
    def exit_program(self):
        # Destroy the ChatBox window
        self.destroy() 
        
        # Save the data structure to a file
        with open(("datas/{}_data.json").format(self.username), "w") as file:
            json.dump(self.msg_database, file)
        # Exit the program
        sys.exit()  

    def verification(self,public_key, hashed_public, server_response):
     # Verify the digital signature.
        # Args:
            # public_key (bytes): Public key used for verification.
            # hashed_public (Crypto.Hash.SHA256.SHA256Hash): Hashed data of the public key.
            # server_response (bytes): Server response containing the digital signature.

        # Returns:
            # bool: True if the verification is successful, False otherwise.
        logging.info("Verification is started")
        logging.info("Public key ->" + str(public_key))
        logging.info("Hashed public key ->" + str(hashed_public))
        logging.info("Server response ->" + str(server_response))

        rsa_public_key = RSA.import_key(public_key)
        try:
            pkcs1_15.new(rsa_public_key).verify(hashed_public, server_response)
            verification = True
        except (ValueError, TypeError):
            verification = False

        return verification
                
    def symmetric_key_encryption_decryption(self, private_key, public_key):
        # Perform symmetric key encryption and decryption.
        # Args:
            # private_key (bytes): Private key used for decryption.
            # public_key (bytes): Public key used for encryption.
        # Returns:
            # tuple: A tuple containing the symmetric key, encrypted key, and decrypted key.

        # Generate a 256-bit symmetric key
        symmetric_key = PBKDF2("password", "salt", dkLen=32)
        
        # Encrypt the symmetric key with the public key
        rsa_public_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        encrypted_key = cipher_rsa.encrypt(symmetric_key)

        # Decrypt the encrypted key with the private key
        rsa_private_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
        decrypted_key = cipher_rsa.decrypt(encrypted_key)

        return symmetric_key, encrypted_key, decrypted_key

    def aes_encryption_decryption(self, symmetric_key,iv, message):
       # Perform AES encryption and decryption.
    # Args:
        # symmetric_key (bytes): Symmetric key used for encryption and decryption.
        # iv (bytes): Initialization vector used for AES encryption.
        # message (str): Message to be encrypted.
    # Returns:
        # tuple: A tuple containing the ciphertext (encrypted message) and decrypted_message.

        # create a cipher object using the random secret
        cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(message.encode().ljust(16))

        # decrypt the ciphertext back to the message
        cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
        decrypted_message = cipher.decrypt(ciphertext).decode().rstrip()

        return ciphertext, decrypted_message


    def sign_message_prvt(self, private_key, message):
        # Sign a message using a private key.

        # Hash the message
        hashed_message = SHA256.new(message)
        # Create a digital signature
        rsa_private_key = RSA.import_key(private_key)
        signature = pkcs1_15.new(rsa_private_key).sign(hashed_message)
        return signature



    def handshake(self, towho, requested_port, mycertificate,public_key_ofreceiver):
        try:
            # Create a socket and connect to the specified port
            message_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            message_socket.connect(('localhost', requested_port))
            # Encode and send the initial hello message along with the sender's certificate
            mycertificatebase64 = base64.b64encode(mycertificate).decode('utf-8')
            hellomsg = {"method":"handshake", "sender":self.username, "to":towho, "message":"hello", "certificate":mycertificatebase64 }
            # convert the message to json format
            json_message = json.dumps(hellomsg)
            # send the message
            message_socket.sendall(json_message.encode())

            # Receive the nonce message from the server and verify the receiver's certificate
            response = message_socket.recv(1024).decode()
            json_response = json.loads(response)
            nonce64 = json_response["nonce"]
            nonce = base64.b64decode(nonce64)
            certificate_ofreceiver_unverified_base64 =  json_response["certificate_ofreceiver_unverified"]
            certificate_ofreceiver_unverified = base64.b64decode(certificate_ofreceiver_unverified_base64)
            hashed_publickeyofreceiver = SHA256.new(public_key_ofreceiver.encode())
            verify = self.verification(serverRSApublic,hashed_publickeyofreceiver,certificate_ofreceiver_unverified)
           
            if not verify:
                # Certificate verification failed
                logging.info("Public key certificate NOT VERIFIED")
                return False

             # Sign the nonce and send it back to the server
            signatured_nonce = self.sign_message_prvt(self.myRSAprivate,nonce)
            message_socket.sendall(signatured_nonce) # nonce gönderildi

             # Receive the acknowledge response from the server
            ack_response = message_socket.recv(1024).decode()
            json_response = json.loads(ack_response)
            ack = int(json_response["ack"])
            if not ack:
                # Acknowledge not found
                logging.info("Acknowledge not found")
                return False


            # Generate a master secret and encrypt it with the receiver's public key
            master_secret = get_random_bytes(32)
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key_ofreceiver))
            encrypted_master_secret = cipher_rsa.encrypt(master_secret)
            message_socket.sendall(encrypted_master_secret)

            
            # Receive the master key acknowledge response from the server
            master_ok_response = message_socket.recv(1024).decode()
            master_ok_json_response = json.loads(master_ok_response)
            master_ok_status = master_ok_json_response["status"]
            if not int(master_ok_status):
                # Master key could not be sent
                logging.info("Master key gönderilemedi.")
                return False

            # Proceed to the 3rd stage: key generation
            symmetric_key,encrypted_key, decrypted_key = self.symmetric_key_encryption_decryption(self.myRSAprivate,self.myRSApublic)
             # Using 256-bit (32-byte) HMAC as an example
            hmac_key_size = 32  
            hmac_key_info = b"HMAC Key"
            hmac_key = hmac.new(master_secret, hmac_key_info, hashlib.sha256).digest()[:hmac_key_size]
            iv = get_random_bytes(16)
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key_ofreceiver))
            encrypted_iv = cipher_rsa.encrypt(iv)
            message_socket.sendall(encrypted_iv)

            # Receive the IV status response from the server
            iv_status = message_socket.recv(1024).decode()
            iv_status_json = json.loads(iv_status)
            if not (int(iv_status_json["status"])):
                logging.info("IV problem.")
                return False

            # Save the secrets to a file and log the details
            with open("secrets/{}_secrets_{}.txt".format(self.username,towho), "w") as file:
                file.write("Master_Secret: " + master_secret.hex() + "\n")
                file.write("IV: " + iv.hex() + "\n")
                file.write("HMAC_Key: " + hmac_key.hex() + "\n")
                file.write("Secret_Key: " + symmetric_key.hex())
                logging.info("Secrets file created.")
                logging.info("Master Secret: " + master_secret.hex())
                logging.info("IV: " + iv.hex())
                logging.info("HMAC Key: " + hmac_key.hex())
                logging.info("Secret Key: " + symmetric_key.hex())


        finally:
            # Close the message socket and return True indicating successful handshake
            message_socket.close()
            return True
        
    def request_indormation_from_server(self, client_socket,towho):
                # Connect to the server
                client_socket.connect(('localhost', 8080))
                
                # Create the request message

                request = {"method":"requested_inf", "requested_username":towho}
                # JSON mesajı oluşturma
                json_message = json.dumps(request)

                # Mesajı sunucuya gönderme
                client_socket.sendall(json_message.encode())

                # Receive the response from the server and parse it as JSON
                response = client_socket.recv(1024).decode()
                json_response = json.loads(response)

                # Extract the requested port, certificate, and public key from the response
                try:
                    requested_port = json_response["requested_port"]
                except:
                    # Error: requested port not found
                    return 0,0,0,0
                certificate_base64 = json_response["requested_certificate"]
                certificate_ofreceiver = base64.b64decode(certificate_base64)
                public_key_ofreceiver = json_response["requested_publickeyofreceiver"]

                # Extract the status from the response
                status = json_response["status"]

                # Log the server response
                logging.info('Sunucudan yanıt: ' + response)
                return requested_port, certificate_ofreceiver, public_key_ofreceiver, status


  
    def clear_message_box(self):
        # Clear the message box by deleting all content
        self.message_text.delete("1.0", tk.END)
    
    def display_chat(self,to_who):
        # Clear the message box first
        self.clear_message_box()
        try:
            # Get the chat messages for the specified recipient
            chat_messages = self.msg_database[to_who]
            for message in chat_messages:
                sender, content = message
                if sender == 0:
                    # Display received messages with left justification
                    self.message_text.insert(tk.END, content + "\n", "received_message")
                elif sender == 1:
                    # Display sent messages with right justification
                    self.message_text.insert(tk.END, content + "\n", "sent_message")

           # Configure the tags for received and sent messages     
            self.message_text.tag_configure("received_message", justify="left")
            self.message_text.tag_configure("sent_message", justify="right")
             # Scroll to the end of the message box
            self.message_text.see(tk.END)
        except:
            pass
        

    def go_chat(self):
        # Get the recipient's username
        towho = self.to_who.get()

        # Create a socket for communication with the server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Request information from the server
            requested_port, certificate_ofreceiver, public_key_ofreceiver, status = self.request_indormation_from_server(client_socket,towho)
            
        finally:
            client_socket.close()
            # Create or update the message frame and text box
            if(status == "ok"):
                    if not hasattr(self, 'message_frame'):
                        self.message_frame = tk.Frame(self)
                        self.message_frame.pack()

                    if not hasattr(self, 'message_text'):
                        self.message_text = tk.Text(self.message_frame, height=10, width=50)
                        self.message_text.pack(side=tk.LEFT, fill=tk.BOTH)
                    if not hasattr(self, 'message_scrollbar'):
                        self.message_scrollbar = tk.Scrollbar(self.message_frame, command=self.message_text.yview)
                        self.message_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

                    if not hasattr(self, 'message_text'):
                        self.message_text.config(yscrollcommand=self.message_scrollbar.set)
                        
                        # Metin alanını en son eklenen mesaja odakla
                        self.message_text.see(tk.END)
                    

                    if not hasattr(self, 'chat_label2'):
                        self.chat_label2 = tk.Label(self, text="Mesajınız")
                        self.chat_label2.pack()
                    
                    if not hasattr(self, 'msg'):
                        self.msg = tk.Entry(self)
                        self.msg.pack()
                    
                     # Create the message send button
                    if not hasattr(self, 'msgbutton'):
                        self.msgbutton = tk.Button(self, text="Mesaj gönder", command=lambda: self.send_message(towho, requested_port, public_key_ofreceiver))
                        self.msgbutton.pack()

                    # Display the chat messages
                    self.display_chat(self.to_who.get())
                    
            else:
                logging.info("Kullanıcıya ulaşılamadı.")
                return False


        # Load the user's certificate
        with open("certificate_{}.bin".format(self.username), "rb") as file:
            mycertificate = file.read()

        try: 
            # Check if the secret file exists for the recipient for handshake
            with open("secrets/{}_secrets_{}.txt".format(self.username, towho), "r") as file:
                lines = file.readlines()
            master_secret = lines[0].strip().split(": ")[1]
            iv = lines[1].strip().split(": ")[1]
            hmac_key = lines[2].strip().split(": ")[1]
            symmetric_key = lines[3].strip().split(": ")[1]
            # Hex değerini byte dizisine dönüştürme
            master_secret = bytes.fromhex(master_secret)
            iv = bytes.fromhex(iv)
            hmac_key = bytes.fromhex(hmac_key)
            symmetric_key = bytes.fromhex(symmetric_key)

                
        except: # yoksa handshake yap

            logging.info("Handshake is needed.")
            # Perform the handshake process
            if(self.handshake(towho,requested_port, mycertificate, public_key_ofreceiver)):
                logging.info("Handshake is successful.")
                with open("secrets/{}_secrets_{}.txt".format(self.username, towho), "r") as file:
                    lines = file.readlines()

                # Extract the secret keys from the file            
                master_secret = lines[0].strip().split(": ")[1]
                iv = lines[1].strip().split(": ")[1]
                hmac_key = lines[2].strip().split(": ")[1]
                symmetric_key = lines[3].strip().split(": ")[1]

                # Convert hex values to byte arrays
                master_secret = bytes.fromhex(master_secret)
                iv = bytes.fromhex(iv)
                hmac_key = bytes.fromhex(hmac_key)
                symmetric_key = bytes.fromhex(symmetric_key)
            else:
                logging.info("Handshake is failed.")
                        
                
            
            
            
    def send_message(self,towho,requested_port,public_key_ofreceiver):
        # Get the message from the input field

        message = self.msg.get()

        try:
            # Load the secret keys for encryption
            with open("secrets/{}_secrets_{}.txt".format(self.username, towho), "r") as file:
                lines = file.readlines()
            master_secret = lines[0].strip().split(": ")[1]
            iv = lines[1].strip().split(": ")[1]
            hmac_key = lines[2].strip().split(": ")[1]
            symmetric_key = lines[3].strip().split(": ")[1]

            # Convert hex values to byte arrays
            master_secret = bytes.fromhex(master_secret)
            iv = bytes.fromhex(iv)
            hmac_key = bytes.fromhex(hmac_key)
            symmetric_key = bytes.fromhex(symmetric_key)


            # Create a socket for communication with the server
            message_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Connect to the recipient's requested port
            message_socket.connect(('localhost', requested_port))

            # Create an AES cipher for encryption
            cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)

            # Pad the message before encryption
            padded_message = pad(message.encode(), cipher.block_size,style='pkcs7')

            # Encrypt the padded message
            ciphertext = cipher.encrypt(padded_message)

            logging.info("Plain Text: {}".format(message))
        

            logging.info("Cipher Text: {}".format(ciphertext))

            # Generate a timestamp to prevent replay attacks
            timestamp = str(time.time()).encode()

            # Encrypt the timestamp with the recipient's public key
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key_ofreceiver))
            encrypted_timestamp = cipher_rsa.encrypt(timestamp)

            # Calculate the digest for HMAC
            digest = hmac.new(hmac_key, ciphertext, hashlib.sha256).digest()
        
            # Append the HMAC to the message for integrity control
            mac = ciphertext + digest + encrypted_timestamp

             # Encode the message in Base64 for transmission           
            mac_base64 = base64.b64encode(mac).decode("utf-8")
            # Create the message request
            request = {"method":"message", "sender":self.username, "to":towho, "message":mac_base64}
                    # Convert the request to JSON

            json_message = json.dumps(request)

              # Send the message to the server

            message_socket.sendall(json_message.encode())
                  # Receive the response from the server

            response = message_socket.recv(1024).decode()
            json_response = json.loads(response)

            # Sunucudan gelen yanıtı yazdırma


        finally:
            # Soketi kapatma

            message_socket.close()
                # Handle the response

            if(json_response["status"] == "ok"):
                            # Add the message to the local database

                if towho in self.msg_database:
                    chat = self.msg_database[towho]
                    chat.append((1,message))

                    logging.info("Message is sent to {}".format(towho))

                else:
                    
                    self.msg_database[towho] = []
                                # Display the updated chat

                    chat = self.msg_database[towho]
                    chat.append((1,message))

                    logging.info("Message is sent to {}".format(towho))


                self.display_chat(towho)
                self.msg.delete(0, tk.END)
            else:

                logging.info("Message is not sent to {}".format(towho))
                        
                
        
    def handshake_for_receiver(self,conn, addr, json_message):
         # Receive the certificate and other information from the sender

        cerfificateofsenderbase64 = json_message["certificate"]
        cerfificateofsender = base64.b64decode(cerfificateofsenderbase64)

        # Request information about the sender from the server
        request_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            requested_port, sw_certificateofsender, public_key_ofsender, status = self.request_indormation_from_server(request_socket,json_message["sender"])
        finally:
            # Soketi kapatma
            request_socket.close()
            if(status == "ok"):
                pass
            else:

                logging.info("User {} is not found".format(json_message["sender"]))
                return False


        # Verify the sender's public key certificate
        hashed_publickeyofsender = SHA256.new(public_key_ofsender.encode())
        verify = self.verification(serverRSApublic,hashed_publickeyofsender,cerfificateofsender)

        if not verify:

            logging.info("Public key certificate of {} is not verified".format(json_message["sender"]))
            return False

        # Generate a nonce for verification
        nonce = get_random_bytes(16)

        # Read the certificate of the receiver
        with open("certificate_{}.bin".format(self.username), "rb") as file:
            mycertificate = file.read()
        mycertificatebase_64 = base64.b64encode(mycertificate).decode('utf-8')
        nonce64 = base64.b64encode(nonce).decode('utf-8')
        
        # Send the nonce and receiver's certificate to the sender
        json_resp = {"nonce":nonce64,"certificate_ofreceiver_unverified": mycertificatebase_64}
        json_send_response = json.dumps(json_resp)
        conn.sendall(json_send_response.encode())

        # Receive the signed nonce from the sender and verify it
        signed_nonce = conn.recv(1024)
        hashed_nonce = SHA256.new(nonce)
        verify_nonce = self.verification(public_key_ofsender,hashed_nonce,signed_nonce)
        if not verify_nonce:

            logging.info("Nonce is not verified")
            ack_msg = {"ack":"0"}
            json_ack_msg = json.dumps(ack_msg)

            # Send unsuccessful ack to the sender
            conn.sendall(json_ack_msg.encode()) #başarısız ack gönderildi
            return False

        # Send the acknowledgment to the sender
        ack_msg = {"ack":"1"}
        json_ack_msg = json.dumps(ack_msg)
        conn.sendall(json_ack_msg.encode()) #ack gönderildi


        # Receive the encrypted master secret from the sender
        encrypt_master_secret = conn.recv(1024)
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.myRSAprivate))
        master_secret = cipher_rsa.decrypt(encrypt_master_secret) 
          
        # Send the confirmation for the master secret
        master_ok = {"status":"1"}
        json_master_ok = json.dumps(master_ok)
        conn.sendall(json_master_ok.encode())

        # Generate the symmetric key and other secrets
        symmetric_key,encrypted_key, decrypted_key = self.symmetric_key_encryption_decryption(self.myRSAprivate,self.myRSApublic)
      
        hmac_key_size = 32  # Use 256-bit (32 byte) HMAC
        hmac_key_info = b"HMAC Key"
        hmac_key = hmac.new(master_secret, hmac_key_info, hashlib.sha256).digest()[:hmac_key_size]

        # Receive the encrypted IV from the sender and send the response
        iv_encrypted= conn.recv(1024)
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.myRSAprivate))
        iv = cipher_rsa.decrypt(iv_encrypted) 
        iv_response_json = {"status":"1"}
        iv_response = json.dumps(iv_response_json)
        conn.sendall(iv_response.encode())

        # Save the secrets to file
        with open("secrets/{}_secrets_{}.txt".format(self.username,json_message["sender"]), "w") as file:
            file.write("Master_Secret: " + master_secret.hex() + "\n")
            file.write("IV: " + iv.hex() + "\n")
            file.write("HMAC_Key: " + hmac_key.hex() + "\n")
            file.write("Secret_Key: " + symmetric_key.hex())

            logging.info(msg="Handshake is completed with {}".format(json_message["sender"]))
            logging.info(msg="Secrets are saved to file")

        return True
        
    def handshake_for_receiver(self, conn, addr, json_message):
        # Receive the sender's certificate
        cerfificateofsenderbase64 = json_message["certificate"]
        cerfificateofsender = base64.b64decode(cerfificateofsenderbase64)

        # Request information about the sender from the server
        request_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            requested_port, sw_certificateofsender, public_key_ofsender, status = self.request_indormation_from_server(request_socket,json_message["sender"])
        finally:
            # Soketi kapatma
            request_socket.close()
            if(status == "ok"):
                pass
            else:

                logging.info(msg="User {} is not found".format(json_message["sender"]))
                return False

        # Verify the sender's public key certificate
        hashed_publickeyofsender = SHA256.new(public_key_ofsender.encode())
        verify = self.verification(serverRSApublic,hashed_publickeyofsender,cerfificateofsender)
        if not verify:

            logging.info("Public key certificate of {} is not verified".format(json_message["sender"]))
            return False

        # Generate a nonce for verification
        nonce = get_random_bytes(16)

        # Read the receiver's certificate
        with open("certificate_{}.bin".format(self.username), "rb") as file:
            mycertificate = file.read()
        mycertificatebase_64 = base64.b64encode(mycertificate).decode('utf-8')
        nonce64 = base64.b64encode(nonce).decode('utf-8')

        # Send the nonce and receiver's certificate to the sender
        json_resp = {"nonce":nonce64,"certificate_ofreceiver_unverified": mycertificatebase_64}
        json_send_response = json.dumps(json_resp)
        conn.sendall(json_send_response.encode())

         # Receive the signed nonce from the sender and verify it
        signed_nonce = conn.recv(1024)
        hashed_nonce = SHA256.new(nonce)
        verify_nonce = self.verification(public_key_ofsender,hashed_nonce,signed_nonce)
        if not verify_nonce:

            logging.info("Nonce is not verified")
            ack_msg = {"ack":"0"}
            json_ack_msg = json.dumps(ack_msg)
            conn.sendall(json_ack_msg.encode()) #başarısız ack gönderildi
            return False

         # Send the acknowledgment to the sender
        ack_msg = {"ack":"1"}
        json_ack_msg = json.dumps(ack_msg)
        conn.sendall(json_ack_msg.encode()) #ack gönderildi

        # Receive the encrypted master secret from the sender
        encrypt_master_secret = conn.recv(1024)
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.myRSAprivate))
        master_secret = cipher_rsa.decrypt(encrypt_master_secret) 
        # Send the confirmation for the master secret

        master_ok = {"status":"1"}
        json_master_ok = json.dumps(master_ok)
        conn.sendall(json_master_ok.encode())

        # Generate the symmetric key and other secrets
        symmetric_key,encrypted_key, decrypted_key = self.symmetric_key_encryption_decryption(self.myRSAprivate,self.myRSApublic)
        
         # Derive the HMAC key
        hmac_key_size = 32  # Örnek olarak 256-bit (32 byte) HMAC kullanılıyor
        hmac_key_info = b"HMAC Key"
        hmac_key = hmac.new(master_secret, hmac_key_info, hashlib.sha256).digest()[:hmac_key_size]

        # Receive the encrypted IV from the sender and send the response
        iv_encrypted= conn.recv(1024)
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.myRSAprivate))
        iv = cipher_rsa.decrypt(iv_encrypted) 
        iv_response_json = {"status":"1"}
        iv_response = json.dumps(iv_response_json)
        conn.sendall(iv_response.encode())

        # Save the secrets to file
        with open("secrets/{}_secrets_{}.txt".format(self.username,json_message["sender"]), "w") as file:
            file.write("Master_Secret: " + master_secret.hex() + "\n")
            file.write("IV: " + iv.hex() + "\n")
            file.write("HMAC_Key: " + hmac_key.hex() + "\n")
            file.write("Secret_Key: " + symmetric_key.hex())

            logging.info(msg="Handshake is completed with {}".format(json_message["sender"]))
            logging.info(msg="Secrets are saved to file")
        return True
 
            
    import time

    def verify_timestamp(self,timestamp):

        # Get the current time
        current_time = int(time.time())  
        timestamp = int.from_bytes(timestamp, byteorder='big')
        # Convert the timestamp in the message to an integer
        message_time = int(timestamp) 

     # Check the timestamp (assuming the message should be received within 60 seconds)
        if current_time - message_time <= 60:
            
            logging.info(msg="Timestamp verification ok.")
            return 1
        else:

            logging.info(msg="Timestamp verification X. The message has timed out.")
            return 0
    def receive_message(self,conn, addr):

        while True:
            data = conn.recv(1024).decode()
            if data:
                # Process the received message
                json_message = json.loads(data)
                method = json_message["method"]
                # Check the method of the received message

                if method == "handshake":
                    
                    # Perform handshake with the sender
                    if not (self.handshake_for_receiver(conn, addr, json_message)):

                        logging.info(msg="Handshake failed. (receiver)")
                elif method == "message":    
                    from_who = json_message["sender"]
                    try: 

                        # Check if the master key exists for the sender
                        with open("secrets/{}_secrets_{}.txt".format(self.username, from_who), "r") as file:
                            lines = file.readlines()
                        master_secret = lines[0].strip().split(": ")[1]
                        iv = lines[1].strip().split(": ")[1]
                        hmac_key = lines[2].strip().split(": ")[1]
                        symmetric_key = lines[3].strip().split(": ")[1]

                        # Convert hex values to byte arrays
                        master_secret = bytes.fromhex(master_secret)
                        iv = bytes.fromhex(iv)
                        hmac_key = bytes.fromhex(hmac_key)
                        symmetric_key = bytes.fromhex(symmetric_key)
                        
                    except:
                        # If the master key doesn't exist, perform handshake
                        logging.info(msg="MASTER KEY NOT FOUND.")

                    
                    message64 = json_message["message"]
                    message = base64.b64decode(message64)
                    receiver = json_message["to"]
                    
                    received_message_mac = message[:-128] # Separate the message and HMAC
                    timestamp = message[-128:] # Get the timestamp
                    received_message = received_message_mac[:-32]
                    received_digest = received_message_mac[-32:]

                    chipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.myRSAprivate))
                    decrypted_timestamp = chipher_rsa.decrypt(timestamp)


                    logging.info(msg="Ciphertext (received) {}".format(received_message))
                     # Create a cipher for decryption

                    cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)

                    # Decrypt the message
                    decrypted_message = cipher.decrypt(received_message)
                    unpadded_message = unpad(decrypted_message, cipher.block_size, style='pkcs7')
                    

                    # Calculate HMAC digest
                    calculated_digest = hmac.new(hmac_key, received_message, hashlib.sha256).digest()

                    # Hesaplanan HMAC ile alınan HMAC'ı karşılaştırma
                    if hmac.compare_digest(calculated_digest, received_digest):

                        logging.info(msg="HMAC integrity verified. OK.")
                        if(self.verify_timestamp(decrypted_timestamp)):
                            with lock:

                                logging.info(msg="Plaintext (received) {}".format(unpadded_message.decode()))

                                # Send acknowledgment to the sender
                                json_response = {"status": "ok"}
                                json_response = json.dumps(json_response)
                                conn.sendall(json_response.encode())
                                if from_who in self.msg_database:
                                    chat = self.msg_database[from_who] 
                                    chat.append((0,unpadded_message.decode()))

                                    logging.info(msg="Receiver1: {}".format(self.msg_database))

                                    # Display the chat if it is currently selected
                                    if(self.to_who.get() == from_who):
                                        self.display_chat(from_who)
                                      
                                    
                                        
                                else:
                                    self.msg_database[from_who] = []
                                    print(self.msg_database)
                                    chat = self.msg_database[from_who]
                                    chat.append((0,unpadded_message.decode()))

                                    logging.info(msg="Receiver2: {}".format(self.msg_database))
                                    try:
                                        # Display the chat if it is currently selected
                                        if(self.to_who.get() == from_who):
                                            self.display_chat(from_who)
                                          
                                    except:
                                        
                                        pass
                        else:
                            with lock:

                                json_response = {"status": "timestamp problem."}
                                json_response = json.dumps(json_response)
                                conn.sendall(json_response.encode())

                    else:
                        # message not verified integrity check failed
                        logging.info(msg="Mesaj doğrulanamadı. Veri bozulmuş olabilir.")
                        json_response = {"status": "HMAC integrity check is not valid."}
                        json_response = json.dumps(json_response)
                        conn.sendall(json_response.encode())
                    
                
                # Keep waiting if no data is received
                continue

            # Exit loop if data is received and connection is lost
            break




def on_login_success(username,port,rsapublic, rsaprivate):
    login_screen.pack_forget()  # Login ekranını gizle
    def run_chat_box():
        chat_box = ChatBox(root, username, port, rsapublic, rsaprivate)
        chat_box.pack()  # ChatBox ekranını göster

    chat_thread = threading.Thread(target=run_chat_box, daemon=True)
    chat_thread.start()

   

     
    

if __name__ == '__main__':
        root = tk.Tk()
     
        root.title("Giriş ve Kayıt Ekranı")
        root.geometry("600x600")
        #  open login screen
        login_screen = LoginScreen(root)
        login_screen.pack()

        root.mainloop()
       
        

