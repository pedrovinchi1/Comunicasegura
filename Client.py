#! /usr/bin/env python


import json
import select
import socket
import sys
import threading
import time
import traceback

from cryptography.hazmat.primitives._asymmetric import *

from Asymmetric import *
from Symmetric import *


global other_key_received # recebo a chave

global my_key_send # enviei a chave



my_private_key = ""

my_public_key = ""

other_public_key_deserilized = ""

global other_public_key_serialized 



class Leitor(threading.Thread):
     
    def initialise(self, receive):
        self.receive = receive

    def run(self):
        global my_key_send

        global other_key_received 

      

        global my_private_key 

        global my_public_key 

        global other_public_key_deserilized 

        global other_public_key_serialized

        other_key_received = False
       
        lis = [self.receive]
        
        ack = 0
        while True:
            read, write, err = select.select(lis, [], [])
            for item in read:
                try:
                    
                    s = item.recv(1024)
                    
                    if my_key_send == False:
                        print("Chegou a chave do outro")
                        other_public_key_serialized = s
                        other_public_key_deserilized = deserilizeAsymmetricKeys(
                            other_public_key_serialized
                        )
                        my_key_send = True 
                    
                   
                    
                    # Pegando mensagem encriptada
                    elif s != '' and ack == 0:
                        chunk = json.loads(s.decode())
                        encrypted_msg = chunk["msg"]
                        sign = chunk["sign"]
                        ack = ack+1
                        
                        s = ''
                    
                    
                    # Pegando chave simetrica encriptada
                    elif s != '' and ack == 1:
                        key = s
                        ack = 0
                        s = ''
                        try:
                           
                            verifiyAsymmetricSignature(sign,other_public_key_deserilized,encrypted_msg.encode())
                                                    
                            decrypted_key = decryptAsymmetric(my_private_key,key)
                                
                            data = decryptSymmetric(decrypted_key,encrypted_msg)
                        
                            print('\n>>' + data.decode() )
                        except(err) :
                           print(err)
                           print("A mensagem não tem assinatura autêntica.")
         
                except:
                    traceback.print_exc(file=sys.stdout)
                    break


class Envio(threading.Thread):
     
    def __init__(self):
        super(Envio, self).__init__()
        self.my_key_send = False
        self.other_key_received = False
        self.my_key_send_primaria = ""
        self.my_key_send_publica = ""
        self.other_key_received_deserilized = ""
        self.other_key_received_serialized = ""
        self.read_to_send = threading.Event()
        self.read_to_send.clear()


    def connect(self, host, port): 
        self.sock.connect((host, port))

    def client(self, host, port, msg):
     
        sent = self.sock.send(msg)

    def run(self):
        global my_key_send

        global other_key_received 

        global my_private_key 

        global my_public_key 

        global other_public_key_deserilized 

        global other_public_key_serialized

        
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            #conectando o sorvidor
            host ="127.0.0.1"
            port = 5535
        except EOFError:
            print("Error")
            return 1

        print("Connecting\n")
        s = ''
        self.connect(host, port)
        print("Connected\n")
        user_name = input("Enter the User Name to be Used\n>>")
        receive = self.sock
       
        
        # gerando chave publica e privada usando rsa
        my_key_send = False
      
        (my_private_key,my_public_key) = generateAsymmetricKeys()
        
        my_public_key_serialized = serializeAsymmetricKeys(my_public_key)


        srv = Leitor()
        srv.initialise(receive)
        srv.daemon = True
        print("Starting service")
        srv.start()
        


        #enviando chave simetrica serializada no formato pem
        time.sleep(1)
        self.client(host, port, my_public_key_serialized) 
        other_key_received = False
         # gerando chave simetrica usando aes gcm

        (key) = generateSymmetricKey()
        
        while True:
           # loop para ficar enviando minha chave até receber a chave de outro usuário
            while my_key_send  == False and other_key_received == False:
                if(my_key_send  == True and other_key_received == False):
                    self.client(host, port, my_public_key_serialized)
                    other_key_received = True
                    

                print("Aguardando chave do outro usuario...")
                time.sleep(5)
                continue
                
           
      
            msg = input('>>')
            if msg == 'exit':
                break
            if msg == '':
                continue
      
            msg = user_name + ': ' + msg
            data = msg.encode()

           
        
            # mensagem encriptada com a chave  
            encrypted_msg = encryptSymmetric(key,data) 
            # assinar mensagem encriptada
            sign = generateAsymmetricSignature(my_private_key,encrypted_msg.encode())
          
            time.sleep(1)
            self.client(host, port,  json.dumps({"msg":encrypted_msg,"sign":sign}).encode())

            other_public_key_deserilized = deserilizeAsymmetricKeys(other_public_key_serialized)
            
            encrypetedKey = encryptAsymmetric(other_public_key_deserilized,key)
            time.sleep(1)
            self.client(host, port, encrypetedKey)
        return (1)


if __name__ == '__main__':
    print("Starting client")
    cli = Envio()
    cli.join()
    cli.start()
