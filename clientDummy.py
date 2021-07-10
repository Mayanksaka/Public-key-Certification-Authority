"""
Client will interact with Certification authority as well as 
with itself.
"""

import socket;
from RSA import encrypt,decrypt,generate_keys_RSA;
from time import time,ctime;
from sys import getdefaultencoding;


def getKeys(tup:str)->tuple:
    tup = tup[1:len(tup)-1];
    l = tup.split(',');
    print(l)
    return (int(l[0]),int(l[1]))

def get_user_input()->int:
    print("""
        __________________________________
        | 1. Get new Certificate.        |
        | 2. Verify Certificate.         |
        | 3. Chat with another client.   |
        |                                |
        | 0. Exit                        |
        |________________________________|
        """)
def loop()->None:
    choice = -1;
    while choice != 0:
        choice = get_user_input();
        if choice == 1:
            #get new certificate
            3+890;
        elif choice == 2:
            #verify certificate
            2+890;
        elif choice == 3:
            #chat with a client
            3+4;


HOST = '127.0.0.1'
server_KEYS = getKeys(str(input("Enter server public key : "))); 
server_e = int(server_KEYS[0])
server_n = int(server_KEYS[1])

server_PORT = int(input("Enter server port number : "));

NAME = input("Enter client Name : ");
PORT = input("Enter "+NAME+"'s port number : ");
print("Some suggestions [229, 233, 239, 241]")
P = int(input("Enter prime number p : "));
Q = int(input("Enter prime number q : "));
KEYS = generate_keys_RSA(P,Q);
e = KEYS['Public'][0];
d = KEYS['Private'][0];
n = KEYS['Public'][1];
assert(n == KEYS['Private'][1]);
print("Keys Generated succesfully!");
print("Your public key = ",(e,n));
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST,server_PORT));
    m = encrypt('getCertificateSelf | '+str((e,n)),server_e,server_n);
    s.sendall(bytes(m.encode('utf-16','surrogatepass')));
    print('sent')
    data = s.recv(10024);
    certificate = decrypt(data.decode('utf-16','surrogatepass'),d,n);
print('Recieved : ',certificate);