"""
Implimentation of certification authority.

Certificate will be stored as a dictionary.
Format of Certificate (as per assignment document)

Certificate (of A(client)) = {
    ID (of A): int 
    Public Key (of A): int (maintain a set of issued IDs)
    Time (of issuing) : ctime (time elapsed since epoch)
    Duration (validity of certificate) : 1000 (seconds), some constant 
    ID (of Certification authority) : 0
}

The certificate will be encrypted (as per requirement). Encryption method 
followed will be to convert dictionary to a string diretly, then encrypt each 
character.
"""
from types import resolve_bases
from RSA import encrypt,decrypt,generate_keys_RSA;
from time import time
import socket;
from _thread import *;
from sys import getdefaultencoding;
from ast import literal_eval;

def provide_certificate(A_e:int, A_n:int)->str:
    """ returns string representation of certificate"""
    global ID,issuedCertificates;

    certificate = dict();
    while(ID in issuedCertificates):
        ID+=1
    certificate['ID_A'] = ID;
    certificate['PU_A'] = (A_e,A_n);
    certificate['TIME'] = time();
    certificate['DURATION'] = 1000; #seconds
    certificate['ID_CA'] = 42;
    issuedCertificates[ID] = certificate;
    return str(certificate);

def getIntTupleFromString(tup:str)->tuple:
    tup = tup[1:len(tup)-1];
    l = tup.split(',');
    return (int(l[0]),int(l[1]))

def threaded_client(conn:socket):
    print("Connected by : ",addr);
    global issuedCertificates;
    
    while True:
    
        inputBytes_fromUser = conn.recv(10024); 
        if not inputBytes_fromUser:
            break;
        encrypted_request = inputBytes_fromUser.decode('utf-16','surrogatepass');
        request = decrypt(encrypted_request,d,n).split('|');
        request_type = ''.join(request[0].split());
        if (request_type == 'getCertificateSelf'):   
            """
            request = getCertificateSelf | (A_e,A_n)
            """
            print()
            print("Generating certificate")
            A_key = getIntTupleFromString(''.join(request[1].split()));
            A_e = int(A_key[0]);
            A_n = int(A_key[1]);
            certificate = provide_certificate(A_e,A_n);
            print("Certificate = "+str(certificate))
            encrypted_response = encrypt(certificate,A_e,A_n);
            conn.sendall(encrypted_response.encode('utf-16','surrogatepass'));
            print()

        elif (request_type == 'getCertificateOther'):
            """
            request = getCertificateOther | (ID_self,ID_other)
            """
            print()
            IDs = getIntTupleFromString(''.join(request[1].split()));
            A = IDs[0];
            B = IDs[1];
            print(str(A)+" requested Certificate of "+str(B))
            #error handling not done here. Will do after full implementation.
            cert_B = issuedCertificates[B];
            print(cert_B)
            cert_A = issuedCertificates[A];
            encrypted_response = encrypt(str(cert_B),cert_A['PU_A'][0],cert_A['PU_A'][1])
            conn.sendall(encrypted_response.encode('utf-16','surrogatepass'));
            print()

        elif (request_type == 'verifyCertificate'):
            """
            request = verifyCertificate | (ID_self,ID_other) | {...}
            """
            print()
            IDs = getIntTupleFromString(''.join(request[1].split()));
            A = IDs[0];
            B = IDs[1];
            print(str(A)+" asked for checking validity of "+str(B)+"'s certificate")
            certificate = literal_eval(''.join(request[2].split()));
            print(str(B)+" -> "+str(certificate))
            #error handling not done here. Possible that certificate of B is not
            # issued yet.
            cert_B = issuedCertificates[B];
            print("From record -> "+str(cert_B))
            result = 'False';
            if(cert_B == certificate):
                limit = cert_B['TIME']+1000
                t = time()
                if ( t < limit):
                    result = 'True';
                else:
                    print("Validity over")
                    print('Current = '+str(t))
                    print('Limit = '+str(limit))
            else:
                print(type(cert_B));
                print(type(certificate));
                print("Failed equality test")
            cert_A = issuedCertificates[A];
            encrypted_response = encrypt(str(result),cert_A['PU_A'][0],cert_A['PU_A'][1])
            conn.sendall(encrypted_response.encode('utf-16','surrogatepass'));
            print()
    print('Closing Connection')
    conn.close();

print("CERTIFICATION AUTHORITY")
HOST = '127.0.0.1';
PORT = int(input("Enter Port number : "));

KEYS = generate_keys_RSA(251, 223);
e = KEYS['Public'][0];
d = KEYS['Private'][0];
n = KEYS['Public'][1];
assert(n == KEYS['Private'][1]);
print("Public Key = "+str(KEYS['Public']))

ID = 1999;
# Verify certificates
issuedCertificates = dict();

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST,PORT));
    s.listen(5);
    while True:
        conn,addr = s.accept();
        start_new_thread(threaded_client,(conn,)); 