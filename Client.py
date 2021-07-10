import socket;
from chat_with_ui import Ui_MainWindow
from RSA import encrypt,decrypt,generate_keys_RSA
from time import time,ctime;
from sys import getdefaultencoding;
from PyQt5 import QtCore, QtGui, QtWidgets
from ast import literal_eval;
from _thread import *;
from client_gui import UI_funcs

class Client(UI_funcs):

    def __init__(self,MainWindow):
        UI_funcs.setupUiFunctions(self,MainWindow);

        self.generateCertificate.clicked.connect(self.get_certificate);
        self.certificate = None;
        self.certificateGenerated = False

        self.getCertificateOfB.clicked.connect(self.get_other_certificate);
        self.certificate_B = None
        self.certificate_BGenerated = False;

        self.verifyCertificateOfB.clicked.connect(self.verify_other_certificate);
        self.certificate_B_valid = False;

        self.start_listening.clicked.connect(self.startListening);
        self.listeningThreadRunning = False

        self.connectToB.clicked.connect(self.connect_to_B);
        self.connectedToB = False;

    def connect_to_B(self):
        if not(self.id_B_set):
            self.log("Set ID of B first")
            return

        if not(self.port_B_set):
            self.log("Set Port of B first")
            return
                
        if not(self.certificate_BGenerated):
            self.log("Get Certificate of B first")
            return

        if not(self.certificate_B_valid):
            self.log("!!! Certificate of B is invalid")
            return

        HOST = '127.0.0.1'
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((HOST, self.port_B))
            e_b = int(self.certificate_B['PU_A'][0])
            n_b = int(self.certificate_B['PU_A'][1])
            self.log('Connected to '+str(self.id_B))
            for i in range(1,4):
                
                s = self.name + " -> " + "Hello "+str(i)
                encrypted_s = encrypt(s,e_b,n_b)
                data_s = encrypted_s.encode('utf-16','surrogatepass')
                sock.sendall(data_s)
                self.chatWindow.append(s);
                
                data_r = sock.recv(1024)
                encrypted_r = data_r.decode('utf-16','surrogatepass');
                r = decrypt(encrypted_r,self.d,self.n)
                self.chatWindow.append(r);
                            
    def verify_other_certificate(self):
        if not(self.certificate_BGenerated):
            self.log("Generate Certificate of B first")
            return
        HOST = '127.0.0.1'
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST,self.serverPort));
            m = encrypt('verifyCertificate | '+str((self.certificate['ID_A'],self.id_B))+" | "+str(self.certificate_B),self.server_e,self.server_n);
            s.sendall(bytes(m.encode('utf-16','surrogatepass')));
            data = s.recv(10024);

        valid = literal_eval(decrypt(data.decode('utf-16','surrogatepass'),self.d,self.n));
        if (valid):
            self.certificate_B_valid = True;
            self.log("B has a valid certificate")
            return
        self.certificate_B_valid = False;
        self.log("B has an invalid certificate")

    def get_other_certificate(self):
        if not(self.serverPortSet):
            self.log("Enter a valid Server port");
            return;
        if (not(self.keysGenerated)):
            self.log("Generate Keys First");
            return;
        if(not(self.id_B_set)):
            self.log("Set valid ID of B first")
            return;
        if not(self.certificateGenerated):
            self.log("Generate your certificate first")
            return;

        HOST = '127.0.0.1'
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST,self.serverPort));
            m = encrypt('getCertificateOther | '+str((self.certificate['ID_A'],self.id_B)),self.server_e,self.server_n);
            s.sendall(bytes(m.encode('utf-16','surrogatepass')));
            data = s.recv(10024);
        
        certificate = decrypt(data.decode('utf-16','surrogatepass'),self.d,self.n);
        self.certificate_B = literal_eval(certificate);    
        self.displayCertificate_IDB.setText(str(self.certificate_B['ID_A']))
        self.displayCertificate_PU_B.setText(str(self.certificate_B['PU_A']))
        self.displayCertificate_Time_B.setText(str(self.certificate_B['TIME']))
        self.displayCertificate_Duration_B.setText(str(self.certificate_B['DURATION']))
        self.displayCertificate_ID_CA_B.setText(str(self.certificate_B['ID_CA']))
        self.certificate_BGenerated = True

    def get_certificate(self):
        if not(self.serverPortSet):
            self.log("Enter a valid Server port");
            return;
        if (not(self.keysGenerated)):
            self.log("Generate Keys First");
            return;
        HOST = '127.0.0.1'
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST,self.serverPort));
            m = encrypt('getCertificateSelf | '+str((self.e,self.n)),self.server_e,self.server_n);
            s.sendall(bytes(m.encode('utf-16','surrogatepass')));
            data = s.recv(10024);
        
        certificate = decrypt(data.decode('utf-16','surrogatepass'),self.d,self.n);
        self.certificate = literal_eval(certificate);    
        self.displayCertificate_IDA.setText(str(self.certificate['ID_A']))
        self.displayCertificate_PU_A.setText(str(self.certificate['PU_A']))
        self.displayCertificate_Time.setText(str(self.certificate['TIME']))
        self.displayCertificate_Duration.setText(str(self.certificate['DURATION']))
        self.displayCertificate_ID_CA.setText(str(self.certificate['ID_CA']))
        self.certificateGenerated = True
    
    def threaded_client(self):
        HOST = '127.0.0.1'
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            self.display_Connection_status.setText("Online");
            sock.bind((HOST,self.myPort));
            sock.listen(5);
            self.log("Listening")
            self.listeningThreadRunning = True
            while True:

                conn,addr = sock.accept();
                if not(self.id_B_set):
                    print("ID of B is not set")
                    conn.close()
                    continue

                if not(self.port_B_set):
                    print("Port of B is not set")
                    conn.close()
                    continue
                
                if not(self.certificate_BGenerated):
                    print("Certificate of B is not generated")
                    conn.close()
                    continue

                if not(self.certificate_B_valid):
                    print("Certificate of B is not valid")
                    conn.close()
                    continue
                updateWindow = False
                l = []
                with conn:
                    e_b = int(self.certificate_B['PU_A'][0])
                    n_b = int(self.certificate_B['PU_A'][1])
                    self.log('Connected by'+str(str))
                    for i in range(1,4):
                        updateWindow = True
                        data = conn.recv(1024)
                        encrypted_r = data.decode('utf-16','surrogatepass');
                        r = decrypt(encrypted_r,self.d,self.n)
                        l.append(r);
                        
                        s = self.name + " -> " + "ACK "+str(i)
                        encrypted_s = encrypt(s,e_b,n_b)
                        data_s = encrypted_s.encode('utf-16','surrogatepass')
                        conn.sendall(data_s)
                        l.append(s);
                if updateWindow:
                    print(l)
                    self.updateChatWindow(l)
    def updateChatWindow(self,l):
        for i in l:
            self.chatWindow.append(i)
                
    def startListening(self):
        if not(self.keysGenerated):
            self.log("Generate Keys first")
            return
        
        if not(self.serverPortSet):
            self.log("Setup Server Port First")
            return

        if not(self.myPortSet):
            self.log("Setup your port first")
            return

        if not(self.certificateGenerated):
            self.log("Generate Certificate First")
            return
        
        if (self.listeningThreadRunning):
            self.log("Thread already running")
            return

        start_new_thread(self.threaded_client,())


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Client(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())