import socket;
from chat_with_ui import Ui_MainWindow
from RSA import encrypt,decrypt,generate_keys_RSA
from time import time,ctime;
from sys import getdefaultencoding;
from PyQt5 import QtCore, QtGui, QtWidgets
from ast import literal_eval;
from _thread import *;

class UI_funcs(Ui_MainWindow):
    """
    Add functions to UI created in previous class.
    The purpose is that previou class static UI can be updated
    and it's functionality can be preserved. Also make code readable.
    """

    def setupUiFunctions(self,MainWindow):
        super().setupUi(MainWindow)

        self.log("Start by telling us your name.")
        self.displayHello.setText("Hello unknown")
        self.set_name.clicked.connect(self.setName);
        self.name = None;

        self.myPort = -1;
        self.set_your_port.clicked.connect(self.setYourPortNumber);
        self.myPortSet = False

        self.serverPort = -1;
        self.set_server_port.clicked.connect(self.setServerPortNumber);
        self.server_e = -1;
        self.server_n = -1;
        self.serverPortSet = False
        
        self.p = -1
        self.q = -1
        self.set_p.clicked.connect(self.setP);
        self.set_q.clicked.connect(self.setQ);

        self.e = -1;
        self.d = -1;
        self.n = -1;
        self.generateKeys.clicked.connect(self.generate_keys);
        self.keysGenerated = False

        self.generateCertificate.clicked.connect(self.get_certificate);
        self.certificate = None;

        self.id_B = None
        self.set_ID_B.clicked.connect(self.readID_B)
        self.id_B_set = False

        self.port_B = None
        self.setPort_B.clicked.connect(self.readPort_B)
        self.port_B_set = False

    def readID_B(self):
        try:
            id = int(self.read_ID_B.text());
            self.id_B = id;
            self.id_B_set = True;
            self.log("ID B set = "+str(self.id_B))
        except TypeError:
            self.log("Enter valid ID")
    
    def readPort_B(self):
        try:
            port = int(self.read_port_B.text());
            if port < 10000 or port > 50000:
                self.log("Enter valid port")
                return
            self.port_B = port;
            self.port_B_set = True;
            self.log("Port B set = "+str(self.port_B))
        except TypeError:
            self.log("Enter valid port")

    

    def setP(self):
        try:
            p = int(self.read_p.text())
            self.p = p;
            self.display_p.setText(str(p))
            self.log("Value of p set")
        except ValueError:
            self.log("Enter valid p");
            return

    def setName(self):
        name = self.read_name.text()
        self.displayHello.setText("Hello "+name)
        self.name = name
        self.log("Name set")

    def setQ(self):
        try:
            q = int(self.read_q.text())
            self.q = q;
            self.display_q.setText(str(q))
            self.log("Value of q set")
        except ValueError:
            self.log("Enter valid q");
            return
        

    def setServerPortNumber(self):
        try:
            port = int(self.read_server_port.text())
            if (port > 60000 or port < 10000):
                self.log("Enter Valid Port number between 10000 and 60000")
                return
            self.serverPort = port;
            server_KEYS = generate_keys_RSA(251, 223);
            self.server_e = server_KEYS['Public'][0];
            self.server_n = server_KEYS['Public'][1];
            assert(self.server_n == server_KEYS['Private'][1])
            self.log("Server Port number set")
            self.serverPortSet = True

        except ValueError:
            self.log("Enter Valid Port number")

    def setYourPortNumber(self):
        try:
            port = int(self.read_your_port.text())
            if (port > 60000 or port < 10000):
                self.log("Enter Valid Port number between 10000 and 60000")
                return
            self.myPort = port;
            self.log("My Port number set")
            self.myPortSet = True
        except ValueError:
            self.log("Enter Valid Port number between 10000 and 60000")
    
    def generate_keys(self):
        if (self.p == -1 or self.q == -1) :
            self.log("Set valid p and q first.Do not forget to click set");
            return

        KEYS = generate_keys_RSA(self.p,self.q)
        self.e = KEYS['Public'][0]
        self.display_e.setText(str(self.e))
        self.d = KEYS['Private'][0]
        self.display_d.setText(str(self.d))
        self.n = KEYS['Public'][1]
        self.display_n.setText(str(self.n))
        assert(self.n == KEYS['Private'][1])
        self.log("Keys generated")
        self.keysGenerated = True

    def log(self,message):
        self.messageFromSystem.setText(message)

