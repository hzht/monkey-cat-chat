'''
Developed by Htay Z Htat, June 2016
github.com/hzht

3rd party libraries:
* PyQt4
* win32gui - https://sourceforge.net/projects/pywin32/files/pywin32/Build%20220
* simpleaudio
* pyftpdlib

Description:
MS Lync clone. Written & tested on Python 3.4.4, Windows7 64
version 1.2
'''

import sys, os.path
from PyQt4 import QtGui, QtCore
import time
import socket
import threading
import random
from hashlib import md5
import pickle

from pyftpdlib.handlers import FTPHandler, ThrottledDTPHandler
from pyftpdlib.servers import ThreadedFTPServer 
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
import ftplib

import emoji # includes class 'SelectEmoji' & 'ed', emoji dict

try: 
    import win32gui, simpleaudio # 3rd party & OS dependent modules
except ImportError:
    print('download win32gui & simpleaudio for better functionality')

# GLOBALS
own_ip = socket.gethostbyname(socket.gethostname()) # IP addr
record = [] # user details
user_file = r".\user.txt"

transceiver_port = 6165
chat_session_port = 6166 # TCP port on which server listens on
beacon_interval = 60
ftp_cloak_port = 14415

known_clients_DB = {} # {'hostname': ['alias', 'first', 'last', 'IP', 75, 6]}

status = False # false = offline, true = online

# main application window and all widgets e.g. buttons, text boxes etc
class MainWindow(QtGui.QMainWindow):
    def __init__(self):
        QtGui.QMainWindow.__init__(self)
        self.sessions = dict() # stores instances of ChatWindow: addr, sock
        self.fit_receive = list() # tracks fit streams (receive)
        self.initUI()

    def initUI(self): # main window with all widget objects
        self.setFixedSize(200, 310)
        self.setWindowIcon(QtGui.QIcon('images/appicon.png'))
        self.setWindowTitle('Monkey Cat Chat')
        
        self.on = QtGui.QPushButton('On', self)
        self.on.setFixedSize(29,29)
        self.on.move(15, 70)
        self.on.setToolTip('Go Online')
        self.on.clicked.connect(self.go_online)

        self.off = QtGui.QPushButton('Off', self)
        self.off.setFixedSize(29,29)
        self.off.move(56, 70)
        self.off.setToolTip('Go Offline')
        self.off.setEnabled(False)
        self.off.clicked.connect(self.go_offline)
    
        self.state = QtGui.QLabel('', self)
        self.state.setGeometry(135,40,48,48) # x, y, width, height
        self.state.setPixmap(QtGui.QPixmap('images/offline.png'))

        self.add = QtGui.QPushButton('Add', self)
        self.add.setFixedSize(70,29)
        self.add.move(15, 70)
        self.add.setIcon(QtGui.QIcon('images/invite.png'))
        self.add.setIconSize(QtCore.QSize(21, 21))
        self.add.setToolTip('Add IP address of colleague to chat')
        self.add.clicked.connect(lambda: adder.show_it(mode=None)) # dialog box for adding IP
        self.add.setVisible(False)

        self.mwL3 = QtGui.QLabel('Double click on person to begin chat', self)
        self.mwL3.setFixedSize(200,12)
        self.mwL3.move(15, 285)

        self.userlist = QtGui.QListWidget(self)  # list of online users
        self.userlist.move(15, 111) # x | y
        self.userlist.setFixedSize(170, 162)
        self.userlist.doubleClicked.connect(
            lambda: self.new_session(conn='', addr='', mode='initiator'))
        
        self.mwSettings = QtGui.QPushButton('Settings', self) # settings diag
        self.mwSettings.setFixedSize(70,29)
        self.mwSettings.move(15,30)
        self.mwSettings.setIcon(QtGui.QIcon('images/settings.png'))
        self.mwSettings.setIconSize(QtCore.QSize(21, 21))
        self.mwSettings.setToolTip('Change Settings')
        self.mwSettings.clicked.connect(SW.show_it)

        self.mwHostname = QtGui.QAction('&Hostname', self)
        self.mwHostname.triggered.connect(lambda: self.msg_box('hostname'))
        self.mwAdd_via_IP = QtGui.QAction('&Add via IP address...', self)
        self.mwAdd_via_IP.triggered.connect(lambda: adder.show_it(mode=None))
        self.mwAdd_via_IP.setEnabled(False) # hurray for mammaries
        self.mwAbout = QtGui.QAction('&About', self)
        self.mwAbout.triggered.connect(lambda: self.msg_box('about')) 

        self.mwMenuBar = QtGui.QHBoxLayout()
        self.mwBar = self.menuBar()
        self.mwHelp = self.mwBar.addMenu('&Help')
        self.mwHelp.addAction(self.mwHostname)
        self.mwHelp.addAction(self.mwAdd_via_IP)
        self.mwHelp.addAction(self.mwAbout)

        self.show()

    def closeEvent(self, event): # pre X checks - added 10 dec 16 LOOL!
        self.go_offline()
    
    def alternate_ui(self, mode):
        global status
        if mode == False: # False = 'basic' mode
            self.go_offline() # initiate entire suite regardless
            
            self.setFixedSize(200, 310)
            self.on.setVisible(True)
            self.off.setVisible(True)
            self.state.setVisible(True)
            self.mwL3.setVisible(True)
            self.userlist.setVisible(True)
            self.add.setVisible(False)

        elif mode == True: # True = 'advanced' mode
            if status == True: # if in basic mode & 'On' state
                self.go_offline()

            self.setFixedSize(100, 111)
            self.on.setVisible(False)
            self.off.setVisible(False)
            self.state.setVisible(False)
            self.mwL3.setVisible(False)
            self.userlist.setVisible(False)
            self.add.setVisible(True)

            status = True # only time all services are offline & status = True
            # why above ln? CW will display 'offline' lest status is True
            # tight coupling to be fixed
            self.tcp_launch() # starts TCP server chain
            self.e = FtpSvr() # instance of threading obj update 5 jan 17 - perhaps move this to init? YES! 
            self.e.start()

    def tcp_launch(self): # TCP server related calls
        self.tcp_server = TcpSvr()
        self.tcp_server.start()
        self.connect(self.tcp_server, QtCore.SIGNAL('server_socket'),
                     self.new_session) # receives 'connection' & 'client_addr'

    def new_session(self, conn, addr, mode): # instance based on ChatWindow
        if mode == 'initiator': # initiate request      
            unpacked = (self.userlist.currentItem().text().split(':'))
            alias_name = unpacked[0][:-4]
            alias_state = unpacked[-1][1:]
            if alias_state == 'online':
                try: # obtain IP from known_clients_DB & pass to CW instance
                    for k, v in known_clients_DB.items():
                        if v[0] == alias_name and v[3] not in self.sessions:
                            self.sessions[v[3]] = ChatWindow(addr=v[3], 
                                mode='initiator') # remote alias name and IP
                        elif v[0] == alias_name and v[3] in self.sessions:
                            self.msg_box('existing')
                except Exception:
                    pass
            else:
                self.msg_box('warning')

        elif mode == 'acceptor': # receive request
            self.sessions[addr] = ChatWindow(conn=conn,
                                             addr=addr, mode='acceptor')
            
        elif mode == 'adv_initiate': 
            try:
                self.sessions[addr] = ChatWindow(addr=addr, mode='initiator')
            except TimeoutError: # unresponsive or offline remote host
                self.msg_box('adv_warning')
                print('ex: A', sys.exc_info())

    def msg_box(self, msgtype): 
        self.info = QtGui.QMessageBox()
        self.info.setStandardButtons(QtGui.QMessageBox.Ok)
        
        if msgtype == 'warning':
            self.info.setText('User is offline, try again when online.')
            self.info.setWindowTitle('Warning!')
        elif msgtype == 'about':
            self.info.setText('                    Developed by HZH, 2016')
            self.info.setWindowTitle('About Monkey Cat Chat')
            self.pic = QtGui.QLabel(self.info)
            self.pic.setGeometry(10, 10, 82, 60)
            self.pic.setPixmap(QtGui.QPixmap(os.getcwd() + '/images/cat.png'))
        elif msgtype == 'hostname':
            self.info.setText(
                'hostname: ' + socket.gethostname() + '\n' + 'IP addr: '
                + own_ip)
            self.info.setWindowTitle('Hostname | IP')
        elif msgtype == 'adv_warning':
            self.info.setText('Unable to connect to specified IP address, '
                              'person may be offline.')
            self.info.setWindowTitle('Warning!')
        elif msgtype == 'existing':
            self.info.setText('You already have an open session with the '
                              'person.')
            self.info.setWindowTitle('Warning')
        self.info.show()

    def go_online(self): # turn all services on
        returning_user() # first determination of global 'status'
        if status == False:
            self.state.setPixmap(QtGui.QPixmap('images/offline.png'))
        elif status == True:
            self.state.setPixmap(QtGui.QPixmap('images/online.png'))
            self.a = threading.Thread(
                target=transceiver, name='transceiver', daemon=True).start()
            self.b = threading.Thread(
                target=beacon, name='beacon', daemon=True).start()
            self.c = threading.Thread(
                target=pinger, name='pinger', daemon=True).start()
            self.d = threading.Thread(
                target=db_cleanup, name='db_cleanup', daemon=True).start()
            self.tcp_launch() # starts TCP server chain
            self.e = FtpSvr() # instance of threading obj
            self.e.start()

            self.on.setEnabled(False) # deterrent for consec on/off clicks
            self.off.setEnabled(True)
            self.mwAdd_via_IP.setEnabled(True)
        
    def go_offline(self): # clears the local DB & self.a-d + TcpSvr stop
        global status
        status = False

        try:
            self.e.stop()
            self.tcp_server.stop()
        except AttributeError:
            print('ex: B', sys.exc_info())

        for i in self.sessions: # bye bye sessions
            self.sessions[i].interrupt()

        self.state.setPixmap(QtGui.QPixmap('images/offline.png'))

        self.on.setEnabled(True) 
        self.off.setEnabled(False)
        self.mwAdd_via_IP.setEnabled(False)

        self.fit_receive.clear()

    def add_or_remove(self): # update list upon pulse
        self.userlist.clear() 
        for host in sorted(known_clients_DB):
            if known_clients_DB[host][5] > 0:
                self.userlist.addItem(
                    known_clients_DB[host][0] + '    : online')
            else:
                self.userlist.addItem(
                    known_clients_DB[host][0] + '    : offline')

    def trunc_alias(alias_long): # class method
        if len(alias_long) > 8:
            return alias_long[:8] + '...'
        else:
            return alias_long


#=============================================================================#


# Advanced mode, add IP dialog box, invite participant interface
class AddIPManually(QtGui.QWidget):
    def __init__(self):
        QtGui.QWidget.__init__(self)
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Chat_v1.0')
        self.setFixedSize(178, 65) # w x h

        label = QtGui.QLabel('Enter remote host\'s IP address:', self)
        label.move(15, 5)

        btn = QtGui.QPushButton('Go', self)
        btn.setFixedSize(30, 26)
        btn.move(132, 27)
        btn.clicked.connect(lambda: self.validate_ip(self.ipbox.displayText()))

        self.ipbox = QtGui.QLineEdit(self)
        self.ipbox.setFixedSize(105, 21)
        self.ipbox.move(15, 30)

    def show_it(self, mode=None): 
        self.mode = mode # clause
        self.ipbox.clear()
        self.show()

    def validate_ip(self, n): # ensure IP entered is to IPv4 format
        ip = n.split('.')
        if len(ip) != 4:
            warn('ip_err')
        else:
            for octet in ip:
                if not octet.isdigit():
                    warn('ip_err')
                    self.ipbox.clear()
                    break
                if int(octet) < 0 or int(octet) > 255:
                    warn('ip_err2')
                    self.ipbox.clear()
                    break
        if self.ipbox.displayText() != '' and len(ip) == 4:
            self.verify_n_launch(n)
    
    def verify_n_launch(self, n): # verify chat_session_port is open n launch
        if n == own_ip:
            warn('ip_err3')
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            test_result = s.connect_ex((n, ftp_cloak_port)) 
        except Exception:
            print('ex: C', sys.exc_info())
        finally:
            s.close()

        if test_result == 0: # port IS open on rhost
            if self.mode == None: 
                if n not in AW.sessions:
                    AW.new_session(conn='', addr=n, mode='adv_initiate')
                    self.close()
                else: 
                    AW.msg_box('existing')
            elif self.mode == 'invite_participants': 
                self.emit(QtCore.SIGNAL('add_moar_cowbell'), n, 'more_peeps')
                self.mode = None
                self.close()
        
        elif test_result != 0:
            AW.msg_box('adv_warning')


#=============================================================================#


# User list snapshot - GUI in basic mode for adding more participants
class UserSnapshot(QtGui.QWidget):
    def __init__(self):
        QtGui.QWidget.__init__(self)
        self.initUI()
    def initUI(self):
        self.setWindowTitle('Add participants')
        self.setFixedSize(180, 176) # w x h

        label = QtGui.QLabel('Double-click or\n'
                             'use IP address to\n'
                             'add person.', self)
        label.move(15, 7) # x & y

        add_button = QtGui.QPushButton('', self)
        add_button.setFixedSize(24, 24)
        add_button.move(110, 16)
        add_button.setIcon(QtGui.QIcon('images/invite.png'))
        add_button.setIconSize(QtCore.QSize(16, 16))
        add_button.setToolTip('Use IP address of person to add into session.')
        add_button.clicked.connect(lambda:adder.show_it('invite_participants'))

        ref_button = QtGui.QPushButton('', self)
        ref_button.setFixedSize(24, 24)
        ref_button.move(140, 16)
        ref_button.setIcon(QtGui.QIcon('images/refresh.png'))
        ref_button.setIconSize(QtCore.QSize(16, 16))
        ref_button.setToolTip('Refresh to see who you can add into session.')
        ref_button.clicked.connect(self.refresh)

        self.snapshot = QtGui.QListWidget(self)
        self.snapshot.move(15, 60)
        self.snapshot.setFixedSize(150, 100)
        self.snapshot.doubleClicked.connect(self.search_kc_DB)
        
    def show_it(self):
        self.show()
        self.refresh()

    def refresh(self):
        self.snapshot.clear()
        for host in sorted(known_clients_DB):
            if known_clients_DB[host][5] > 0:
                self.snapshot.addItem(known_clients_DB[host][0])
    def search_kc_DB(self): # search known_clients_DB and map IP
        selection = self.snapshot.currentItem().text()
        try:
            for k, v in known_clients_DB.items():
                if v[0] == selection:
                    ip = v[3] # ip
                    self.emit(
                        QtCore.SIGNAL('add_moar_bongos'), ip, 'more_peeps')
                    self.close()
        except Exception:
            print('ex: D', sys.exc_info())


#=============================================================================#


# TCP SERVER
class TcpSvr(QtCore.QThread):
    def __init__(self):
        QtCore.QThread.__init__(self)
        self.end_flag = False
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('', chat_session_port))
        self.server.listen(20)

    def __del__(self):
        self.wait()

    def run(self):
        try: 
            while status == True and self.end_flag == False:
                connection, client_addr = self.server.accept()
                self.emit(QtCore.SIGNAL('server_socket'),
                          connection, client_addr[0], 'acceptor')
        except OSError:
            print('ex: U', sys.exc_info())

    def stop(self):
        self.server.close()
        self.end_flag = True

class ClientThreadRecv(QtCore.QThread): # incoming sock loop
    def __init__(self, conn, addr=None):
        QtCore.QThread.__init__(self)
        self.conn = conn
        self.addr = addr
        
    def __del__(self): 
        self.wait()
        
    def run(self):
        try:    
            while status == True: # sentinel                
                data = self.conn.recv(4096) # incoming...! 
                self.emit(QtCore.SIGNAL(self.addr), data, self.addr)
                if data == b'':
                    break
        except (ConnectionAbortedError, ConnectionResetError,
                OSError, WindowsError): # catch em all (or almost all)
            print('ex: E, E for expected.', sys.exc_info()) 
            pass 
        finally:
            self.conn.close() # clean up
            if status == True: # global status conditions
                self.emit(QtCore.SIGNAL(self.addr + '_conn_err'),
                          'closed_gracefully', self.addr)
            elif status == False:
                self.emit(QtCore.SIGNAL('connection_error'),
                          'big_off_button')


#=============================================================================#


# INDIVIDUAL CHAT WINDOWS - new process for each chat window
class ChatWindow(QtGui.QWidget):

    def __init__(self, conn=None, addr=None, mode=None): 
        QtGui.QWidget.__init__(self)
        self.wintitle = ''
        self.conn = conn
        self.addr = addr # required? 
        self.mode = mode
        self.party = {} # key=str(IP), val=['alias', send_conn, recv_conn]
        self.facilitator = 0 # increment on 'more_peeps'. i.e. ID trunk host

        self.add_participants(ip=self.addr, flag='initial')
        self.add_participants(ip=own_ip, flag='self')
        
        self.multiple_fit = dict() # keeps entries of all FIT streams (send)
        self.f_in_transit = False # flag for file(s) transfer in prog (send)

        self.emo_kid = emoji.SelectEmoji() # emoji
        self.emo_buffer_send = [] # buffer per message - cleared upon 'send'
        self.emo_buffer_log = [] # mirrored list - cleared upon update to log

        self.connect(self.emo_kid,
                     QtCore.SIGNAL('emoji_to_input'), self.add_emoji)
        self.connect(adder,
                     QtCore.SIGNAL('add_moar_cowbell'), self.add_participants)
        self.connect(online_users_snapshot,
                     QtCore.SIGNAL('add_moar_bongos'), self.add_participants)
        self.initUI()

    def add_participants(self, ip, flag, control_sig=None, party_dict=None):
        if flag == 'self':
            self.party[own_ip] = [ # own details
                record[0], 
                None,
                None
            ]
            return # skip establish_callbacks(ip)
        elif flag == 'initial':
            if self.mode == 'initiator': # initiate conn calls for send/receive
                cl_sock = self.connect_to_svr()
                cl_sock.connect((ip, chat_session_port))
                associated_sock_recv = ClientThreadRecv(conn=cl_sock, addr=ip)

                self.party[ip] = [ # remote host
                    None, # alias
                    cl_sock, # send sock
                    associated_sock_recv # recv sock
                    ]
                
            elif self.mode == 'acceptor': # initiate conn calls for send/recv
                associated_sock_recv = ClientThreadRecv(conn=self.conn, addr=ip)
                
                self.party[ip] = [
                    None,
                    self.conn,
                    associated_sock_recv
                    ]
        elif flag == 'more_peeps':
            if ip in self.party:
                warn('existing_participant')
                return 
            else:
                cl_sock = self.connect_to_svr()
                cl_sock.connect((ip, chat_session_port))
                associated_sock_recv = ClientThreadRecv(conn=cl_sock, addr=ip)
                
                self.party[ip] = [
                    None,
                    cl_sock,
                    associated_sock_recv
                    ]

                self.facilitator += 1
        elif flag == 'update_alias': # INCOMING CONTROL_SIGS from remote host
            if control_sig == b'\xe2\xa2\x84': # first signal from initiator
                try: # update self.party w received details in pickled obj
                    for ip_addr in party_dict:
                        if ip_addr in self.party:
                            self.party[ip_addr][0] = party_dict[ip_addr] 
                        else:
                            self.party[ip_addr] = [party_dict[ip_addr]]
                    self.party_alias_repopulate() 
                    self.alias_exchange('reply') # chain of events 4 reply-msg
                except Exception:
                    print('ex: F', sys.exc_info())
            elif control_sig == b'\xe2\xa2\x85': # 'Reply' from 'acceptor'
                try: 
                    for ip_addr in party_dict:
                        self.party[ip_addr][0] = party_dict[ip_addr]
                        reply_er = ip_addr 
                    if len(self.party) > 2: # to relay or not to relay, titq
                        self.party_alias_repopulate()
                        self.alias_exchange('forward', exclusion=reply_er) 
                    else:
                        self.party_alias_repopulate()
                except Exception:
                    print('ex: G', sys.exc_info())
            elif control_sig == b'\xe2\xa2\x86': # 'Forward' signal
                try:
                    for ip_addr in party_dict:
                        if ip_addr in self.party:
                            self.party[ip_addr][0] = party_dict[ip_addr]
                        else:
                            self.party[ip_addr] = [party_dict[ip_addr]] 
                    self.party_alias_repopulate()
                    self.alias_exchange('forward', exclusion=ip)
                except Exception:
                    print('ex: H', sys.exc_info())
            elif control_sig == b'\xe2\xa2\x87': # 'leaver' signal
                self.alias_exchange(flag='leaver', exclusion=ip, obj=party_dict)
                del self.party[party_dict]
                self.party_alias_repopulate()
                
        if flag != 'update_alias': 
            self.establish_callbacks(ip)
            self.party[ip][2].start()

    def party_alias_repopulate(self): # mod wintitle and self.participants GUI
        if len(self.party) > 2: # i.e. group
            self.participants.clear() # first clear
            for ip in self.party:
                if ip != own_ip and self.party[ip][0] != None: 
                    self.participants.append(
                        MainWindow.trunc_alias(self.party[ip][0])
                        )
            self.setWindowTitle('Group Session...') 
        else: # 2 people only
            for ip in self.party:
                if ip != own_ip:
                    two_of_two = ip # the other party in 2 person session
            self.setWindowTitle(self.party[two_of_two][0])
            self.participants.clear()
            self.participants.append(
                MainWindow.trunc_alias(self.party[two_of_two][0])
                )
        
    def establish_callbacks(self, ip):
        self.connect(self.party[ip][2], # receive_pipe
                    QtCore.SIGNAL(ip), self.receive_msg)
        self.connect(self.party[ip][2], # error & control messages
                     QtCore.SIGNAL(ip + '_conn_err'), self.msgs_n_errors)

    def closeEvent(self, event): # pre X checks
        self.fit_mechanism(mode='update_f_in_transit_flag')
        if (self.f_in_transit == True or self.addr in AW.fit_receive):
            fit_warn = QtGui.QMessageBox.question(
                self, 'Message', self.fit_msg,
                QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)
            if fit_warn == QtGui.QMessageBox.Yes:
                try:
                    self.close_sockets()
                except Exception:
                    print('ex: I', sys.exc_info())
                finally:
                    del AW.sessions[self.addr] 
                    self.close()
            else:
                event.ignore()
        else: 
            if self.facilitator > 0: # i.e. acting as trunk
                fac_warn = QtGui.QMessageBox.question(
                    self, 'Warning', self.fac_msg,
                    QtGui.QMessageBox.Yes, QtGui.QMessageBox.No
                    )
                if fac_warn == QtGui.QMessageBox.Yes:                    
                    self.close_sockets()
                    del AW.sessions[self.addr]
                    self.close()
                else:
                    event.ignore()
            else:
                self.close_sockets()
                del AW.sessions[self.addr]
                self.close()

    def connect_to_svr(self): 
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return client

    def close_sockets(self): # close session related TCP socks
        try: 
            for ip in self.party:
                if len(self.party[ip]) > 1 and self.party[ip][1] != None:
                    self.party[ip][1].close() 
        except Exception:
            print('ex: J', sys.exc_info())
       
    def initUI(self):
        self.setWindowIcon(QtGui.QIcon('images/appicon.png'))
        self.setFixedSize(300, 330)
        self.setWindowTitle(str(self.wintitle)) 

        # send message 
        self.send = QtGui.QPushButton('&send', self)
        self.send.setFixedSize(87, 24)
        self.send.move(198, 198)
        self.send.clicked.connect(self.send_msg)

        self.log = QtGui.QTextEdit(self)
        self.log.setFixedSize(270, 175)
        self.log.move(15,15)
        self.log.setReadOnly(True)
        self.log.verticalScrollBar()
        self.cursor = QtGui.QTextCursor(self.log.document())

        self.user_input = QtGui.QTextEdit(self)
        self.user_input.setFixedSize(166, 80) # w | h 
        self.user_input.move(15, 230) # x | y

        # send file button
        self.send_file_button = QtGui.QPushButton('', self)
        self.send_file_button.setFixedSize(24, 24)
        self.send_file_button.move(15, 198)
        self.send_file_button.setIcon(QtGui.QIcon('images/attach.png'))
        self.send_file_button.setIconSize(QtCore.QSize(22, 22))
        self.send_file_button.setToolTip('Send a file to remote users')
        self.send_file_button.clicked.connect(self.transfer_file)

        # poke button
        self.poke_button = QtGui.QPushButton('', self)
        self.poke_button.setFixedSize(24, 24)
        self.poke_button.move(45, 198)
        self.poke_button.setIcon(QtGui.QIcon('images/poke.png'))
        self.poke_button.setIconSize(QtCore.QSize(22, 22))
        self.poke_button.setToolTip('Send audio and visual notification '
                                    'to remote user')
        self.poke_button.clicked.connect(self.do_some_poking)

        # emoji button
        self.add_emoji_button = QtGui.QPushButton('', self)
        self.add_emoji_button.setFixedSize(24, 24)
        self.add_emoji_button.move(75, 198)
        self.add_emoji_button.setIcon(QtGui.QIcon('images/smiley.png'))
        self.add_emoji_button.setIconSize(QtCore.QSize(22, 22))
        self.add_emoji_button.setToolTip('Add emoji to your message')
        self.add_emoji_button.clicked.connect(self.emo_kid.show_it)

        # invite to conversation: to complete
        self.invite_button = QtGui.QPushButton('', self)
        self.invite_button.setFixedSize(24, 24)
        self.invite_button.move(105, 198)
        self.invite_button.setIcon(QtGui.QIcon('images/invite.png'))
        self.invite_button.setIconSize(QtCore.QSize(22, 22))
        self.invite_button.setToolTip('Invite others to this conversation')
        if SW.mode_of_operation == True: # adv mode
            self.invite_button.clicked.connect(
                lambda: adder.show_it(mode='invite_participants')
                )
        else: # basic mode
            self.invite_button.clicked.connect(
                lambda: online_users_snapshot.show_it()
                )
        
        # participants list - for basic mode
        self.participants = QtGui.QTextEdit(self)
        self.participants.setFixedSize(87, 80) # w | h
        self.participants.move(198, 230) # x | y
        self.participants.setReadOnly(True)
        self.participants.setFontPointSize(7) 
        self.participants.setStyleSheet('background: lightGray')
        self.participants.setToolTip('List of participants in session')
        
        self.show()
        
        if self.mode == 'acceptor':
            self.alias_exchange('hit_me') # all alias exchange starts here

    # OUTGOING CONTROL_SIGS to exchange participant ip/alias tween hosts
    def alias_exchange(self, flag, exclusion=None, target=None, obj=None):
        party_dict = {}
        if flag == 'hit_me': # kick off mechanism 
            header = b'\xe2\xa2\x83'
            self.send_msg(msgs='alias_exchange', party_dict=header)
            return
        elif flag == 'initiate': 
            header = b'\xe2\xa2\x84' 
        elif flag == 'forward':
            header = b'\xe2\xa2\x86'
        elif flag == 'leaver':
            header = b'\xe2\xa2\x87'
            body = pickle.dumps(obj) # ip of leaver
            self.send_msg(msgs='alias_exchange', party_dict=header+body,
                          exclude=exclusion) 
            return 
            
        if flag == 'reply':
            header = b'\xe2\xa2\x85'
            party_dict[own_ip] = record[0] # own ip & alias
        else:
            try: # collect all IP/alias pairs prior to transmission
                for ip in self.party: 
                    if self.party[ip][0] != None: # [0] holds alias
                        party_dict[ip] = self.party[ip][0] 
            except Exception:
                print('ex: T', sys.exc_info())

        body = pickle.dumps(party_dict)

        if exclusion == None:
            if target == None: 
                self.send_msg(msgs='alias_exchange', party_dict=header+body)
                print('B')
            else: 
                self.party[target][1].sendall(header+body)
        else:
            self.send_msg(msgs='alias_exchange', party_dict=header+body,
                          exclude=exclusion)
            
    def add_emoji(self, icon):
        smiley = QtGui.QPixmap(emoji.ed[icon]).toImage()
        self.user_input.textCursor().insertImage(smiley)
        self.emo_buffer_send.append(icon) # transmission of msg
        self.emo_buffer_log.append(icon) # updating self.log

    # for emoji, 1)send 2)log or 3)receive
    def parse_msg(self, raw, mode, source=None): 
        parsing = ''
        if mode == 'to_transf':
            for char in raw:
                if char == '\ufffc':
                    lookup = self.emo_buffer_send.pop(0)
                    parsing += lookup
                else: # normal text
                    parsing += char
            return parsing
        elif mode == 'sender_self.log':
            self.log.insertPlainText('you: ')
            for char in raw:
                if char == '\ufffc':
                    smiley = QtGui.QPixmap(
                        emoji.ed[self.emo_buffer_log.pop(0)]).toImage()
                    self.log.textCursor().insertImage(smiley)
                else: # normal text
                    self.log.insertPlainText(char)
        elif mode == 'recv_self.log':
            disect = str(raw, 'utf-8')
            split = disect.split('<?>')
            for block in split:
                if '<?>'+block+'<?>' in emoji.ed: # found in emo dict
                    smiley = QtGui.QPixmap(
                        emoji.ed['<?>'+block+'<?>']).toImage()
                    self.log.textCursor().insertImage(smiley)
                else: # normal text
                    self.log.insertPlainText(block)
        elif mode == 'control_sig':
            cs = raw[:3]
            party = pickle.loads(raw[3:])
            self.add_participants(
                ip=source, flag='update_alias',
                control_sig=cs, party_dict=party
                ) 
            
        self.log.setTextCursor(self.cursor) # cursor to bottom                

    def send_msg(self, msgs=None, fname=None,
                 fnamealt=None, party_dict=None, exclude=None):
        self.log.setTextCursor(self.cursor) # cursor to bottom
        if not msgs: # text & emoji - send it away! 
            try:
                string = self.user_input.toPlainText() + '\n'
                parsed = self.parse_msg(string, mode='to_transf')
                for ip in self.party:
                    if len(self.party[ip]) > 1 and self.party[ip][1] != None:
                        self.party[ip][1].sendall( # to refactor
                            bytearray((record[0] + ': ' +
                                       parsed).encode('utf-8')))
            except Exception:
                print('ex: K', sys.exc_info())

            self.parse_msg(string, mode='sender_self.log') 
            self.user_input.clear() 
            self.emo_buffer_send.clear() 
            self.emo_buffer_log.clear() 

        elif msgs == 'ft_initiate': # cheat: FT signals controlled by client
            if fnamealt != None:
                string = ('\n*** receiving file [' + fname + '] as ' +
                               fnamealt + ' ***\n')
            else:
                string = '\n*** receiving file [' + fname + '] ***\n'
            try:
                self.conn.sendall(bytearray((string).encode('utf-8')))
            except Exception:
                print('ex: L', sys.exc_info()) 
        elif msgs == 'ft_complete':
            try:
                self.conn.sendall(
                    b'\n*** file successfully received ***\n')
            except Exception:
                 print('ex: M', sys.exc_info())
        elif msgs == 'alias_exchange': 
            try: 
                for ip in self.party:
                    if (len(self.party[ip]) > 1 and
                        self.party[ip][1] != None) and ip != exclude:
                           self.party[ip][1].sendall(party_dict)
            except Exception:
                print('ex: N', sys.exc_info())
        
    def receive_msg(self, msg, source): 
        self.log.setTextCursor(self.cursor) 
        if msg[:3] not in self.control_signals: # normal message
            self.parse_msg(msg, mode='recv_self.log')
            if len(self.party) > 2: # disseminate to others in group 
                for ip in self.party:  
                    if ip != source and (len(self.party[ip]) > 1 and
                                         self.party[ip][1] != None): # x-sender
                        self.party[ip][1].sendall(msg)
        else: # control signals
            if msg[:3] == b'\xe2\xa2\x82': # poke 
                self.poked()
            elif msg[:3] == b'\xe2\xa2\x83': # instigator to initiate
                self.alias_exchange('initiate', target=source)
            else: 
                self.parse_msg(msg, mode='control_sig', source=source)
                
        try: # flash window - require win32gui mod
            self.flash_window()
        except NameError:
            print('ex: O', sys.exc_info())

        self.btf()

    def btf(self): # bring chat window to front upon msg receive
        if SW.btf_toggle_state == True: 
            self.setWindowState(
                self.windowState() &
                ~QtCore.Qt.WindowMinimized |
                QtCore.Qt.WindowActive)
            self.activateWindow()

    def flash_window(self):
        if not self.isActiveWindow():
            self.flash = win32gui.FindWindow(None, self.wintitle)
            win32gui.FlashWindow(self.flash, True)
     
    def transfer_file(self): 
        folder_file_path = QtGui.QFileDialog.getOpenFileName() # entire path
        if folder_file_path == '': # action cancelled
            pass
        else: 
            placeholder = []
            file_ext_len = 0
            file_name = ''

            for char in folder_file_path[-1::-1]: # extract only filename
                if char not in '\/':
                    placeholder.append(char)
                else: break

            for char in placeholder: # determine length of file extension
                if char != '.':
                    file_ext_len += 1
                else: break
                
            placeholder.reverse() # rearrange filename

            for char in placeholder: # build filename
                file_name += char

            if self.mode == 'initiator': # launch FTP client session
                self.transf_obj = FtpClient(self.addr, folder_file_path,
                                            file_name, file_ext_len) 
            elif self.mode == 'acceptor': 
                self.transf_obj = FtpClient(self.addr, folder_file_path,
                                            file_name, file_ext_len)    
            # reference dict() built to call methods in bulk 
            self.multiple_fit[file_name] = ([self.transf_obj, True]) 
                
            self.transf_obj.start()
            
            self.fit_mechanism(mode='update_f_in_transit_flag')
            
            self.connect(self.transf_obj, QtCore.SIGNAL(
                'stageA_from_ftransfer'), self.msgs_n_errors)
            self.connect(self.transf_obj, QtCore.SIGNAL(
                'stageB_from_ftransfer'), self.msgs_n_errors)
            self.connect(self.transf_obj, QtCore.SIGNAL(
                'exception_from_ftransfer'), self.msgs_n_errors)
            self.connect(self.transf_obj, QtCore.SIGNAL(
                'ftp_login_error'), self.msgs_n_errors)
            
    def do_some_poking(self):
        for ip in self.party: # ignore self entry & non-trunk 
            if len(self.party[ip]) > 1 and self.party[ip][1] != None: 
                self.party[ip][1].sendall(b'\xe2\xa2\x82')

    def poked(self):
        if SW.snd_toggle_state == True:
            ding = simpleaudio.WaveObject.from_wave_file('audio/ting.wav')
            ding.play()
        else:
            pass
        try:
            self.flash_window()
        except NameError:
            pass

    def sock_verifier(self, ip, index, mode=None): # check existance of sockObj
        if mode == 'nullify':
            self.alias_exchange(flag='leaver', exclusion=ip, obj=ip) # new entry 6 jan 17 
            del self.party[ip]
        at_least_one_sock = False
        if len(self.party) >= 2: 
            for ip in self.party: 
                if len(self.party[ip]) > 1 and self.party[ip][index] != None: 
                    at_least_one_sock = True # an entry with a socket exists
                    break 
                else: 
                    continue 
        return at_least_one_sock 
    
    def msgs_n_errors(self, msgtype, ip, fobj=None, fobjalt=None):
        try:
            if msgtype == 'sent_file':
                self.log.insertPlainText('\n*** file successfully sent ***\n')
                self.send_msg(msgs='ft_complete')
                self.multiple_fit[fobj][1] = False
                self.f_in_transit = False 
            else: 
                if msgtype == 'closed_gracefully': # 'gracefully' is a misnomer
                    verified = self.sock_verifier(ip, 1, mode='nullify')
                    if verified == False: 
                        self.log.insertPlainText(
                            '\n*** Session was closed by remote user. Close '
                            'this session window and relaunch once the remote'
                            ' user status shows \'online\' again. ***\n'
                            )
                        self.fit_mechanism()
                        self.lockout_cw()
                    self.facilitator -= 1
                elif msgtype == 'big_off_button': # interrupt
                    self.log.insertPlainText(
                        '\n*** You have currently gone \'offline\', please '
                        'close all open session windows, go back \'online\' '
                        'and restart sessions or wait for others to initiate '
                        'session. ***\n'
                        )
                    self.fit_mechanism()
                    self.lockout_cw()
                elif msgtype == 'sending_file':
                    if fobjalt != None:
                        self.log.insertPlainText(
                            '\n*** sending file [%s] as [%s] ***\n'
                            % (fobj, fobjalt)
                            )
                    else:
                        self.log.insertPlainText(
                            '\n*** sending file [%s] ***\n' % fobj
                            )
                    self.send_msg(
                        msgs='ft_initiate', fname=fobj, fnamealt=fobjalt
                        )
                elif msgtype == 'ft_cancelled':
                    self.log.insertPlainText(
                        '\n*** file transfer failed ***\n'
                        )
                    self.fit_mechanism() # required?
                elif msgtype == 'ft_refused':
                    self.log.insertPlainText(
                        '\n*** remote user appears to be offline ***\n'
                        )
            self.party_alias_repopulate()
            self.log.setTextCursor(self.cursor)
            
        except AttributeError: # caters for non-existent self.f_in_transit
            print('ex: P', sys.exc_info())
            pass 

    def fit_mechanism(self, mode=None):
        if mode == 'update_f_in_transit_flag':
            try:
                for i in self.multiple_fit:
                    if self.multiple_fit[i][1] == True:
                        self.f_in_transit = True
            except Exception:
                print('ex: Q', sys.exc_info())
        else:
            try:
                for i in self.multiple_fit:
                    if self.multiple_fit[i][1] == True:
                        self.multiple_fit[i][0].breaker = True
                        self.multiple_fit[i][1] = False # make false
                self.f_in_transit = False # guarantee: ensures warning
            except Exception:
                self.f_in_transit = False
            
    def lockout_cw(self):
        self.send.setEnabled(False)
        self.send_file_button.setEnabled(False)
        self.poke_button.setEnabled(False)
        self.invite_button.setEnabled(False)
        self.add_emoji_button.setEnabled(False)
        self.user_input.setReadOnly(True)
        self.emo_kid.close()

    def interrupt(self): # called by MW when going 'offline'
        try:
            self.conn.close()
        except Exception:
            print('ex: R', sys.exc_info())

    # messages embedded in class, used by inheritance search
    fac_msg = ('You are a facilitator in this group session as you have '
               'added one or more participants to the current chat session. '
               'If you close the session, those who you added will also be '
               'disconnected from the current group session. Do you want '
               'to continue?')
    fit_msg = ('Warning: file(s) transfer currently in progress. Are you '
               'sure you want to Quit session and end file transfer?')

    control_signals = {b'\xe2\xa2\x82', b'\xe2\xa2\x83', b'\xe2\xa2\x84',
                       b'\xe2\xa2\x85', b'\xe2\xa2\x86', b'\xe2\xa2\x87'} 


#=============================================================================#


# SETTINGS WINDOW
class SettingsWindow(QtGui.QWidget):
    def __init__(self):
        QtGui.QWidget.__init__(self)
        self.mode_of_operation = False # False = 'basic', True = 'advanced'
        if os.path.isfile(r'settings.txt') == False: # first time? create file
            self.btf_toggle_state = False # chat window: bring to front
            self.snd_toggle_state = False # tea-time
            self.write_settings()
        elif os.path.isfile(r'settings.txt') == True: # load from settings.txt
            with open(r'settings.txt', 'rb') as settings_file:
                (self.btf_toggle_state,
                 self.snd_toggle_state) = pickle.load(settings_file)
        self.initUI()

    def closeSettings(self):
        self.close()

    def initUI(self):
        self.setFixedSize(200, 300)
        self.setWindowTitle('Chat_v1.0 settings')

        # labels
        self.L0 = QtGui.QLabel('Alias: ', self)
        self.L0.move(15,15)
        self.L1 = QtGui.QLabel('First Name: ', self)
        self.L1.move(15,45)
        self.L2 = QtGui.QLabel('Last Name: ', self)
        self.L2.move(15,75)

        # text boxes
        self.alias = QtGui.QLineEdit(self)
        self.alias.move(75, 12)
        self.alias.setMaxLength(16) # gratuitous
        self.first = QtGui.QLineEdit(self)
        self.first.move(75, 43)
        self.last = QtGui.QLineEdit(self) 
        self.last.move(75, 73)

        if len(record) > 0: # returning user file
            self.alias.setText(record[0])   
            self.first.setText(record[1])
            self.last.setText(record[2])

        # operation mode
        group_a = QtGui.QGroupBox(self)
        group_a.setTitle('Operation Mode')
        group_a.move(15, 106)
        group_a.setFixedSize(171, 53)

        self.operation_mode = QtGui.QCheckBox(self)
        self.operation_mode.move(25, 126)
        self.operation_mode.setText(' Advanced (stealth mode)')
        self.operation_mode.setToolTip(
            'Appear \'offline\' but be available for manual IP connection. \n'
            'Connect to another user by manually adding their IP address. \n'
            'Note, you won\'t be able to see the status of others either.'
            )
        
        # messenger window settings
        group_b = QtGui.QGroupBox(self)
        group_b.setTitle('Chat Window Options')
        group_b.move(15,166)
        group_b.setFixedSize(171, 86)

        self.btf_tog = QtGui.QCheckBox(self)
        self.btf_tog.move(25, 186)
        self.btf_tog.setText(' Always bring to front upon\n message receive')

        self.snd_tog = QtGui.QCheckBox(self)
        self.snd_tog.move(25, 220)
        self.snd_tog.setText(' Audio alert when poked')

        # save & cancel 
        self.save = QtGui.QPushButton('Save', self) 
        self.save.move(15, 264)
        self.save.clicked.connect(self.capture_settings)
        
        self.cancel = QtGui.QPushButton('Cancel', self)
        self.cancel.move(110, 264)
        self.cancel.clicked.connect(self.closeSettings)
        
    def show_it(self): # repopulate as required
        if len(record) > 0:            
            self.alias.setText(record[0])
            self.first.setText(record[1])
            self.last.setText(record[2])

        if self.mode_of_operation == False:
            self.operation_mode.setChecked(False)
        elif self.mode_of_operation == True:
            self.operation_mode.setChecked(True)
            
        self.btf_tog.setChecked(self.btf_toggle_state)
        self.snd_tog.setChecked(self.snd_toggle_state)

        self.show()

    def capture_settings(self):
        if (len(self.alias.displayText().strip()) == 0 or
            len(self.first.displayText().strip()) == 0 or
            len(self.last.displayText().strip()) == 0):
            warn('blank')
        else:
            global record # to be replace with object attribs
            record = [] # clear
            record.append(self.alias.displayText())
            record.append(self.first.displayText())
            record.append(self.last.displayText())

            new_user_details() # write details to file again

            self.btf_toggle_state = bool(self.btf_tog.checkState())
            self.snd_toggle_state = bool(self.snd_tog.checkState())
            self.alternate_state() # only modify GUI if state changes

            self.write_settings()    
            self.closeSettings()

    def write_settings(self):
        with open(r'settings.txt', 'wb') as settings_file:
            pickle.dump((self.btf_toggle_state,
                         self.snd_toggle_state), settings_file)

    def alternate_state(self): # ensures change to state only if state changes
        if self.mode_of_operation != bool(self.operation_mode.checkState()):
            self.mode_of_operation = bool(self.operation_mode.checkState())
            AW.alternate_ui(bool(self.operation_mode.checkState()))
        else:
            pass


#=============================================================================#


# USER DETAILS - put in MainWindow obj attributes
def returning_user():
    global status
    if os.path.isfile(user_file) == True:
        old_user_details() # open or create file
        status = True 
    else: # first time running app, requires alias, first & last name
        status = False 
        warn('first')
    
def old_user_details():
    global record
    record = []
    with open(user_file, 'r') as u:
        for i in u:
            record.append(i.strip())

def new_user_details():
    with open(user_file, 'w') as u: 
        for i in record:
            print(i, end='\n', file=u)


# FIRST LAUNCH or NO SETTINGS SET - to be mw obj attrib
def warn(flag):
    msg = QtGui.QMessageBox()
    msg.setWindowTitle("Chat v1")
    if flag == 'first':
        msg.setText(
            'First time using Chat app? Be sure to populate Alias, '
            'First and Last name fields in the settings menu.'
            )
    elif flag == 'blank':
        msg.setText('You need to ensure all fields are filled in.')
    elif flag == 'ip_err':
        msg.setText('You need to enter an IP address in the proper format '
                    'e.g. 192.168.0.2')
    elif flag == 'ip_err2':
        msg.setText('IP address entered is out of range.')
    elif flag == 'ip_err3':
        msg.setText('IP address entered is your own IP!')
    elif flag == 'existing_participant':
        msg.setText('The participant you\'re trying to add is already '
                    'in the conversation') 
    msg.exec()


#=============================================================================#


# NETWORK: TRANSCEIVER
# receives broadcasts from remote host beacon service, collects data in dict 
def transceiver():
    global known_clients_DB
    trans = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
    trans.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    trans.bind(('', transceiver_port))
    
    while status == True and SW.mode_of_operation == False: # sentinel
        msg = trans.recvfrom(1024)
        if msg[1][0] == own_ip: 
            continue # ignore local broadcasts - requires dirty trick below
        if msg[0].decode('utf-8').split(',')[0] == 'hola': # msg from pinger
            host = msg[0].decode('utf-8').split(',')[1]
            if host in known_clients_DB: 
                known_clients_DB[host][5] = 4 # 4 sec ttl # todo: add t-lock
            else:
                pinger(ip=host, mode='on_demand') # keep alive
        else: # a beacon alert (occurs less often)
            alias, first, last, host = msg[0].decode('utf-8').split(',')
            ip = msg[1][0]
            if host not in known_clients_DB: # first time bcast? # add t-lock
                pinger(ip=ip, mode='reactive_beacon') # reply back 
            known_clients_DB[host] = [alias, first, last, ip, 75, 6]
            # 75 seconds no bcast countdown, if 0 then removed from dict,
            # else a broadcast received from same host will reset to 80
    trans.close()


#=============================================================================#


# NETWORK: KEEP ALIVE: beacon, pinger
# 2 types of beacon message:
# 1) broadcasts message to other hosts running chat program (transceiver)
# on the network indicating 'alias, first, last, hostname, IP'.
# 2) udp packet to verify host exists ('hola'); handled by pinger

def create_message(msg):
    if msg == 'record':
        message = ''
        for i in record:
            message += i + ','
        return message + socket.gethostname() # 'alias, first, last, hostname'
    else: 
        return msg + ',' + socket.gethostname() 

def beacon(): 
    global beacon_interval
    beacon_interval = 60
    
    broadcast = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while status == True and SW.mode_of_operation == False: # sentinel
        broadcast.sendto(
            bytearray(create_message('record').encode('utf-8')),
            ('255.255.255.255', transceiver_port))
        while status == True: # nested loop creates 'immediate' end
            time.sleep(1)
            beacon_interval -= 1
            if beacon_interval != 0:
                continue
            else:
                break
        beacon_interval = 60
    broadcast.close()

def pinger(ip=None, mode=None): # starts when len(records) > 0 in DB
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    if mode == 'on_demand': # caters for quirk "online, 4sec, offline"
        sock.sendto(
            bytearray(create_message('hola').encode('utf-8')),
            (ip, transceiver_port)
            )  
    elif mode == 'reactive_beacon': # back to broadcaster
        sock.sendto(
            bytearray(create_message('record').encode('utf-8')),
            (ip, transceiver_port)
            )
    else: 
        while status == True and SW.mode_of_operation == False:
            try: 
                if len(known_clients_DB) > 0: # sentinel
                    for host in known_clients_DB:
                        sock.sendto(
                            bytearray(create_message('hola').encode('utf-8')),
                            (host, transceiver_port)
                            ) # calling card
                else:
                    pass
                time.sleep(1) # every 2 sec send Q
                if status == False:
                    break
                else:
                    time.sleep(1) # trick to ensure quick thread stop
            except RuntimeError:    # caters for dictionary size change quirk # update: won't be necessary once lock mechanism is in place
                print('caught a furball *** ', sys.exc_info())
        # dirty trick ends Transceiver daemon.
        # Self pinger sends to own transceiver
        # to initiate first clause and thus end loop.
        sock.sendto(
            bytearray(create_message('hola').encode('utf-8')),
            (socket.gethostname(), transceiver_port)
            ) 
    sock.close()


#=============================================================================#


# NETWORK: FTP SERVER
# Don't reinvent the wheel
class FtpSvr(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True

    def run(self):
        self.authorizer = DummyAuthorizer()
        # to be hardened - with md5hash pw, 'settings': option to specify dir
        self.authorizer.add_user(
            username='userA',
            password='12345',
            homedir='.',
            perm='elradfmwM'
            ) 

        self.dtp_handler = ThrottledDTPHandler
        self.dtp_handler.read_limit = 30720  # 30kb/sec (30 * 1024)
        self.dtp_handler.write_limit = 30720
        
        self.handler = FtpSvrHandler
        self.handler.authorizer = self.authorizer
        self.server = ThreadedFTPServer(('0.0.0.0', ftp_cloak_port),
                                        self.handler)
        self.server.serve_forever() 

    def stop(self):
        try:
            self.server.close_all()
        except Exception:
            print('ex: V - ftpsvr stopped', sys.exc_info())

class FtpSvrHandler(FTPHandler):
    def on_connect(self):
        AW.fit_receive.append(self.remote_ip)
        print('connected')

    def on_disconnect(self):
        if self.remote_ip in AW.fit_receive:
            try:
                AW.fit_receive.remove(self.remote_ip)
            except ValueError:
                print('disconnected *** ', sys.exc_info())
        print('disconnected')

    def on_login(self, username):
        print('logged IN')

    def on_logout(self, username):
        print('logged OUT')

    def on_incomplete_file_received(self, file):
        os.remove(file)
        AW.fit_receive.remove(self.remote_ip)

    def on_file_received(self, file):
        print('received file: ', file)


#=============================================================================#


# ENCRYPTION: FtpSvr user password - to be developed in another module
class MD5Protect(DummyAuthorizer):
    pass 


#=============================================================================#


# NETWORK: FTP CLIENT
# to include size limitation mechanism - include in settings, set on server
class FtpClient(QtCore.QThread):
    def __init__(self, svr, ffpath, filename, file_ext_len):
        QtCore.QThread.__init__(self)
        self.breaker = False
        self.svr = svr
        self.ffpath = ffpath
        self.filename = filename
        self.fel = file_ext_len + 1
        
    def __del__(self):
        self.wait()

    def run(self):
        try: # ever tried. ever failed. no matter
            self.sess = ftplib.FTP()
            self.sess.connect(self.svr, ftp_cloak_port)
            self.sess.login(user='userA', passwd='12345')
            with open(self.ffpath, 'rb') as self.file_obj:
                try: # nihongo desu ka? (is it japanese? or greek?)
                    self.connection = self.sess.transfercmd(
                        'STOR ' + self.filename, rest=None
                        )
                    self.emit(QtCore.SIGNAL('stageA_from_ftransfer'),
                              'sending_file', self.filename)
                except UnicodeEncodeError:
                    funky = (record[0] + '_' + str(random.randrange(1,100)) +
                             self.filename[-(self.fel)::])
                    self.connection = self.sess.transfercmd(
                        'STOR ' + funky, rest=None
                        )
                    self.emit(QtCore.SIGNAL('stageA_from_ftransfer'),
                              'sending_file', self.filename, funky)
                try: # over the wire 
                    while self.breaker == False:
                        chunk = self.file_obj.read(8192)
                        self.connection.sendall(chunk)
                        if not chunk:
                            self.emit(QtCore.SIGNAL('stageB_from_ftransfer'),
                                      'sent_file', self.filename)   # sent
                            print('beetle?') # rem me & small files wont send
                            break 
                        elif self.breaker == True: # ABOR ensures file removal
                            self.sess.transfercmd('ABOR')
                            break
                # remote host ftpsvr stops
                except (ConnectionResetError, ConnectionAbortedError,
                        OSError, AttributeError, EOFError): 
                    self.emit(QtCore.SIGNAL('exception_from_ftransfer'),
                              'ft_cancelled', self.filename) # canned locally
                    pass
                finally:
                    self.connection.close()
                    self.sess.close()
        except (ConnectionRefusedError, EOFError):
            self.emit(QtCore.SIGNAL('ftp_login_error'), 'ft_refused')
            print('except: #15', sys.exc_info())
            pass

    def byebye(self): # quaint attrib, already fulfilled by 'breaker' flag
        try:
            self.connection.close()
            self.sess.close()
        except IOError:
            pass


#=============================================================================#


# DATABASE: to become main window obj attribute
# Keep alive component
# todo: locking mechanism required for the modification of known_clients_DB
def db_cleanup(): 
    global known_clients_DB
    expired = []
    
    while status == True and SW.mode_of_operation == False:
        time.sleep(1) # fixes cpu spike
        if len(known_clients_DB) <= 0:
            expired = []
            continue
        else:
            try: # surplus
                for host in known_clients_DB:
                    if known_clients_DB[host][4] <= 0:                    
                        expired.append(host)
                    else:
                        known_clients_DB[host][4] -= 1 # decayed host ttl
                        known_clients_DB[host][5] -= 1 # livedie ttl
                for host in expired:
                    if host in known_clients_DB:
                        del known_clients_DB[host]
            except Exception:
                print('ex: S', sys.exc_info())
            finally:
                AW.add_or_remove() # ensures no multiple identical entries
    AW.userlist.clear()
    known_clients_DB.clear()


#=============================================================================#


# MAIN LOOP
if __name__ == '__main__':
    
    Application = QtGui.QApplication(sys.argv)
    returning_user() # check if first run or returning user

    SW = SettingsWindow()
    adder = AddIPManually()
    online_users_snapshot = UserSnapshot()
    AW = MainWindow()

    sys.exit(Application.exec_()) # to do - ensure all threads stop properly

