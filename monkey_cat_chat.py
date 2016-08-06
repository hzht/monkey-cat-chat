'''
Developed by Htay Z Htat, June 2016
github.com/hzht

3rd party libraries:
* PyQt4
* win32gui - https://sourceforge.net/projects/pywin32/files/pywin32/Build%20220
* simipleaudio
* pyftpdlib

Description:
MS Lync clone. Furball? Kinda. Written & tested on Python 3.4.4, Windows7 64
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

try: 
    import win32gui, simpleaudio # 3rd party & OS dependent modules
except ImportError:
    print('download win32gui & simpleaudio for better functionality')

# GLOBALS
record = [] # user details
user_file = r".\user.txt"

transceiver_port = 6165
chat_session_port = 6166 # TCP port on which server listens on
beacon_interval = 60
ftp_cloak_port = 14415

known_clients_DB = {} # DB: info received from remote chat clients

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
        self.state.setGeometry(135,40,48,48)  # x, y, width, height
        self.state.setPixmap(QtGui.QPixmap('images/offline.png'))

        self.add = QtGui.QPushButton('Add', self)
        self.add.setFixedSize(70,29)
        self.add.move(15, 70)
        self.add.setIcon(QtGui.QIcon('images/invite.png'))
        self.add.setIconSize(QtCore.QSize(21, 21))
        self.add.setToolTip('Add IP address of colleague to chat')
        self.add.clicked.connect(adder.show_it) # dialog box for adding IP
        self.add.setVisible(False)

        self.mwL3 = QtGui.QLabel('Double click on person to begin chat', self)
        self.mwL3.setFixedSize(200,12)
        self.mwL3.move(15, 285)

        self.userlist = QtGui.QListWidget(self)  # list of online users
        self.userlist.move(15, 111)
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
        self.mwAbout = QtGui.QAction('&About', self)
        self.mwAbout.triggered.connect(lambda: self.msg_box('about')) 

        self.mwMenuBar = QtGui.QHBoxLayout()
        self.mwBar = self.menuBar()
        self.mwHelp = self.mwBar.addMenu('&Help')
        self.mwHelp.addAction(self.mwHostname)
        self.mwHelp.addAction(self.mwAbout)

        self.show()

    def alternate_ui(self, mode):
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

            self.tcp_launch() # starts TCP server chain
            self.e = FtpSvr() # instance of threading obj
            self.e.start()

            self.setFixedSize(100, 111)
            self.on.setVisible(False)
            self.off.setVisible(False)
            self.state.setVisible(False)
            self.mwL3.setVisible(False)
            self.userlist.setVisible(False)
            self.add.setVisible(True)

            global status
            status = True # only time all services are offline & status = True

    def tcp_launch(self): # TCP server related calls
        self.tcp_server = TcpSvr()
        self.tcp_server.start()
        self.connect(self.tcp_server, QtCore.SIGNAL('server_socket'),
                     self.new_session) # receives 'connection' & 'client_addr'

    def new_session(self, conn, addr, mode): # instance based on ChatWindow
        if mode == 'initiator': # initiate request      
            self.unpacked = (self.userlist.currentItem().text().split(':'))
            self.alias_name = self.unpacked[0][:-4]
            self.alias_state = self.unpacked[-1][1:]
            if self.alias_state == 'online':
                try: # obtain IP from known_clients_DB & pass to CW instance
                    for k, v in known_clients_DB.items():
                        if v[0] == self.alias_name:
                            self.sessions[v[0]] = ChatWindow(
                                name=self.alias_name,
                                ip=known_clients_DB[k][3],
                                mode='initiator') # remote alias name and IP
                except Exception:
                    pass
            else:
                self.msg_box('warning')

        elif mode == 'acceptor': # receive request
            self.conn = conn
            self.addr = addr
            self.sessions[self.addr[0]] = ChatWindow(
                name=self.addr[0],
                conn=self.conn,
                addr=self.addr,
                mode='acceptor')

        elif mode == 'adv_initiate': # add manually IP addr in adv mode
            self.addr = addr
            try:
                self.sessions[addr] = ChatWindow(name=self.addr, ip=self.addr, mode='initiator')
            except TimeoutError: # unresponsive or offline remote host
                self.msg_box('adv_warning')
                print(sys.exc_info())

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
                + socket.gethostbyname(socket.gethostname()))
            self.info.setWindowTitle('Hostname | IP')
        elif msgtype == 'adv_warning':
            self.info.setText('Unable to connect to specified IP address, '
                              'person may be offline.')
            self.info.setWindowTitle('Warning!')
        self.info.show()

    def go_online(self): # turn all services on
        returning_user()
        if status == False:
            self.state.setGeometry(135,36,48,48)
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

            self.on.setEnabled(False) # deterrent for consecutive on/off clicks
            self.off.setEnabled(True)
        
    def go_offline(self): # clears the local DB & self.a-d + TcpSvr stop
        global status
        status = False

        try:
            self.e.stop()
        except AttributeError:
            pass

        for i in self.sessions: # bye bye sessions
            self.sessions[i].interrupt()

        self.state.setPixmap(QtGui.QPixmap('images/offline.png'))

        self.on.setEnabled(True) 
        self.off.setEnabled(False)

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


#=============================================================================#

# Advanced mode, add IP dialog box
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

    def show_it(self):
        self.ipbox.clear()
        self.show()
    
    def port_verifier(self, n): # verify chat_session_port is open on rhost
        try:            
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.settimeout(1)
            self.test_result = self.s.connect_ex((n, chat_session_port))
        except Exception:
            print(sys.exc_info())
        finally:
            print(self.s)
            self.s.close()
            print(self.test_result)

        if self.test_result == 0: # chat_session_port IS open on rhost
            self.launch_connection(n) # kick it off!
        elif self.test_result != 0:
            AW.msg_box('adv_warning')
    
    def validate_ip(self, n): # ensure IP entered is to IPv4 standard
        self.ip = n.split('.')
        if len(self.ip) != 4:
            warn('ip_err')
        else:
            for octet in self.ip:
                if not octet.isdigit():
                    warn('ip_err')
                    self.ipbox.clear()
                    break
                if int(octet) < 0 or int(octet) > 255:
                    warn('ip_err2')
                    self.ipbox.clear()
                    break
            self.port_verifier(n)

    def launch_connection(self, ip):
        AW.new_session(conn='', addr=ip, mode='adv_initiate')
        self.close()


#=============================================================================#

# TCP SERVER
class TcpSvr(QtCore.QThread):
    def __init__(self):
        QtCore.QThread.__init__(self)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('', chat_session_port))
        self.server.listen(20)

    def __del__(self):
        self.wait()

    def run(self):
        while status == True:
            connection, client_addr = self.server.accept()
            self.emit(QtCore.SIGNAL('server_socket'),
                      connection, client_addr, 'acceptor')

class ClientThreadRecv(QtCore.QThread): # receiving component loop
    def __init__(self, conn, addr=None):
        QtCore.QThread.__init__(self)
        self.conn = conn
        self.addr = addr

    def __del__(self): 
        self.wait()

    def run(self):
        try:    
            while status == True: # sentinel                
                self.data = self.conn.recv(4096) # incoming...! 
                self.emit(QtCore.SIGNAL('chat_window_recv'), self.data) # pipe
                if self.data == b'':
                    break
                elif self.data == b'<<b>>':
                    self.emit(QtCore.SIGNAL('poke_request'))
                # elif statement for emojis! 
        except (ConnectionAbortedError, ConnectionResetError,
                OSError, WindowsError):
            print(sys.exc_info()) # catch em all (or almost all)! 
            pass 
        finally:
            self.conn.close() # clean up
            if status == True: # global status conditions
                self.emit(QtCore.SIGNAL('connection_error'),
                          'closed_gracefully')
            elif status == False:
                self.emit(QtCore.SIGNAL('connection_error'), 'big_off_button')

#=============================================================================#

# INDIVIDUAL CHAT WINDOWS - new process for each chat window
class ChatWindow(QtGui.QWidget):
    def __init__(self, name=None, ip=None, conn=None, addr=None, mode=None):
        QtGui.QWidget.__init__(self)
        self.wintitle = name
        self.ip = ip
        self.conn = conn
        self.addr = addr
        self.mode = mode

        self.multiple_fit = dict() # keeps entires of all FIT streams (send)
        self.f_in_transit = False # flag for file(s) transfer in prog (send)
        
        if self.mode == 'initiator': # initiate conn calls for send/receive
            self.cl_socket = self.connect_to_svr() # sender
            self.cl_socket.connect((ip, chat_session_port))
            self.associated_sock_recv = ClientThreadRecv(self.cl_socket) # recv
            self.addr = [None] # cheat: caters for closeEvent self.addr[0]
    
        elif self.mode == 'acceptor': # initiate conn calls for send/receive
            self.associated_sock_recv = ClientThreadRecv(self.conn,
                                                         addr=self.addr)
            for key in known_clients_DB: # for missing alias
                if known_clients_DB[key][3] == addr[0]:
                    self.wintitle = known_clients_DB[key][0] 

        self.associated_sock_recv.start()

        self.connect(self.associated_sock_recv,
                     QtCore.SIGNAL('chat_window_recv'), self.receive_text)
        self.connect(self.associated_sock_recv,
                     QtCore.SIGNAL('poke_request'), self.poked)
        self.connect(self.associated_sock_recv,
                     QtCore.SIGNAL('connection_error'), self.msgs_n_errors)
        
        self.initUI()

    def closeEvent(self, event): # pre X checks
        self.fit_mechanism(mode='update_f_in_transit_flag')
        if (self.f_in_transit == True or
            self.ip in AW.fit_receive or self.addr[0] in AW.fit_receive):
            fit_msg = ('Warning: file(s) transfer currently in progress. '
                       'Are you sure you want to Quit session and end '
                       'file transfer?')
            self.fit_warn = QtGui.QMessageBox.question(
                self, 'Message', fit_msg,
                QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)
            if self.fit_warn == QtGui.QMessageBox.Yes:
                try:
                    self.close_sockets()
                except Exception:
                    print(sys.exc_info())
                finally:
                    self.close()
            else:
                event.ignore()
        else:         
            self.close_sockets()
            self.close()

    def close_sockets(self): # close session related TCP socks
        try:
            if self.mode == 'initiator': 
                self.client.close()
            elif self.mode == 'acceptor':
                self.conn.close()
        except Exception:
            print(sys.exc_info())
       
    def initUI(self):
        self.setWindowIcon(QtGui.QIcon('images/appicon.png'))
        self.setFixedSize(300, 330)
        self.setWindowTitle(str(self.wintitle)) # Alias of remote client

        # send message 
        self.send = QtGui.QPushButton('&send', self)
        self.send.move(210, 230)
        self.send.clicked.connect(self.send_text)

        self.log = QtGui.QTextEdit(self)
        self.log.setFixedSize(270, 175)
        self.log.move(15,15)
        self.log.setReadOnly(True)
        self.log.verticalScrollBar()
        self.cursor = QtGui.QTextCursor(self.log.document())

        self.user_input = QtGui.QTextEdit(self)
        self.user_input.setFixedSize(180, 80)
        self.user_input.move(15, 230)

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

        # invite to conversation
        self.invite_button = QtGui.QPushButton('', self)
        self.invite_button.setFixedSize(24, 24)
        self.invite_button.move(75, 198)
        self.invite_button.setIcon(QtGui.QIcon('images/invite.png'))
        self.invite_button.setIconSize(QtCore.QSize(22, 22))
        self.invite_button.setToolTip('Invite others to this conversation')
        
        self.show()

    def send_text(self, msgs=None, fname=None, fnamealt=None):
        self.log.setTextCursor(self.cursor) # move cursor to bottom
        if not msgs:
            try: 
                if self.mode == 'initiator':    
                    self.string = self.user_input.toPlainText() + '\n'
                    self.cl_socket.sendall(
                        bytearray((record[0] + ': ' + self.string)
                                  .encode('utf-8'))) # alias prefix
                    self.log.insertPlainText('you: ' + self.string) # log
                elif self.mode == 'acceptor':
                    self.string = self.user_input.toPlainText() + '\n'
                    self.conn.sendall(
                        bytearray((record[0] + ': ' + self.string)
                                  .encode('utf-8')))
                    self.log.insertPlainText('you: ' + self.string)
            except Exception:
                print(sys.exc_info())
            self.user_input.clear() # clear the input text box
        elif msgs == 'ft_initiate': # cheat - all FT sigs controlled by client
            if fnamealt != None:
                self.string = ('\n*** receiving file [' + fname + '] as ' +
                               fnamealt + ' ***\n')
            else:
                self.string = '\n*** receiving file [' + fname + '] ***\n'
            try:    
                if self.mode == 'initiator':
                    self.cl_socket.sendall(
                        bytearray((self.string).encode('utf-8')))
                elif self.mode == 'acceptor': # to refactor
                    self.conn.sendall(
                        bytearray((self.string).encode('utf-8')))
            except Exception:
                print(sys.exc_info()) 
        elif msgs == 'ft_complete':
            try:
                if self.mode == 'initiator':
                    self.cl_socket.sendall(
                        b'\n*** file successfully received ***\n')
                elif self.mode == 'acceptor':
                    self.conn.sendall(
                        b'\n*** file successfully received ***\n')
            except Exception:
                 print(sys.exc_info())
        
    def receive_text(self, datapipe): # refactor?
        self.datapipe = datapipe # holds ClientThreadRecv i.e. self.conn.recv()
        self.log.setTextCursor(self.cursor)
        if self.mode == 'initiator' and datapipe != b'<<b>>':
            self.log.insertPlainText(str(self.datapipe, 'utf-8'))
        elif self.mode == 'acceptor' and datapipe != b'<<b>>':
            self.log.insertPlainText(str(self.datapipe, 'utf-8'))
        elif datapipe == b'<<b>>':
            pass
        
        try: # flash window - require win32gui mod
            self.flash_window()
        except NameError:   # incase win32gui is not imported
            print(sys.exc_info())

        if SW.btf_toggle_state == True: # bring to front
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
                self.transf_obj = FtpClient(self.ip, folder_file_path,
                                            file_name, file_ext_len) 
            elif self.mode == 'acceptor': 
                self.transf_obj = FtpClient(self.addr[0], folder_file_path,
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
        if self.mode == 'initiator':
            self.cl_socket.sendall(b'<<b>>')
        elif self.mode == 'acceptor':
            self.conn.sendall(b'<<b>>')

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
            
    def connect_to_svr(self): # important: initiator mode, sock obj
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return self.client

    def msgs_n_errors(self, msgtype, fobj=None, fobjalt=None):
        try:
            if msgtype == 'sent_file':
                self.log.insertPlainText('\n*** file successfully sent ***\n')
                self.send_text(msgs='ft_complete')
                self.multiple_fit[fobj][1] = False
                self.f_in_transit = False    
            else: 
                if msgtype == 'closed_gracefully':
                    self.log.insertPlainText(
                        '\n*** Session was closed by remote user. Close this '
                        'session window and relaunch once the remote user '
                        'status shows \'online\' again. ***\n')
                    self.fit_mechanism()
                    self.lockout_cw()
                elif msgtype == 'big_off_button': # interrupt
                    self.log.insertPlainText(
                        '\n*** You have currently gone \'offline\', please '
                        'close all open session windows, go back \'online\' '
                        'and restart sessions or wait for others to initiate '
                        'session. ***\n')
                    self.fit_mechanism()
                    self.lockout_cw()
                elif msgtype == 'sending_file':
                    if fobjalt != None:
                        self.log.insertPlainText(
                            '\n*** sending file [%s] as [%s] ***\n'
                            % (fobj, fobjalt))
                    else:
                        self.log.insertPlainText(
                            '\n*** sending file [%s] ***\n' % fobj)
                    self.send_text(
                        msgs='ft_initiate', fname=fobj, fnamealt=fobjalt)
                elif msgtype == 'ft_cancelled':
                    self.log.insertPlainText(
                        '\n*** file transfer failed ***\n')
                    self.fit_mechanism() # required?
                elif msgtype == 'ft_refused':
                    self.log.insertPlainText(
                        '\n*** remote user appears to be offline ***\n')
        except AttributeError: # caters for non-existent self.f_in_transit
            print(sys.exc_info())
            pass 

    def fit_mechanism(self, mode=None):
        if mode == 'update_f_in_transit_flag':
            try:
                for i in self.multiple_fit:
                    if self.multiple_fit[i][1] == True:
                        self.f_in_transit = True
            except Exception:
                print(sys.exc_info())
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
        self.user_input.setReadOnly(True)

    def interrupt(self): # called by MW when going 'offline'
        try:
            if self.mode == 'initiator': 
                self.client.close()
            elif self.mode == 'acceptor':
                self.conn.close()
        except Exception:
            print(sys.exc_info())

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
            'Disable publishing of status, '
            'use manual IP add to '
            'connect to other users')
        
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
        if (len(self.alias.displayText()) == 0 or
            len(self.first.displayText()) == 0 or
            len(self.last.displayText()) == 0):
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

    def alternate_state(self): # ensures change state only if state changes
        if self.mode_of_operation != bool(self.operation_mode.checkState()):
            self.mode_of_operation = bool(self.operation_mode.checkState())
            AW.alternate_ui(bool(self.operation_mode.checkState()))
        else:
            pass


#=============================================================================#

# USER DETAILS - to become MainWindow obj attributes
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
            'First and Last name fields in the settings menu.')
    elif flag == 'blank':
        msg.setText('You need to ensure all fields are filled in.')
    elif flag == 'ip_err':
        msg.setText('You need to enter an IP address in the proper format '
                    'e.g. 192.168.0.2')
    elif flag == 'ip_err2':
        msg.setText('IP address entered is out of range.')
    msg.exec()

#=============================================================================#

# NETWORK: TRANSCEIVER
# receives broadcasts from remote host beacon service, collects data in dict 
def transceiver():
    global known_clients_DB
    trans = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
    trans.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    trans.bind(('', transceiver_port))
    
    while status == True: # sentinel
        msg = trans.recvfrom(1024)
        if msg[1][0] == socket.gethostbyname(socket.gethostname()): 
            continue # ignore local broadcasts - requires dirty trick below
        if msg[0].decode('utf-8').split(',')[0] == 'hola': # msg from pinger
            host = msg[0].decode('utf-8').split(',')[1]
            if host in known_clients_DB: 
                known_clients_DB[host][5] = 4 # 4 sec ttl
            else:
                pinger(ip=host, mode='on_demand') # keep alive
        else: # a beacon alert (occurs less often)
            alias, first, last, host = msg[0].decode('utf-8').split(',')
            ip = msg[1][0]
            if host not in known_clients_DB: # first time bcast? 
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

def beacon():   # needs to run as a daemon / service
    global beacon_interval
    beacon_interval = 60
    
    broadcast = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while status == True: # sentinel - nested loop creates 'immediate' end
        broadcast.sendto(
            bytearray(create_message('record').encode('utf-8')),
            ('255.255.255.255', transceiver_port))
        while status == True:
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
            (ip, transceiver_port))  
    elif mode == 'reactive_beacon': # back to broadcaster
        sock.sendto(
            bytearray(create_message('record').encode('utf-8')),
            (ip, transceiver_port))
    else: 
        while status == True:
            try: 
                if len(known_clients_DB) > 0: # sentinel
                    for host in known_clients_DB:
                        sock.sendto(
                            bytearray(create_message('hola').encode('utf-8')),
                            (host, transceiver_port)) # calling card
                else:
                    pass
                time.sleep(1) # every 2 sec send Q
                if status == False:
                    break
                else:
                    time.sleep(1) # trick to ensure quick thread stop
            except RuntimeError:    # caters for dictionary size change quirk
                print('caught a furball *** ', sys.exc_info())
        # dirty trick ends Transceiver daemon.
        # Self pinger sends to own transceiver
        # to initiate first clause and thus end loop.
        sock.sendto(
            bytearray(create_message('hola').encode('utf-8')),
            (socket.gethostname(), transceiver_port)) 
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
            perm='elradfmwM') 

        self.dtp_handler = ThrottledDTPHandler
        self.dtp_handler.read_limit = 30720  # 30kb/sec (30 * 1024)
        self.dtp_handler.read_limit = 30720
        self.dtp_handler.write_limit = 30720
        
        self.handler = FtpSvrHandler
        self.handler.authorizer = self.authorizer
        self.server = ThreadedFTPServer(('', ftp_cloak_port), self.handler)
        self.server.serve_forever() 

    def stop(self):
        try:
            self.server.close_all()
        except Exception:
            print('ftpsvr stopped', sys.exc_info())

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
                        'STOR ' + self.filename, rest=None)
                    self.emit(QtCore.SIGNAL('stageA_from_ftransfer'),
                              'sending_file', self.filename)
                except UnicodeEncodeError:
                    funky = (record[0] + '_' + str(random.randrange(1,100)) +
                             self.filename[-(self.fel)::])
                    self.connection = self.sess.transfercmd(
                        'STOR ' + funky, rest=None)
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
        except ConnectionRefusedError:
            self.emit(QtCore.SIGNAL('ftp_login_error'), 'ft_refused')
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
def db_cleanup(): 
    global known_clients_DB
    expired = []
    
    while status == True:
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
                print(sys.exc_info())
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
    AW = MainWindow()

    sys.exit(Application.exec_()) # to do - ensure all threads stop properly

