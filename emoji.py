'''
Samsung emojis:
Artwork and copyright belong to their respective font creators.
http://emojipedia.org/samsung/
'''

from PyQt4 import QtGui, QtCore
import sys

emoji_dictionary = {':emo1:': '/images/emoji/bigsmile.png',
                    ':emo2:': '/images/emoji/wideeyedsmile.png',
                    ':emo3:': '/images/emoji/overjoyed.png',
                    ':emo4:': '/images/emoji/thinking.png',
                    ':emo5:': '/images/emoji/nerdluck.png',
                    ':emo6:': '/images/emoji/moarnerdluck.png',
                    ':emo7:': '/images/emoji/stoopidface.png',}

class SelectEmoji(QtGui.QWidget):
    def __init__(self):
        QtGui.QWidget.__init__(self)
        self.initUI()
        
    def init(self):
        self.pick_n_choose = QtGui.QTextEdit()
        pass
            
        

if __name__ == '__main__':
    w = QtGui.QApplication(sys.argv)
    z = QtGui.QPixmap(r'c:\temp\stoopid2.jpg')
    zz = z.scaled(40, 0, QtCore.Qt.KeepAspectRatio).toImage()
    a = QtGui.QTextEdit()
    a.textCursor().insertImage(zz)
    a.show()

# emoji
