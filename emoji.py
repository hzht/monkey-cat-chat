'''
Samsung emojis:
Artwork and copyright belong to their respective font creators.
http://emojipedia.org/samsung/
'''

from PyQt4 import QtGui, QtCore
from collections import OrderedDict
import sys

emoji_dictionary = {':emo1:': 'images/emoji/bigsmile.png',
                    ':emo2:': 'images/emoji/wideeyedsmile.png',
                    ':emo3:': 'images/emoji/overjoyed.png',
                    ':emo4:': 'images/emoji/thinking.png',
                    ':emo5:': 'images/emoji/nerdluck.png',
                    ':emo6:': 'images/emoji/moarnerdluck.png',
                    ':emo7:': 'images/emoji/stoopidface.png',
                    }

class SelectEmoji():
    def __init__(self):
        self.pick_n_choose = QtGui.QTextBrowser()
        self.initUI()
        
    def initUI(self):
        for i in emoji_dictionary:
            slot = QtGui.QPixmap(emoji_dictionary[i])
            resized = slot.scaled(24, 24, QtCore.Qt.KeepAspectRatio).toImage()
            self.pick_n_choose.textCursor().insertImage(resized)
        self.show()

    def show(self):
        self.pick_n_choose.show()
        
xxx = QtGui.QApplication(sys.argv) # remove after testing
