'''
Samsung emojis:
Artwork and copyright belong to their respective font creators.
http://emojipedia.org/samsung/
'''

from PyQt4 import QtGui, QtCore
import sys

ed = {':emo1:': 'images/emoji/bigsmile.png', # emoji dictionary
      ':emo2:': 'images/emoji/nerdluck.png',
      ':emo3:': 'images/emoji/overjoy.png',
      ':emo4:': 'images/emoji/stoopid.png',
      ':emo5:': 'images/emoji/thinking.png',
      ':emo6:': 'images/emoji/wideeyed.png',
      ':emo7:': 'images/emoji/cryjoy.png',
      ':emo8:': 'images/emoji/nomouth.png',
      ':emo9:': 'images/emoji/shocked.png',
      ':emo10:': 'images/emoji/yuck.png',
      ':emo11:': 'images/emoji/unamused.png',
      ':emo12:': 'images/emoji/zipped.png',
      ':emo13:': 'images/emoji/ohh.png',
      ':emo14:': 'images/emoji/noexpress.png',
      ':emo15:': 'images/emoji/natural.png',
      }

class SelectEmoji(QtGui.QTextBrowser): 
    def __init__(self): 
        QtGui.QTextBrowser.__init__(self)
        self.setWindowTitle('select an emoticon')
        self.setFixedSize(232,135)

        bs = '''&nbsp;&nbsp;&nbsp;'''
        self.setHtml(
            '<a href="::emo1:"><img src=' + ed[':emo1:'] + '/></a>'+bs+
            '<a href="::emo2:"><img src=' + ed[':emo2:'] + '/></a>'+bs+
            '<a href="::emo3:"><img src=' + ed[':emo3:'] + '/></a>'+bs+
            '<a href="::emo4:"><img src=' + ed[':emo4:'] + '/></a>'+bs+
            '<a href="::emo5:"><img src=' + ed[':emo5:'] + '/></a>'
            '<a href="::emo6:"><img src=' + ed[':emo6:'] + '/></a>'+bs+
            '<a href="::emo7:"><img src=' + ed[':emo7:'] + '/></a>'+bs+
            '<a href="::emo8:"><img src=' + ed[':emo8:'] + '/></a>'+bs+
            '<a href="::emo9:"><img src=' + ed[':emo9:'] + '/></a>'+bs+
            '<a href="::emo10:"><img src=' + ed[':emo10:'] + '/></a>'
            '<a href="::emo11:"><img src=' + ed[':emo11:'] + '/></a>'+bs+
            '<a href="::emo12:"><img src=' + ed[':emo12:'] + '/></a>'+bs+
            '<a href="::emo13:"><img src=' + ed[':emo13:'] + '/></a>'+bs+
            '<a href="::emo14:"><img src=' + ed[':emo14:'] + '/></a>'+bs+
            '<a href="::emo15:"><img src=' + ed[':emo15:'] + '/></a>'
            )
        
        self.setFocusPolicy(QtCore.Qt.NoFocus) # hide dotted border on click
        self.setSource(QtCore.QUrl()) # ensures 'page' doesn't change
        self.anchorClicked.connect(self.select_individual_icon) # lock/load
        self.show()
        
    def select_individual_icon(self, link):
        self.setSource(QtCore.QUrl())
        icon = str(link.toString())
        print(type(icon))
        print(icon)
        if icon in ed:
            print('yayaya') # add item to send text box in main
    def closeEvent(self, event):
        print('properly closed!')

xxx = QtGui.QApplication(sys.argv) # remove after testing
