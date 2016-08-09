'''
Samsung emojis:
Artwork and copyright belong to their respective font creators.
http://emojipedia.org/samsung/
'''

from PyQt4 import QtGui, QtCore

ed = {':emo01:': 'images/emoji/bigsmile.png', # emoji dictionary
      ':emo02:': 'images/emoji/nerdluck.png',
      ':emo03:': 'images/emoji/overjoy.png',
      ':emo04:': 'images/emoji/stoopid.png',
      ':emo05:': 'images/emoji/thinking.png',
      ':emo06:': 'images/emoji/wideeyed.png',
      ':emo07:': 'images/emoji/cryjoy.png',
      ':emo08:': 'images/emoji/nomouth.png',
      ':emo09:': 'images/emoji/shocked.png',
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

        bs = '&nbsp;' * 3
        self.setHtml(
            '<a href="::emo01:"><img src=' + ed[':emo01:'] + '/></a>'+bs+
            '<a href="::emo02:"><img src=' + ed[':emo02:'] + '/></a>'+bs+
            '<a href="::emo03:"><img src=' + ed[':emo03:'] + '/></a>'+bs+
            '<a href="::emo04:"><img src=' + ed[':emo04:'] + '/></a>'+bs+
            '<a href="::emo05:"><img src=' + ed[':emo05:'] + '/></a>'
            '<a href="::emo06:"><img src=' + ed[':emo06:'] + '/></a>'+bs+
            '<a href="::emo07:"><img src=' + ed[':emo07:'] + '/></a>'+bs+
            '<a href="::emo08:"><img src=' + ed[':emo08:'] + '/></a>'+bs+
            '<a href="::emo09:"><img src=' + ed[':emo09:'] + '/></a>'+bs+
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
        
    def select_individual_icon(self, link): # link=PyQt4.QtCore.QUrl(':emo1:')
        self.setSource(QtCore.QUrl())
        icon = str(link.toString()) # icon = :emo1:
        self.emit(QtCore.SIGNAL('emoji_to_input'), icon)

    def show_it(self):
        self.show()
        self.activateWindow()
        

