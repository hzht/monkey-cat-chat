'''
Samsung emojis:
Artwork and copyright belong to their respective font creators.
http://emojipedia.org/samsung/
'''

from PyQt4 import QtGui, QtCore

ed = {'<?>01<?>': 'images/emoji/bigsmile.png', # emoji dictionary
      '<?>02<?>': 'images/emoji/nerdluck.png',
      '<?>03<?>': 'images/emoji/overjoy.png',
      '<?>04<?>': 'images/emoji/stoopid.png',
      '<?>05<?>': 'images/emoji/thinking.png',
      '<?>06<?>': 'images/emoji/wideeyed.png',
      '<?>07<?>': 'images/emoji/cryjoy.png',
      '<?>08<?>': 'images/emoji/nomouth.png',
      '<?>09<?>': 'images/emoji/shocked.png',
      '<?>10<?>': 'images/emoji/yuck.png',
      '<?>11<?>': 'images/emoji/unamused.png',
      '<?>12<?>': 'images/emoji/zipped.png',
      '<?>13<?>': 'images/emoji/ohh.png',
      '<?>14<?>': 'images/emoji/noexpress.png',
      '<?>15<?>': 'images/emoji/natural.png',
      }

class SelectEmoji(QtGui.QTextBrowser): 
    def __init__(self): 
        QtGui.QTextBrowser.__init__(self)
        self.setWindowTitle('select an emoticon')
        self.setFixedSize(232,135)

        bs = '&nbsp;' * 3
        self.setHtml(
            '<a href="<?>01<?>"><img src=' + ed['<?>01<?>'] + '/></a>'+bs+
            '<a href="<?>02<?>"><img src=' + ed['<?>02<?>'] + '/></a>'+bs+
            '<a href="<?>03<?>"><img src=' + ed['<?>03<?>'] + '/></a>'+bs+
            '<a href="<?>04<?>"><img src=' + ed['<?>04<?>'] + '/></a>'+bs+
            '<a href="<?>05<?>"><img src=' + ed['<?>05<?>'] + '/></a>'
            '<a href="<?>06<?>"><img src=' + ed['<?>06<?>'] + '/></a>'+bs+
            '<a href="<?>07<?>"><img src=' + ed['<?>07<?>'] + '/></a>'+bs+
            '<a href="<?>08<?>"><img src=' + ed['<?>08<?>'] + '/></a>'+bs+
            '<a href="<?>09<?>"><img src=' + ed['<?>09<?>'] + '/></a>'+bs+
            '<a href="<?>10<?>"><img src=' + ed['<?>10<?>'] + '/></a>'
            '<a href="<?>11<?>"><img src=' + ed['<?>11<?>'] + '/></a>'+bs+
            '<a href="<?>12<?>"><img src=' + ed['<?>12<?>'] + '/></a>'+bs+
            '<a href="<?>13<?>"><img src=' + ed['<?>13<?>'] + '/></a>'+bs+
            '<a href="<?>14<?>"><img src=' + ed['<?>14<?>'] + '/></a>'+bs+
            '<a href="<?>15<?>"><img src=' + ed['<?>15<?>'] + '/></a>'
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
        

