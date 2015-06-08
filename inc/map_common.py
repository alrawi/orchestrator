import ConfigParser
import sys

class MapCommon(object):
    
    def __init__(self):
        sys.path.append("/Users/qcri/Documents/Tools/malware_project/")
        self.loadConfig()
        return

    def loadConfig(self,path=''):
        #if no config given, load default
        if path=='':
            path='./config.cfg'

        config=ConfigParser.ConfigParser()
        config.read(path)
        #location and paths
        self.root=config.get('system', 'root')
        self.incpath=self.root+config.get('system', 'incpath')
        self.incoming=self.root+config.get('system', 'incoming')
        #log setting
        self.logpath=self.root+config.get('system', 'logpath')
        self.maxLogSize=int(config.get('system', 'maxLogSize'), 16)
        #DB settings
        self.db=config.get('system', 'db')

