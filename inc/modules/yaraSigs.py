import yara
import ConfigParser
import logging
import logging.handlers
import pika
from pika.exceptions import AMQPConnectionError
from pymongo import MongoClient
from inc.map_common import MapCommon

#=== abstract to config ===#
root="/Users/qcri/Documents/Tools/malware_project/"
incoming="/incoming"
incpath="/inc/"
logpath="/logs/"
maxLogSize=0x989680
db="mongodb://localhost:27017/"
queueName='yara'
qHost='localhost'
#=== abstract to config ===#

class YaraSigs(MapCommon):
    
    def __init__(self):
        super(YaraSigs, self)

        self.filePath=root+incoming+"/data/yara_rules/python.yara"
        self.rules=yara.compile(self.filepath)
        self.logPath = root+logpath
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        hdlr = logging.handlers.RotatingFileHandler(logPath+"yaraSigs.log", maxBytes=maxLogSize, backupCount=1)
        hdlr.setLevel(logging.INFO)
        frmtr = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        hdlr.setFormatter(frmtr)
        self.logger.addHandler(hdlr)

        #DB init connection, try except connection not avail
        try:
            self.db_client=MongoClient(db)
            self.db_bins=self.db_client.bins
        except ConnectionFailure as e:
            self.logger.error("ConnectionFailure", exc_info=True)
            raise e
        return

        #Connect to Queuing system NOTE: get queue ips from the db.
        # try:
        #     con=pika.BlockingConnection(pika.ConnectionParameters(host=qHost))
        #     chn=con.channel()
        #     chn.queue_declare(queue=queueName)
        #     self.qChn=chn
        # except AMQPConnectionError as e:
        #     self.logger.error("AMQPConnectionError", exc_info=True)
        #     raise e

    def updateNCompileRuleFile(self):
        self.rules=yara.compile(filepath=self.filepath)

    def saveCompiledRules(self):
        self.rules.save(self.filepath+'/rules_all.compiled')

    def loadCompiledRules(self):
        self.rules.load(self.filepath+'/rules_all.compiled')

    def match(self, data):
        match_list=[]
        matches=self.rules.match(data=data)
        for match in matches:
            tmp_dict={}
            tmp_dict['meta']=match.meta
            tmp_dict['rule']=match.rule
            tmp_dict['strings']=match.strings
            tmp_dict['tags']=match.tags
            match_list.append(tmp_dict)
        return match_list

    def processFile(self,filename):
        return

    def dequeueFiles(self):
        for mth_frame, properties, body in self.qChn.consume(queueName):
            print body, properties, mth_frame
