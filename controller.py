import logging
import logging.handlers
import pika
from pika.exceptions import AMQPConnectionError
from pymongo import MongoClient
from inc.map_common import MapCommon

class Controller(MapCommon):

    def __init__(self):
        self.state = 0
        super(Controller, self)

        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        hdlr = logging.handlers.RotatingFileHandler(self.logpath+"/controller.log", maxBytes=self.maxLogSize, backupCount=1)
        hdlr.setLevel(logging.INFO)
        frmtr = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        hdlr.setFormatter(frmtr)
        self.logger.addHandler(hdlr)

        #DB init connection
        try:
            self.db_client=MongoClient(self.db)
            self.db_modules=self.db_client.modules
            self.db_analysis=self.db_client.analysis
        except ConnectionFailure as e:
            self.logger.error("ConnectionFailure", exc_info=True)
            raise e

    #Get a list of analysis modules
    def getModuleList(self):
        return list(self.db_modules.analyzers.find({},{'_id':0}))

    #Get a list of files for queuing
    #param, file type (ftype) list of file types, analyzer- string name of analyzer
    def getFileList(self, analyzer, ftypes=[]):
        db=self.db_analysis
        if "all" in ftypes:
            return list(db.malware.find({analyzer:{'$exists':False}}))
        else:
            return list(db.malware.find({'id.filetype':{ '$in':ftypes}, analyzer:{'$exists':False}}))

    #connect to Rabbitmq and queue files for analyzer
    #analyzer, string name of the analyzer to start queuing
    def queueFiles(self, analyzer):
        #get handle on the modules collection
        db=self.db_modules
        cur=db.analyzers.find({analyzer:{'$exists':True}})
        #does the analyzer exist?
        if cur.count()<1:
            self.logger.info("No Analyzer %s found"%(analyzer))
            return
        #assign analyzer
        anlyzr=list(cur)[0][analyzer]
        #get queue IPs
        quIPs=anlyzr['rmq']
        #get file types that can be analyzed by the analyzer
        ftypes=anlyzr['ftypes']
        #list of connections
        lcon=[]
        #for each queue IP create a channel for publishing
        for ip in quIPs:
            try:
                tmp_con=pika.BlockingConnection(pika.ConnectionParameters(host=ip))
                tmp_ch=tmp_con.channel()
                tmp_ch.queue_declare(queue=analyzer)
                lcon.append(tmp_ch)
            except AMQPConnectionError as e:
                #if queue ip is bad skip and move to the next one
                self.logger.error("AMQPConnectionError", exc_info=True)
                continue
        #are there any connections?
        if len(lcon)<1:
             self.logger.info("No queue found to queue files, terminating queue thread for %s"%(analyzer))
             return
        rr_c=0 # round robin counter to distribute work
        for f in self.getFileList(analyzer, ftypes):
            lcon[rr_c%len(lcon)].basic_publish(exchange='',routing_key=analyzer,body=f['_id'])
            rr_c+=1
        #return or sleep?


    
# fl=c.getFileList(ml[0]['pepy']['ftypes'],ml[0].keys()[0])
