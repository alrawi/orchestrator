#TODO 
#use config file to customize controller
#use timers for metric capture

import logging
import logging.handlers
import hashlib
import ssdeep
import magic
import exiftool
import zlib
import Queue
import time
import datetime
import os
import threading
import signal
from pymongo import MongoClient
from pymongo.errors import PyMongoError, ConnectionFailure
from bson.binary import Binary
from inc.map_common import MapCommon

class Feeder(MapCommon):

    def __init__(self):
        self.state = 0
        super(Feeder, self)

        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        hdlr = logging.handlers.RotatingFileHandler(self.logpath+"feeder.log", maxBytes=maxLogSize, backupCount=1)
        hdlr.setLevel(logging.INFO)
        frmtr = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        hdlr.setFormatter(frmtr)
        self.logger.addHandler(hdlr)

        #DB init connection, try except connection not avail
        try:
            self.db_client=MongoClient(self.db)
            self.db_analysis=self.db_client.analysis
            self.db_bins=self.db_client.bins
        except ConnectionFailure as e:
            self.logger.error("ConnectionFailure", exc_info=True)
            raise e

        #Start ExifTool
        self.et=exiftool.ExifTool()
        self.et.start()

        #Queue init
        self.filesqueue=Queue.Queue()

    # Get file properties
    def getFileProperties(self, filename,fc):
        self.logger.info("Getting file ID")
        fp={'filename':filename}
        try:
            #File size
            fp['size']=len(fc)
            #MD5
            m=hashlib.md5()
            m.update(fc)
            fp['md5']=m.hexdigest()
            #SHA1
            m=hashlib.sha1()
            m.update(fc)
            fp['sha1']=m.hexdigest()
            #SHA256
            m=hashlib.sha256()
            m.update(fc)
            fp['sha256']=m.hexdigest()
            #SSDEEP
            fp['ssdeep']=ssdeep.hash(fc)
            #Magic
            fp['magic']=magic.from_buffer(fc)
            #Exiftool
            #NOTE: exiftool shits itself on certian formats, wipe it's ass someday
            fp['filetype']=self.et.get_tag('FileType',self.incoming+filename)
            #Tag
            if fp['magic'] is not '':
                fp['tags']=[fp['magic'].split()[0].lower()]
            else:
                fp['tags']=[]

        except IOError as e:
            self.logger.error("IO Error", exc_info=True)

        return {'_id':fp['sha1'],'id':fp}

    #create a record
    def createRecord(self, filename):
        dba=self.db_analysis
        dbb=self.db_bins
        try:
            fd=open(self.incoming+filename,'rb')
            fc=fd.read()
            fd.close()

            fp=self.getFileProperties(filename, fc)
            dba.malware.insert(fp)
            dbb.bins.insert({'_id':fp['id']['sha1'],'data':Binary(zlib.compress(fc))})
        except IOError as e:
            self.logger.error("IO Error", exc_info=True)
        except PyMongoError as e:
            self.logger.error("PyMongoError", exc_info=True)
        
    #Read files from incoming folder
    def queueFiles(self):
        while self.state:
            for f in os.listdir(self.incoming):
                self.filesqueue.put(f,block=True)

            self.logger.info("Directory empty, taking a 10 sec nap")
            time.sleep(10)

    def processQueue(self):
        while self.state:
            try:
                filename=self.filesqueue.get(False) 
                self.createRecord(filename)
                #TODO: Need to safely remove files, if failed to process
                os.remove(self.incoming+filename)
            except Queue.Empty:
                self.logger.info("File Queue is empty, sleeping.")
                time.sleep(15)

    def getThePartyStarted(self, nthreads=1):
        #Create thread for queuing
        q_thread=threading.Thread(target=self.queueFiles)
        q_thread.daemon=False

        #Create n threads for processing
        w_threads=[]
        for t in range(0,nthreads):
            tmp_t=threading.Thread(target=self.processQueue)
            tmp_t.daemon=False
            w_threads.append(tmp_t)

        #Set state on
        self.state=1
        #start threads
        q_thread.start()
        for t in w_threads:
            t.start()

        signal.signal(signal.SIGINT, self.shutItDown)
        self.logger.info("Started... :-)")
        signal.pause()   
        self.logger.info("Adios!")

    #Signal threads to stop
    def shutItDown(self, signal, frame):
        #Unset state
        self.state=0
        #Close db connection
        self.db_client.close()
        #Shutdown Exiftool facility
        self.et.terminate()
        #Shutdown logging facility
        logging.shutdown()
        self.logger.info("Exiting... (waiting on threads)")
        time.sleep(5)


