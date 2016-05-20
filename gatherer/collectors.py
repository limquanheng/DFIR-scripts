__author__ = 'spydir'

import pytsk3
import datetime
import hashlib
import csv
import pyewf
import os
import re
import sys
from subprocess import Popen,PIPE
from artifacts import files,directories

class ewf_Img_Info(pytsk3.Img_Info):
  def __init__(self, ewf_handle):
    self._ewf_handle = ewf_handle
    super(ewf_Img_Info, self).__init__(
        url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

  def close(self):
    self._ewf_handle.close()

  def read(self, offset, size):
    self._ewf_handle.seek(offset)
    return self._ewf_handle.read(size)

  def get_size(self):
    return self._ewf_handle.get_media_size()

def directoryRecurse(directoryObject,parentPath,search,extract,timeline):
  for entryObject in directoryObject:
      if entryObject.info.name.name in [".", ".."]:
        continue
      #print entryObject.info.name.name
      try:
        f_type = entryObject.info.name.type
        size = entryObject.info.meta.size
      except Exception as error:
          #print "Cannot retrieve type or size of",entryObject.info.name.name
          #print error.message
          continue

      try:

        filepath = '/%s/%s' % ('/'.join(parentPath),entryObject.info.name.name)
        outputPath ='./%s/' % ('/'.join(parentPath))

        if f_type == pytsk3.TSK_FS_NAME_TYPE_DIR:
            sub_directory = entryObject.as_directory()
            print "Entering Directory: %s" % filepath
            parentPath.append(entryObject.info.name.name)
            directoryRecurse(sub_directory,parentPath,search,False,True)
            parentPath.pop(-1)
            print "Leaving Directory: %s" % filepath


        elif f_type == pytsk3.TSK_FS_NAME_TYPE_REG and entryObject.info.meta.size != 0:
            searchResult = re.match(search,entryObject.info.name.name)
            if not searchResult:
              continue
            #print "File:",parentPath,entryObject.info.name.name,entryObject.info.meta.size
            BUFF_SIZE = 1024 * 1024
            offset=0
            md5hash = hashlib.md5()
            sha1hash = hashlib.sha1()
            # if extract == True:
            #     if not os.path.exists(outputPath):
            #         os.makedirs(outputPath)
            #         extractFile = open(outputPath+entryObject.info.name.name,'w')
            while offset < entryObject.info.meta.size:
                available_to_read = min(BUFF_SIZE, entryObject.info.meta.size - offset)
                filedata = entryObject.read_random(offset,available_to_read)
                md5hash.update(filedata)
                sha1hash.update(filedata)
                offset += len(filedata)

            #     if args.extract == True:
            #         extractFile.write(filedata)
            #         extractFile.close()

            #if timeline == True:
            wr.writerow(['/'.join(parentPath)+entryObject.info.name.name,datetime.datetime.fromtimestamp(entryObject.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S'),datetime.datetime.fromtimestamp(entryObject.info.meta.mtime).strftime('%Y-%m-%d %H:%M:%S'),datetime.datetime.fromtimestamp(entryObject.info.meta.atime).strftime('%Y-%m-%d %H:%M:%S'),int(entryObject.info.meta.size),md5hash.hexdigest(),sha1hash.hexdigest()])
        elif f_type == pytsk3.TSK_FS_NAME_TYPE_REG and entryObject.info.meta.size == 0:
            #if timeline == True:
            wr.writerow(['/'.join(parentPath)+entryObject.info.name.name,datetime.datetime.fromtimestamp(entryObject.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S'),datetime.datetime.fromtimestamp(entryObject.info.meta.mtime).strftime('%Y-%m-%d %H:%M:%S'),datetime.datetime.fromtimestamp(entryObject.info.meta.atime).strftime('%Y-%m-%d %H:%M:%S'),int(entryObject.info.meta.size),"d41d8cd98f00b204e9800998ecf8427e","da39a3ee5e6b4b0d3255bfef95601890afd80709"])

        else:
          print "This went wrong",entryObject.info.name.name,f_type

      except IOError as e:
        #print e
        continue

def hashing(iFile,oDir,systemName,search):
    dirPath="/"
    oDir = os.path.join(oDir,systemName)
    if not os.path.exists(oDir): os.makedirs(oDir)
    outfile = open(os.path.join(oDir,"hashes.txt"),'w')
    outfile.write('"Full Path","Creation Time","Modified Time","Accessed Time","Size","MD5 Hash","SHA1 Hash"')
    global wr
    wr = csv.writer(outfile, quoting=csv.QUOTE_ALL)

    if iFile.lower().endswith(".e01") or iFile.lower().endswith("vmdk"):
        filenames = pyewf.glob(iFile)
        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames)
        imagehandle = ewf_Img_Info(ewf_handle)
        partitionTable = pytsk3.Volume_Info(imagehandle)

    else:
        imagehandle = pytsk3.Img_Info(iFile)
        partitionTable = pytsk3.Volume_Info(imagehandle)

    for partition in partitionTable:
      print partition.addr, partition.desc, "%ss(%s)" % (partition.start, partition.start * 512), partition.len
      if 'Basic data partition' in partition.desc or 'NTFS' in partition.desc:
        filesystemObject = pytsk3.FS_Info(imagehandle, offset=(partition.start*512))
        directoryObject = filesystemObject.open_dir(path=dirPath)
        print "Directory:",dirPath
        print search
        directoryRecurse(directoryObject,[],search,False,True)

def collectFromDisk(iFile,oDir,systemName):
    if not os.path.exists(oDir): os.makedirs(oDir)
    if iFile.lower().endswith(".e01"):
        filenames = pyewf.glob(iFile)
        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames)
        imagehandle = ewf_Img_Info(ewf_handle)

        partitionTable = pytsk3.Volume_Info(imagehandle)

    else:
        imagehandle = pytsk3.Img_Info(iFile)
        partitionTable = pytsk3.Volume_Info(imagehandle)


    for partition in partitionTable:
      #print partition.addr, partition.desc, "%ss(%s)" % (partition.start, partition.start * 512), partition.len

      if 'Basic data partition' in partition.desc or 'NTFS' in partition.desc:
        try:

            for entry in files:

                path = entry["path"]
                print "Collecting ", path, " from", iFile
                try:

                    filesystemObject = pytsk3.FS_Info(imagehandle, offset=(partition.start*512))
                    fileobject = filesystemObject.open(path)

                    # I normally print the following items for debugging purposes.

                    '''
                    print path
                    print "File Inode:",fileobject.info.meta.addr
                    print "File Name:",fileobject.info.name.name
                    print "File Creation Time:",datetime.datetime.fromtimestamp(fileobject.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S')
                    '''

                    outdir = os.path.join(oDir,systemName,entry["name"])
                    if not os.path.exists(outdir): os.makedirs(outdir)
                    outFileName = os.path.join(outdir,str(partition.addr)+"_"+fileobject.info.name.name)

                    #This writes the evidence file to disk

                    outfile = open(outFileName, 'w')
                    filedata = fileobject.read_random(0,fileobject.info.meta.size)

                    outfile.write(filedata)
                    outfile.close()


                #here we have some terrible exception handling with no descriptions of what is going on.

                except:

                    pass

            for entry in directories:
                directory = entry["path"]
                print "Collecting ", directory ," from ", iFile

                try:
                    filesystemObject = pytsk3.FS_Info(imagehandle, offset=(partition.start*512))
                    directoryObject = filesystemObject.open_dir(directory)
                    for entryObject in directoryObject:
                        if entryObject.info.name.name in [".", ".."]:
                            continue

                        filepath =(directory+"/"+entryObject.info.name.name)
                        #print oDir
                        #print directory, entryObject.info.name.name
                        #print filepath

                        fileobject = filesystemObject.open(filepath)
                        #print "File Inode:",fileobject.info.meta.addr
                        #print "File Name:",fileobject.info.name.name
                        #print "File Creation Time:",datetime.datetime.fromtimestamp(fileobject.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S')
                        outdir = os.path.join(oDir,systemName,entry["name"])
                        if not os.path.exists(outdir): os.makedirs(outdir)
                        outFileName = os.path.join(outdir,str(partition.addr)+"_"+fileobject.info.name.name)

                        outfile = open(outFileName, 'w')
                        filedata = fileobject.read_random(0,fileobject.info.meta.size)
                        outfile.write(filedata)
                        outfile.close()

                except:
                    pass
        except:
            pass

def fastIR_systems(iDir,oDir):
    systems = []
    mostIps = 0
    if not os.path.exists(oDir): os.makedirs(oDir)
    for root, dirs, files in os.walk(iDir, topdown=False):
        for name in files:
            if name.endswith("_registry_services.csv"):

                fname = os.path.join(root, name)
                print "Reading: ", fname
                csvfile= open(fname,'rU')
                reader = csv.reader(x.replace('\00','') for x in csvfile)
                linecount = 0

                computer = []
                for row in reader:
                    linecount +=1
                    try:
                        if "Parameters\\Tcpip" in row[4] and row[5] == "IPAddress":
                            computer.append(row[0])
                            computer.append(row[8])
                            if computer:
                               computer.sort()
                               last = computer[-1]
                               for i in range(len(computer)-2, -1, -1):
                                   if last == computer[i]:
                                       del computer[i]
                                   else:
                                       last = computer[i]
                            if len(computer) > mostIps:
                                print len(computer)
                                mostIps = len(computer)
                            systems.append(computer)

                    except IndexError:
                        pass

    if systems:
       systems.sort()
       last = systems[-1]
       for i in range(len(systems)-2, -1, -1):
           if last == systems[i]:
               del systems[i]
           else:
               last = systems[i]

    header = "COMPUTERNAME"
    for i in range(mostIps-1):
        header+=",IP Address"
    header += "\n"
    outfile = open(os.path.join(oDir,"systems.csv"),'w')
    outfile.write(header)
    for i in systems:
        row = i[0]
        for x in i :
            if i > 0:
                ip = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",x)
                try:
                    row += ","+ip[0]
                except IndexError:
                    pass
        row += "\n"
        outfile.write(row)

def fastIR_EVT_Logins(iDir,oDir):
    logons = []
    if not os.path.exists(oDir): os.makedirs(oDir)
    for root, dirs, files in os.walk(iDir, topdown=False):
        for name in files:
            if name.endswith("_evts.csv"):

                fname = os.path.join(root, name)
                print "Reading: ", fname
                csvfile= open(fname,'rU')
                reader = csv.reader(x.replace('\00','') for x in csvfile)
                linecount = 0

                for row in reader:
                    linecount +=1
                    try:
                        if row[5] == "528" or row[5] == "540" or row[5] == "552" or row[5] == "4624":
                            if row[11] == "2":
                                string =  str(row[7] + ",Interactive," + row[8]+ "," +row[9]+","+row[5]+","+row[11]+","+row[13]+","+row[21]+","+row[0] + ","  + fname+ "\n")
                                logons.append(string)

                            elif row[11] == "3":
                                string =  str(row[7] + ",Network," + row[8]+ "," +row[9]+","+row[5]+","+row[11]+","+row[13]+","+row[21]+","+row[0] + ","  + fname+ "\n")
                                logons.append(string)

                            elif row[11] == "10":
                                string =  str(row[7] + ",RDP," + row[8]+ "," +row[9]+","+row[5]+","+row[11]+","+row[13]+","+row[21]+","+row[0] + ","  + fname+ "\n")
                                logons.append(string)

                    except IndexError:
                        print "Parsing error on line", linecount, " of ", fname
                csvfile.close()

    outfile = open(os.path.join(oDir,"logons.csv"),'w')
    outfile.write("Date Time,Type,User,Domain,Event ID,Logon Type,Auth Protocol,Source,Destination,Log File\n")
    for i in logons:
        outfile.write(i)

def fastIR_MFT_Timeline(iDir,oDir):
    timeline = []
    if not os.path.exists(oDir): os.makedirs(oDir)
    for root, dirs, files in os.walk(iDir, topdown=False):
        for name in files:
                fnameregex = re.search('(?<=_)mft_..csv',name)
                if fnameregex != None:
                    fname = os.path.join(root, name)
                    print "Reading: ", fname
                    csvfile= open(fname,'rU')
                    linecount = 0

                    for line in csvfile:
                        linecount +=1
                        "".join(line.split("\n"))
                        if not "Corrupt" in line and not "NoFNRecord" in line and not "Filename #1" in line:
                            row = str(line).split("|")
                            try:
                                string =  str(row[7] + ","+ row[8]+ "," +row[9]+","+row[12]+","+row[13]+","+row[51]+","+ fname +"\n")
                                timeline.append(string)
                            except IndexError:
                                pass
                    csvfile.close()
    outfile = open(os.path.join(oDir,"timeline.csv"),'w')
    outfile.write("Filename #1,Std Info Creation date,Std Info Modification date,FN Info Creation date,FN Info Modification date,STF FN Shift,Evidence File\n")
    for i in timeline:
        outfile.write("".join(i.split('"')))

def fileExtract(iDir,oDir):
    if not os.path.exists(oDir): os.makedirs(oDir)
    for root, dirs, files in os.walk(iDir, topdown=False):
        for name in files:
            if name.lower().endswith(".e01") or name.lower().endswith(".vmdk"):
                fname = os.path.join(root, name)
                output = os.path.join(root,"FileExtractor")

                try:
                    collectFromDisk(fname,oDir,name)

                except IOError:
                    pass

                print "Extracting Files From: ", fname

def fileHashing(iDir,oDir,search):
    if not os.path.exists(oDir): os.makedirs(oDir)
    for root, dirs, files in os.walk(iDir, topdown=False):
        for name in files:

            if name.lower().endswith(".e01") or name.lower().endswith(".vmdk"):
                fname = os.path.join(root, name)

                try:

                    hashing(fname,oDir,name,search)

                except IOError as e:
                    print e


                #print "Extracting Files From: ", fname

def parseEVTX(iDir,oDir):
    events = ""
    if not os.path.exists(oDir): os.makedirs(oDir)
    for root, dirs, files in os.walk(iDir, topdown=False):
        for name in files:

            if name.lower() == "security.evtx" or name.lower().endswith("_security.evtx")or name.lower() == "secevent.evt" or name.lower().endswith("_secevent.evt"):
                fname = os.path.join(root, name)
                try:
                    print fname
                    process = Popen("psloglist -s -l " + fname, stdout=PIPE)
                    (output,err)=process.communicate()
                    exit_code = process.wait()

                    events += output


                except IOError as e:
                    print e

    outfile = open(os.path.join(oDir,"events.csv"),'w')
    outfile.write(events)
    outfile.close()

def parseEVTX2(iDir,oDir):
    infile = "events.csv"
    outfile = open('logons.csv','a')
    print "Reading: ", infile
    csvfile= open(infile,'rU')
    reader = csv.reader(x.replace('\00','') for x in csvfile)
    linecount = 0
    for row in reader:
        linecount +=1
        try:
            if row[6]=="4624" and row[8].split(" ")[15] == "10":
                entry = {
                "datetime":row[5]+",",
                "cleartype":"RDP,",
                "user":row[8].split(" ")[12]+",",
                "domain":row[8].split(" ")[13]+",",
                "eventID":row[6]+",",
                "logonType":row[8].split(" ")[15]+",",
                "authType":row[8].split(" ")[16]+",",
                "src" : row[8].split(" ")[26]+",",
                "dst" : row[4]+",",
                }
                output = entry['datetime']+\
                        entry['cleartype']+\
                         entry['user']+\
                         entry['domain']+\
                         entry['eventID']+\
                         entry['logonType']+\
                         entry['authType']+\
                         entry['src']+\
                         entry['dst']

                outfile.write(output+"\n")

            elif row[6]=="4624" and row[8].split(" ")[15] == "3":
                entry = {
                "datetime":row[5]+",",
                "cleartype":"Network,",
                "user":row[8].split(" ")[12]+",",
                "domain":row[8].split(" ")[13]+",",
                "eventID":row[6]+",",
                "logonType":row[8].split(" ")[15]+",",
                "authType":row[8].split(" ")[16]+",",
                "src" : row[8].split(" ")[26]+",",
                "dst" : row[4]+",",
                }
                output = entry['datetime']+\
                        entry['cleartype']+\
                         entry['user']+\
                         entry['domain']+\
                         entry['eventID']+\
                         entry['logonType']+\
                         entry['authType']+\
                         entry['src']+\
                         entry['dst']

                outfile.write(output+"\n")

            elif row[6]=="4624" and row[8].split(" ")[15] == "2":
                entry = {
                "datetime":row[5]+",",
                "cleartype":"Interactive,",
                "user":row[8].split(" ")[12]+",",
                "domain":row[8].split(" ")[13]+",",
                "eventID":row[6]+",",
                "logonType":row[8].split(" ")[15]+",",
                "authType":row[8].split(" ")[16]+",",
                "src" : row[8].split(" ")[26]+",",
                "dst" : row[4]+",",
                }
                output = entry['datetime']+\
                        entry['cleartype']+\
                         entry['user']+\
                         entry['domain']+\
                         entry['eventID']+\
                         entry['logonType']+\
                         entry['authType']+\
                         entry['src']+\
                         entry['dst']

                outfile.write(output+"\n")
        except IndexError as e:
           pass








