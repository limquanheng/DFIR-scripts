__author__ = 'spydir'
'''
evt_parser is designed to parse windows evt and evtx files.
It's depending on microsoft logparser which means that you must
have it installed and be running this script from a windows system.
'''

from subprocess import call
import os
import csv
import json
import time


def evtParse2csv(directory):
    for file in os.listdir(directory):
        if file.endswith(".evtx"):
            evtfile = "'" + directory +"\\" +file + "'"
            csvfile = directory +"\\"+ "test"+"\\"+ file.replace(" ","_") + ".csv"
            command = 'logparser -i:evt -o:csv "select EventLog,RecordNumber,TimeGenerated,TimeWritten,EventID,EventType,EventTypeName,EventCategory,EventCategoryName,SourceName,ComputerName,SID,Message,Data from ' + evtfile +'"'+" > " +csvfile

            try:
                print command
                os.system(command)
            except:
                pass
        elif file.endswith(".evt"):
            evtfile = '"' + directory +"/" +file + '"'
            csvfile = '"' + directory +"/"+ "test"+"/"+ file + '.csv"'
            command = 'logparser -i:evt -o:csv "select EventLog,RecordNumber,TimeGenerated,TimeWritten,EventID,EventType,EventTypeName,EventCategory,EventCategoryName,SourceName,ComputerName,SID,Message,Data from ' + evtfile +'" > ' +csvfile
            try:
                print file
                os.system(command)
            except:
                pass

def evtParse2json(directory):
    for file in os.listdir(directory):
        if file.endswith(".csv"):
            jfile = file.split(".csv",1)[0]
            csvfile = open(file, 'r')
            jsonfile = open(jfile+'.json', 'w')

            fieldnames = ("EventLog","RecordNumber","TimeGenerated","TimeWritten","EventID","EventType","EventTypeName","EventCategory","EventCategoryName","SourceName","ComputerName","SID","Message","Data")
            reader = csv.DictReader( csvfile, fieldnames)
            for row in reader:
                json.dump(row, jsonfile)
                jsonfile.write('\n')

if __name__ == "__main__":
    evtParse2csv("c:\\users\\spydir\\desktop\\logs")
    evtParse2json("c:\\users\\spydir\\desktop\\logs")



