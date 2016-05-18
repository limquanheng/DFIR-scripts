#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys 
import os 
import zipfile
import datetime


def create_doc(template_file, out_file, replaceText):
    templateDocx = zipfile.ZipFile(template_file)
    outdir = '/'.join(out_file.split('/')[:-1])
    if not os.path.exists(outdir):
        os.makedirs(outdir)
    newDocx = zipfile.ZipFile(out_file, "w")
    for file in templateDocx.filelist:
        content = templateDocx.read(file)
        for key in replaceText.keys():
            content = content.replace(str(key), str(replaceText[key]))
        newDocx.writestr(file.filename, content)
    templateDocx.close()
    newDocx.close()
    
basepath_in = 'c:/tools/github/dfir-scripts/reporter/'
basepath_out = 'c:/tools/github/dfir-scripts/reporter/output/'

for template_file in os.listdir(basepath_in):
  if template_file.endswith('.docx'):
    replaceText = {
                    "Document Control and Distribution" : 'Document Control',
                    "{{PID}}" : 'P12345',
                    "{{PROJECT_TITLE}}" : 'Go to Mars',
                    "{{PROJECT_AREA}}" : 'Long shots',
                    "{{PROJECT_DESCRIPTION}}":"Take a ship and go.",
                    "{{DATE}}" : datetime.datetime.today().strftime("%d/%m/%Y"),
                    "{{STATUS}}":"FINAL"
                    }
    out_file = basepath_out+template_file
    for key in replaceText.keys():
        out_file = out_file.replace(str(key), str(replaceText[key]))
    create_doc(template_file, out_file,replaceText)