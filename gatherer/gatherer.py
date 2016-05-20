#!/usr/bin/python
# Sample program or step 11 in becoming a DFIR Wizard!
# No license as this code is simple and free!
import sys
import argparse

from collectors import *

argparser = argparse.ArgumentParser(description='Hash files recursively from all NTFS parititions in a live system and optionally extract them')


argparser.add_argument(
        '-i', '--input',
        dest='input',
        action="store",
        type=str,
        default=None,
        required=False,
        help='Working Evidence Folder'
    )

argparser.add_argument(
        '-o', '--output',
        dest='output',
        action="store",
        type=str,
        default='.',
        required=False,
        help='Folder to Store Results'
    )

args = argparser.parse_args()

if __name__ == "__main__":


    #fastIR_systems(args.input,args.output)
    fastIR_EVT_Logins(args.input,args.output)
    #fastIR_MFT_Timeline(args.input,args.output)
    #fileExtract(args.input,args.output)
    #fileHashing(args.input,args.output,".dll$|.exe$|.js$")
    #parseEVTX(args.input,args.output)
    parseEVTX2(args.input,args.output)


