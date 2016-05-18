__author__ = 'spydir'

import geoip2.database
import re
import hashlib
import os
import urllib, urllib2
import gzip

#gi = pygeoip.GeoIP('GeoIP.dat')

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def untar(fname):
    try:
        inF = gzip.GzipFile(fname,'rb')
        s = inF.read()
        inF.close()

        outF = file("GeoLite2-Country.mmdb",'wb')
        outF.write(s)
        outF.close()
    except:
        print "Error Extracting File"

def downloadDB():
        fname = 'GeoLite2-Country.mmdb.gz'
        downloadUrl = 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz'
        dlFile = urllib.URLopener()
        dlFile.retrieve(downloadUrl,fname)
        untar(fname)

def checkUpdate():
    fname = 'GeoLite2-Country.mmdb'
    if not os.path.isfile(fname):
        print "Database Not Found, Downloading"
        downloadDB()

    if os.path.isfile(fname):
        print "Checking for Updates"
        currentDB = md5(fname)
        response = urllib2.urlopen('http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.md5')
        latestDB = response.read()

        if currentDB != latestDB:
            print "Update Needed, Downloading:"
            downloadDB()
        elif currentDB == latestDB:
            print "Database Is Up To Date"

def geoLocateIpsFromFile(fname):
    checkUpdate()
    db = 'GeoLite2-Country.mmdb'
    reader = geoip2.database.Reader(db)

    with open(fname,'rb') as fin:
        read_data = fin.read()
        ip_candidates = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", read_data)
        ip_candidates.sort()
        for i in ip_candidates:
            response = reader.country(i)
            print i,',',response.country.name

if __name__ == '__main__':
    geoLocateIPS('test_ips.txt')