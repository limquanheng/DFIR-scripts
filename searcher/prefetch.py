#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#############################################################################
##                                                                         ##
## Copyright (C) 2014 Cassidian CyberSecurity SAS. All rights reserved.    ##
## This document is the property of Cassidian SyberSecurity SAS, it may    ##
## not be circulated without prior licence                                 ##
##                                                                         ##
##  Author: Jean-Michel Picod <jean-michel.picod@cassidian.com>            ##
##                                                                         ##
#############################################################################

import os
import struct
import sys
import datetime
from collections import defaultdict
import copy
import argparse


class Formatter(object):
    def __init__(self, outstream):
        super(Formatter, self).__init__()
        self.outstream = outstream

    def text(self, prefetches):
        """Writes a human readable format of the object"""
        for data in prefetches:
            rv = []
            rv.append(u"###### %s ######" % data['name'].decode('UTF-8', 'ignore'))
            rv.append(u"  magic    = %s" % data['magic'])
            rv.append(u"  version  = %s" % data['version'])
            rv.append(u"  OS       = %s" % data['versionString'])
            rv.append(u"  filesize = %d" % data['filesize'])
            rv.append(u"  crc      = %08X" % data['crc'])
            rv.append(u"  appName  = %s" % data['appname'])
            rv.append(u"  appPath  = %s" % (data['appPath'] if data['appPath'] is not None else "Unknown"))
            rv.append(u"  dwRun    = %d" % data['dwRun'])
            rv.append(u"  lastRun  = %s" % datetime.datetime.utcfromtimestamp(data['lastrun']).isoformat(" "))
            for t in data['prevRuns']:
                rv.append(u"  prevRun  = %s" % datetime.datetime.utcfromtimestamp(t).isoformat(" "))
            rv.append(u"  Fileset")
            for f in data['fileset']:
                rv.append(u"      %s" % f)
            rv.append(u"  Dirsets")
            for k, d in data['dirsets'].iteritems():
                rv.append(u"      volume     = %s" % d["volumepath"])
                rv.append(u"      volumeSN   = %04X-%04X" % (d["volSN"] >> 16, d["volSN"] & 0x0ffff))
                rv.append(u"      createTime = %s" %
                          datetime.datetime.utcfromtimestamp(d["volCreateTime"]).isoformat(" "))
                rv.append(u"      Entries")
                for dd in d["dirset"]:
                    rv.append(u"            %s" % dd)
                rv.append(u"")
            self.outstream.write(unicode(os.linesep).join(rv))

    def json(self, prefetches):
        import json

        out = []
        for data in prefetches:
            data['lastrun'] = datetime.datetime.utcfromtimestamp(data['lastrun']).isoformat(" ")
            data['prevRuns'] = [datetime.datetime.utcfromtimestamp(t).isoformat(" ") for t in data['prevRuns']]
            data['crc'] = "%08X" % data['crc']
            del data['sectionA']
            del data['sectionB']
            for d in data['dirsets'].keys():
                del data['dirsets'][d]["S1"]
                t = datetime.datetime.utcfromtimestamp(data['dirsets'][d]['volCreateTime']).isoformat(" ")
                data['dirsets'][d]['volCreateTime'] = t
            out.append(data)
        json.dump(out, self.outstream)

    def xml(self, prefetches):
        import xml.etree.ElementTree as ET

        pfroot = ET.Element('prefetches')
        for data in prefetches:
            data['lastrun'] = datetime.datetime.utcfromtimestamp(data['lastrun']).isoformat(" ")
            data['prevRuns'] = [datetime.datetime.utcfromtimestamp(t).isoformat(" ") for t in data['prevRuns']]
            del data['sectionA']
            del data['sectionB']
            for d in data['dirsets'].keys():
                del data['dirsets'][d]["S1"]
                t = datetime.datetime.utcfromtimestamp(data['dirsets'][d]['volCreateTime']).isoformat(" ")
                data['dirsets'][d]['volCreateTime'] = t
            root = ET.SubElement(pfroot, 'prefetch')
            ET.SubElement(root, 'name').text = data['name']
            ET.SubElement(root, 'magic').text = data['magic']
            ET.SubElement(root, 'version').text = str(data['version'])
            ET.SubElement(root, 'OS').text = data['versionString']
            ET.SubElement(root, 'filesize').text = str(data['filesize'])
            ET.SubElement(root, 'crc').text = "%08X" % data['crc']
            ET.SubElement(root, 'appName').text = data['appname']
            ET.SubElement(root, 'appPath').text = data['appPath'] if data['appPath'] is not None else "Unknown"
            ET.SubElement(root, 'dwRun').text = str(data['dwRun'])
            ET.SubElement(root, 'lastRun').text = data['lastrun']
            prevRuns = ET.SubElement(root, 'prevRuns')
            for t in data['prevRuns']:
                ET.SubElement(prevRuns, 'prevRun').text = t
            fileset = ET.SubElement(root, 'fileset')
            for f in data['fileset']:
                ET.SubElement(fileset, "fileEntry").text = f
            dirsets = ET.SubElement(root, 'dirsets')
            for k, d in data['dirsets'].iteritems():
                dirset = ET.SubElement(dirsets, 'dirset')
                ET.SubElement(dirset, 'volume').text = d["volumepath"]
                ET.SubElement(dirset, 'volumeSN').text = "%04X-%04X" % (d["volSN"] >> 16, d["volSN"] & 0x0ffff)
                ET.SubElement(dirset, 'createTime').text = d["volCreateTime"]
                entries = ET.SubElement(dirset, 'entries')
                for dd in d["dirset"]:
                    ET.SubElement(entries, 'directory').text = dd
        ET.ElementTree(pfroot).write(self.outstream)


def winTS2epoch(qword):
    """Helper to convert Windows 64-bits timestamp to Linux EPOCH format"""
    return (qword / 10000000) - 11644473600


class Eater(object):
    """This class is a helper for parsing binary structures."""

    def __init__(self, raw, offset=0, end=None, endianness="<"):
        self.raw = raw
        self.ofs = offset
        if end is None:
            end = len(raw)
        self.end = end
        self.endianness = endianness

    def prepare_fmt(self, fmt):
        """Internal use. Prepend endianness to the given format if it is not
        already specified.

        fmt is a format string for struct.unpack()

        Returns a tuple of the format string and the corresponding data size.

        """
        if fmt[0] not in ["<", ">", "!", "@"]:
            fmt = self.endianness + fmt
        return fmt, struct.calcsize(fmt)

    def read(self, fmt):
        """Parses data with the given format string without taking away bytes.

        Returns an array of elements or just one element depending on fmt.

        """
        fmt, sz = self.prepare_fmt(fmt)
        v = struct.unpack_from(fmt, self.raw, self.ofs)
        if len(v) == 1:
            v = v[0]
        return v

    def eat(self, fmt):
        """Parses data with the given format string.

        Returns an array of elements or just one element depending on fmt.

        """
        fmt, sz = self.prepare_fmt(fmt)
        v = struct.unpack_from(fmt, self.raw, self.ofs)
        if len(v) == 1:
            v = v[0]
        self.ofs += sz
        return v

    def eat_string(self, length):
        """Eats and returns a string of length characters"""
        return self.eat("%us" % length)

    def eat_length_and_string(self, fmt):
        """Eats and returns a string which length is obtained after eating
        an integer represented by fmt

        """
        l = self.eat(fmt)
        return self.eat_string(l)

    def pop(self, fmt):
        """Eats a structure represented by fmt from the end of raw data"""
        fmt, sz = self.prepare_fmt(fmt)
        self.end -= sz
        v = struct.unpack_from(fmt, self.raw, self.end)
        if len(v) == 1:
            v = v[0]
        return v

    def pop_string(self, length):
        """Pops and returns a string of length characters"""
        return self.pop("%us" % length)

    def pop_length_and_string(self, fmt):
        """Pops and returns a string which length is obtained after poping an
        integer represented by fmt.

        """
        l = self.pop(fmt)
        return self.pop_string(l)

    def remain(self):
        """Returns all the bytes that have not been eated nor poped yet."""
        return self.raw[self.ofs:]

    def eat_sub(self, length):
        """Eats a sub-structure that is contained in the next length bytes"""
        sub = self.__class__(self.raw[self.ofs:self.ofs + length],
                             endianness=self.endianness)
        self.ofs += length
        return sub

    def __nonzero__(self):
        return self.ofs < self.end


class Prefetch(object):
    """
    Factory class that builds prefetch parser
    """
    _subclasses = {}
    _versions = defaultdict(lambda: "Unsupported")
    magic = "SCCA"

    @classmethod
    def register_subclass(cls, subclass):
        if issubclass(subclass, cls):
            cls._subclasses[subclass.version] = subclass
        cls._versions[subclass.version] = subclass.description

    @classmethod
    def build(cls, data):
        v, magic = struct.unpack_from("<L4s", data)
        if magic != cls.magic:
            raise ValueError("Invalid magic. This might not be a prefetch file")
        if v not in cls._subclasses:
            raise ValueError("Unsupported version of prefetch file: 0x%08x" % v)
        return cls._subclasses[v](data)

    def todict(self):
        """returns a Python dict that represents the object"""
        rv = {'magic': self.magic, 'version': self.version, 'filesize': self.filesize, 'crc': self.crc,
              'appname': self.appname, 'appPath': self.apppath, 'dwRun': self.dwRun, 'lastrun': self.lastrun,
              'prevRuns': copy.copy(self.prevRuns), 'fileset': copy.copy(self.fileset),
              'dirsets': copy.copy(self._entriesD), 'sectionA': copy.copy(self._entriesA),
              'sectionB': copy.copy(self._entriesB), 'versionString': self.version_string()}
        return rv

    def parse(self, data):
        self._entriesA = []
        self._entriesB = []
        self.fileset = []
        self._entriesD = {}
        self.apppath = None
        self.lastrun = 0
        self.dwRun = 0
        self.prevRuns = []

        header = Eater(data.remain(), endianness="<")
        (self._rawVersion, _, _, self.filesize) = header.eat("L4s2L")
        self.appname = header.eat_string(60)
        x = self.appname.find("\x00\x00")
        x += x & 1
        self.appname = self.appname[:x].decode('UTF-16LE')
        (self.crc, _) = header.eat("2L")
        (self.offSectA, self.nbSectA) = header.eat("2L")
        (self.offSectB, self.nbSectB) = header.eat("2L")
        (self.offSectC, self.lenSectC) = header.eat("2L")
        (self.offSectD, self.nbSectD, self.lenSectD) = header.eat("3L")

        self.parseSectionA(Eater(data.remain()[self.offSectA:], endianness="<"))
        self.parseSectionB(Eater(data.remain()[self.offSectB:], endianness="<"))
        self.parseSectionC(Eater(data.remain()[self.offSectC:self.offSectC + self.lenSectC], endianness="<"))
        self.parseSectionD(Eater(data.remain()[self.offSectD:self.offSectD + self.lenSectD], endianness="<"))

        for f in self.fileset:
            if f.endswith(self.appname):
                self.apppath = f
                break

        self.finish_header(header)

    def version_string(self):
        """Returns a readable version of Prefetch file"""
        return self._versions[self._rawVersion]

    def parseSectionB(self, data):
        self._entriesB = []
        for i in xrange(self.nbSectB):
            self._entriesB.append(data.eat("12s"))

    def parseSectionC(self, data):
        self.fileset.extend([x for x in data.remain().decode("UTF-16LE").split("\x00") if x != ''])

    def parseSectionD(self, data):
        raw = data.remain()
        for d in xrange(self.nbSectD):
            entry = {"dirset": []}
            head = self.eatSectionDHeader(data)
            (offVolid, lenvolid, entry["volCreateTime"], entry["volSN"], offSubS1, lenSubS1, offDirset,
             nbdirset) = head.eat("2LQ5L")
            entry["volCreateTime"] = winTS2epoch(entry["volCreateTime"])
            entry["volumepath"] = raw[offVolid:offVolid + 2 * lenvolid].decode("UTF-16LE")
            entry["S1"] = raw[offSubS1:offSubS1 + lenSubS1]
            e = Eater(raw[offDirset:], endianness="<")
            for i in xrange(nbdirset):
                l = e.eat("H")
                value = e.eat("%ds" % (2 * (l + 1))).decode("UTF-16LE").rstrip("\x00")
                entry["dirset"].append(value)
            self._entriesD[entry["volumepath"]] = copy.copy(entry)


class PrefetchXP(Prefetch):
    version = 0x11
    description = "WinXP"

    def __init__(self, data):
        self.parse(Eater(data, endianness="<"))

    @staticmethod
    def hashFilename(filename):
        """filename is the UTF-16 full uppercase file name"""
        hash_value = 0
        for c in filename:
            hash_value = ((hash_value * 37) + ord(c)) % 0x100000000
        hash_value = (hash_value * 312159269) % 0x100000000
        if hash_value > 0x80000000:
            hash_value = 0x100000000 - hash_value
        return (abs(hash_value) % 1000000007) % 0x100000000

    def parseSectionA(self, data):
        self._entriesA = []
        for i in xrange(self.nbSectA):
            self._entriesA.append(data.eat("20s"))

    def eatSectionDHeader(self, data):
        return data.eat_sub(40)

    def finish_header(self, header):
        self.lastrun = winTS2epoch(header.eat("Q"))
        (_, _, _, _, self.dwRun) = header.eat("5L")


class PrefetchWin7(PrefetchXP):
    version = 0x17
    description = "Win7"

    @staticmethod
    def hashFilename(filename):
        """filename is the UTF-16 full uppercase file name"""
        hash_value = 314159
        fname_index = 0
        fname_len = len(filename)
        while fname_index + 8 < fname_len:
            c = ord(filename[fname_index + 1]) * 37
            c += ord(filename[fname_index + 2])
            c *= 37
            c += ord(filename[fname_index + 3])
            c *= 37
            c += ord(filename[fname_index + 4])
            c *= 37
            c += ord(filename[fname_index + 5])
            c *= 37
            c += ord(filename[fname_index + 6])
            c *= 37
            c += ord(filename[fname_index]) * 442596621
            c += ord(filename[fname_index + 7])
            hash_value = ((c - (hash_value * 803794207))) % 0x100000000
            fname_index += 8
        while fname_index < fname_len:
            hash_value = (((37 * hash_value) + ord(filename[fname_index])) % 0x100000000)
            fname_index += 1
        return hash_value

    def parseSectionA(self, data):
        self._entriesA = []
        for i in xrange(self.nbSectA):
            self._entriesA.append(data.eat("32s"))

    def eatSectionDHeader(self, data):
        return data.eat_sub(104)

    def finish_header(self, header):
        header.eat("2L")
        self.lastrun = winTS2epoch(header.eat("Q"))
        (_, _, _, _, self.dwRun) = header.eat("5L")


class PrefetchWin8(PrefetchWin7):
    version = 0x1a
    description = "Win8"

    @staticmethod
    def hashFilename(filename):
        """filename is the UTF-16 full uppercase file name"""
        return PrefetchWin7.hashFilename(filename)

    def finish_header(self, header):
        header.eat("2L")
        self.lastrun = winTS2epoch(header.eat("Q"))
        for i in xrange(7):
            t = header.eat("Q")
            if t != 0:
                self.prevRuns.append(winTS2epoch(t))
        (_, _, _, _, self.dwRun) = header.eat("5L")


Prefetch.register_subclass(PrefetchXP)
Prefetch.register_subclass(PrefetchWin7)
Prefetch.register_subclass(PrefetchWin8)


def process_file(fname):
    data = ""
    try:
        fd = open(fname, 'rb')
        data = fd.read()
        fd.close()
    except IOError, e:
        print >> sys.stderr, u"[!] Can't open file %s (%s)" % (fname.decode('UTF-8', 'ignore'), str(e))
        raise e
    if len(data) < 8:
        print >> sys.stderr, u"[!] File %s is to short to be a Prefetch" % fname.decode('UTF-8', 'ignore')
        return 1, None
    try:
        pf = Prefetch.build(data)
        d = pf.todict()
        d['name'] = fname
        return 0, d
    except Exception, e:
        print >> sys.stderr, u"[!] Error while parsing file %s (%s)" % (fname.decode('UTF-8', 'ignore'), str(e))
        import traceback
        print traceback.format_exc()
        return 2, None
    return 0

if __name__ == '__main__':
    import codecs

    sys.stdout = codecs.getwriter('UTF-8')(sys.stdout)
    sys.stderr = codecs.getwriter('UTF-8')(sys.stderr)

    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", metavar="FILE", dest="output", default=sys.stdout,
                        help="Outputs the result to the given file")
    parser.add_argument("-f", "--format", metavar="FORMAT", dest="outformat", default="TEXT",
                        choices=[x.upper() for x in dir(Formatter) if not x.startswith('__')])
    parser.add_argument("-r", "--recursive", dest="recursive", action="store_true", default=False)
    parser.add_argument("prefetch_files", nargs="+")
    options = parser.parse_args(sys.argv[1:])

    if options.output is not sys.stdout:
        if options.output == "-":
            options.output = sys.stdout
        else:
            options.output = open(options.output, 'wb')
    fmt = Formatter(options.output)

    exit_code = 0
    rv = []
    for f in options.prefetch_files:
        if options.recursive and os.path.isdir(f):
            for root, dirs, files in os.walk(f):
                for ff in files:
                    e, d = process_file(os.path.join(root, ff))
                    exit_code |= e
                    if d is not None:
                        rv.append(d)
        elif os.path.isfile(f):
            e, d = process_file(f)
            exit_code |= e
            if d is not None:
                rv.append(d)
        else:
            print >> sys.stderr, u"[!] Ignoring '%s' because it is not a file" % f.decode('UTF-8', 'ignore')
            exit_code |= 4
    getattr(fmt, options.outformat.lower())(rv)
    if options.output is not sys.stdout:
        options.output.close()
    sys.exit(exit_code)