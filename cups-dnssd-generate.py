#!/usr/bin/env python3

## cups-dnssd-generate.py

## Author:
##  Douglas Kosovic <doug@uq.edu.au>

## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.

## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.

# This script assumes the zone file contains an $ORIGIN line similar to :
# $ORIGIN _tcp.example.com.

"""
Generate Wide Area Bonjour DNS Zone file fragment from querying a CUPS server
"""

import cups, os, optparse, re, urllib.parse
import os.path
import sys

DOCUMENT_TYPES = {
    'application/postscript': True,
    'application/vnd.cups-raster': True,
    'image/png': True,
    'image/jpeg': True,
    'image/pwg-raster': True,
    'image/urf': True
}

class DNSZoneGenerate(object):
    def __init__(self, host=None, user=None, port=None, adminurl=False):
        self.host = host
        self.user = user
        self.port = port
        self.adminurl = adminurl

        if self.user:
            cups.setUser(self.user)

    def encode(self, qstring):
        """DNS Encode the characters in a string which need it.

        @param qstring: the string
        @type qstring: string
        @returns: the escaped string
        @rtype: string
        """

        text = ''
        for c in qstring:
            if c == '"' or c== '\\' :
                text += '\\' + c
            elif ord(c) >= 0x20 and ord(c) < 0x7F:
                text += c
            else:
                # RFC 1035 - zero padded decimal number described by \DDD
                text += '\\%03d' % ord(c)
        return text


    def generate(self):
        if not self.host:
            conn = cups.Connection()
        else:
            if not self.port:
                self.port = 631
            conn = cups.Connection(self.host, self.port)

        printers = conn.getPrinters()

        for p in sorted(printers.keys()):
            v = printers[p]
            if v['printer-is-shared']:
                attrs = conn.getPrinterAttributes(p)
                uri = urllib.parse.urlparse(v['printer-uri-supported'])

                f = conn.getPPD(p)
                ppd = cups.PPD(f)
                os.unlink(f)

                port_no = None
                if hasattr(uri, 'port'):
                    port_no = uri.port
                if not port_no:
                    port_no = self.port
                if not port_no:
                    port_no = cups.getPort()

                if not self.host:
                    self.host = uri.hostname

                if hasattr(uri, 'path'):
                    rp = uri.path
                else:
                    rp = uri[2]
                rp = rp[1:]

                txtRec = []
                txtRec.append('"rp={0}"'.format(rp));
                txtRec.append('"ty={0}"'.format(v['printer-make-and-model']))
                txtRec.append('"adminurl=https://{0}:{1}/{2}"'.format(self.host, port_no, rp))
                
                txtRec.append('"priority=0"')

                product = ppd.findAttr('Product').value
                txtRec.append('"product={0}"'.format(product))

                txtRec.append('"note={0}"'.format(v['printer-location']))

                fmts = []
                for a in attrs['document-format-supported']:
                    if a in DOCUMENT_TYPES:
                        fmts.append(a)
                fmts = ','.join(fmts)
                txtRec.append('"pdl=application/pdf,{0}"'.format(fmts))
                
                txtRec.append('"air=username,password"')

                txtRec.append('"UUID={0}"'.format(attrs['printer-uuid'].replace('urn:uuid:', '')))

                txtRec.append('"TLS=1.2"')

                txtRec.append('"Transparent=F" "Binary=F"')

                printer_type = v['printer-type']

                if (printer_type & cups.CUPS_PRINTER_FAX):
                    txtRec.append('"Fax=T"')
                else:
                    txtRec.append('"Fax=F"')
    
                if (printer_type & cups.CUPS_PRINTER_COLOR):
                    txtRec.append('"Color=T"')
                else:
                    txtRec.append('"Color=F"')

                if (printer_type & cups.CUPS_PRINTER_DUPLEX):
                    txtRec.append('"Duplex=T"')
                else:
                    txtRec.append('"Duplex=F"')

                if (printer_type & cups.CUPS_PRINTER_STAPLE):
                    txtRec.append('"Staple=T"')
                else:
                    txtRec.append('"Staple=F"')

                if (printer_type & cups.CUPS_PRINTER_COPIES):
                    txtRec.append('"Copies=T"')
                else:
                    txtRec.append('"Copies=F"')

                if (printer_type & cups.CUPS_PRINTER_COLLATE):
                    txtRec.append('"Collate=T"')
                else:
                    txtRec.append('"Collate=F"')

                if (printer_type & cups.CUPS_PRINTER_PUNCH):
                    txtRec.append('"Punch=T"')
                else:
                    txtRec.append('"Punch=F"')

                if (printer_type & cups.CUPS_PRINTER_BIND):
                    txtRec.append('"Bind=T"')
                else:
                    txtRec.append('"Bind=F"')

                if (printer_type & cups.CUPS_PRINTER_SORT):
                    txtRec.append('"Sort=T"')
                else:
                    txtRec.append('"Sort=F"')

                # if (printer_type & cups.CUPS_PRINTER_MFP):
                if (printer_type & 0x4000000):
                    txtRec.append('"Scan=T"')
                else:
                    txtRec.append('"Scan=F"')

                txtRec.append('"printer-state=3"')
                txtRec.append('"printer-type={0:#x}"'.format(v['printer-type']))
                txtRec.append('"URF=DM3"')

                encodedLabel = self.encode(p)
                # print ipp records
                print('_ipp\t\t\tPTR\t{0}._ipp'.format(encodedLabel))
                print('_cups._sub._ipp\t\tPTR\t{0}._ipp'.format(encodedLabel))
                print('_universal._sub._ipp\tPTR\t{0}._ipp'.format(encodedLabel))

                print('{0}._ipp\t\tSRV\t0 0 {1} {2}.'.format(encodedLabel, port_no, self.host))

                sys.stdout.write('{0}._ipp\t\tTXT\t"txtvers=1" "qtotal=1" '.format(encodedLabel))
                print(' '.join(txtRec))
                print()

                # print ipps records
                print('_ipps\t\t\tPTR\t{0}._ipps'.format(encodedLabel))
                print('_cups._sub._ipps\tPTR\t{0}._ipps'.format(encodedLabel))
                print('_universal._sub._ipps\tPTR\t{0}._ipps'.format(encodedLabel))

                print('{0}._ipps\t\tSRV\t0 0 {1} {2}.'.format(encodedLabel, port_no, self.host))

                sys.stdout.write('{0}._ipps\t\tTXT\t"txtvers=1" "qtotal=1" '.format(encodedLabel))
                print(' '.join(txtRec))
                print()

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-H', '--host', action="store", type="string",
        dest='hostname', help='Hostname of CUPS server (optional)', metavar='HOSTNAME')
    parser.add_option('-P', '--port', action="store", type="int",
        dest='port', help='Port number of CUPS server', metavar='PORT')
    parser.add_option('-u', '--user', action="store", type="string",
        dest='username', help='Username to authenticate with against CUPS',
        metavar='USER')
    parser.add_option('-a', '--admin', action="store_true", dest="adminurl",
        help="Include the printer specified uri as the adminurl")

    (options, args) = parser.parse_args()

    from getpass import getpass
    cups.setPasswordCB(getpass)

    zone = DNSZoneGenerate(
        user=options.username,
        host=options.hostname,
        port=options.port,
        adminurl=options.adminurl
    )

    zone.generate()
