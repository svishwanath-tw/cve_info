#!/usr/bin/env python3
import argparse
import csv
from functools import reduce
from html.parser import HTMLParser
from html.entities import name2codepoint
import json
import logging
import sys
import re 
from urllib.request import urlopen

#No longer needed
class MyHTMLParser(HTMLParser):
    def __init__(self, logError):
        super().__init__()
        self.captureTagContent = False
        self.description = set([])

    def handle_starttag(self, tag, attrs):
        if tag != "p":
            self.showdata = False
            return
        for attr in attrs:
            logging.debug("attr " + attr + "of p tag")
            self.showdata = attr[0] == 'data-testid' and attr[1].startswith('vuln')

    def handle_data(self, data):
        value = str(data).strip()
        logging.debug("ShouldCaptureTagContent:" + str(self.captureTagContent) + "  value to description:" + value)
        if self.captureTagContent:
            logging.debug("Adding value to description" + value)
            self.description.add(value)

    def getDescription(self):
        result = ""
        for d in self.description:
            result += self.description + "\n"
        return result.strip()

parser = argparse.ArgumentParser(description='Print offcial description of a CVE')

parser.add_argument('cveids', metavar='CVEID', type=str, nargs='*',
                    help='a CVE ID, eg: cve-2021-21697')

parser.add_argument('-d', '--debug', action=argparse.BooleanOptionalAction, required=False, help="log at debug level", default=False)

parser.add_argument('-i', '--infile', nargs='?', type=argparse.FileType('r'), default=sys.stdin, help="input file containing cve-ids 1 per line defaults to standard input")

parser.add_argument('-o', '--outfile', nargs='?', type=argparse.FileType('w'), default=sys.stdout, help="output csv filename 1 entry per line defaults to standard output")
cve_pattern = re.compile("(?P<CVEID>CVE-\d+-\d+)")
args = parser.parse_args()

root = logging.getLogger()
root.setLevel(logging.ERROR)
log_format = '%(levelname)s [%(asctime)s] %(message)s'
formatter = logging.Formatter(log_format)
formatter.datefmt = '%Y-%m-%d %H:%M:%S'
handler = logging.StreamHandler(sys.stderr)
handler.setFormatter(formatter)    
root.addHandler(handler)

if args.debug:
    root.setLevel(logging.DEBUG)
    handler.setLevel(logging.DEBUG)
    
logging.debug("CVE strings found %s"% (args.cveids))
logging.debug("output file %s"%( args.outfile))
logging.debug("input file %s"%( args.infile))
feilds = ['CVE ID', 'Description']

if args.cveids:
    cves = args.cveids
else:
    cves = args.infile.read().split()

with args.outfile:
    writer = csv.DictWriter(args.outfile, fieldnames=feilds)
    writer.writeheader()
    for cve in set(cves):
        matched = cve_pattern.search(cve)
        if matched == None:
            logging.error("Could not parse CVE-ID in %s" % (cve))
            continue
        cveId = matched.groupdict()['CVEID']
        logging.debug("CVEID %s" % (cveId))
        url = "https://services.nvd.nist.gov/rest/json/cve/1.0/%s" % (cveId)
        try:
            httpResponse = urlopen(url)
            body = httpResponse.read()
            parsedResult = json.loads(body)
            description = parsedResult['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
            writer.writerow({'CVE ID': cveId, 'Description': description})
        except Exception:
            e = sys.exc_info()
            logging.error("could not fetch data for %s : reason %s", cveId, e[1].reason)
        

