#!/usr/bin/env python3
import argparse
import csv
import json
import logging
import sys
import re 
from urllib.request import urlopen


parser = argparse.ArgumentParser(description='Fetch description of CVEs from nvd api')

parser.add_argument('cveids', metavar='CVEID', type=str, nargs='*',
                    help='a CVE ID, eg: cve-2021-21697')

parser.add_argument('-d', '--debug', action=argparse.BooleanOptionalAction, required=False, help="log at debug level", default=False)

parser.add_argument('-i', '--infile', nargs='?', type=argparse.FileType('r'), default=sys.stdin, help="input file containing cve-ids 1 per line defaults to standard input")

parser.add_argument('-o', '--outfile', nargs='?', type=argparse.FileType('w'), default=sys.stdout, help="output csv filename, will contain 1 entry per valid input cveid defaults to standard output")
cve_pattern = re.compile("(?P<CVEID>CVE-\d+-\d+)")
args = parser.parse_args()

#Setup logging
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
    
logging.debug("CVE strings found %s"% (args.cveids))
logging.debug("output file %s"%( args.outfile))
logging.debug("input file %s"%( args.infile))
feilds = ['CVE ID', 'Description']

cves = None
if args.cveids:
    cves = args.cveids
else:
    logging.warning("Waiting for input on stdin")
    cves = args.infile

if cves == None:
    parser.print_usage()
    exit(0)

with args.outfile:
    writer = csv.DictWriter(args.outfile, fieldnames=feilds)
    writer.writeheader()
    for cve in set(cves):
        matched = cve_pattern.search(cve)
        if matched == None:
            logging.error("Could not parse CVE-ID in %s" % (cve.strip()))
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
        

#Take a look at https://repolinux.wordpress.com/2012/10/09/non-blocking-read-from-stdin-in-python/