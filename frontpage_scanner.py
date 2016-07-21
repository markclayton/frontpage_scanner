#!/usr/bin/python

import requests
import sys
import getopt
import threading

target = ""
ip_file = ""
url_file = ""


def usage():
    print "FrontPage Scanner"
    print
    print "Usage: frontpage_scanner.py -t target"
    print "-i --ip-file    - import file of IPs to scan"
    print "-u --url-file   - import file of URLs to scan"
    print "-h --help    - prints this usage prompt"
    print
    print
    print "Examples: "
    print "frontpage_scanner.py -t http://www.google.com/"
    print "frontpage_scanner.py -u target_urls.txt"
    print "frontpage_scanner.py -i target_ips.txt"
    sys.exit(0)

def scanner():
    global target
    global ip_file
    global url_file

    if target.endswith("/"):
        target = target[:-1]
        print target

    f = open("frontpage_fuzz", "r")
    f = f.readlines()
    if target:
        for line in f:
            path = target + line
            requests_thread = threading.Thread(target=requests_handler, args=(path,))
            requests_thread.start()
    elif ip_file:
        ip_list = open(ip_file, "r")
        ip_list = ip_list.readlines()
        for ip in ip_list:
            for line in f:
                path = "http://" + ip.rstrip("\n") + line
                path = path.rstrip('\n')
                requests_thread = threading.Thread(target=requests_handler, args=(path,))
                requests_thread.start()
    elif url_file:
        url_list = open(url_file, "r")
        url_list = url_list.readlines()
        for url in url_list:
            url = url.rstrip("\n")
            for line in f:
                path = url[:-1] + line
                requests_thread = threading.Thread(target=requests_handler, args=(path,))
                requests_thread.start()


def requests_handler(path):
    try:
        r = requests.get(path)
        # print "[%s] - %s" % (r.status_code, path)
        if r.status_code == 200:
            output = "[200 OK] - %s" % path
            print output.rstrip("\n")
    except:
        pass



def main():
    global target
    global ip_file
    global url_file

    if not len(sys.argv[1:]):
        usage()

    try:
        opts,args = getopt.getopt(sys.argv[1:], "ht:i:u:", ["help","ip-file", "url-file"])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o,a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-t", "--target"):
            target = a
            scanner()
        elif o in ("-i", "--ip-list"):
            ip_file = a
            scanner()
        elif o in ("-u", "--url-list"):
            url_file = a
            scanner()
        else:
            assert False, "Unhandled Option"

main()
