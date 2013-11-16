#!/usr/bin/env python
import bcrypt
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-u", "--user", dest="username", help="Username")
parser.add_option("-p", "--password", dest="password", help="Password which will be hashed using bcrypt")
parser.add_option("-w", "--workfactor", dest="workfactor", default="7", help="Workfactor of bcrypt, the higher the more secure [Default is %default]")

(options, args) = parser.parse_args()
if options.username == None or options.password == None:
    parser.print_help()
else:
    hashed = bcrypt.hashpw(options.password,bcrypt.gensalt(int(options.workfactor)))
    print "%s:%s" % (options.username,hashed)
