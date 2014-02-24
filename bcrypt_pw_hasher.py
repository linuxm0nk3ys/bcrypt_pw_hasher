#!/usr/bin/env python
import bcrypt
import getpass
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-u", "--user", dest="username", help="Username")
parser.add_option("-w", "--workfactor", dest="workfactor", default="7", help="Workfactor of bcrypt, the higher the more secure [Default is %default]")

password = getpass.getpass()

(options, args) = parser.parse_args()
if options.username == None or password == None:
    parser.print_help()
else:
    hashed = bcrypt.hashpw(password,bcrypt.gensalt(int(options.workfactor)))
    print "%s:%s" % (options.username,hashed)
