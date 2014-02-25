#!/usr/bin/env python
import bcrypt
import getpass as gp
from optparse import OptionParser


parser = OptionParser()
parser.add_option("-u", "--user", dest="username", help="Username")
parser.add_option("-w", "--workfactor", dest="workfactor", default="7", help="Workfactor of bcrypt, the higher the more secure [Default is %default]")

(options, args) = parser.parse_args()
if (options.username == None):
    parser.print_help()
else:
    password = gp.getpass()
    verify = gp.getpass("Verify Password: ")
    if (password == verify):
        hashed = bcrypt.hashpw(password,bcrypt.gensalt(int(options.workfactor)))
        print "%s:%s" % (options.username,hashed)
    else:
        print "Password doesn't match!"
