#!/usr/bin/env python

import spdeliver
import sys
import time

def ping(address):
    service = spdeliver.email_service(host='mail1.spcfd.com')
    print service.deliver({
        'to':address,
        'from':address,
        'subject':'Ping!',
        'text':'The time is now ' + time.ctime() + ' and you\'ve been pinged',
    })

if __name__ == '__main__':
    address = sys.argv[1] if len(sys.argv) > 1 else str(raw_input('Email address? '))
    ping(address)