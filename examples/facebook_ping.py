#!/usr/bin/env python

import BaseHTTPServer
import spdeliver
import sys
import time
import urllib
import urllib2
import urlparse
import webbrowser

FB_APP_ID = None
FB_APP_SECRET = None
FB_ACCESS_TOKEN = None
PORT = 1337
REDIRECT = 'http://localhost:' + str(PORT) + '/'

def developer_create_app():
    print 'Sending you to the Facebook website to create an app'
    print 'Please ensure that your web site is listed as "http://localhost" and that your site domain is listed as "localhost"'
    webbrowser.open('https://developers.facebook.com/setup')
    app_id = raw_input('What is your new App ID? ')
    app_secret = raw_input('What is your new App secret? ')
    return (app_id, app_secret)

def user_authorize_app(fb_app_id, fb_app_secret):
    class TokenGrabber(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            code = urlparse.parse_qs(urlparse.urlparse(self.path).query).get('code', [None])[0]
            if code is None:
                self.wfile.write('Failed, try again?')
            else:
                response = urllib2.urlopen('https://graph.facebook.com/oauth/access_token?' + urllib.urlencode({
                    'client_id':fb_app_id,
                    'redirect_uri':REDIRECT,
                    'client_secret':fb_app_secret,
                    'code':code})).read()
                self.server.fb_access_token = urlparse.parse_qs(response)['access_token'][0]
                self.wfile.write('Success!  You can close this window.')

    webbrowser.open('https://graph.facebook.com/oauth/authorize?' + urllib.urlencode({
        'client_id':fb_app_id,
        'redirect_uri':REDIRECT,
        'scope':'publish_stream'}))
    grabber = BaseHTTPServer.HTTPServer(('127.0.0.1', int(PORT)), TokenGrabber)
    grabber.fb_access_token = None
    while grabber.fb_access_token is None:
        grabber.handle_request()
    return grabber.fb_access_token

def ping(fb_access_token):
    service = spdeliver.facebook_service()
    service.authenticate(fb_access_token=fb_access_token)
    print service.deliver({
        'message':'I love Python!',
    })

if __name__ == '__main__':
    fb_app_id = FB_APP_ID
    fb_app_secret = FB_APP_SECRET
    fb_access_token = FB_ACCESS_TOKEN
    if fb_access_token is None:
        if fb_app_id is None or fb_app_secret is None:
            (fb_app_id, fb_app_secret) = developer_create_app()
        fb_access_token = user_authorize_app(fb_app_id, fb_app_secret)
    ping(fb_access_token)