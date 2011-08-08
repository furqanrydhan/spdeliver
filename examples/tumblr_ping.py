#!/usr/bin/env python

import BaseHTTPServer
import oauth2
import spdeliver
import sys
import time
import urllib
import urllib2
import urlparse
import webbrowser

TUMBLR_APP_NAME = None
TUMBLR_CONSUMER_KEY = None
TUMBLR_CONSUMER_SECRET = None
ACCESS_TOKEN_KEY = None
ACCESS_TOKEN_SECRET = None
PORT = 1337
REDIRECT = 'http://127.0.0.1:' + str(PORT) + '/'

def developer_create_app():
    print 'Sending you to the Tumblr website to create an app'
    print 'Please ensure that your callback is listed as "http://127.0.01:' + str(PORT) + '"'
    webbrowser.open('http://www.tumblr.com/oauth/apps')
    tumblr_app_name = raw_input('What is the name of your app? ')
    tumblr_consumer_key = raw_input('What is your new consumer key? ')
    tumblr_consumer_secret = raw_input('What is your new consumer secret? ')
    return (tumblr_app_name, tumblr_consumer_key, tumblr_consumer_secret)

def user_authorize_app(tumblr_app_name, tumblr_consumer_key, tumblr_consumer_secret):
    consumer = oauth2.Consumer(tumblr_consumer_key, tumblr_consumer_secret)
    client = oauth2.Client(consumer)
    request_token = dict(urlparse.parse_qsl(client.request('http://www.tumblr.com/oauth/request_token', 'GET')[1]))
    oauth_token = request_token['oauth_token']
    oauth_token_secret = request_token['oauth_token_secret']
    
    class TokenGrabber(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            params = urlparse.parse_qs(urlparse.urlparse(self.path).query)
            oauth_verifier = params.get('oauth_verifier', [None])[0]
            if oauth_verifier is None:
                self.wfile.write('Failed, try again?')
            else:
                self.wfile.write('got verifier ' + oauth_verifier)

                token = oauth2.Token(oauth_token, oauth_token_secret)
                token.set_verifier(oauth_verifier)
                client = oauth2.Client(consumer, token)
                access_token = dict(urlparse.parse_qsl(client.request('http://www.tumblr.com/oauth/access_token', 'POST')[1]))
                print access_token
                
                self.server.oauth_token = access_token['oauth_token']
                self.server.oauth_token_secret = access_token['oauth_token_secret']
                self.wfile.write('Success!  You can close this window.')

    webbrowser.open('http://www.tumblr.com/oauth/authorize?oauth_token=' + request_token['oauth_token'])
    grabber = BaseHTTPServer.HTTPServer(('127.0.0.1', int(PORT)), TokenGrabber)
    grabber.oauth_token = None
    grabber.oauth_token_secret = None
    while grabber.oauth_token is None or grabber.oauth_token_secret is None:
        grabber.handle_request()
    return (grabber.oauth_token, grabber.oauth_token_secret)

def ping(tumblr_app_name, tumblr_consumer_key, tumblr_consumer_secret, access_token_key, access_token_secret):
    service = spdeliver.tumblr_service(generator=tumblr_app_name, consumer_key=tumblr_consumer_key, consumer_secret=tumblr_consumer_secret)
    service.authenticate(access_token_key=access_token_key, access_token_secret=access_token_secret)
    print service.deliver({
        'type':'regular',
        'title':'Ping!',
        'body':'I love tumbling in Python!',
    })

if __name__ == '__main__':
    tumblr_app_name = TUMBLR_APP_NAME
    tumblr_consumer_key = TUMBLR_CONSUMER_KEY
    tumblr_consumer_secret = TUMBLR_CONSUMER_SECRET
    access_token_key = ACCESS_TOKEN_KEY
    access_token_secret = ACCESS_TOKEN_SECRET
    if access_token_key is None or access_token_secret is None:
        if tumblr_app_name is None or tumblr_consumer_key is None or tumblr_consumer_secret is None:
            (tumblr_app_name, tumblr_consumer_key, tumblr_consumer_secret) = developer_create_app()
        (access_token_key, access_token_secret) = user_authorize_app(tumblr_app_name, tumblr_consumer_key, tumblr_consumer_secret)
    ping(tumblr_app_name, tumblr_consumer_key, tumblr_consumer_secret, access_token_key, access_token_secret)