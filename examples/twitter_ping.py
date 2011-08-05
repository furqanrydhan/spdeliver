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

TWITTER_CONSUMER_KEY = '3Dz3rNCqvpb377wrYMlLmQ'
TWITTER_CONSUMER_SECRET = 'JNcmJQZUkqbLePStAKh8DnUzNOWyOmQ7aUxTvmQo'
ACCESS_TOKEN_KEY = None
ACCESS_TOKEN_SECRET = None
PORT = 1337
REDIRECT = 'http://127.0.0.1:' + str(PORT) + '/'

def developer_create_app():
    print 'Sending you to the Twitter website to create an app'
    print 'Please ensure that your callback is listed as "http://127.0.01:' + str(PORT) + '"'
    webbrowser.open('https://dev.twitter.com/apps/new')
    twitter_consumer_key = raw_input('What is your new consumer key? ')
    twitter_consumer_secret = raw_input('What is your new consumer secret? ')
    return (twitter_consumer_key, twitter_consumer_secret)

def user_authorize_app(twitter_consumer_key, twitter_consumer_secret):
    consumer = oauth2.Consumer(twitter_consumer_key, twitter_consumer_secret)
    client = oauth2.Client(consumer)
    request_token = dict(urlparse.parse_qsl(client.request('https://api.twitter.com/oauth/request_token', 'GET')[1]))
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
                access_token = dict(urlparse.parse_qsl(client.request('https://api.twitter.com/oauth/access_token', 'POST')[1]))
                print access_token
                
                self.server.oauth_token = access_token['oauth_token']
                self.server.oauth_token_secret = access_token['oauth_token_secret']
                self.wfile.write('Success!  You can close this window.')

    webbrowser.open('https://api.twitter.com/oauth/authorize?oauth_token=' + request_token['oauth_token'] + '&oauth_callback=' + REDIRECT)
    grabber = BaseHTTPServer.HTTPServer(('127.0.0.1', int(PORT)), TokenGrabber)
    grabber.oauth_token = None
    grabber.oauth_token_secret = None
    while grabber.oauth_token is None or grabber.oauth_token_secret is None:
        grabber.handle_request()
    return (grabber.oauth_token, grabber.oauth_token_secret)

def ping(twitter_consumer_key, twitter_consumer_secret, access_token_key, access_token_secret):
    service = spdeliver.twitter_service(consumer_key=twitter_consumer_key, consumer_secret=twitter_consumer_secret)
    service.authenticate(access_token_key=access_token_key, access_token_secret=access_token_secret)
    print service.deliver({
        'text':'I love tweeting in Python!',
    })

if __name__ == '__main__':
    twitter_consumer_key = TWITTER_CONSUMER_KEY
    twitter_consumer_secret = TWITTER_CONSUMER_SECRET
    access_token_key = ACCESS_TOKEN_KEY
    access_token_secret = ACCESS_TOKEN_SECRET
    if access_token_key is None or access_token_secret is None:
        if twitter_consumer_key is None or twitter_consumer_secret is None:
            (twitter_consumer_key, twitter_consumer_secret) = developer_create_app()
        (access_token_key, access_token_secret) = user_authorize_app(twitter_consumer_key, twitter_consumer_secret)
    ping(twitter_consumer_key, twitter_consumer_secret, access_token_key, access_token_secret)