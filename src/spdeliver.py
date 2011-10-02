#!/usr/bin/env python

__version_info__ = (0, 1, 1)
__version__ = '.'.join([str(i) for i in __version_info__])
version = __version__

import copy
import email.mime.image
import email.mime.multipart
import email.mime.text
import json
import os.path
import smtplib
import socket
import ssl
import struct
import sys
import time
import traceback
import urllib
import urllib2
import xml.etree.ElementTree

import atom
import facebook
import gdata
import gdata.auth
import gdata.blogger.service
import gdata.service
import oauth2
import twitter
from twilio.rest import TwilioRestClient

class DeliveryException(Exception):
    def __init__(self, message=None):
        self.message = message
    def __str__(self):
        return self.message or 'please check callstack'

# Permanent conditions
class CredentialsInvalid(DeliveryException):
    def __init__(self):
        self.message = 'Credentials invalid'

class ParameterMissing(DeliveryException):
    def __init__(self, message=None):
        self.message = message or 'Parameter missing'

# Temporary conditions
class RateLimited(DeliveryException):
    def __init__(self, retry_in):
        self.message = 'Rate limit exceeded'
        self.retry_in = retry_in

class ServiceNotAvailable(DeliveryException):
    def __init__(self, message=None, retry_in=10):
        self.message = message or 'Service not available'
        self.retry_in = retry_in



# Class-based approach
class _delivery_service(object):
    def __init__(self, *args, **kwargs):
        pass
    
class receipt(dict):
    def __init__(self, type, recipients, link=None, timestamp=None):
        self['type'] = type
        self['recipients'] = recipients
        if link is not None:
            self['link'] = link
        self['timestamp'] = timestamp or time.time()
    def __str__(self):
        return 'Delivered ' + self['type'] + ' message to ' + ', '.join(self['recipients']) + ' at ' + time.ctime(self['timestamp']) + (' (' + self['link'] + ')' if 'link' in self else '')

class email_service(_delivery_service):
    def __init__(self, **kwargs):
        _delivery_service.__init__(self, **kwargs)
        self._host = kwargs['host']
        self._port = str(kwargs.get('port', smtplib.SMTP_PORT))
        self.__server = None
    def _server(self):
        if self.__server is None:
            self.__server = smtplib.SMTP(self._host, self._port)
        return self.__server
    def deliver(self, message):
        try:
            assert('text' in message or 'html' in message)
        except AssertionError:
            raise ParameterMissing('text')
        try:
            assert('subject' in message)
        except AssertionError:
            raise ParameterMissing('subject')
        try:
            assert('to' in message)
        except AssertionError:
            raise ParameterMissing('to')
        try:
            assert('from' in message)
        except AssertionError:
            raise ParameterMissing('from')

        envelope = email.mime.multipart.MIMEMultipart('alternative')        
        recipients = []
        for key in ['to', 'cc', 'bcc']:
            if key in ['to', 'cc']:
                envelope[key] = ', '.join(message.get(key, []) if isinstance(message.get(key, []), list) else [message[key]])
            recipients.extend(message.get(key, []) if isinstance(message.get(key, []), list) else [message[key]])
        envelope['from'] = message['from']
        envelope['subject'] = message['subject']
        for image in message.get('images', {}):
            value = message['images'][image]
            enclosure = None
            if value.startswith('data:image/'):
                subtype = value.split('data:image/')[1].split(';')[0]
                data = value.split('base64,')[1].split('=')[0]
                enclosure = email.mime.image.MIMEImage(data, subtype, email.mime.image.encoders.encode_noop)
                enclosure.add_header('Content-Transfer-Encoding', 'base64')
            else:
                enclosure = email.mime.image.MIMEImage(urllib2.urlopen(value).read())#
            if enclosure is not None:
                enclosure.add_header('Content-ID', '<' + image + '>')
                enclosure.add_header('Content-Disposition', 'inline')
                envelope.attach(enclosure)
        for attachment in message.get('attachments', {}):
            # TODO attach arbitrary data
            pass
        # Try attaching the text/html after images to see if that placates the Cupertino enigma
        if 'text' in message:
            body = email.mime.text.MIMEText(message['text'], 'plain')
            body.set_charset('utf-8')
            envelope.attach(body)
        if 'html' in message:
            body = email.mime.text.MIMEText(message['html'], 'html')
            body.set_charset('utf-8')
            envelope.attach(body)
        self._server().sendmail(envelope['from'], recipients, envelope.as_string())
        return receipt('email', recipients)

class facebook_service(_delivery_service):
    def __init__(self, **kwargs):
        _delivery_service.__init__(self, **kwargs)
        self.__api = None
        self._fb_access_token = None
        self._fb_id = None
    def _api(self):
        assert(self._fb_access_token is not None)
        if self.__api is None:
            self.__api = facebook.GraphAPI(self._fb_access_token)
            self._fb_id = self.__api.get_object('me')['id']
        return self.__api
    def authenticate(self, **kwargs):
        self.__api = None
        self._fb_id = None
        self._fb_access_token = kwargs['fb_access_token']
        #try:
        self._api()
        #except:
        #    raise CredentialsInvalid
    def deliver(self, message):
        if message.get('fb_access_token', None) is not None:
            if self.__api is None or message['fb_access_token'] != self._fb_access_token:
                self.authenticate(**message)
        try:
            # Must be authed
            assert(self.__api is not None)
        except AssertionError:
            raise ParameterMissing('fb_access_token')
        
        envelope = {}
        # Here are some keys we recognize:
        for key in ['message', 'picture', 'name', 'caption', 'description', 'link']:
            if message.get(key, None) is not None and message[key].strip() != '':
                envelope[key] = message[key]
        for key in ['actions']:
            if message.get(key, None) is not None:
                envelope[key] = json.dumps(message[key])
        try:
            fb_status_id = self._api().put_object(message.get('to', 'me'), message.get('type', 'feed'), **envelope)['id']
            return receipt('facebook', [message.get('to', self._fb_id)], 'http://www.facebook.com/' + fb_status_id.split('_')[0] + '/posts/' + fb_status_id.split('_')[1])
        except facebook.GraphAPIError as e:
            if '(#341)' in e.message:
                raise RateLimited(300)
            else:
                raise

class twitter_service(_delivery_service):
    def __init__(self, **kwargs):
        try:
            assert('consumer_key' in kwargs)
        except AssertionError:
            raise ParameterMissing('consumer_key')
        try:
            assert('consumer_secret' in kwargs)
        except AssertionError:
            raise ParameterMissing('consumer_secret')
        _delivery_service.__init__(self, **kwargs)
        self.__api = None
        self._consumer_key = kwargs['consumer_key']
        self._consumer_secret = kwargs['consumer_secret']
        self._access_token_key = None
        self._access_token_secret = None
        self._username = None
    def _api(self):
        assert(self._access_token_key is not None)
        assert(self._access_token_secret is not None)
        if self.__api is None:
            self.__api = twitter.Api(
                consumer_key=self._consumer_key,
                consumer_secret=self._consumer_secret,
                access_token_key=self._access_token_key,
                access_token_secret=self._access_token_secret,
            )
            self._username = self.__api.VerifyCredentials().AsDict()['screen_name']
        return self.__api
    def authenticate(self, **kwargs):
        self.__api = None
        self._access_token_key = kwargs['access_token_key']
        self._access_token_secret = kwargs['access_token_secret']
    def deliver(self, message):
        assert('text' in message)
        if 'to' in message:
            tweet_id = self._api().PostDirectMessage(message['to'], message['text']).AsDict()['id']
        else:
            tweet_id = self._api().PostUpdate(message['text']).AsDict()['id']
        return receipt('twitter', [message.get('to', self._username)], 'http://www.twitter.com/' + self._username + '/status/' + tweet_id)
class twilio_service(_delivery_service):
    def __init__(self, **kwargs):
        try:
            assert('account_id' in kwargs)
        except AssertionError:
            raise ParameterMissing('account_id')
        try:
            assert('account_token' in kwargs)
        except AssertionError:
            raise ParameterMissing('account_token')
        _delivery_service.__init__(self, **kwargs)
        self._account_id = kwargs['account_id']
        self._account_token = kwargs['account_token']
        
    def deliver(self, message):
        assert('to' in message)
        assert('from' in message)
        assert('body' in message)
        
        client = TwilioRestClient(self._account_id, self._account_token)

        message = client.sms.messages.create(to=message['to'], from_=message['from'], body=message['body'])
class tumblr_service(_delivery_service):
    def __init__(self, **kwargs):
        try:
            assert('consumer_key' in kwargs)
        except AssertionError:
            raise ParameterMissing('consumer_key')
        try:
            assert('consumer_secret' in kwargs)
        except AssertionError:
            raise ParameterMissing('consumer_secret')
        try:
            assert('generator' in kwargs)
        except AssertionError:
            raise ParameterMissing('generator')
        _delivery_service.__init__(self, **kwargs)
        self._consumer_key = kwargs['consumer_key']
        self._consumer_secret = kwargs['consumer_secret']
        self._generator = kwargs['generator']
        self._consumer = oauth2.Consumer(key=self._consumer_key, secret=self._consumer_secret)
        self._access_token_key = None
        self._access_token_secret = None
        self._username = None
        self._token = None
    def _do(self, url, parameters={}, method='POST'):
        envelope = {
            'oauth_version':'1.0',
            'oauth_nonce':oauth2.generate_nonce(),
            'oauth_timestamp':int(time.time()),
            'oauth_token':self._token.key,
            'oauth_consumer_key':self._consumer.key,
        }
        envelope.update(parameters)
        req = oauth2.Request(method=method, url=url, parameters=envelope)
        signature_method = oauth2.SignatureMethod_HMAC_SHA1()
        req.sign_request(signature_method, self._consumer, self._token)

        return urllib2.urlopen(url, data=req.to_postdata()).read()
    def authenticate(self, **kwargs):
        self._username = None
        self._token = None
        self._access_token = kwargs['access_token_key']
        self._access_token_secret = kwargs['access_token_secret']
        self._token = oauth2.Token(key=self._access_token, secret=self._access_token_secret)
        
        response = self._do('http://www.tumblr.com/api/authenticate')
        for blog in xml.etree.ElementTree.fromstring(response).findall('tumblelog'):
            if blog.attrib.get('is-primary', 'no') == 'yes':
                self._username = blog.attrib['name']
                break
        assert(self._username is not None)
    def deliver(self, message):
        assert('type' in message)
        assert('title' in message)
        if message['type'] in ['photo']:
            assert('caption' in message)
            assert('source' in message)
            assert('click-through-url' in message)
        elif message['type'] in ['regular']:
            assert('body' in message)
        try:
            assert(self._username is not None)
            assert(self._token is not None)
        except AssertionError:
            self.authenticate(**message)

        response = self._do('http://www.tumblr.com/api/write', message)
        return receipt('tumblr', [self._username], 'http://' + self._username + '.tumblr.com/post/' + response.strip('"'))

class blogger_service(_delivery_service):
    def __init__(self, **kwargs):
        try:
            assert('consumer_key' in kwargs)
        except AssertionError:
            raise ParameterMissing('consumer_key')
        try:
            assert('consumer_secret' in kwargs)
        except AssertionError:
            raise ParameterMissing('consumer_secret')
        try:
            assert('source' in kwargs)
        except AssertionError:
            raise ParameterMissing('source')
        _delivery_service.__init__(self, **kwargs)
        self._consumer_key = kwargs['consumer_key']
        self._consumer_secret = kwargs['consumer_secret']
        self._source = kwargs['source']
        self._service = gdata.blogger.service.BloggerService(source=self._source)
        self._service.SetOAuthInputParameters(
            gdata.auth.OAuthSignatureMethod.HMAC_SHA1,
            self._consumer_key,
            self._consumer_secret
        )
        self._token = None
    def authenticate(self, **kwargs):
        self._token = None
        self._token = gdata.auth.OAuthToken(
            key=kwargs['access_token_key'],
            secret=kwargs['access_token_secret'],
            scopes=[gdata.service.CLIENT_LOGIN_SCOPES['blogger']],
            oauth_input_params=self._service.GetOAuthInputParameters()
        )
        self._service.SetOAuthToken(self._token)
    def deliver(self, message):
        assert('title' in message)
        assert('content' in message)
        try:
            assert(self._token is not None)
        except AssertionError:
            self.authenticate(**message)
            
        feed = self._service.GetBlogFeed()
        blog_id = feed.entry[0].GetSelfLink().href.split("/")[-1]
        envelope = gdata.GDataEntry()
        envelope.title = atom.Title('xhtml', message['title'])
        envelope.content = atom.Content(content_type='html', text=message['content'])
        response = self._service.Post(entry, '/feeds/' + blog_id + '/posts/default')
        return receipt('blogger', [], response.GetAlternateLink().href)

class android_push_service(_delivery_service):
    def __init__(self, **kwargs):
        _delivery_service.__init__(self, **kwargs)
        self._token = None

        self._url = 'https://www.google.com/accounts/ClientLogin'
        self._send_url = 'https://android.apis.google.com/c2dm/send'
        self._service = 'ac2dm'
        self._collapse_key = 1

        self._accountType = kwargs['accountType']
        self._email = kwargs['email']
        self._password = kwargs['password']
        self._source = kwargs['source']
        
        self._registration_id = None
			
    def _getToken(self):
        if self._token is None:
            # Build payload
            values = {'accountType' : self._accountType,
            'Email' : self._email,
            'Passwd' : self._password,
            'source' : self._source,
            'service' : self._service}
            # Build request
            data = urllib.urlencode(values)
            request = urllib2.Request(self._url, data)
            
            # Post
            response = urllib2.urlopen(request)
            responseAsString = response.read()
            # Format response
            responseAsList = responseAsString.split('\n')

            self._token = responseAsList[2].split('=')[1]
        return self._token
    def authenticate(self, **kwargs):
        self._device_token = kwargs['device_token'].decode('hex')
    def deliver(self, message):
        try:
            assert(self._token is not None)
        except AssertionError:
            self._getToken()
            return self.sendMessage(message)
            
    def sendMessage(self, message):
        self._registration_id = message.get('registration_id', None)
        if message['registration_id'] is None:
            return False
        
        # Build payload
        values = {'registration_id' : self._registration_id,
                    'collapse_key' : time.time()}		
        if 'data' in message:
            for val in message['data'].keys():
                values['data.'+val] = message['data'][val]
            #values['data'] = message['data']
        # Build request
        headers = {'Authorization': 'GoogleLogin auth=' + self._token}
        data = urllib.urlencode(values)
        
        request = urllib2.Request(self._send_url, data, headers)

        # Post
        try:
            response = urllib2.urlopen(request)
            responseAsString = response.read()
            return responseAsString
        except urllib2.HTTPError, e:
            print 'HTTPError ' + str(e)
            
class ios_push_service(_delivery_service):
    def __init__(self, **kwargs):
        try:
            assert('certificate' in kwargs)
        except AssertionError:
            raise ParameterMissing('certificate')
        _delivery_service.__init__(self, **kwargs)
        self._certificate = kwargs['certificate']
        self._host = 'gateway.sandbox.push.apple.com' if kwargs.get('sandbox', False) else 'gateway.push.apple.com'
        self._port = 2195
        self._device_token = None
        self.__socket = None
    def _socket(self):
        if self.__socket is None:
            self.__socket = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), certfile=self._certificate)
            self.__socket.connect((self._host, self._port))
        return self.__socket
    def authenticate(self, **kwargs):
        self._device_token = kwargs['device_token'].decode('hex')
    def deliver(self, message):
        assert('alert' in message)
        assert('badge' in message)
        try:
            assert(self._device_token is not None)
        except AssertionError:
            self.authenticate(**message)
        
        payload = {
            'aps':{
            },
        }
        if 'alert' in message:
            payload['aps']['alert'] = message['alert']
        if 'badge' in message:
            payload['aps']['badge'] = message['badge']
        if 'sound' in message:
            payload['aps']['sound'] = message['sound']
        else:
            payload['aps']['sound'] = 'default'
        payload = json.dumps(payload)
        envelope = struct.pack('!BH' + str(len(self._device_token)) + 'sH' + str(len(payload)) + 's', 0, len(self._device_token), self._device_token, len(payload), payload)
        for attempt in xrange(0, 2):
            try:
                assert(self._socket().write(envelope) > 0)
                break
            except (socket.error, AssertionError):
                self.__socket = None
        return receipt('ios_push', [self._device_token])