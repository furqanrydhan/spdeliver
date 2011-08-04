#!/usr/bin/env python

import email.mime.image
import email.mime.multipart
import email.mime.text
import json
import os.path
import smtplib
import sys
import time
import traceback
import urllib
import urllib2

import atom
import facebook
import gdata
import gdata.auth
import gdata.blogger.service
import gdata.service
import oauth2
import twitter



# Permanent conditions
class CredentialsInvalid(Exception):
    def __init__(self):
        self.message = 'Credentials invalid'
    def __str__(self):
        return self.message

class ParameterMissing(Exception):
    def __init__(self, message=None):
        self.message = message or 'Parameter missing'
    def __str__(self):
        return self.message

# Temporary conditions
class RateLimited(Exception):
    def __init__(self, retry_in):
        self.message = 'Rate limit exceeded'
        self.retry_in = retry_in
    def __str__(self):
        return self.message

class ServiceNotAvailable(Exception):
    def __init__(self, message=None, retry_in=10):
        self.message = message or 'Service not available'
        self.retry_in = retry_in
    def __str__(self):
        return self.message



# Class-based approach
class _delivery_service(object):
    def __init__(self, *args, **kwargs):
        pass
    
class receipt(object):
    def __init__(self, recipients, link=None, timestamp=None):
        self.recipients = recipients
        self.link = link
        self.timestamp = timestamp or time.time()

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
            assert('subject' in message)
            assert('to' in message)
            assert('from' in message)
        except AssertionError:
            raise ParameterMissing
        
        envelope = email.mime.multipart.MIMEMultipart('alternative')
        envelope['to'] = message['to']
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
        recipients = [envelope['to']]
        for bcc in message.get('bcc', []):
            if bcc.strip() != '':
                recipients.append(bcc.strip())
        print self._server().sendmail(envelope['from'], recipients, envelope.as_string())
        return receipt(recipients)

class facebook_service(_delivery_service):
    def __init__(self, **kwargs):
        _delivery_service.__init__(self, **kwargs)
        self.__api = None
        self.__fb_access_token = None
    def _api(self):
        assert(self.__fb_access_token is not None)
        if self.__api is None:
            self.__api = facebook.GraphAPI(self.__fb_access_token)
        return self.__api
    def authenticate(self, kwargs):
        self.__api = None
        self.__fb_access_token = kwargs['fb_access_token']
    def deliver(self, message):
        if message.get('fb_access_token', None) is not None:
            if self.__api is None or message['fb_access_token'] != self.__fb_access_token:
                self.authenticate(**message)
        try:
            # Must be authed
            assert(self.__api is not None)
        except AssertionError:
            raise ParameterMissing
        # Here are some keys we recognize:
        for key in ['message', 'picture', 'name', 'caption', 'description', 'link']:
#        for (facebook_key, template_key) in [
#            ('message', 'text'),
#            ('picture', 'image'),
#            ('name', 'title'),
#            ('caption', 'caption'),
#            ('description', 'description'),
#            ('link', 'link'),
#            ('target', 'target'),
#        ]:
            if message.get(key, None) is not None and message[key].strip() != '':
                envelope[key] = message[key]
        for key in ['actions']:
            if message.get(key, None) is not None:
                envelope[key] = json.dumps(message[key])
        try:
            fb_status_id = self._api().put_object(message.get('target', 'me'), message.get('type', 'feed'), **envelope)['id']
            return receipt(target, 'http://www.facebook.com/' + fb_status_id.split('_')[0] + '/posts/' + fb_status_id.split('_')[1])
        except facebook.GraphAPIError as e:
            if '(#341)' in e.message:
                raise RateLimited(300)
            else:
                raise

#class TwitterDeliveryMechanism(DeliveryMechanism):
#    def package(self, message_entry, message, context_evaluation):
#        user = context_evaluation['users'].get('from', context_evaluation['users']['to'])
#        try:
#            return {
#                'text':message['text'],
#                'token':unicode(user['credentials']['twitter']['twitter_token']),
#                'secret':unicode(user['credentials']['twitter']['twitter_secret']),
#                'username':unicode(user['credentials']['twitter'].get('twitter_id', user['profile'].get('twitter_username'))),
#            }
#        except KeyError:
#            if user['flags'].get('twitter_credentials_pending', False):
#                raise CredentialsPending
#            else:
#                raise CompositionImpossible('Missing Twitter creds')
#    def deliver(self, envelope):
#        try:
#            api = twitter.Api(
#                consumer_key=self._settings['twitter']['key'],
#                consumer_secret=self._settings['twitter']['secret'],
#                access_token_key=envelope['token'],
#                access_token_secret=envelope['secret'],
#            )
#            tweet_id = str(api.PostUpdate(envelope['text']).AsDict()['id'])
#            return {'tweet_id':tweet_id, 'link':'http://www.twitter.com/' + envelope['username'] + '/status/' + tweet_id}
#        except:
#            raise
#
#class TumblrDeliveryMechanism(DeliveryMechanism):
#    def package(self, message_entry, message, context_evaluation):
#        user = context_evaluation['users'].get('from', context_evaluation['users']['to'])
#        try:
#            envelope = {
#                'token':unicode(user['credentials']['tumblr']['tumblr_token']),
#                'secret':unicode(user['credentials']['tumblr']['tumblr_secret']),
#                'username':unicode(user['credentials']['tumblr']['tumblr_id']),
#                'generator':self._settings['messaging']['domain'],
#            }
#        except KeyError:
#            if user['flags'].get('tumblr_credentials_pending', False):
#                raise CredentialsPending
#            else:
#                raise CompositionImpossible('Missing Tumblr creds')
#        for (tumblr_key, template_key) in [
#            ('type', 'type'),
#            ('title', 'title'),
#            ('caption', 'caption'),
#            ('source', 'source'),
#            ('click-through-url', 'click-through-url'),
#        ]:
#            if template_key in message and template_key != '':
#                envelope[tumblr_key] = message[template_key]
#        return envelope
#    def deliver(self, envelope):
#        try:
#            url = 'http://www.tumblr.com/api/write'
#            username = envelope['username']
#            del envelope['username']
#        
#            envelope['oauth_version'] = '1.0'
#            envelope['oauth_nonce'] = oauth2.generate_nonce()
#            envelope['oauth_timestamp'] = int(time.time())
#
#            token = oauth2.Token(key=envelope['token'], secret=envelope['secret'])
#            del envelope['token']
#            del envelope['secret']
#            consumer = oauth2.Consumer(key=self._settings['tumblr']['key'], secret=self._settings['tumblr']['secret'])
#
#            envelope['oauth_token'] = token.key
#            envelope['oauth_consumer_key'] = consumer.key
#
#            req = oauth2.Request(method='POST', url=url, parameters=envelope)
#            signature_method = oauth2.SignatureMethod_HMAC_SHA1()
#            req.sign_request(signature_method, consumer, token)
#
#            tumblr_post_id = urllib2.urlopen(url, data=req.to_postdata()).read().strip('"')
#            return {'tumblr_post_id':tumblr_post_id, 'link':'http://' + username + '.tumblr.com/post/' + tumblr_post_id}
#        except:
#            raise
#        
#class BloggerDeliveryMechanism(DeliveryMechanism):
#    def package(self, message_entry, message, context_evaluation):
#        user = context_evaluation['users'].get('from', context_evaluation['users']['to'])
#        try:
#            envelope = {
#                'token':str(user['credentials']['blogger']['blogger_token']),
#                'secret':str(user['credentials']['blogger']['blogger_secret']),
#            }
#        except KeyError:
#            if user['flags'].get('blogger_credentials_pending', False):
#                raise CredentialsPending
#            else:
#                raise CompositionImpossible('Missing Blogger creds')
#        for (blogger_key, template_key) in [
#            ('title', 'title'),
#            ('content', 'content'),
#        ]:
#            if template_key in message and template_key != '':
#                envelope[blogger_key] = message[template_key]
#        return envelope
#    def deliver(self, envelope):
#        try:
#            blogger_service = gdata.blogger.service.BloggerService(source=self._settings['blogger']['source'])
#            blogger_service.SetOAuthInputParameters(
#                gdata.auth.OAuthSignatureMethod.HMAC_SHA1,
#                self._settings['blogger']['key'],
#                consumer_secret=self._settings['blogger']['secret'])
#            blogger_token = gdata.auth.OAuthToken(key=envelope['token'], secret=envelope['secret'], scopes=[gdata.service.CLIENT_LOGIN_SCOPES['blogger']], oauth_input_params=blogger_service.GetOAuthInputParameters())
#            blogger_service.SetOAuthToken(blogger_token)
#            feed = blogger_service.GetBlogFeed()
#            blog_id = feed.entry[0].GetSelfLink().href.split("/")[-1]
#            entry = gdata.GDataEntry()
#            entry.title = atom.Title('xhtml', envelope['title'])
#            entry.content = atom.Content(content_type='html', text=envelope['content'])
#            receipt = blogger_service.Post(entry, '/feeds/' + blog_id + '/posts/default')
#            return {'blogger_post_id':receipt.id.text, 'link':receipt.GetAlternateLink().href}
#        except:
#            raise
#            
#class ApplePushDeliveryMechanism(DeliveryMechanism):
#    def package(self, message_entry, message, context_evaluation):
#        user = context_evaluation['users'].get('from', context_evaluation['users']['to'])
#        try:
#            envelope = {
#                'token':str(user['credentials']['blogger']['blogger_token']),
#                'secret':str(user['credentials']['blogger']['blogger_secret']),
#            }
#        except KeyError:
#            if user['flags'].get('blogger_credentials_pending', False):
#                raise CredentialsPending
#            else:
#                raise CompositionImpossible('Missing Blogger creds')
#        for (blogger_key, template_key) in [
#            ('title', 'title'),
#            ('content', 'content'),
#        ]:
#            if template_key in message and template_key != '':
#                envelope[blogger_key] = message[template_key]
#        return envelope
#    def deliver(self, envelope):
#        try:
#            blogger_service = gdata.blogger.service.BloggerService(source=self._settings['blogger']['source'])
#            blogger_service.SetOAuthInputParameters(
#                gdata.auth.OAuthSignatureMethod.HMAC_SHA1,
#                self._settings['blogger']['key'],
#                consumer_secret=self._settings['blogger']['secret'])
#            blogger_token = gdata.auth.OAuthToken(key=envelope['token'], secret=envelope['secret'], scopes=[gdata.service.CLIENT_LOGIN_SCOPES['blogger']], oauth_input_params=blogger_service.GetOAuthInputParameters())
#            blogger_service.SetOAuthToken(blogger_token)
#            feed = blogger_service.GetBlogFeed()
#            blog_id = feed.entry[0].GetSelfLink().href.split("/")[-1]
#            entry = gdata.GDataEntry()
#            entry.title = atom.Title('xhtml', envelope['title'])
#            entry.content = atom.Content(content_type='html', text=envelope['content'])
#            receipt = blogger_service.Post(entry, '/feeds/' + blog_id + '/posts/default')
#            return {'blogger_post_id':receipt.id.text, 'link':receipt.GetAlternateLink().href}
#        except:
#            raise



# Imperative approach
# This is fundamentally inefficient for sending any quanitity of messages,
# since it creates the service class anew for each one.  It is provided as a
# convenience for one-off operations, demonstrations, and to enable sloppy
# engineering so I can have something to look good compared to.
def deliver(service, message):
    for delivery in [email_delivery, facebook_delivery]:
        service = delivery(**service)
        print service.deliver(message)