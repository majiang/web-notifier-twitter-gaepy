from google.appengine.ext import db
from google.appengine.ext.webapp.template import render
from google.appengine.api.urlfetch import fetch

import webapp2, tweepy, logging
from webapp2_extras import sessions

from urllib import quote
from hashlib import sha1
from time import mktime
from cgi import escape
from datetime import datetime

from consumer import *



class MyHandler(webapp2.RequestHandler):

	def dispatch(self):
		self.session_store = sessions.get_store(request=self.request)
		try:
			webapp2.RequestHandler.dispatch(self)
		finally:
			self.session_store.save_sessions(self.response)

	@webapp2.cached_property
	def session(self):
		return self.session_store.get_session()

	def render(self, template, content):
		self.response.out.write(render('templates/%s.html' % template, content))


class MainHandler(MyHandler):

	def get(self):
		self.response.out.write('''
<form method="post" action="/">
	<button type="submit">Authenticate</button>
</form>
''')

	def post(self):
		auth = tweepy.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
		url = auth.get_authorization_url().encode('ascii', 'ignore')
		self.session['request_token'] = (auth.request_token['oauth_token'], auth.request_token['oauth_token_secret'])
		self.redirect(url)


class TwitterException(Exception):
	pass


def onetime_token(twitter_id, nonce):
	return sha1('%d%015x' % (twitter_id, nonce)).hexdigest()


class CallbackHandler(MyHandler):

	def get(self):
		auth = tweepy.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
		try:
			request_key, request_secret = self.session.get('request_token')
		except:
			raise TwitterException('No request token stored in session')
		self.session.pop('request_token')
		auth.request_token = {'oauth_token': request_key, 'oauth_token_secret': request_secret}
		if self.request.get('denied'):
			raise TwitterException('user denied')
		api, access_key, access_secret, nonce = add_user(
			auth,
			self.request.get('oauth_verifier')
		)
		self.render('register', {
			'twitter_id': str(api.me().id),
			'token': onetime_token(api.me().id, nonce)
		})


class RegistrationHandler(MyHandler):

	def get(self):
		auth = tweepy.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
		url = auth.get_authorization_url().encode('ascii', 'ignore')
		self.session['request_token'] = (auth.request_token['oauth_token'], auth.request_token['oauth_token_secret'])
		self.redirect(url)

	def post(self):
		twitter_id = escape(self.request.get('twitter_id'))
		user = User().get_by_key_name(str(twitter_id))
		if user.nonce == 0x1000000000000000:
			raise MyException('expired one-time token')
		if onetime_token(int(twitter_id), user.nonce) != escape(self.request.get('token')):
			raise MyException('invalid one-time token')
		user.nonce = 0x1000000000000000
		user.put()
		target_url = escape(self.request.get('target_url'))
		add_page(user, target_url)
		if add_watchlist(user, target_url):
			msg = 'Successfully added %s to your watchlist.'
		else:
			msg = '%s is already in your watchlist.'
		self.render('result', {
			'msg': msg % target_url,
			'watchlist': user.target_urls.split('\n')
			})


def add_watchlist(user, target_url):
	try:
		target_urls = user.target_urls.split('\n')
	except:
		target_urls = []
	if target_url in target_urls:
		return False
	user.target_urls = '\n'.join(target_urls + [target_url])
	user.put()
	return True

class User(db.Model):
	access_key = db.StringProperty()
	access_secret = db.StringProperty()
	nonce = db.IntegerProperty()
	target_urls = db.TextProperty()


def add_user(auth, oauth_verifier):
	auth.get_access_token(oauth_verifier)
	access_key = auth.access_token
	access_secret = auth.access_token_secret
	auth.set_access_token(access_key, access_secret)
	api = tweepy.API(auth)
	user = User().get_or_insert(str(api.me().id))
	user.access_key = access_key
	user.access_secret = access_secret
	from random import getrandbits
	user.nonce = getrandbits(60)
	user.put()
	return api, access_key, access_secret, user.nonce

class Page(db.Model):
	content = db.TextProperty()
	modified = db.DateTimeProperty(auto_now=True)


def get_hash(url):
	result = fetch(url)
	logging.debug('fetch(%s).status_code = %d' % (url, result.status_code))
	if result.status_code != 200:
		logging.debug('ignore this page for error')
		return ''
	return sha1(result.content).hexdigest()

def add_page(user, url):
	kn = user.key().name() + ' ' + url
	page = Page().get_by_key_name(kn)
	if page:
		return False
	page = Page(key_name=kn, content=get_hash(url))
	page.put()
	return True


config = {}
config['webapp2_extras.sessions'] = {'secret_key': SECRET_COOKEY}
DEBUG = True
app = webapp2.WSGIApplication([
	('/', MainHandler),
	('/callback', CallbackHandler),
	('/register', RegistrationHandler)
], debug=True, config=config)
