from google.appengine.ext import db
from google.appengine.ext.webapp.template import render
from google.appengine.api.urlfetch import fetch

import webapp2, tweepy, logging
from webapp2_extras import sessions

from urllib import quote
from hashlib import sha1
from time import mktime
from cgi import escape
from datetime import datetime, timedelta
from time import sleep

from consumer import *


class CronJobHandler(webapp2.RequestHandler):

	def tweet(self, user, url):
		import tweepy
		auth = tweepy.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
		auth.set_access_token(user.access_key, user.access_secret)
		new_status = 'update detected: check %s!' % url
		self.debug('tweeting "%s"' % new_status)
		tweepy.API(auth).update_status(new_status)
		self.debug('tweeting success!')

	def debug(self, msg):
		logging.debug(msg)
		if self.is_developer():
			self.response.out.write('debug: %s<br>\n' % msg)

	def is_developer(self):
		return 'X-AppEngine-Cron' not in self.request.headers

	def get(self):
		from main import User, Page, get_hash
		max_check = 100
		max_tweet = 1
		if self.is_developer():
			max_check = 1
		visited_users = set()
		visited_page = 0
		tweet_made = 0
		conti = True
		for page in Page.all().order('modified'):
			if not conti:
				break
			self.debug('%d-th page' % visited_page)
			user_id, url = page.key().name().split()
			self.debug('Page(user=%s, url=%s)' % (user_id, url))
			if user_id in visited_users:
				self.debug("don't tweet more than once from a user per a cron job.")
				continue

			visited_page += 1
			if visited_page == max_check:
				self.debug('will be the last to process')
				conti = False
			content = get_hash(url)
			if page.content != content:
				page.content = content
				self.tweet(User.get_by_key_name(user_id), url)
				tweet_made += 1
				if tweet_made == max_tweet:
					self.debug('the last to tweet')
					conti = False
				visited_users.add(user_id)
			else:
				self.debug('no update detected in %s' % url)
			page.put()
		else:
			self.debug('checked all pages. terminate.')
			return
		self.debug('processed %d pages, tweeting %d times. terminate.' % (visited_page, tweet_made))

#DEBUG = True
app = webapp2.WSGIApplication([
	('/cron', CronJobHandler)
], debug=True)
