#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import re
import jinja2
import shutil
import hmac
import random
import string
import hashlib
import logging
import json
from google.appengine.ext import db
from google.appengine.api import mail
from google.appengine.ext.webapp import blobstore_handlers

#Defines database entities
class Exp(db.Model):
    title = db.StringProperty(required = True)
    organization = db.StringProperty(required = True)
    start = db.StringProperty(required = True)
    end = db.StringProperty()
    description = db.TextProperty(required = True)

class Edu(db.Model):
    title = db.StringProperty(required = True)
    organization = db.StringProperty(required = True)
    start = db.StringProperty(required = True)
    end = db.StringProperty()
    description = db.TextProperty(required = True)

class Project(db.Model):
    title = db.StringProperty(required = True)
    year = db.StringProperty(required = True)
    description = db.TextProperty(required = True)
    link = db.LinkProperty()

class Technology(db.Model):
    title = db.StringProperty(required = True)
    notes = db.TextProperty()

class GermanyPost(db.Model):
    name = db.StringProperty(required = True)
    location = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)
    description = db.TextProperty()
    imageFolder = db.StringProperty()
    imageNames = db.StringListProperty()

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    cookie = db.TextProperty(required = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def validUsername(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def validPassword(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def validEmail(email):
    return not email or EMAIL_RE.match(email)

SECRET = 'imsosecret'
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name, pw, salt)

#Sets up templating
templateDir = os.path.join(os.path.dirname(__file__), 'templates')
jinjaEnv = jinja2.Environment(loader = jinja2.FileSystemLoader(templateDir), autoescape = True)

#Generic handler setup
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def renderStr(self, template, **params):
        t = jinjaEnv.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.renderStr(template, **kw))

#Handler for home page
class Home(Handler):
    def get(self):
        '''experiences = db.GqlQuery('select * from Exp order by start desc')
        education = db.GqlQuery('select * from Edu order by start desc')
        projects = db.GqlQuery('select * from Project order by year desc')
        technology = db.GqlQuery('select * from Technology')'''

        self.render('index.html')

#Handler for email page
class Email(Handler):
    def get(self, error='', name='', email='', subject='', message=''):
        self.render('email.html', error=error, name=name, email=email, subject=subject, message=message)

    def post(self):
        inputName = self.request.get('nameField')
        inputEmail = self.request.get('emailField')
        inputSubject = self.request.get('subjectField')
        inputMessage = self.request.get('messageField')

        if not validEmail(inputEmail):
            self.get(error='Please enter a valid email address.', name=inputName, email=inputEmail, subject=inputSubject, message=inputMessage)

        else:
            if inputName and inputEmail and inputSubject and inputMessage:
                subjectLine = '%s (%s): %s' %(inputName, inputEmail, inputSubject)
                mail.send_mail('riley@rileylundquist.com', 'rlundquist3@gmail.com', subjectLine, inputMessage)
                mail.send_mail('riley@rileylundquist.com', 'riley@rileylundquist.com', subjectLine, inputMessage)

                thanksSubject = 'Thanks for Your Message!'
                thanksMessage = 'Hi %s,\n\nYour message below has been received. I will be in touch soon.\n\nThanks,\nRiley\n\nSubject: %s\nMessage: %s' %(inputName, inputSubject, inputMessage)
                mail.send_mail('riley@rileylundquist.com', inputEmail, thanksSubject, thanksMessage)

                self.redirect('/thanks')

            else:
                self.get(error='All fields must be completed.', name=inputName, email=inputEmail, subject=inputSubject, message=inputMessage)

#Handler for email thanks page
class Thanks(Handler):
    def get(self):
        self.render('thanks.html')

#Handler for Germany page
class Germany(Handler):
    def get(self):
        posts = db.GqlQuery('SELECT * FROM GermanyPost ORDER BY created DESC')
        posts = list(posts)

        self.render('gedanken_und_bilder.html', posts=posts)

class NewGermanyPost(Handler):
    def renderPost(self, name='', location='', description='', imageFolder='', error=''):
        self.render('neue_gedanken_und_bilder.html', name=name, location=location, description=description, imageFolder=imageFolder, error=error)

    def get(self):
        self.renderPost()

    def post(self):
        name = self.request.get('nameField')
        location = self.request.get('locationField')
        description = self.request.get('descriptionField')
        imageFolder = self.request.get('imageFolder')
        inputUsername = self.request.get('usernameField')
        inputPassword = self.request.get('passwordField')

        if inputUsername == 'rlundquist3':
            user = db.GqlQuery('SELECT * FROM User WHERE username=:1 LIMIT 1', inputUsername)
            if user:
                h = make_pw_hash(user[0].username, user[0].password)
                if valid_pw(user[0].username, user[0].password, h):
                    imageNames = list()
                    nameFile = open(os.path.join(templateDir, 'image_names', unicode(imageFolder)+'.txt'), 'r')
                    logging.info('name file: %s', nameFile)
                    for line in nameFile:
                        imageNames.append(line.strip())

                    post = GermanyPost(name = name, location = location, description = description, imageFolder = imageFolder, imageNames = imageNames)
                    post.put()
                    self.redirect('/gedanken_und_bilder')
            else:
                self.renderPost(name, location, ('''%s''', description), imageFolder, 'Invalid Login')

class SignupPage(Handler):
    params = dict(username = "",
                  usernameError = "",
                  passwordError = "",
                  verifyError = "",
                  email = "",
                  emailError = "")

    def renderForm(self, params):
        self.render('signupForm.html', username = params['username'],
                    usernameError = params['usernameError'],
                    passwordError = params['passwordError'],
                    verifyError = params['verifyError'],
                    email = params['email'],
                    emailError = params['emailError'])

    def get(self):
        for p in self.params:
            p = ""
        self.renderForm(self.params)

    def post(self):
        inputUsername = self.request.get('username')
        inputPassword = self.request.get('password')
        inputVerify = self.request.get('verify')
        inputEmail = self.request.get('email')

        for p in self.params:
            p = ""
        self.params['username'] = inputUsername
        self.params['email'] = inputEmail

        errorExist = False

        if not validUsername(inputUsername):
            self.params['usernameError'] = "Invalid Username"
            errorExist = True
        if not validPassword(inputPassword):
            self.params['passwordError'] = "Invalid Password"
            errorExist = True
        elif inputPassword != inputVerify:
            self.params['verifyError'] = "Passwords do not match"
            errorExist = True
        if not validEmail(inputEmail):
            self.params['emailError'] = "Invalid email"
            errorExist = True

        if errorExist:
            self.renderForm(self.params)
        else:
            cookie = make_secure_val(inputUsername)
            self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % str(cookie))
            passHash = make_pw_hash(inputUsername, inputPassword)
            u = User(username = inputUsername, password = passHash, email = inputEmail, cookie = cookie)
            u.put()
            self.redirect('/neue_gedanken_und_bilder')

app = webapp2.WSGIApplication([
    ('/?', Home),
    ('/email', Email),
    ('/thanks', Thanks),
    ('/gedanken_und_bilder', Germany),
    ('/neue_gedanken_und_bilder', NewGermanyPost),
    ('/signup', SignupPage)
], debug=True)
