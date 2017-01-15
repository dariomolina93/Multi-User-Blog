
import os
import jinja2
import random
import hashlib
import hmac
from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# secret for password hashing
secret = 'HelloWOrld!!!23232323'


# render the the html with jinja syntax
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def users_key(group='default'):
    return db.Key.from_path('users', group)


# make a secure value
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


# check to see if the value is correct
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def make_salt(length=5):
        # this returns 5 random letters to join to a password
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    # this makes hash based on sha256
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    # takes name and password and applies salt
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


class User(db.Model):
    # parameters for the user login
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Post(db.Model):
    subject = db.StringProperty(required=True, multiline=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty(required=True)
    likes = db.IntegerProperty(required=True)
    dislikes = db.IntegerProperty(required=True)
    liked_by = db.ListProperty(str)
    unliked_by = db.ListProperty(str)

    def render(self):
    	self._render_text = self.content.replace('\n', '<br>')
    	return render_str("post.html", p=self)


class Comment(db.Model):
	# parameters for the blog
    comment = db.TextProperty()
    post = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
