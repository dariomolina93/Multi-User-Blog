import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

#tell where the html directory is
template_dir = os.path.join(os.path.dirname(__file__), 'templates')

#creates the template
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

#secret for password hashing
secret = 'HelloWOrld!!!23232323'

#render the the html with jinja syntax
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


#make a secure value
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

#check to see if the value is correct
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#main handler that will be used
class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

#page where user will frist see
class MainPage(BlogHandler):

    def get(self):
        self.redirect("/blog")


# user stuff
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


def users_key(group='default'):
    return db.Key.from_path('users', group)


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


# blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Comment(db.Model):
    # parameters for the blog
    comment = db.StringProperty(required = True)
    post = db.StringProperty(required=True)
    author = db.StringProperty(required = True)



class NewComment(BlogHandler):

    def get(self, post_id):
        # first will check to see if the person is a user
        if not self.user:
            self.redirect("/login")
            return

        post = Post.get_by_id(int(post_id), parent=blog_key())

        if self.user.name == post.author:
            error = "You cannot comment your own posts!!!!!!!!!"
            self.render('error.html', error = error)
            return


        if post == None:
            # this makes sure that the blog exists
            self.redirect('/')
        else:
            subject = post.subject
            content = post.content
            self.render("newcommnent.html",
                        subject=subject,
                        content=content)

    def post(self, post_id):
        key = db.Key.from_path('Post',
                               int(post_id),
                               parent=blog_key())
        post = db.get(key)
        if not post:
            # if post does not exist
            self.error(404)
            return

        if not self.user:
            # checks user
            self.redirect("/login")

        comment = self.request.get("comment")

        print "Comment: ", comment

        if comment:
            author = self.user.name

            print"COmment: ", comment
            print "Post_ID: ", post_id
            print"Author: ", author

            c = Comment(comment=comment, post=post_id, author=author, parent = self.user.key())
            c.put()
            self.redirect('/blog')

        else:
            error = "please provide a comment!"
            self.render("newcommnent.html",
                        post=post,
                        error=error)


class Post(db.Model):
    # imporant information for a post that a user may want.
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty(required=True)
    likes = db.IntegerProperty(required=True)
    liked_by = db.ListProperty(str)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    @property
    def comments(self):
        return Comment.all().filter("post = ", str(self.key().id()))


class UpdateComment(BlogHandler):

    def get(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment:
            self.render("updatecomment.html",
                        subject=post.subject,
                        content=post.content,
                        comment=comment.comment)
        else:
            self.redirect('/commenterror')

    def post(self, post_id, comment_id):
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment.parent().key().id() == self.user.key().id():
            comment.comment = self.request.get('comment')
            comment.put()
        self.redirect('/blog/%s' % str(post_id))


class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        author = post.author
        loggedUser = self.user.name

        # checks to see if comment exists
        if comment == None:
            self.redirect('/')

        # makes sure the person is a user
        elif not self.user:
            self.redirect("/login")

        # checks if the user is the author
        elif author != loggedUser:
            self.redirect("/login")

        elif comment:
            comment.delete()
            self.redirect('/blog/%s' % str(post_id))
        else:
            self.redirect('/commenterror')

class DeletePost(BlogHandler):
    def get(self,post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)
        author = post.author
        loggedUser = self.user.name

        if post == None:
            self.redirect('/')

        elif not self.user:
            self.redirect('login')

        elif author != loggedUser:
            error = "You cannot delete other peoples post."
            self.render("front.html", error = error)

        else:
            post.delete()
            error = "Your post has been deleted!"
            self.render("front.html", error = error) 


class CommentError(BlogHandler):

    def get(self):
        self.write('Something went wrong.')


class BlogFront(BlogHandler):

    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        comments = db.GqlQuery("SELECT * FROM Comment ORDER BY created DESC")

        for p in posts:
            print p
        #comments are in my datastore but none display, what could be the problem? I'm trying to render them in front.html
        for c in comments:
            print c
            print "Hello world"
            print "Inside for loop"

        print "Hello world"

        self.render('front.html', posts=posts, comments= comments)

    def post(self):

        newpost = self.request.get("newPost")

        if newpost:
            self.redirect("/blog/newpost")


class PostPage(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class RemovePost(BlogHandler):

    def get(self, post_id):
        # checks user
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            author = post.author
            loggedUser = self.user.name

            if author == loggedUser:
                post.delete()
                self.render("removepost.html")
            else:
                self.redirect("/")


class LikePost(BlogHandler):

    def get(self, post_id):\
            # checks user
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if post == None:
                self.redirect('/')
            else:
                author = post.author
                logged_user = self.user.name

            if author == logged_user or logged_user in post.liked_by:
                self.redirect('/error')
            else:
                post.likes += 1
                post.liked_by.append(logged_user)
                post.put()
                self.redirect("/blog")


class EditPost(BlogHandler):

    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if post == None:
                self.redirect('/')
            else:
                author = post.author
                loggedUser = self.user.name

            # authenticates user before edit
            if author == loggedUser:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                error = ""
                self.render("edit.html", subject=post.subject,
                            content=post.content, error=error)
            else:
                error = "You cannot edit other people's post"
                self.render("front.html", error = error)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        author = post.author
        loggedUser = self.user.name
        if not self.user:
            self.redirect("/login")

        elif author != loggedUser:
            self.redirect("/login")

        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            p = db.get(key)
            p.subject = self.request.get('subject')
            p.content = self.request.get('content')
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))


class NewPost(BlogHandler):

    def get(self):
        # checks user
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name
        print"Subject: ", subject
        print"Content: ", content
        print "Author", author

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, author=author, likes=0, liked_by=[])
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render(
                "newpost.html", subject=subject, content=content, error=error)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
# this allows the user to use letters and numbers for a username


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
# password


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
# email


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    # shows sign-up page

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        # validates if user put in the correct info

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):
    # shows log in page

    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Error(BlogHandler):

    def get(self):
        self.render('error.html')


class Logout(BlogHandler):
    # runs logout sequence

    def get(self):
        self.logout()
        self.redirect('/signup')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)/removepost', RemovePost),
                               ('/signup', Register),
                               ('/blog/([0-9]+)/edit', EditPost),
                               ('/blog/([0-9]+)/like', LikePost),
                               ('/login', Login),
                               ('/error', Error),
                               ('/logout', Logout),
                               ('/blog/([0-9]+)/newcomment', NewComment),
                               ('/blog/([0-9]+)/updatecomment/([0-9]+)',
                                UpdateComment),
                               ('/blog/([0-9]+)/deletecomment/([0-9]+)',
                                DeleteComment),
                               ('/commenterror', CommentError),
                               ('/blog/([0-9]+)/deletepost', DeletePost)
                               ],
                              debug=True)