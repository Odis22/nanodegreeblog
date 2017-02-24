import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'fart'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

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

def user_owns_post(self, post):
    return self.user.key == post.author
    if not user_owns_post(post_variable):
        return self.redirect('/')

def post_exists(function):
    @wraps(function)
    def wrapper(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        if post:
            return function(self, post_id, post)
        else:
            self.error(404)
            return
    return wrapper

class MainPage(BlogHandler):
  def get(self):
      self.write('<a href="/signup">Hello, Udacity!</a>')


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.ReferenceProperty(User)
    last_modified = db.DateTimeProperty(auto_now_add = True)
    likes = db.IntegerProperty(default=0)
    liked_by = db.ListProperty(str)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)
    
class Comment(db.Model):
    post_id = db.IntegerProperty(required = True)
    author = db.ReferenceProperty(User)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    @property
    def comments(self):
        return Comment.all().filter("post = ", str(self.key().id()))
    

class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = %s ORDER BY created DESC"
                               % int(post_id))
        liked = False
        
        if not post:
            self.error(404)
            return
        
        if self.user:
            if self.user.name in post.liked_by:
                liked = True

        self.render("post.html", post = post, comments = comments, liked=liked)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = %s ORDER BY created DESC"
                               % int(post_id))
        if not self.user:
            return self.redirect('/login')
        else:
            if post.author.name != self.user.name:
                if self.request.get("like"):
                    post.likes += 1
                    post.liked_by.append(self.user.name)
                post.put()
                self.redirect("/%s" % post_id)
            else:
                error = "You can't like your own post!"
                self.render("post.html", post=post, error=error)

            content = self.request.get("content")

            if content:
                comment = Comment(content=str(content), author=self.user,
                                  post_id=int(post_id))
                comment.put()
                self.redirect("/%s" % post_id)
            else:
                self.render("post.html", post=post)
                    
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post = Post(parent = blog_key(), subject = subject, content = content,
                        author=self.user)
            post.put()
            self.redirect("/%s" % str(post.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class EditPost(BlogHandler):
    def get(self):
        if self.user:
            post_id = self.request.get("post")
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            author = post.author
            logged_user = self.user.name
            
            if post.author.name == self.user.name:
                self.render("editpost.html", subject=post.subject, content=post.content, post=post)
            else:
                if not post:
                    self.redirect('/notallowed0')
        else:
            self.redirect("/login")
            
    def post(self):
        post_id = self.request.get("post")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')
        
        if subject and content:   
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            author = post.author
            logged_user = self.user.name
            post.subject = self.request.get('subject')
            post.content = self.request.get('content')
            post.put()
            self.redirect('/%s' % str(post.key().id()))

class DeletePost(BlogHandler):
    def get(self):
        post_id = self.request.get("post")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        
        if self.user:
            post_id = self.request.get("post")
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            logged_user = self.user.name
            

            if post.author.name == self.user.name:
                self.render("deletepost.html", post=post)
            else:
                self.error(404)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')
            
        post_id = self.request.get("post")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        author = post.author
        logged_user = self.user.name
        
        if post and post.author.name == self.user.name:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            db.delete(post)
            self.write('Post deleted. <a href="/blog">To main page</a>')


class EditComment(BlogHandler):
    def get(self):
        comment_id = self.request.get("comment")
        key = db.Key.from_path('Comment', int(comment_id), parent=self.user.key())
        comment= db.get(key)
        
        if self.user:
            comment_id = self.request.get("comment")
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

            if not self.user:
                self.write('not allowed')
            else:
                self.render("editcomment.html", content=comment.content, post_id=comment.post_id)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')
        else:
            comment_id = self.request.get("comment")
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

        if comment and comment.author.name == self.user.name:
            content = self.request.get("content")
                           
            if content:
                comment.content = content
                comment.put()
                self.redirect("/%s" % comment.post_id)
            else:
                error = "subject and content, please!"
                self.render("editcomment.html", post_id=comment.post_id,
                            content=content, error=error)
        else:
            self.redirect("/%s" % comment.post_id)
            
class DeleteComment(BlogHandler):
    def get(self):
        comment_id = self.request.get("comment")
        key = db.Key.from_path('Comment', int(comment_id), parent=self.user.key())
        comment= db.get(key)
        
        if self.user:
            comment_id = self.request.get("comment")
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            if comment:
                self.render("deletecomment.html", comment=comment)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')
        else:
            comment_id = self.request.get("comment")
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

        if comment and comment.author.name == self.user.name:
            post_id = comment.post_id
            db.delete(key)
                           

        self.redirect("/%s" % post_id)

class NotAllowed(BlogHandler):
    def get(self, post_comment):
        if post_comment == "0":
            post_comment = "Post"
        else:
            post_comment = "Comment"
        self.render('notallowed.html', type=post_comment)


            

        


###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

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

class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
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
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/login')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/Welcome')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/Welcome', Welcome),
                               ('/blog', BlogFront),
                               ('/([0-9]+)', PostPage),
                               ('/newpost', NewPost),
                               ('/editpost', EditPost),
                               ('/deletepost', DeletePost),
                               ('/comment/edit', EditComment),
                               ('/comment/delete', DeleteComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)                              
