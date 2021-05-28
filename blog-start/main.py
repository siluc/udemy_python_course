from flask import abort, Flask, render_template, redirect, url_for, request, flash, session
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditor, CKEditorField
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from datetime import datetime as dt
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##User class
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = db.relationship('BlogPost', back_populates="author")
    comments = db.relationship('BlogComment', back_populates="author")


##Blog class
class BlogPost(db.Model):
    __tablename__ = "blogs"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = db.relationship('User', back_populates="posts")
    img_url = db.Column(db.String(250), nullable=False)
    comments = db.relationship('BlogComment', back_populates="blog")


##Comment class
class BlogComment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = db.relationship('User', back_populates="comments")
    blog_id = db.Column(db.Integer, db.ForeignKey('blogs.id'))
    blog = db.relationship('BlogPost', back_populates="comments" )


db.create_all() # only run it at the first time

##WTForm for creating post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content")
    submit = SubmitField("Submit Post")


##WTForm for commenting on post
class CommentForm(FlaskForm):
    body = CKEditorField("Comment")
    submit = SubmitField("Submit Comment")


##WTForm for registering new user
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign me up!")


##WTForm for registering new user
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("Let me in!")

## admin-only decorator
def admin_only(f):
    @wraps(f)
    def wrapped_func(*args, **kwargs):
        if not current_user.is_authenticated or current_user.email != "icebear@gmail.com":
            return abort(403)
        return f(*args, **kwargs)
    return wrapped_func


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route('/')
def get_all_posts():
    posts = db.session.query(BlogPost).all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route("/post/<int:index>")
def show_post(index):
    requested_post = BlogPost.query.get(index)
    comment_form = CommentForm()
    return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/comment_post/<int:post_id>", methods=['POST'])
def add_comment(post_id):
    requested_post = BlogPost.query.get(post_id)
    new_comment = BlogComment(
        text = request.form.get('body'),
        author_id = current_user.id,
        blog_id = post_id
    )
    db.session.add(new_comment)
    db.session.commit()
    return redirect(url_for('show_post', index=post_id))


@app.route("/edt_post/<int:post_id>", methods=['GET','POST'])
def edit_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
            title = requested_post.title,
            subtitle = requested_post.subtitle,
            body = requested_post.body,
            author = requested_post.author,
            img_url = requested_post.img_url      
    )
    if edit_form.validate_on_submit():
        requested_post.title = request.form.get("title")
        requested_post.subtitle = request.form.get("subtitle")
        requested_post.body = request.form.get("body")
        requested_post.author = request.form.get("author")
        requested_post.img_url = request.form.get("img_url")
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template('edit-post.html', form=edit_form, post=requested_post)



@app.route("/new-post", methods=["POST", "GET"])
def add_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title = request.form.get("title"),
            subtitle = request.form.get("subtitle"),
            date = dt.now().strftime("%B %d, %Y"), 
            body = request.form.get("body"),
            author_id = current_user.id,
            img_url = request.form.get("img_url")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template("make-post.html", form=form)


@app.route("/delete_post/<int:post_id>")
def delete_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    db.session.delete(requested_post)    
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route('/register', methods=["GET","POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user_from_db = User.query.filter_by(email=request.form.get("email")).first()
        # check whether the user already exists
        if user_from_db:
            flash("The email has been registered. Please log in.")
            return redirect(url_for('login'))
        
        # if it doesn't exist, go ahead to register it
        else:
            new_user = User(
                email=request.form.get("email"),
                password=generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8),
                name=request.form.get("name")
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user) # log user in right after they register
            return redirect(url_for('get_all_posts'))

    return render_template('register.html', form=form)


@app.route('/login', methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_from_db = User.query.filter_by(email=request.form.get("email")).first()
        # If the user already exists
        if user_from_db:
            pw_provided = request.form.get("password")
            pw_record = user_from_db.password
            # If the password matches with the record
            if check_password_hash(pw_record, pw_provided):
                login_user(load_user(user_from_db.id))
                flash('Logged in successfully!')
                return redirect(url_for('get_all_posts'))
            else:
                flash("Wrong Password. Try again!")
                return render_template('login.html', form=form)
        else:
            flash("This email hasn't been registered. Please register a new account.")
            return redirect(url_for('register'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    session.pop('_flashes', None)
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)