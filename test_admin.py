from datetime import datetime
from flask import Flask, redirect, current_app
from flask.ext.admin import Admin
from flask.ext.admin.contrib.sqla import ModelView
from flask.ext.admin.menu import MenuLink
from flask.ext.security import (
    current_user,
    url_for_security,
    UserMixin,
    RoleMixin,
    SQLAlchemyUserDatastore,
    Security
)
from flask.ext.security.utils import encrypt_password
from flask.ext.sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'super-secret'
app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha512'
app.config['SECURITY_PASSWORD_SALT'] = '16a0af319890f662055ba10aecff37e7e033db3fba737e55'
app.config['SECURITY_USER_IDENTITY_ATTRIBUTES'] = 'email'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)


class Role(db.Model, RoleMixin):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(length=64), unique=True)
    description = db.Column(db.Unicode(length=255), nullable=True)

    def __unicode__(self):
        return u"{name} ({role})".format(name=self.name, role=self.description or 'Role')

user_to_role = db.Table('user_to_role',
    db.Column('user_id', db.Integer(), db.ForeignKey('users.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('roles.id')))


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    first_name = db.Column(db.Unicode(length=255), nullable=False)
    last_name = db.Column(db.Unicode(length=255), nullable=False)

    email = db.Column(db.Unicode(length=254), unique=True, nullable=True)
    password = db.Column(db.Unicode(length=255), nullable=False)
    active = db.Column(db.Boolean(), default=False)

    roles = db.relationship('Role', secondary=user_to_role, backref=db.backref('users', lazy='select'))

    def __unicode__(self):
        return u"{first_name} ({last_name})".format(first_name=self.first_name, last_name=self.last_name)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text, nullable=False)

    def __unicode__(self):
        return self.title


def get_current_user():
    from flask.ext.security import current_user
    try:
        return User.objects.get(id=current_user.id)
    except Exception as e:
        # logger.warning("No user found: %s", str(e))
        return current_user


def is_accessible(roles_accepted=None, user=None):
    user = user or get_current_user()
    # uncomment if "admin" has access to everything
    # if user.has_role('admin'):
    #     return True
    if roles_accepted:
        accessible = any(
            [user.has_role(role) for role in roles_accepted]
        )
        return accessible
    return True


class Roled(object):

    def is_accessible(self):
        roles_accepted = getattr(self, 'roles_accepted', None)
        return is_accessible(roles_accepted=roles_accepted, user=current_user)

    def _handle_view(self, name, *args, **kwargs):
        if not current_user.is_authenticated():
            return redirect(url_for_security('login', next="/admin"))
        if not self.is_accessible():
            # return self.render("admin/denied.html")
            return "<p>Access denied</p>"

class AdminView(Roled, ModelView):

    def __init__(self, *args, **kwargs):
        self.roles_accepted = kwargs.pop('roles_accepted', list())
        super(AdminView, self).__init__(*args, **kwargs)


class UserView(AdminView):
    form_excluded_columns = ('password')


class RoleView(AdminView):
    pass


class PostView(AdminView):
    pass


# Setup Flask-Security
security = Security(app, SQLAlchemyUserDatastore(db, User, Role))

@app.route('/')
def index():
    _login = url_for_security('login', next="/admin")
    _logout = url_for_security('logout', next="/admin")
    return '''
        <a href="/admin/">Click me to get to Admin!</a><br>
        <a href="{login}">Click me to get to login!</a><br>
        <a href="{logout}">Click me to get to logout!</a>
        '''.format(login=_login, logout=_logout)


# Create admin
admin = Admin(app, name='Admin')
admin.add_view(UserView(model=User, session=db.session, category='Account', name='Users', roles_accepted=['admin']))
admin.add_view(RoleView(model=Role, session=db.session, category='Account', name='Roles', roles_accepted=['admin']))
admin.add_view(PostView(model=Post, session=db.session, category='Blog', name='Posts (Editor Only)', roles_accepted=['editor']))
admin.add_view(PostView(model=Post, session=db.session, category='Blog', name='Posts (Admins & Editors)', endpoint="post_special", roles_accepted=['editor', 'admin']))
admin.add_link(MenuLink(name='Public Website', category='', url='/'))


def build_db():
    users = [
        {
            'first_name': 'Super',
            'last_name': 'User',
            'email': 'admin@example.com',
            'active': True,
            'password' : encrypt_password('password'),
            'roles': ['admin']
        },
        {
            'first_name': u'Post',
            'last_name': u'Editor',
            'email': 'editor@example.com',
            'active': True,
            'password': encrypt_password('password'),
            'roles': ['editor']
        },

    ]

    posts = [
        {
            'title': "de Finibus Bonorum et Malorum - Part I",
            'content': "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut"
        },
        {
            'title': "de Finibus Bonorum et Malorum - Part II",
            'content': "Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque"
        },
        {
            'title': "de Finibus Bonorum et Malorum - Part III",
            'content': "At vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium"
        }
    ]

    db.drop_all()
    db.create_all()

    security = current_app.extensions.get('security')

    security.datastore.create_role(name=u"admin", description=u'Administers the system')
    security.datastore.create_role(name=u"editor", description=u'Can edit posts')

    for user in users:
        roles = user.pop('roles')
        user_db = security.datastore.create_user(**user)
        for role_name in roles:
            role_from_db = security.datastore.find_role(role_name)
            security.datastore.add_role_to_user(user_db, role_from_db)
        security.datastore.activate_user(user_db)
        user_db.confirmed_at = datetime.now()

    security.datastore.commit()

    for row in posts:
        post = Post(**row)
        db.session.add(post)

    db.session.commit()


@app.before_first_request
def create_user():
    build_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)