# -*- coding: utf-8 -*-
from flask import Flask, session, render_template, url_for, request, redirect, abort, _app_ctx_stack, g, flash
from sqlite3 import dbapi2 as sqlite3
from datetime import datetime, date
import time
from werkzeug import check_password_hash, generate_password_hash
from hashlib import md5
import sys
default_encoding = 'utf-8'
if sys.getdefaultencoding() != default_encoding:
    reload(sys)
    sys.setdefaultencoding(default_encoding)


DATABASE = 'yhfWeibo.db'
PER_PAGE = 30
DEBUG = True
SECRET_KEY = 'development key'


app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS', silent=True)


@app.teardown_appcontext
def close_database(exception):  
    top = _app_ctx_stack.top
    if hasattr(top, 'sqlite_db'):
        top.sqlite_db.close()

def get_db():
    top = _app_ctx_stack.top
    if not hasattr(top, 'sqlite_db'):
        top.sqlite_db = sqlite3.connect(app.config['DATABASE'])
        top.sqlite_db.row_factory = sqlite3.Row
    return top.sqlite_db

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def get_user_id(username):
    rv = query_db('select user_id from user where username = ?',
                  [username], one=True)
    return rv[0] if rv else None

def get_username(user_id):
    rv = query_db('select username from user where user_id = ?',
                  [user_id], one=True)
    return rv[0] if rv else None


def format_datetime(timestamp):
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')


def gravatar_url(email, size=80):
    return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
        (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = query_db('select * from user where user_id = ?',
                          [session['user_id']], one=True)


@app.route('/')
def weibo():
    if not g.user:                  # not logged in 
        return redirect(url_for('public_weibo'))
    profile_user = query_db('select * from user where username = ?',
                            [get_username(session['user_id'])], one=True)
    if profile_user is None:
        abort(404)
    following = len(query_db('''select * from follower where who_id=
            (select user_id from user where username=? )''',
            [g.user['username']]))
    fans = len(query_db('''select * from follower where whom_id=
            (select user_id from user where username=? )''',
            [g.user['username']]))
    num_weibo = len(query_db('''select * from message where author_id=
            (select user_id from user where username=? )''', [g.user['username']]))
    return render_template('weibo.html', messages=query_db('''
            select message.*, user.* from message, user
            where message.author_id = user.user_id and (
                user.user_id = ? or 
                user.user_id in (select whom_id from follower
                                        where who_id = ?))
            order by message.pub_date desc limit ?''',
            [session['user_id'], session['user_id'], PER_PAGE]), profile_user=profile_user,
            following=following, fans=fans, num_weibo=num_weibo)


@app.route('/public')
def public_weibo():
    following = None
    fans = None
    num_weibo = None
    if g.user:
        profile_user = query_db('select * from user where username = ?',
                            [get_username(session['user_id'])], one=True)
        following = len(query_db('''select * from follower where who_id=
            (select user_id from user where username=? )''',
            [get_username(g.user['username'])]))
        fans = len(query_db('''select * from follower where whom_id=
            (select user_id from user where username=? )''',
            [get_username(g.user['username'])]))
        num_weibo = len(query_db('''select * from message where author_id=
            (select user_id from user where username=? )''', [g.user['username']]))
        if profile_user is None:
            abort(404)
    else: 
        profile_user = None
    return render_template('weibo.html', messages=query_db('''
            select message.*, user.* from message, user
            where message.author_id = user.user_id
            order by message.pub_date desc limit ?''', [PER_PAGE]), profile_user=profile_user, 
            following=following, fans=fans, num_weibo=num_weibo)


@app.route('/people/<username>')
def user_weibo(username):
    profile_user = query_db('select * from user where username = ?',
                            [username], one=True)
    if profile_user is None:
        abort(404)
    followed = False
    if g.user:
        followed = query_db('''select 1 from follower where
            follower.who_id = ? and follower.whom_id = ?''',
            [session['user_id'], profile_user['user_id']],
            one=True) is not None
    following = len(query_db('''select * from follower where who_id=
            (select user_id from user where username=? )''',
            [username]))
    fans = len(query_db('''select * from follower where whom_id=
            (select user_id from user where username=? )''',
            [username]))
    num_weibo = len(query_db('''select * from message where author_id=
            (select user_id from user where username=? )''', [username]))
    return render_template('weibo.html', messages=query_db('''
            select message.*, user.* from message, user where
            user.user_id = message.author_id and user.user_id = ?
            order by message.pub_date desc limit ?''',
            [profile_user['user_id'], PER_PAGE]), followed=followed,
            profile_user=profile_user, following=following, fans=fans, num_weibo=num_weibo)


@app.route('/profile')
def profile():
    if not g.user:
        abort(401)
    profile_user = query_db('select * from user where username = ?',
                            [get_username(session['user_id'])], one=True)
    if profile_user is None:
        abort(404)
    following = len(query_db('''select * from follower where who_id=
            (select user_id from user where username=? )''',
            [g.user['username']]))
    fans = len(query_db('''select * from follower where whom_id=
            (select user_id from user where username=? )''',
            [g.user['username']]))
    num_weibo = len(query_db('''select * from message where author_id=
            (select user_id from user where username=? )''', [g.user['username']]))
    return render_template('profile.html', profile_user=profile_user, 
            following=following, fans=fans, num_weibo=num_weibo)


@app.route('/all_user')
def all_user():
    following = fans = num_weibo = 0
    profile_user = None
    if g.user:
        profile_user = query_db('select * from user where username = ?',
                            [get_username(session['user_id'])], one=True)
        following = len(query_db('''select * from follower where who_id=
            (select user_id from user where username=? )''',
            [g.user['username']]))
        fans = len(query_db('''select * from follower where whom_id=
            (select user_id from user where username=? )''',
            [g.user['username']]))
        num_weibo = len(query_db('''select * from message where author_id=
            (select user_id from user where username=? )''', [g.user['username']]))
    all_user = query_db('select * from user')
    if all_user is None:
        flash('目前还没有用户.')
        return redirect(url_for('weibo'))
    else:
        return render_template('users.html', all_user=all_user, profile_user=profile_user,
            following=following, fans=fans, num_weibo=num_weibo)

@app.route('/following/<username>')
def following(username):
    if not g.user:
        abort(401)
    profile_user = query_db('select * from user where username = ?',
                            [username], one=True)
    following = len(query_db('''select * from follower where who_id=
            (select user_id from user where username=? )''',
            [username]))
    fans = len(query_db('''select * from follower where whom_id=
            (select user_id from user where username=? )''',
            [username]))
    num_weibo = len(query_db('''select * from message where author_id=
            (select user_id from user where username=? )''', [username]))
    myfollow_users = query_db('''select * from user where user_id=
            (select whom_id from follower where who_id=
            (select user_id from user where username=? ))''', 
            [username])
    return render_template('myfollow.html', profile_user=profile_user, 
        following=following, fans=fans, num_weibo=num_weibo, myfollow_users=myfollow_users)

@app.route('/fans/<username>')
def fans(username):
    if not g.user:
        abort(401)
    profile_user = query_db('select * from user where username = ?',
                            [username], one=True)
    following = len(query_db('''select * from follower where who_id=
            (select user_id from user where username=? )''',
            [username]))
    fans = len(query_db('''select * from follower where whom_id=
            (select user_id from user where username=? )''',
            [username]))
    num_weibo = len(query_db('''select * from message where author_id=
            (select user_id from user where username=? )''', [username]))
    myfollow_users = query_db('''select * from user where user_id=
            (select who_id from follower where whom_id=
            (select user_id from user where username=? ))''', 
            [username])
    return render_template('myfollow.html', profile_user=profile_user, 
        following=following, fans=fans, num_weibo=num_weibo, myfollow_users=myfollow_users)


@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if not g.user:
        abort(401)
    profile_user = query_db('select * from user where username = ?',
                            [get_username(session['user_id'])], one=True)
    if profile_user is None:
        abort(404)
    return render_template('profile.html', profile_user=profile_user)


@app.route('/edit', methods=['POST'])
def edit():
    if 'user_id' not in session:
        abort(401)
    if request.method == 'POST':
        if not request.form['username']:
            error = '请输入用户名'
        elif not request.form['email'] or \
                 '@' not in request.form['email']:
            error = '请输入有效的邮箱地址.'
        elif not request.form['signature']:
            error = '请输入签名.'
        elif get_user_id(request.form['username']) is not None:
            error = '用户名已存在!'
        else:
            db = get_db()
            db.execute('''update user set username=? where user_id=?''',
                (request.form['username'], session['user_id']))
            db.execute('''update user set email=? where user_id=?''',
                (request.form['email'], session['user_id']))
            db.execute('''update user set signature=? where user_id=?''',
                (request.form['signature'], session['user_id']))
            db.commit()
            flash('您已修改资料.')
        return redirect(url_for('profile'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.user:
        return redirect(url_for('weibo'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = '请输入用户名'
        elif not request.form['email'] or \
                 '@' not in request.form['email']:
            error = '请输入有效的邮箱地址.'
        elif not request.form['password']:
            error = '请输入密码.'
        elif request.form['password'] != request.form['password2']:
            error = '两次输入的密码不匹配.'
        elif not request.form['signature']:
            error = '请输入签名.'
        elif get_user_id(request.form['username']) is not None:
            error = '用户名已存在!'
        else:
            reg_date = str(date.today())
            db = get_db()
            db.execute('''insert into user (
              username, email, pw_hash, signature, reg_date) values (?, ?, ?, ?, ?)''',
              [request.form['username'], request.form['email'],
               generate_password_hash(request.form['password']),
               request.form['signature'], reg_date])
            db.commit()
            flash('您已成功注册.')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('weibo'))
    error = None
    if request.method == 'POST':
        user = query_db('''select * from user where
            username = ?''', [request.form['username']], one=True)
        if user is None:
            error = '用户名错误'
        elif not check_password_hash(user['pw_hash'],
                                     request.form['password']):
            error = '密码错误'
        else:
            flash('您已登录.')
            session['user_id'] = user['user_id']
            return redirect(url_for('weibo'))
    return render_template('login.html', error=error)



@app.route('/logout')
def logout():
    flash('您已登出.')
    session.pop('user_id', None)
    return redirect(url_for('public_weibo'))


@app.route('/<username>/follow')
def follow_user(username):
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    db = get_db()
    db.execute('insert into follower (who_id, whom_id) values (?, ?)',
              [session['user_id'], whom_id])
    db.commit()
    flash('您正在关注 "%s"' % username)
    return redirect(url_for('user_weibo', username=username))


@app.route('/<username>/unfollow')
def unfollow_user(username):
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    db = get_db()
    db.execute('delete from follower where who_id=? and whom_id=?',
              [session['user_id'], whom_id])
    db.commit()
    flash('您已取消关注 "%s"' % username)
    return redirect(url_for('user_weibo', username=username))


@app.route('/add_message', methods=['POST'])
def add_message():
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        db = get_db()
        db.execute('''insert into message (author_id, text, pub_date)
            values (?, ?, ?)''', (session['user_id'], request.form['text'],
            int(time.time())))
        db.commit()
        flash('已发布.')
    return redirect(url_for('weibo'))

@app.route('/<message_id>/delete')
def delete(message_id):
    db = get_db()
    db.execute('delete from message where message_id=?', [message_id])
    db.commit()
    flash('已删除.')
    return redirect(url_for('weibo'))



app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url
app.jinja_env.filters['addmessage'] = add_message

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0')
