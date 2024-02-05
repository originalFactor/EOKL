from flask import Blueprint, session, render_template, request, redirect
from SQLExecutor import db_sql, db_returnValue, executeEvent, finishEvent
from manyCrypt import sha512_encrypt, aes_decrypt, aes_encrypt

# create blueprint
bp = Blueprint('member',__name__,'member/static',None,'member/template','/member')

# login
@bp.get('/login')
def loginInterface():
    return render_template('login.html', errCode=session.get('loginErr',''))
@bp.post('/login')
def loginBackend():
    global db_sql,db_returnValue
    if not ((request.form.get('username') and request.form.get('password'))or(request.form.get('card'))):
        session["loginErr"] = "缺失凭据。确保填写了用户名和密码，亦或者工卡秘钥。"
        return redirect('login')
    db_sql = f"SELECT * FROM USERS WHERE USERNAME={sha512_encrypt(request.form['username'])}"
    executeEvent.set()
    finishEvent.wait(3)
    if not db_returnValue:
        session["loginErr"] = "数据库错误。请联系管理员：yxymsg@126.com"
        return redirect('login')
    for data in db_returnValue:
        if aes_decrypt(data[2])==request.form["password"]:
            session["userInfo"] = {
                "id": data[0],
                "username": data[1],
                'nickname': data[3],
                'gender': data[4],
                'description': data[5],
                'role': data[6],
                'bindedAccounts': data[7],
                'bornYear': data[8],
                'bornMonth': data[9],
                'bornDay': data[10],
                'tags': data[11]
            }
            return redirect('/home')
    session["loginErr"] = "账户不存在或密码错误"
    return redirect('login')

# register
@bp.get('/register')
def registerFront():
    return render_template('register.html',errCode=session.get("registerErr",""))
@bp.post('/register')
def registerBack():
    global db_sql, db_returnValue
    if not(request.form.get("username") and request.form.get("password")):
        session["registerErr"] = "未输入用户名"
        return redirect('register')
    if len(request.form["password"])<8:
        session["registerErr"] = "密码太弱，必须大于8位"
        return redirect('register')
    db_sql = f"SELECT ID FROM USERS WHERE USERNAME={sha512_encrypt(request.form['username'])}"
    executeEvent.set()
    finishEvent.wait(3)
    if db_returnValue:
        session["registerErr"] = "这个用户名已经注册过乐"
        return redirect('register')
    db_sql = f"INSERT INTO USERS (USERNAME, PWD) VALUES ('{sha512_encrypt(request.form['username'])}', '{aes_encrypt(request.form['password'])}')"
    executeEvent.set()
    finishEvent.wait(3)
    return redirect('login')