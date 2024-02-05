from sqlite3 import connect
from random import choices
from string import ascii_letters
from os.path import exists
from os import remove

if exists('./userPasswordEncryptionAES256-DO-NOT-REMOVE-THIS.key') or exists('./data.db'):
    print("该脚本非常危险！这将使您的现有用户无法登陆。请输入'I am very sure about this'继续。")
    if input().strip()!="I am very sure about this":
        exit(0)

if exists("./userPasswordEncryptionAES256-DO-NOT-REMOVE-THIS.key"): remove('./userPasswordEncryptionAES256-DO-NOT-REMOVE-THIS.key')
if exists("./data.db"): remove('./data.db')
    
print("开始初始化……")

with open('./defaultDatabase.sql')as f:
    sqlCursor = connect('data.db').cursor()
    sqlCursor.executescript(f.read())

with open('userPasswordEncryptionAES256-DO-NOT-REMOVE-THIS.key','w')as f:
    f.write(''.join(choices(ascii_letters,k=16)))

print("初始化结束")