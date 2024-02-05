from sqlite3 import connect
from threading import Thread, Event
from time import sleep

db_sql = ""
db_returnValue = None

executeEvent = Event()
finishEvent = Event()
exitEvent = Event()

def executeSql():
    db_conn = connect("data.db")
    db_c = db_conn.cursor()
    global db_sql, db_returnValue
    while True:
        if executeEvent.is_set():
            finishEvent.clear()
            db_returnValue = db_c.execute(db_sql)
            executeEvent.clear()
            finishEvent.set()
        if exitEvent.is_set():
            break
        sleep(0.1)

sqlExecutor = Thread(target=executeSql)
sqlExecutor.start()
