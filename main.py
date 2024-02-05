from flask import Flask, redirect
from homepage import bp as homepage
from member import bp as member
from SQLExecutor import exitEvent

# create application
app = Flask(__name__)

# register blueprint
app.register_blueprint(homepage)
app.register_blueprint(member)

# Homepage redirect
@app.route('/')
def redirectToHomepage():
    return redirect("/home/")

if __name__=="__main__":
    app.run("127.0.0.1",37089,True)
    exitEvent.set()