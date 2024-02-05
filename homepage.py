from flask import Blueprint, render_template

# create blueprint
bp = Blueprint("homepage", __name__, './homepage/static', None, './homepage/templates', '/home')

# homepage
@bp.route('/')
def homepage():
    return render_template("homepage.html")