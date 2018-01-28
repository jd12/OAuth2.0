from flask import Flask, render_template, request, redirect, jsonify, url_for, flash

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CatalogItem, User

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests





app = Flask(__name__)

#CLIENT_ID = json.loads(
#    open('client_secrets.json', 'r').read())['web']['client_id']

APPLICATION_NAME = "Item Catalog Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
            for x in xrange(32))
    login_session['state'] = state
    # Render login template
    return render_template('login.html', STATE=state);

# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        if login_session['provider'] == 'github':
            githubdisconnect()
            del login_session['client_id']

        # Finish cleaning out the login_session
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have been successfully logged out.")
        return redirect(url_for('showCategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCategories'))

@app.route('/catalog/JSON')
def catalogJSON():
    categories = session.query(Category).all()
    items = session.query(CatalogItem).all()
    return jsonify(categories=[c.serialize for c in categories], items=[i.serialize for i in items])

# Show all restaurants
@app.route('/')
@app.route('/catalog/')
def showCategories():
  categories = session.query(Category).order_by(asc(Category.name))
  # if 'username' not in login_session:
  #     return render_template('publicrestaurants.html', restaurants=restaurants)
  # else:
  return render_template('categories.html', categories=categories)

if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
