import os
import requests
import logging
import logging.handlers

import paho.mqtt.publish as publish
import paho.mqtt.client as mqtt

from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy 
from flask_user import login_required, UserManager, UserMixin, SQLAlchemyAdapter 
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user
from threading import Thread

#logging, max 2M a file e ne tengo solo 5
LOG_FILENAME = 'server.log'
logger = logging.getLogger('server')
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s (%(threadName)-10s) %(levelname)s %(message)s')
handler = logging.handlers.RotatingFileHandler(
			  LOG_FILENAME, maxBytes=2097152, backupCount=5)
handler.setFormatter(formatter)
logger.addHandler(handler)
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(formatter)
logger.addHandler(consoleHandler)

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisisasecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['CSRF_ENABLED'] = True 
app.config['USER_ENABLE_EMAIL'] = False 
app.config['USER_ENABLE_REGISTRATION'] = False 

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
	__tablename__ ='user'
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(50), nullable=False, unique=True)
	password = db.Column(db.String(255), nullable=False, server_default='')
	active = db.Column(db.Boolean(), nullable=False, server_default='0')

class Accessi(db.Model):
	__tablename__ ='accessi'
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(50), nullable=False)
	porte = db.Column(db.String(50), nullable=False)
	desc = db.Column(db.String(50), nullable=True)
	#checkin = db.Column(db.DateTime())
	#checkout = db.Column(db.DateTime())


admin = Admin(app, name='key', template_mode='bootstrap3')
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Accessi, db.session))

db_adapter = SQLAlchemyAdapter(db, User)
user_manager = UserManager(db_adapter, app)
#admin.add_view(ModelView(User, db.session))



@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
	user = current_user.username
	porte = Accessi.query.filter_by(username=current_user.username)
	porteHtml=[]
	porteDescHtml=[]
	for porta in porte:
		porteHtml.append(porta.porte)
		porteDescHtml.append(porta.desc)
		print (porteDescHtml)

	errors = []
	results = {}
	if request.method == "POST":
		print(request.form['submit'])
		
		portamqtt = request.form['submit'][-1:]

		# get url that the user has entered
		try:
			publish.single(str.upper(request.form['submit'][:-1]) + "/PORTA" + str(portamqtt), "apri", hostname="localhost")
		except:
			errors.append(
				"Unable to get URL. Please make sure it's valid and try again."
			)
	return render_template('index.html', errors=errors, results=results, user=user, porte=zip(porteHtml,porteDescHtml))

def mqqClient():

	# The callback for when the client receives a CONNACK response from the server.
	logger.info('START')
	def on_connect(client, userdata, flags, rc):
		logger.info("Connected with result code "+str(rc))

		# Subscribing in on_connect() means that if we lose the connection and
		# reconnect then subscriptions will be renewed.
		client.subscribe("test")

	# The callback for when a PUBLISH message is received from the server.
	def on_message(client, userdata, msg):
			logger.info(msg.topic+" "+msg.payload.decode('utf-8'))

	client = mqtt.Client()
	client.on_connect = on_connect
	client.on_message = on_message

	client.connect("www.romito.net", 1883, 60)

	# Blocking call that processes network traffic, dispatches callbacks and
	# handles reconnecting.
	# Other loop*() functions are available that give a threaded interface and a
	# manual interface.
	client.loop_forever()

if __name__ == "__main__":

	app.run(host='0.0.0.0', port=5000, debug=False)
	#app.run()

#Thread(target=mqqClient).start()
#Thread(target=startWeb).start()

#startWeb()
