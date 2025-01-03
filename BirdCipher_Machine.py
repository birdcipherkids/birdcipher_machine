import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import time
from playsound import playsound
import hashlib
from cryptography.fernet import Fernet
import pyperclip
import psycopg2
import os
import pyhibp
from pyhibp import pwnedpasswords as pw

from imagenes_ing_social import *
from tests_ing_social import *
from hash import *
from hash_hashing import *
from hash_file import *
from ReverseCipher import *
from CaesarCipher import *
from TranspositionEncrypt import *
from TranspositionDecrypt import *
from TranspositionColumnarEncrypt import *



points = 0
coins = 0
feathers = 0
diamonds = 0
lives = 5
counter_social_eng = -1
directoryHash = ''


# ------------------------------------ Functions -------------------------------------------------

def login_user():

	wdatos = bytes(password_dbc.get(), 'utf-8')
	h = hashlib.new(algoritmo, wdatos)
	hash2 = HASH.generaHash(h)

	miConexion1 = psycopg2.connect(host = 'bps57o4k0svfjp9fi4vv-postgresql.services.clever-cloud.com', port = 50013, 
	user = 'u8kpoxoaaxlswsvwrn12', dbname = 'bps57o4k0svfjp9fi4vv', password = 'AgCdmPuBEd0gAhai93vqWI2qoIz85G')
		
	miCursor1 = miConexion1.cursor()

	sql1 = 'select * from users where username = (%s)'
	sql1_data = (username_dbc.get(), )

	sql2 = 'insert into users(username, password, position, points, coins, feathers, emeralds, diamonds) values(%s,%s,%s,%s,%s,%s,%s,%s)'
	sql2_data = (username_dbc.get(), hash2, position_dbc.get(), 0, 0, 0, 0, 0)

	miCursor1.execute(sql1, sql1_data)
	dlt1 = miCursor1.fetchall()

	if len(dlt1) == 0:

		miCursor1.execute(sql2, sql2_data)
		hash256_passw_label.config(text = hash2)
		#playsound('NuevoUsuarioCreado.mp3')
		#playsound('NewUserCreated.mp3')
		time.sleep(2)
		labelPlayerBCM.config(text = 'Welcome, {}'.format(username_dbc.get()))
		labelPlayerBCM2.config(text = 'Welcome, {}'.format(username_dbc.get()))
		labelPlayerBCM3.config(text = 'Welcome, {}'.format(username_dbc.get()))
		labelPlayerBCM4.config(text = 'Welcome, {}'.format(username_dbc.get()))

	elif len(dlt1) > 0 and hash2 == dlt1[0][2]:

		hash256_passw_label.config(text = dlt1[0][2])
		#playsound('CorrectoLogin.mp3')
		#playsound('UtilFuncionesBC.mp3')
		#playsound('CorrectLogin.mp3')
		time.sleep(2)
		#playsound('UseMachine.mp3')
		labelPlayerBCM.config(text = 'Welcome to BirdCipher, {}'.format(username_dbc.get()))
		labelPlayerBCM2.config(text = 'Welcome to BirdCipher, {}'.format(username_dbc.get()))
		labelPlayerBCM3.config(text = 'Welcome to BirdCipher, {}'.format(username_dbc.get()))
		labelPlayerBCM4.config(text = 'Welcome to BirdCipher, {}'.format(username_dbc.get()))
		labelPlayerLoginHashing.config(text = 'Welcome to BirdCipher, {}'.format(username_dbc.get()))

	elif len(dlt1) > 0 and hash2 != dlt1[0][2]:

		playsound('ContrasenaIncorrectaVI.mp3')

	miConexion1.commit()
	miConexion1.close()


def selectDirectory():

	global directory

	directory = filedialog.askdirectory(title = 'Open directory')
	ramsonDirectoryUrl.config(text = directory)

def selectDirectoryHash():

	global directoryHash

	directoryHash = filedialog.askopenfilename(title = 'Open file to hash')
	archiveURLShow.config(text = archive_url.set(directoryHash))

def generate_key_ramson():

	global key_ramson

	key_ramson = Fernet.generate_key()
	ramsonKey.config(text = key_ramson)

def bring_key_ramson():

	global key_ramson

	wdatos = bytes(password_for_ramson.get(), 'utf-8')
	h = hashlib.new(algoritmo, wdatos)
	hash2 = HASH.generaHash(h)

	miConexion13 = psycopg2.connect(host = 'bps57o4k0svfjp9fi4vv-postgresql.services.clever-cloud.com', port = 50013, 
	user = 'u8kpoxoaaxlswsvwrn12', dbname = 'bps57o4k0svfjp9fi4vv', password = 'AgCdmPuBEd0gAhai93vqWI2qoIz85G')
		
	miCursor13 = miConexion13.cursor()

	sql_verf_hash_ramson = 'select * from Players where nickname = (%s)'
	sql_verf_hash_data_ramson = (nickname_db,)
	miCursor13.execute(sql_verf_hash_ramson, sql_verf_hash_data_ramson)
	dlt453 = miCursor13.fetchall()

	if dlt453[0][5] >= 1 and hash2 == dlt453[0][3]:

		if target_receiver_ramson != '':

			sql_bring_key_ramson = 'select * from ramson_bird where (client = (%s) and server = (%s) and packet = (%s))'
			sql_bring_key_data_ramson = (nickname_db, target_receiver_ramson, packet.get())
			miCursor13.execute(sql_bring_key_ramson, sql_bring_key_data_ramson)
			dlt456 = miCursor13.fetchall()
			key_ramson = dlt456[0][4]
			ramsonKey.config(text = key_ramson)

	miConexion13.commit()
	miConexion13.close()


def execution_encrypt_files(items, key):

	i = Fernet(key)

	for x in items:

		with open(x, 'rb') as file:

			file_data = file.read()

		data = i.encrypt(file_data)

		with open(x, 'wb') as file:

			file.write(data)


def execution_decrypt_files(items, key):

	i = Fernet(key)

	for x in items:

		with open(x, 'rb') as file:

			file_data = file.read()

		data = i.decrypt(file_data)

		with open(x, 'wb') as file:

			file.write(data)


def encrypt_files_ramson_funct():


	wdatos = bytes(password_for_ramson.get(), 'utf-8')
	h = hashlib.new(algoritmo, wdatos)
	hash2 = HASH.generaHash(h)

	miConexion12 = psycopg2.connect(host = 'bps57o4k0svfjp9fi4vv-postgresql.services.clever-cloud.com', port = 50013, 
	user = 'u8kpoxoaaxlswsvwrn12', dbname = 'bps57o4k0svfjp9fi4vv', password = 'AgCdmPuBEd0gAhai93vqWI2qoIz85G')
	
	miCursor12 = miConexion12.cursor()

	sql_verf_hash_ramson = 'select * from Players where nickname = (%s)'
	sql_verf_hash_data_ramson = (nickname_db,)
	miCursor12.execute(sql_verf_hash_ramson, sql_verf_hash_data_ramson)
	dlt5 = miCursor12.fetchall()

	if dlt5[0][5] >= 1 and hash2 == dlt5[0][3]:

		if target_receiver_ramson != '':

			sql_ramson_verf = 'select * from ramson_bird where (client = (%s) and server = (%s) and packet = (%s))'
			sql_ramson_verf_data = (nickname_db, target_receiver_ramson, packet.get())
			miCursor12.execute(sql_ramson_verf, sql_ramson_verf_data)
			df20 = miCursor12.fetchall()
			df12_test = True

			if len(df20) == 0 and df12_test == True:

				if directory != '' and ramsonBird_message.get("1.0", "end-1c") != '' and packet.get() != 0:

					sql1234 = 'insert into ramson_bird(client, password, server, key_c, description, packet) values(%s,%s,%s,%s,%s,%s)'
					datos_sql1234 = (nickname_db, hash2, target_receiver_ramson, key_ramson.decode(), ramsonBird_message.get('1.0', 'end-1c'), packet.get())
					miCursor12.execute(sql1234, datos_sql1234)
					archivos = directory
					items = os.listdir(archivos)
					archivos2 = [archivos + '/' + x for x in items]
					execution_encrypt_files(archivos2, key_ramson)
					print(key_ramson)

					playsound('bambu_click.mp3')

				elif directory == '' or ramsonBird_message.get('1.0', 'end-1c') == '' or packet.get() == 0:

					playsound('cartoon121.mp3')


			elif len(df20) > 0 and df12_test == True:

				if directory != '' and ramsonBird_message.get("1.0", "end-1c") != '' and packet.get() != 0:

					sql1235 = 'update ramson_bird set (client, password, server, key_c, description, packet) = (%s,%s,%s,%s,%s,%s) where (client = (%s) and server = (%s) and packet = (%s))'
					datos_sql1235 = (nickname_db, hash2, target_receiver_ramson, key_ramson.decode(), ramsonBird_message.get('1.0', 'end-1c'), packet.get(), nickname_db, target_receiver_ramson, packet.get())
					miCursor12.execute(sql1235, datos_sql1235)
					archivos = directory
					items = os.listdir(archivos)
					archivos2 = [archivos + '/' + x for x in items]
					execution_encrypt_files(archivos2, key_ramson)
					print(key_ramson)

					playsound('bambu_click.mp3')

				elif directory == '' or ramsonBird_message.get('1.0', 'end-1c') == '' or packet.get() == 0:

					playsound('cartoon121.mp3')


		elif target_receiver_ramson == '':

			playsound('RecipientUsername.mp3')
			df12_test = False


	if dlt5[0][5] >= 1 and hash2 != dlt5[0][3]:

		playsound('WrongPass.mp3')

	elif dlt5[0][5] < 1:

		playsound('AuthorizationSendMssg.mp3')



	miConexion12.commit()
	miConexion12.close()


def decrypt_files_ramson_funct():

	wdatos = bytes(password_for_ramson.get(), 'utf-8')
	h = hashlib.new(algoritmo, wdatos)
	hash2 = HASH.generaHash(h)

	miConexion122 = psycopg2.connect(host = 'bps57o4k0svfjp9fi4vv-postgresql.services.clever-cloud.com', port = 50013, 
	user = 'u8kpoxoaaxlswsvwrn12', dbname = 'bps57o4k0svfjp9fi4vv', password = 'AgCdmPuBEd0gAhai93vqWI2qoIz85G')
		
	miCursor122 = miConexion122.cursor()

	sql_verf_hash_ramson = 'select * from Players where nickname = (%s)'
	sql_verf_hash_data_ramson = (nickname_db,)
	miCursor122.execute(sql_verf_hash_ramson, sql_verf_hash_data_ramson)
	dlt909 = miCursor122.fetchall()

	if dlt909[0][5] >= 1 and hash2 == dlt909[0][3]:

		if target_receiver_ramson != '':

			sql_ramson_verf = 'select * from ramson_bird where (client = (%s) and server = (%s) and packet = (%s))'
			sql_ramson_verf_data = (target_receiver_ramson, nickname_db, packet.get())
			miCursor122.execute(sql_ramson_verf, sql_ramson_verf_data)
			df202 = miCursor122.fetchall()
			df12_test = True

			if len(df202) > 0 and df12_test == True:

				archivos = directory
				items = os.listdir(archivos)
				archivos2 = [archivos + '/' + x for x in items]
				execution_decrypt_files(archivos2, key_ramson)
				print(key_ramson)
				ramsonBird_message.insert(tk.END, df202[0][5])

			elif len(df202) == 0:

				playsound('cartoon121.mp3')

	miConexion122.commit()
	miConexion122.close()



def send_message():

	global nickname_db
	global key_encryption
	global token
	global target_person

	bdatos = bytes(passw_em.get(), 'utf-8')
	h = hashlib.new(algoritmo, bdatos)
	hash2 = HASH.generaHash(h)

	miConexion2 = psycopg2.connect(host = 'bps57o4k0svfjp9fi4vv-postgresql.services.clever-cloud.com', port = 50013, 
	user = 'u8kpoxoaaxlswsvwrn12', dbname = 'bps57o4k0svfjp9fi4vv', password = 'AgCdmPuBEd0gAhai93vqWI2qoIz85G')
		
	miCursor2 = miConexion2.cursor()

	sql_verf_hash = 'select * from Players where nickname = (%s)'
	sql_verf_hash_data = (nickname_db,)
	miCursor2.execute(sql_verf_hash, sql_verf_hash_data)
	dlt5 = miCursor2.fetchall()

	if dlt5[0][5] >= 10 and hash2 == dlt5[0][3]:

		if target_person != '':

			sql_verf_server = 'select * from encryptedMessages where (nickname = (%s) and server = (%s))'
			sql_verf_server_data = (nickname_db, target_person)
			miCursor2.execute(sql_verf_server, sql_verf_server_data)
			df1 = miCursor2.fetchall()
			df1_test = True

			if len(df1) == 0 and df1_test == True:

				if token != '' and key_encryption != '':

					#key_encryption = key_encryption.decode()
					sql110 = 'insert into encryptedMessages(nickname, password, server, actual_message, key_b) values(%s,%s,%s,%s,%s)'
					datos_sql110 = (nickname_db, hash2, target_person, token.decode(), key_encryption.decode())
					miCursor2.execute(sql110, datos_sql110)
					playsound('cartoon130.mp3')
					playsound('message_sent_success.mp3')

				elif token == '' or key_encryption == '':

					playsound('StepsForSending.mp3')

			elif len(df1) > 0 and df1_test == True:

				if token != '' and key_encryption != '':

					sql111 = 'update encryptedMessages set (nickname, password, server, actual_message, key_b) = (%s,%s,%s,%s,%s) where (nickname = (%s) and server = (%s))'
					datasql111 = (nickname_db, hash2, target_person, token.decode(), key_encryption.decode(), nickname_db, target_person)
					miCursor2.execute(sql111, datasql111)
					playsound('cartoon130.mp3')
					playsound('message_sent_success.mp3')

				elif token == '' or key_encryption == '':

					playsound('StepsForSending.mp3')

		elif target_person == '':

			playsound('RecipientUsername.mp3')
			df = -1
			df1_test = False


	elif dlt5[0][5] >= 10 and hash2 != dlt5[0][3]:

		playsound('WrongPass.mp3')

	elif dlt5[0][5] < 10:

		playsound('AuthorizationSendMssg.mp3')


	miConexion2.commit()
	miConexion2.close()

	
def displayCiphertext():

	global nickname_db
	global key_encryption
	global token
	global target_person_decrypt
	global message_sent_decrypt
	global key_sent_decrypt
	

	cdatos = bytes(password_for_decrypt.get(), 'utf-8')
	g = hashlib.new(algoritmo, cdatos)
	hash3 = HASH.generaHash(g)

	miConexion3 = psycopg2.connect(host = 'bps57o4k0svfjp9fi4vv-postgresql.services.clever-cloud.com', port = 50013, 
	user = 'u8kpoxoaaxlswsvwrn12', dbname = 'bps57o4k0svfjp9fi4vv', password = 'AgCdmPuBEd0gAhai93vqWI2qoIz85G')
		
	miCursor3 = miConexion3.cursor()

	sql33 = 'select * from Players where nickname = (%s)'
	datasql33 = (nickname_db,)

	sql330 = 'select * from encryptedMessages where server = (%s) and nickname = (%s)'
	datasql330 = (nickname_db, target_person_decrypt)

	miCursor3.execute(sql33, datasql33)
	dlt6 = miCursor3.fetchall()

	if hash3 == dlt6[0][3]:

		if target_person_decrypt != '':

			miCursor3.execute(sql330, datasql330)
			dlt7 = miCursor3.fetchall()

		elif target_person_decrypt == '':

			playsound('perder_incorrecto_no_valido.mp3')
			playsound('activatePersonFirst_toReceive.mp3')

		if len(dlt7) > 0:

			message_sent_decrypt = dlt7[0][5]
			key_sent_decrypt = dlt7[0][4]

			cipher_text3.insert(tk.END, dlt7[0][5])
			cipher_text3.config(font = ("Comic Sans MS", 10))
				
			key_fernet_text2.config(text = dlt7[0][4], justify = 'center', wraplength = 700, font = ('Comic Sans MS', 10))

	elif hash3 != dlt6[0][3]:

		playsound('WrongPass.mp3')


	miConexion3.commit()
	miConexion3.close()


def bc_decription_machine():

	global message_sent_decrypt
	global key_sent_decrypt
	global nickname_db
	global target_person_decrypt

	miConexion3 = psycopg2.connect(host = 'bps57o4k0svfjp9fi4vv-postgresql.services.clever-cloud.com', port = 50013, 
	user = 'u8kpoxoaaxlswsvwrn12', dbname = 'bps57o4k0svfjp9fi4vv', password = 'AgCdmPuBEd0gAhai93vqWI2qoIz85G')

	miCursor3 = miConexion3.cursor()

	sql555 = 'select * from encryptedMessages where server = (%s) and nickname = (%s)'
	datasql555 = (nickname_db, target_person_decrypt)

	miCursor3.execute(sql555, datasql555)
	dlt555 = miCursor3.fetchall()

	a = dlt555[0][5].encode()
	b = dlt555[0][4].encode()
	k = Fernet(b)
	token2 = k.decrypt(a)
	token2 = token2.decode()
	cipher_text2_encrp2.insert(tk.END, token2)
	cipher_text2_encrp2.config(font = ("Comic Sans MS", 10))

	miConexion3.commit()
	miConexion3.close()


# def comd_decrypt():

# 		global key
# 		global keys
# 		global message
# 		global chances_decrypt
# 		global match
# 		global coins

# 		message = secret_messages[index]
# 		key = player_answer_decrypt.get()
		

# 		if chances_decrypt <= 3 and key == keys[index]:

# 			playsound('C:/BirdCipher/Audios/VoiceAudios/CorrectKey.mp3')
# 			time.sleep(2)
# 			cipher_text.config(text = getTranslatedMessage(message, key), font = ("Comic Sans MS", 9))
# 			cipher_text.config(bg = '#050005', fg = '#7e086c')
# 			coins = coins + 1
# 			playsound("rightDecrypt.mp3")
# 			playsound("GoldCoin.mp3")
# 			updatePlayer_coins()
# 			labelCoins.config(text = coins)
# 			match = True
# 			decrypt_button.config(state = 'disabled')
			

# 		elif chances_decrypt <= 3 and key!= keys[index]:

# 			playsound('C:/BirdCipher/Audios/VoiceAudios/WrongKey.mp3')
# 			cipher_text.config(text = getTranslatedMessage(message, key), font = ("Comic Sans MS", 9))
# 			cipher_text.config(bg = '#050005', fg = '#FFFFFF')
# 			chances_decrypt = chances_decrypt + 1

# 		elif chances_decrypt > 3:

# 			decrypt_button.config(state = 'disabled')
# 			playsound('C:/BirdCipher/Audios/VoiceAudios/chances_decrypt.mp3')


def fernet_key_gen():

	global key_encryption
	global key_encryption_test

	key_encryption = Fernet.generate_key()
		
	key_fernet_text.config(text = key_encryption)
	clipboard.copy(key_encryption)
	key_encryption_test = True


def fernet_encryption_function():

	global key_encryption
	global key_encryption_test
	global token

	if key_encryption_test == True:

		message_to_encrypt = cipher_text2.get("1.0", "end-1c")
		message_to_encrypt = message_to_encrypt.encode()
		f = Fernet(key_encryption)
		token = f.encrypt(message_to_encrypt)
		#token = token.decode()
		cipher_text2_encrp.insert(tk.END, token)
		clipboard.copy(token)

	elif key_encryption_test == False:

		playsound('MustGenerateKey.mp3')


def listen_decrypt_text():

	global key
	global keys
	global chances_decrypt
	global crypto_audios_k
	global match

	key = player_answer_decrypt.get()

	if match == True and chances_decrypt <= 3:

		playsound(crypto_audios_k[index])

	elif match == False and chances_decrypt <= 3:
			
		playsound('C:/BirdCipher/Audios/VoiceAudios/WrongKey.mp3')

	elif chances_decrypt > 3:

		playsound('C:/BirdCipher/Audios/VoiceAudios/chances_decrypt.mp3')

def audioPoints():

	playsound()

def coinsAudio():

	playsound()

def feathersAudio():

	playsound()

def diamondsAudio():

	playsound()

def closeMachine():

	global chances_decrypt
	global match
	global target_person
	global target_person_decrypt

	chances_decrypt = 0
	target_person = ''
	target_person_decrypt = ''
	playsound('HastaLuego.mp3')
	playsound('Bye.mp3')
	time.sleep(2)
	decrypt.destroy()


def person1_actv():

	global target_person

	if person1_var.get() != '':

		person1_activated = True
		person2_activated = False
		person3_activated = False
		person4_activated = False
		target_person = person1_var.get()
		playsound('bambu_click.mp3')
		playsound('activatedPersonA.mp3')

	elif person1_var.get() == '':

		playsound('EnterUsername.mp3')


def person2_actv():

	global target_person

	if person2_var.get() != '':

		person1_activated = False
		person2_activated = True
		person3_activated = False
		person4_activated = False
		target_person = person2_var.get()
		playsound('bambu_click.mp3')
		playsound('activatedPersonA.mp3')

	elif person2_var.get() == '':

		playsound('EnterUsername.mp3')

def person3_actv():

	global target_person

	if person3_var.get() != '':

		person1_activated = False
		person2_activated = False
		person3_activated = True
		person4_activated = False
		target_person = person3_var.get()
		playsound('bambu_click.mp3')
		playsound('activatedPersonA.mp3')

	elif person3_var.get() == '':

		playsound('EnterUsername.mp3')

def person4_actv():

	global target_person

	if person4_var.get() != '':

		person1_activated = False
		person2_activated = False
		person3_activated = False
		person4_activated = True
		target_person = person4_var.get()
		playsound('bambu_click.mp3')
		playsound('activatedPersonA.mp3')

	elif person4_var.get() == '':

		playsound('EnterUsername.mp3')


def person1c_actv():

	global target_person_decrypt

	if person1c_var.get() != '':

		person1c_activated = True
		person2c_activated = False
		person3c_activated = False
		person4c_activated = False
		target_person_decrypt = person1c_var.get()
		playsound('button_click.mp3')
		playsound('activatedPersonB.mp3')

	elif person1c_var.get() == '':

		playsound('activatePersonReceiveMessages.mp3')

def person2c_actv():

	global target_person_decrypt

	if person2c_var.get() != '':

		person1c_activated = False
		person2c_activated = True
		person3c_activated = False
		person4c_activated = False
		target_person_decrypt = person2c_var.get()
		playsound('button_click.mp3')
		playsound('activatedPersonB.mp3')

	elif person2c_var.get() == '':

		playsound('activatePersonReceiveMessages.mp3')

def person3c_actv():

	global target_person_decrypt

	if person3c_var.get() != '':

		person1c_activated = False
		person2c_activated = False
		person3c_activated = True
		person4c_activated = False
		target_person_decrypt = person3c_var.get()
		playsound('button_click.mp3')
		playsound('activatedPersonB.mp3')

	elif person3c_var.get() == '':

		playsound('activatePersonReceiveMessages.mp3')

def person4c_actv():

	global target_person_decrypt

	if person4c_var.get() != '':

		person1c_activated = False
		person2c_activated = False
		person3c_activated = False
		person4c_activated = True
		target_person_decrypt = person4c_var.get()
		playsound('button_click.mp3')
		playsound('activatedPersonB.mp3')

	elif person4c_var.get() == '':

		playsound('activatePersonReceiveMessages.mp3')


def receiver_ramson_actv():

	global target_receiver_ramson

	if receiver_var.get() != '':

		target_receiver_ramson = receiver_var.get()
		playsound('bambu_click.mp3')

	elif receiver_var.get() == '':

		playsound('bambu_click.mp3')


# ------------------------------------------------------------------------------------------------------------------



decrypt = tk.Tk()

decrypt.title("BirdCipher Cryptographic Machine")
decrypt.geometry('1050x550')
decrypt.resizable(0, 0)

username_dbc = tk.StringVar()
password_dbc = tk.StringVar()
position_dbc = tk.StringVar()
player_answer_decrypt = tk.IntVar()
packet = tk.IntVar()
player_message_encrypt = tk.StringVar()
passw_em = tk.StringVar()
password_for_decrypt = tk.StringVar()
password_for_ramson = tk.StringVar()


person1_var = tk.StringVar()
person2_var = tk.StringVar()
person3_var = tk.StringVar()
person4_var = tk.StringVar()

person1c_var = tk.StringVar()
person2c_var = tk.StringVar()
person3c_var = tk.StringVar()
person4c_var = tk.StringVar()

receiver_var = tk.StringVar()

person1_activated = False
person2_activated = False
person3_activated = False
person4_activated = False
	

person1c_activated = False
person2c_activated = False
person3c_activated = False
person4c_activated = False

encrypt_buttonImg = tk.PhotoImage(file = "Encrypt-logo1.png")
decrypt_buttonImg = tk.PhotoImage(file = "Decrypt-logo1.png")
directory_browser = tk.PhotoImage(file = 'Browse directories.png')
ramson_instructions = tk.PhotoImage(file = 'Instructions.png')
generateRamsonKey_de = tk.PhotoImage(file = 'Generate RamsonBird Key.png')
bringRamsonKey_de = tk.PhotoImage(file = 'Bring RamsonBird key.png')
encryptFilesImage = tk.PhotoImage(file = 'Decrypt files.png')
decryptFilesImage = tk.PhotoImage(file = 'Encrypt files.png')
bc_logo_loginImage = tk.PhotoImage(file = 'BirdCipher Machine-logoLogin-white1.png')
hashingImage = tk.PhotoImage(file = 'Hashing-logo-white1.png')

notebk = ttk.Notebook(decrypt)
notebk.pack(expand=True)

hr = ttk.Frame(notebk, width = 1050, height=540)
hr.configure(style = "BW.TLabel")
hr.pack(fill = 'both', expand = True)
notebk.add(hr, text = " Login")

passcheck = ttk.Frame(notebk, width = 1050, height = 540)
passcheck.pack(fill = 'both', expand = True)
notebk.add(passcheck, text = '   Password Checking')

hashing = ttk.Frame(notebk, width = 1050, height = 540)
hashing.pack(fill = 'both', expand = True)
notebk.add(hashing, text = '   Hashing')

fr0 = ttk.Frame(notebk, width = 1050, height = 540)
fr0.pack(fill = 'both', expand = True)
notebk.add(fr0, text = '   Cybersecurity and social engineering')
		
fr = ttk.Frame(notebk, width = 1050, height=540)
fr.configure(style = "BW.TLabel")
fr.pack(fill = 'both', expand = True)
notebk.add(fr, text = "      Classic Cryptography")

fr2 = ttk.Frame(notebk, width = 1150, height = 540)
fr2.pack(fill = 'both', expand = True)
notebk.add(fr2, text = "   Encryption Machine")

fr3 = ttk.Frame(notebk, width = 1050, height = 540)
fr3.pack(fill = 'both', expand = True)
notebk.add(fr3, text = "   Decryption Machine")

fr0a = ttk.Frame(notebk, width = 1050, height = 540)
fr0a.pack(fill = 'both', expand = True)
notebk.add(fr0a, text = '   RamsonBird Machine')

login_label = tk.Label(hr, text = 'Log in the BirdCipher Machine!!', font = ("Comic Sans MS", 14))
login_label.config(fg = "#7e086c")
login_label.place(x = 50, y = 20)

username_label = tk.Label(hr, text = 'Username', font = ('Comic Sans MS', 12))
username_label.config(fg = "#7e086c")
username_label.place(x = 50, y = 70)

username_entry = tk.Entry(hr, textvariable = username_dbc, font = ('Comic Sans MS', 15), justify = 'center')
username_entry.config(bg = '#050005', fg = '#f7a6f1')
username_entry.place(x = 50, y = 100)

password_label = tk.Label(hr, text = 'Password', font = ('Comic Sans MS', 12))
password_label.config(fg = "#7e086c")
password_label.place(x = 50, y = 160)

password_entry = tk.Entry(hr, textvariable = password_dbc, font = ('Comic Sans MS', 15), justify = 'center')
password_entry.config(bg = '#050005', fg = '#f7a6f1', show = '*')
password_entry.place(x = 50, y = 190)

position_label = tk.Label(hr, text = 'Position', font = ('Comic Sans MS', 12))
position_label.config(fg = "#7e086c")
position_label.place(x = 50, y = 240)

position_entry = tk.Entry(hr, textvariable = position_dbc, font = ('Comic Sans MS', 15), justify = 'center')
position_entry.config(bg = '#050005', fg = '#f7a6f1')
position_entry.place(x = 50, y = 270)

send_login_data = tk.Button(hr, text = 'Send login data', command = lambda:login_user())
send_login_data.config(fg = '#7e086c', font = ('Comic Sans MS', 9))
send_login_data.place(x = 200, y = 320)

hash256_passw = tk.Label(hr, text = 'Your password hash (SHA 256) is:', font = ('Comic Sans MS', 12))
hash256_passw.config(fg = "#7e086c")
hash256_passw.place(x = 20, y = 440)

hash256_passw_label = tk.Label(hr, font = ('Comic Sans MS', 8), width = 62)
hash256_passw_label.config(bg = '#050005', fg = '#f7a6f1')
hash256_passw_label.place(x = 20, y = 480)

hash256passw_copy_btt = tk.Button(hr, text = 'Copy hash to clipboard')
hash256passw_copy_btt.config(fg = '#7e086c', font = ('Comic Sans MS', 9))
hash256passw_copy_btt.place(x = 480, y = 475)

close_machine_from_login = tk.Button(hr, text = '  Close the BirdCipher Machine  ', command = lambda:closeMachine())
close_machine_from_login.config(fg = '#7e086c', font = ('Comic Sans MS', 14))
close_machine_from_login.place(x = 700, y = 460)

bc_logo_login = tk.Button(hr, image = bc_logo_loginImage, command = lambda:login_user())
bc_logo_login.config(bg = '#260223')
bc_logo_login.place(x = 420, y = 30)

# ----------------------------------------------------


def check_password():

	# Required: A descriptive user agent must be set describing the application consuming
	#   the HIBP API
	pyhibp.set_user_agent(ua="Awesome application/0.0.1 (An awesome description)")

	# Check a password to see if it has been disclosed in a public breach corpus
	resp = pw.is_password_breached(password = password_user_entry.get())

	if resp:

		result_check.delete(1.0, tk.END)
		result_check.insert(tk.END, 'Password breached! \n\nThis password was used the \nfollowing time(s) before: \n\nThe Have I Been Pwned Portal recommends that you change \nor improve your password')
		result_check.config(fg = '#ef1d13')
		time_breached.config(text = resp)
		time_breached.config(fg = '#ef1d13', font = ('Comic Sans MS', 30))
		playsound('ContrasenaInsegura.mp3')
		time.sleep(2)
		playsound('ImprovePass.mp3')

	elif resp == False:

		result_check.delete(1.0, tk.END)
		result_check.insert(tk.END, 'Secure password! \n\nThis password was used the \nfollowing time(s) before: \n\nThe Have I Been Pwned Portal recommends that you can use \nyour password safely')
		result_check.config(fg = '#7ed2ef')
		time_breached.config(text = resp)
		time_breached.config(fg = '#7ed2ef', width = 5, height = 1, font = ('Comic Sans MS', 45))
		playsound('ContrasenaSegura.mp3')
		time.sleep(2)
		playsound('SafePass.mp3')


def passchecking_explanation():

	playsound('explicacion_passwordHIBP.mp3')
	playsound('passcheck_explant.mp3')
	

password_checking_logo = tk.PhotoImage(file = 'Password checking-logo-white1.png')
hibp1_logo = tk.PhotoImage(file = 'hibp1.png')
hibp_info_logo = tk.PhotoImage(file = 'Password Check Info-logo-white1.png')
padlock_image = tk.PhotoImage(file = 'Candado4a.png')
password_user_entry = tk.StringVar()

password_checking_button = tk.Button(passcheck, image = password_checking_logo, command = lambda:check_password())
password_checking_button.config(bg = '#067297')
password_checking_button.place(x = 610, y = 20)

hibp_logo = tk.Label(passcheck, image = hibp1_logo)
hibp_logo.place(x = 610, y = 400)

hibp_info = tk.Button(passcheck, image = hibp_info_logo, command = lambda:passchecking_explanation())
hibp_info.config(bg = '#067297')
hibp_info.place(x = 920, y = 401)

enter_password_label = tk.Label(passcheck, text = 'Enter your password')
enter_password_label.config(fg = '#067297', font = ('Comic Sans MS', 14))
enter_password_label.place(x = 40, y = 30)

enter_password_entry = tk.Entry(passcheck, textvariable = password_user_entry, font = ('Comic Sans MS', 14), justify = 'center')
enter_password_entry.config(bg = '#050005', fg = '#7ed2ef', width = 25)
enter_password_entry.place(x = 40, y = 70)

result_check_label = tk.Label(passcheck, text = 'Results report', font = ('Comic Sans MS', 14))
result_check_label.config(fg = '#067297')
result_check_label.place(x = 40, y = 130)

result_check = tk.Text(passcheck, font = ('Comic Sans MS', 14))
result_check.config(bg = '#050005', fg = '#7ed2ef', width = 23, height = 10, padx = 15)
result_check.place(x = 40, y = 170)

times_label = tk.Label(passcheck, text = 'Times used before: ', font = ('Comic Sans MS', 14))
times_label.config(fg = '#067297')
times_label.place(x = 400, y = 220)

time_breached = tk.Label(passcheck, text = '', font = ('Comic Sans MS', 30), justify = 'center')
time_breached.config(bg = '#050005', fg = '#7ed2ef', width = 7, height = 3)
time_breached.place(x = 400, y = 260)

padlock = tk.Label(passcheck, image = padlock_image)
padlock.place(x = 387, y = 25)



# ------------------------------------------------------

def hashingExecution():

	global algorithm_hashing

	archive_url_funct = archive_url.get()

	if archive_url_funct == '':

		wbdatos = bytes(textToHashing.get('1.0', 'end-1c'), 'utf-8')
		hd = hashlib.new(algorithm_hashing[hashOption.get()], wbdatos)
		hash200 = HASH.generaHash(hd)
		labelHashResult.config(text = hash200)

	elif archive_url_funct != '':

		hashForFile = hash_file_birdcipher(archive_url_funct, algorithm_hashing[hashOption.get()])
		labelHashResult.config(text = hashForFile)



hashOption = tk.IntVar()
archive_url = tk.StringVar()
algorithm_hashing = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'shake_128', 'shake_256']


hashing_logo = tk.Button(hashing, image = hashingImage, command = lambda:hashingExecution())
hashing_logo.config(bg = '#330237')
hashing_logo.place(x = 40, y = 15)

labelPlayerLoginHashing = tk.Label(hashing, text = "Welcome, ", font = ("Comic Sans MS", 11))
labelPlayerLoginHashing.config(fg = "#eba5f1", bg = "#050005")
labelPlayerLoginHashing.place(x = 540, y = 20)

labelTextHashing = tk.Label(hashing, text = 'Enter the text to hash:', font = ("Comic Sans MS", 14))
labelTextHashing.config(fg = '#7a0684')
labelTextHashing.place(x = 540, y = 55)

textToHashing = tk.Text(hashing, font = ('Comic Sans MS', 14))
textToHashing.config(bg = '#050005', fg = '#eba5f1', width = 34, height = 5, padx = 30)
textToHashing.place(x = 530, y = 90)

labelHashEntry = tk.Label(hashing, text = 'The hash of your message/file is:', font = ("Comic Sans MS", 14))
labelHashEntry.config(fg = '#7a0684')
labelHashEntry.place(x = 40, y = 440)

labelHashResult = tk.Label(hashing, font = ('Comic Sans MS', 9), width = 130)
labelHashResult.config(bg = '#050005', fg = '#f7a6f1')
labelHashResult.place(x = 40, y = 480)

logoBrowseDirectoriesHash = tk.Button(hashing, image = directory_browser, command = lambda:selectDirectoryHash())
logoBrowseDirectoriesHash.place(x = 925, y = 365)

labelArchive = tk.Label(hashing, text = 'The URL of your file is:', font = ("Comic Sans MS", 14))
labelArchive.config(fg = '#7a0684')
labelArchive.place(x = 540, y = 360)

archiveURLShow = tk.Entry(hashing, textvariable = archive_url, font = ('Comic Sans MS', 7), width = 62)
archiveURLShow.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
archiveURLShow.place(x = 530, y = 400)

rad_button_md5 = tk.Radiobutton(hashing, text = 'md5', variable = hashOption, value = 0)
rad_button_md5.config(font = ('Comic Sans MS', 10), justify = 'left', fg = '#7a0684')
rad_button_md5.place(x = 540, y = 250)

rad_button_sha1 = tk.Radiobutton(hashing, text = 'sha1', variable = hashOption, value = 1)
rad_button_sha1.config(font = ('Comic Sans MS', 10), justify = 'left', fg = '#7a0684')
rad_button_sha1.place(x = 610, y = 250)

rad_button_sha224 = tk.Radiobutton(hashing, text = 'sha224', variable = hashOption, value = 2)
rad_button_sha224.config(font = ('Comic Sans MS', 10), justify = 'left', fg = '#7a0684')
rad_button_sha224.place(x = 680, y = 250)

rad_button_sha256 = tk.Radiobutton(hashing, text = 'sha256', variable = hashOption, value = 3)
rad_button_sha256.config(font = ('Comic Sans MS', 10), justify = 'left', fg = '#7a0684')
rad_button_sha256.place(x = 770, y = 250)

rad_button_sha384 = tk.Radiobutton(hashing, text = 'sha384', variable = hashOption, value = 4)
rad_button_sha384.config(font = ('Comic Sans MS', 10), justify = 'left', fg = '#7a0684')
rad_button_sha384.place(x = 540, y = 300)

rad_button_sha512 = tk.Radiobutton(hashing, text = 'sha512', variable = hashOption, value = 5)
rad_button_sha512.config(font = ('Comic Sans MS', 10), justify = 'left', fg = '#7a0684')
rad_button_sha512.place(x = 620, y = 300)

rad_button_shake_128 = tk.Radiobutton(hashing, text = 'shake_128', variable = hashOption, value = 6)
rad_button_shake_128.config(font = ('Comic Sans MS', 10), justify = 'left', fg = '#7a0684')
rad_button_shake_128.place(x = 690, y = 300)

rad_button_shake_256 = tk.Radiobutton(hashing, text = 'shake_256', variable = hashOption, value = 7)
rad_button_shake_256.config(font = ('Comic Sans MS', 10), justify = 'left', fg = '#7a0684')
rad_button_shake_256.place(x = 780, y = 300)



# --------------------------------------------------------


mode_classic = ''
translate = ''
keyApply = 0
keyApply_transLinear = 0
translate_tl = ''
translation = ''

keyCaesarAnswer = tk.IntVar()
keyLinearTranspostAnswer = tk.IntVar()
keyInverseTranspostAnswer = tk.IntVar()



def reverse_adjust():

	global translation

	translation = reverse_cipher_apl(plaintext.get("1.0", "end-1c"))
	ciphertext.delete(1.0, tk.END)
	ciphertext.insert(tk.END, translation)

def enc_classic():

	global mode_classic

	mode_classic = 'e'


def dec_classic():

	global mode_classic

	mode_classic = 'd'


def caesarApply():

	global mode_classic
	global translation
	global keyApply

	if mode_classic == 'e':

		message_apply = plaintext.get('1.0', 'end-1c')

	elif mode_classic == 'd':

		message_apply = ciphertext.get('1.0', 'end-1c')

	elif mode_classic == '':

		playsound('Hello.mp3')


	if mode_classic != '':

		keyApply = keyCaesarAnswer.get()

		if keyApply != 0:

			translation = getTranslatedMessage(mode_classic, message_apply, keyCaesarAnswer.get())

			# ciphertext.delete(1.0, tk.END)
			# ciphertext.insert(tk.END, translate)

			if mode_classic == 'e':

				ciphertext.delete(1.0, tk.END)
				ciphertext.insert(tk.END, translation)

			elif mode_classic == 'd':

				plaintext.delete(1.0, tk.END)
				plaintext.insert(tk.END, translation)


		elif keyApply == 0:

			playsound('Hello.mp3')


def TranspositionApply():

	global mode_classic
	global translation
	global keyApply_transLinear
		

	if mode_classic == 'e':

		message_apply_tl = plaintext.get('1.0', 'end-1c')
		print(len(message_apply_tl))

	elif mode_classic == 'd':

		message_apply_tl = ciphertext.get('1.0', 'end-1c')

	elif mode_classic == '':

		playsound('Hello.mp3')

	if mode_classic == 'e':

		keyApply_transLinear = keyLinearTranspostAnswer.get()

		if keyApply_transLinear != 0:

			translation = encryptMessageTransLinear(keyApply_transLinear, message_apply_tl)

			ciphertext.delete(1.0, tk.END)
			ciphertext.insert(tk.END, translation)

	if mode_classic == 'd':

		keyApply_transLinear = keyLinearTranspostAnswer.get()

		if keyApply_transLinear != 0:

			translation = decryptMessages(keyApply_transLinear, message_apply_tl)
			plaintext.delete(1.0, tk.END)
			plaintext.insert(tk.END, translation)


def TranspositionInverseApply():

	global mode_classic
	global translation
	global keyApply_transLinear
		

	if mode_classic == 'e':

		message_apply_tl = plaintext.get('1.0', 'end-1c')
		print(len(message_apply_tl))

	elif mode_classic == 'd':

		message_apply_tl = ciphertext.get('1.0', 'end-1c')

	elif mode_classic == '':

		playsound('Hello.mp3')

	if mode_classic == 'e':

		keyApply_transInverse = keyInverseTranspostAnswer.get()

		if keyApply_transInverse != '':

			translation = TranspositionColumnarInverse(keyApply_transInverse, message_apply_tl)
			ciphertext.delete(1.0, tk.END)
			ciphertext.insert(tk.END, translation)



def copyText():

	pyperclip.copy(translation)


titleBirdCipherMachine = tk.Label(fr, text = "Enter your message to encrypt (Plaintext)", font = ("Comic Sans MS", 12))
titleBirdCipherMachine.config(fg = "#7e086c")
titleBirdCipherMachine.place(x = 70, y = 3)

scrollPlaintext = ttk.Scrollbar(fr, orient = tk.VERTICAL)
scrollPlaintext.place(x = 683, y = 30, height = 85)

plaintext = tk.Text(fr, font = ("Comic Sans MS", 11))
plaintext.config(bg = '#050005', fg = '#FFFFFF', width = 62, height = 4, padx = 30)
plaintext.place(x = 60, y = 30)
scrollPlaintext.config(command = plaintext.yview)

titleBirdCipherMachine2 = tk.Label(fr, text = 'Your encrypted message (ciphertext) is: ', font = ("Comic Sans MS", 12))
titleBirdCipherMachine2.config(fg = "#7e086c")
titleBirdCipherMachine2.place(x = 70, y = 124)

scrollCiphertext = tk.Scrollbar(fr, orient = tk.VERTICAL)
scrollCiphertext.place(x = 683, y = 160, height = 75)

ciphertext = tk.Text(fr, font = ("Comic Sans MS", 11))
ciphertext.config(bg = '#050005', fg = '#FFFFFF', width = 62, height = 4, padx = 30)
ciphertext.place(x = 60, y = 160)
scrollCiphertext.config(command = ciphertext.yview)

nicknameCuad = tk.Entry(fr, textvariable=player_answer_decrypt, font = ("Comic Sans MS", 13), justify = "center")
#nicknameCuad.config(bg="black", fg="green")
#nicknameCuad.place(x=50, y=55)
#nicknameCuad.pack(padx = 30, pady = 30)
nicknameCuad.config(bg = '#050005', fg = '#7e086c')
nicknameCuad.place(x = 790, y = 90)
	
encrypt_button_classic = tk.Button(fr, image = encrypt_buttonImg, command = lambda:enc_classic())
encrypt_button_classic.config(fg = '#1af017')
encrypt_button_classic.place(x = 800, y = 140)
	
decrypt_button_classic = tk.Button(fr, image = decrypt_buttonImg, command = lambda:dec_classic())
decrypt_button_classic.config(fg = '#1af017')
decrypt_button_classic.place(x = 900, y = 140)
	
imagen_caesar_cipher = tk.PhotoImage(file = 'Imagen_caesar.png')
imageCaesar = tk.PhotoImage(file = "Caesar Cipher-logo1.png")
imageReverse = tk.PhotoImage(file = "Reverse Cipher-logo1.png")
imageLinearTransposition = tk.PhotoImage(file = "Linear Transposition -logo1.png")
imageInverseTransposition = tk.PhotoImage(file = "Inverse Transposition -logo1.png")
imageLives = tk.PhotoImage(file = "Lives-logo1.png")
cryptoMachineImage = tk.PhotoImage(file = "Cryptographic Machine-logo1.png")
ramson_image = tk.PhotoImage(file = 'RamsonBird_MachineImage.png')

imagen_caesar_cipher_lab = tk.Label(fr, image = imagen_caesar_cipher)
#imagen_caesar_cipher_lab.config(bg = '#FFFFFF')
imagen_caesar_cipher_lab.place(x = 30, y = 265)

buttonReverse = tk.Button(fr, image = imageReverse, command = lambda:reverse_adjust())
buttonReverse.place(x = 195, y = 260)

buttonCaesar = tk.Button(fr, image = imageCaesar, command = lambda:caesarApply())
buttonCaesar.place(x = 300, y = 260)

buttonLinearTransposition = tk.Button(fr, image = imageLinearTransposition, command = lambda:TranspositionApply())
buttonLinearTransposition.place(x = 400, y = 260)

buttonInverseTransposition = tk.Button(fr, image = imageInverseTransposition, command = lambda:TranspositionInverseApply())
buttonInverseTransposition.place(x= 530, y = 260)

# buttonLives = tk.Button(fr, image = imageLives, command = lambda:livesAudio())
# buttonLives.place(x = 615, y = 300)

keyCaesar = tk.Entry(fr, textvariable = keyCaesarAnswer, font = ("Comic Sans MS", 13), justify = "center", width = 8)
keyCaesar.config(bg = "#050005", fg = '#f90417')
keyCaesar.place(x = 300, y = 360)

keyLinearTransposition = tk.Entry(fr, textvariable = keyLinearTranspostAnswer, font = ("Comic Sans MS", 13), justify = "center", width = 11)
keyLinearTransposition.config(bg = "#050005", fg = "#a8f6a4")
keyLinearTransposition.place(x = 400, y = 360)

keyInverseTransposition = tk.Entry(fr, textvariable = keyInverseTranspostAnswer, font = ("Comic Sans MS", 13), justify = "center", width = 13)
keyInverseTransposition.config(bg = "#050005", fg = "#a4f6f0")
keyInverseTransposition.place(x = 530, y = 360)

labelQuestionKey = tk.Label(fr, text = "Enter your password", font = ("Comic Sans MS", 13))
labelQuestionKey.config(fg = "#7e086c")
labelQuestionKey.place(x = 805, y = 50)

labelPlayerBCM = tk.Label(fr, text = "Welcome, ", font = ("Comic Sans MS", 11))
labelPlayerBCM.config(fg = "#eba5f1", bg = "#050005")
labelPlayerBCM.place(x = 780, y = 10)

imageCryptographicMachine = tk.Button(fr, image = cryptoMachineImage, command = lambda:copyText())
imageCryptographicMachine.place(x = 730, y = 230)

closeMachineButton = tk.Button(fr, text = "Close the BirdCipher Cryptographic Machine", font = ("Comic Sans MS", 12), command = lambda:closeMachine())
closeMachineButton.place(x = 700, y = 475)
closeMachineButton.config(fg = "#7e086c")


# ---------------

def play_social_eng_audio():

	playsound(social_eng_audio[index_social_eng_choose])

def send_answer_social_eng():

	global feathers

	if varOption.get() == correct_answers_social_eng[index_social_eng_choose]:

		playsound('wonFeather.mp3')
		feathers = feathers + 1
		updatePlayer_feathers()
		labelFeathers.config(text = feathers)
		answer_button_social_eng.config(state = 'disabled')

	elif varOption.get() != correct_answers_social_eng[index_social_eng_choose]:

		playsound('lostFeather.mp3')
		answer_button_social_eng.config(state = 'disabled')


counter_social_eng = counter_social_eng + 1
index_social_eng = list(range(44))
index_social_eng_choose = index_social_eng[counter_social_eng]
img_social_eng = tk.PhotoImage(file = imagenes_ing_social[index_social_eng_choose])
varOption = tk.IntVar()

img_social_eng_label = tk.Button(fr0, image = img_social_eng, command = lambda:play_social_eng_audio())
img_social_eng_label.place(x = 30, y = 30)
img_social_eng_label.config(bg = '#20011c')

rad_button1 = tk.Radiobutton(fr0, text = tests_ing_social[index_social_eng_choose][0], variable = varOption, value = 0)
rad_button1.place(x = 550, y = 40)
rad_button1.config(font = ('Comic Sans MS', 9), justify = 'left')

rad_button2 = tk.Radiobutton(fr0, text = tests_ing_social[index_social_eng_choose][1], variable = varOption, value = 1)
rad_button2.place(x = 550, y = 80)
rad_button2.config(font = ('Comic Sans MS', 9), justify = 'left')

rad_button3 = tk.Radiobutton(fr0, text = tests_ing_social[index_social_eng_choose][2], variable = varOption, value = 2)
rad_button3.place(x = 550, y = 120)
rad_button3.config(font = ('Comic Sans MS', 9), justify = 'left')

rad_button4 = tk.Radiobutton(fr0, text = tests_ing_social[index_social_eng_choose][3], variable = varOption, value = 3)
rad_button4.place(x = 550, y = 160)
rad_button4.config(font = ('Comic Sans MS', 9), justify = 'left')

answer_button_social_eng = tk.Button(fr0, text = 'Send answer', command = lambda:send_answer_social_eng())
answer_button_social_eng.place(x = 600, y = 200)
answer_button_social_eng.config(fg = 'purple', font = ('Comic Sans MS', 9))
	

# ---------------

	
encryption_machine_logo = tk.PhotoImage(file = "Send Encrypted Message-logo.png")
generate_key_image = tk.PhotoImage(file = "Generate Key-logo.png")
encrypt_message_image = tk.PhotoImage(file = "Encrypt Message-logo1.png")
person1_image = tk.PhotoImage(file = 'Person1.png')
person2_image = tk.PhotoImage(file = 'Person2.png')
person3_image = tk.PhotoImage(file = 'Person3.png')
person4_image = tk.PhotoImage(file = 'Person4.png')
receiver_ramson_image = tk.PhotoImage(file = 'Receiver.png')

scrollVetrn = ttk.Scrollbar(fr2, orient = tk.VERTICAL)
#cipher_text2['yscrollcommand'] = scrollVetrn.set()
scrollVetrn.place(x = 710, y = 40, height = 70)

cipher_text2 = tk.Text(fr2, font = ("Comic Sans MS", 10), width = 73)
cipher_text2.config(bg = '#050005', fg = '#FFFFFF', padx = 30)
cipher_text2.place(x = 60, y = 40, height = 70)
scrollVetrn.config(command = cipher_text2.yview)



key_fernet_label = tk.Label(fr2, text = "Key for Fernet algorithm")
key_fernet_label.config(font = ("Comic Sans MS", 12), fg = "#7e086c")
key_fernet_label.place(x = 65, y = 120)

key_fernet_text = tk.Label(fr2, text = "", font = ("Comic Sans MS", 10), width = 80)
key_fernet_text.config(bg = "#050005", fg = "#FFFFFF")
key_fernet_text.place(x = 60, y = 150)

encrypted_label = tk.Label(fr2, text = "Your encrypted message is: ")
encrypted_label.config(font = ("Comic Sans MS", 12), fg = "#7e086c")
encrypted_label.place(x = 65, y = 180)
	
cipher_text2_encrp = tk.Text(fr2, font = ("Comic Sans MS", 10), width = 73)
cipher_text2_encrp.config(bg = '#050005', fg = '#FFFFFF', padx = 30)
cipher_text2_encrp.place(x = 60, y = 210, height = 80)

scrollVetrn2 = tk.Scrollbar(fr2, command = cipher_text2_encrp.yview)
scrollVetrn2.place(x = 710, y = 210)

nicknameCuad2 = tk.Entry(fr2, textvariable = passw_em, font = ("Comic Sans MS", 13), justify = "center")
nicknameCuad2.config(bg = '#050005', fg = '#7e086c')
nicknameCuad2.place(x = 790, y = 100)
	
fernet_key_button = tk.Button(fr2, image = generate_key_image, font = ("Comic Sans MS", 8), command = lambda:fernet_key_gen())
fernet_key_button.config(fg = '#7e086c')
fernet_key_button.place(x = 800, y = 150)
	
fernet_encryption_message = tk.Button(fr2, image = encrypt_message_image, font = ("Comic Sans MS", 8), command = lambda:fernet_encryption_function())
fernet_encryption_message.config(fg = '#1af017')
fernet_encryption_message.place(x = 900, y = 150)

imagen_caesar_cipher_lab2 = tk.Label(fr2, image = imagen_caesar_cipher)
imagen_caesar_cipher_lab2.place(x = 30, y = 300)

titleBirdCipherMachine2 = tk.Label(fr2, text = "BirdCipher Encryption Machine: a tool to guarantee the confidentiality of your messages", font = ("Comic Sans MS", 12))
titleBirdCipherMachine2.config(fg = "#7e086c")
titleBirdCipherMachine2.place(x = 70, y = 8)

buttonPoints2 = tk.Button(fr2, image = imageCaesar, command = lambda:pointsAudio())
buttonPoints2.place(x = 210, y = 300)

buttonPerson1a = tk.Button(fr2, image = person1_image, command = lambda:person1_actv())
buttonPerson1a.place(x = 300, y = 300)

buttonPerson2a = tk.Button(fr2, image = person2_image, command = lambda:person2_actv())
buttonPerson2a.place(x = 400, y = 300)

buttonPerson3a = tk.Button(fr2, image = person3_image, command = lambda:person3_actv())
buttonPerson3a.place(x= 500, y = 300)

buttonPerson4a = tk.Button(fr2, image = person4_image, command = lambda:person4_actv())
buttonPerson4a.place(x = 615, y = 300)

labelPoints2 = tk.Label(fr2, text = points, font = ("Comic Sans MS", 13), justify = "center", width = 6)
labelPoints2.config(bg = "#050005", fg = "#7e086c")
labelPoints2.place(x = 212, y = 410)

person1 = tk.Entry(fr2, textvariable = person1_var, font = ("Comic Sans MS", 13), justify = "center", width = 8)
person1.config(bg = "#050005", fg = "#7e086c")
person1.place(x = 300, y = 410)

person2 = tk.Entry(fr2, textvariable = person2_var, font = ("Comic Sans MS", 13), justify = "center", width = 8)
person2.config(bg = "#050005", fg = "#7e086c")
person2.place(x = 400, y = 410)

person3 = tk.Entry(fr2, textvariable = person3_var, font = ("Comic Sans MS", 13), justify = "center", width = 8)
person3.config(bg = "#050005", fg = "#7e086c")
person3.place(x = 500, y = 410)

person4 = tk.Entry(fr2, textvariable = person4_var, font = ("Comic Sans MS", 13), justify = "center", width = 7)
person4.config(bg = "#050005", fg = "#7e086c")
person4.place(x = 617, y = 410)

labelQuestionKey2 = tk.Label(fr2, text = "Enter your password", font = ("Comic Sans MS", 13))
labelQuestionKey2.config(fg = "#7e086c")
labelQuestionKey2.place(x = 805, y = 60)

labelPlayerBCM2 = tk.Label(fr2, text = "Welcome", font = ("Comic Sans MS", 11))
labelPlayerBCM2.config(fg = "#eba5f1", bg = "#050005")
labelPlayerBCM2.place(x = 780, y = 20)

imageCryptographicMachine2 = tk.Button(fr2, image = encryption_machine_logo, command = lambda:send_message())
imageCryptographicMachine2.place(x = 760, y = 290)
imageCryptographicMachine2.config(bg = "#3f0322")

closeMachineButton2 = tk.Button(fr2, text = "Close the BirdCipher Cryptographic Machine", font = ("Comic Sans MS", 12), command = lambda:closeMachine())
closeMachineButton2.place(x = 250, y = 460)
closeMachineButton2.config(fg = "#7e086c")

# --------------

cipher_text3 = tk.Text(fr3, font = ("Comic Sans MS", 10), width = 72, height = 4)
cipher_text3.config(bg = '#050005', fg = '#FFFFFF', padx = 8)
cipher_text3.place(x = 60, y = 40)

scrollVetrn3 = tk.Scrollbar(fr3, command = cipher_text3.yview)
scrollVetrn3.place(x = 710, y = 40)

nicknameCuad3 = tk.Entry(fr3, textvariable=password_for_decrypt, font = ("Comic Sans MS", 13), justify = "center")
nicknameCuad3.config(bg = '#050005', fg = '#7e086c')
nicknameCuad3.place(x = 790, y = 100)

decrypt_button3 = tk.Button(fr3, image = encrypt_buttonImg, font = ("Comic Sans MS", 8), command = lambda:displayCiphertext())
decrypt_button3.config(fg = '#1af017')
decrypt_button3.place(x = 800, y = 150)
	
decrypt_listen3 = tk.Button(fr3, image = decrypt_buttonImg, font = ("Comic Sans MS", 8), command = lambda:listen_decrypt_text())
decrypt_listen3.config(fg = '#1af017')
decrypt_listen3.place(x = 900, y = 150)

imagen_caesar_cipher_lab3 = tk.Label(fr3, image = imagen_caesar_cipher)
#imagen_caesar_cipher_lab.config(bg = '#FFFFFF')
imagen_caesar_cipher_lab3.place(x = 30, y = 300)

titleBirdCipherMachine3 = tk.Label(fr3, text = "BirdCipher Decryption Machine", font = ("Comic Sans MS", 12))
titleBirdCipherMachine3.config(fg = "#7e086c")
titleBirdCipherMachine3.place(x = 70, y = 8)

key_fernet_label2 = tk.Label(fr3, text = "Key for Fernet algorithm")
key_fernet_label2.config(font = ("Comic Sans MS", 12), fg = "#7e086c")
key_fernet_label2.place(x = 65, y = 120)

key_fernet_text2 = tk.Label(fr3, text = "", font = ("Comic Sans MS", 10), width = 80)
key_fernet_text2.config(bg = "#050005", fg = "#FFFFFF")
key_fernet_text2.place(x = 60, y = 150)

encrypted_label2 = tk.Label(fr3, text = "Your decrypted message is: ")
encrypted_label2.config(font = ("Comic Sans MS", 12), fg = "#7e086c")
encrypted_label2.place(x = 65, y = 180)
	
cipher_text2_encrp2 = tk.Text(fr3, font = ("Comic Sans MS", 10), width = 80)
cipher_text2_encrp2.config(bg = '#050005', fg = '#FFFFFF', padx = 8)
cipher_text2_encrp2.place(x = 60, y = 210, height = 80)

scrollVetrn4 = tk.Scrollbar(fr3, command = cipher_text2_encrp2.yview)
scrollVetrn4.place(x = 710, y = 210)

buttonPoints3 = tk.Button(fr3, image = imageCaesar, command = lambda:pointsAudio())
buttonPoints3.place(x = 210, y = 300)

buttonPerson1b = tk.Button(fr3, image = person1_image, command = lambda:person1c_actv())
buttonPerson1b.place(x = 300, y = 300)

buttonPerson2b = tk.Button(fr3, image = person2_image, command = lambda:person2c_actv())
buttonPerson2b.place(x = 400, y = 300)

buttonPerson3b = tk.Button(fr3, image = person3_image, command = lambda:person3c_actv())
buttonPerson3b.place(x= 500, y = 300)

buttonPerson4b = tk.Button(fr3, image = person4_image, command = lambda:person4c_actv())
buttonPerson4b.place(x = 615, y = 300)

labelPoints3 = tk.Label(fr3, text = points, font = ("Comic Sans MS", 13), justify = "center", width = 6)
labelPoints3.config(bg = "#050005", fg = "#7e086c")
labelPoints3.place(x = 212, y = 410)

person1_c = tk.Entry(fr3, text = person1c_var, font = ("Comic Sans MS", 13), justify = "center", width = 8)
person1_c.config(bg = "#050005", fg = "#7e086c")
person1_c.place(x = 300, y = 410)

person2_c = tk.Entry(fr3, text = person2c_var, font = ("Comic Sans MS", 13), justify = "center", width = 8)
person2_c.config(bg = "#050005", fg = "#7e086c")
person2_c.place(x = 400, y = 410)

person3_c = tk.Entry(fr3, text = person3c_var, font = ("Comic Sans MS", 13), justify = "center", width = 8)
person3_c.config(bg = "#050005", fg = "#7e086c")
person3_c.place(x = 500, y = 410)

person4_c = tk.Entry(fr3, text = person4c_var, font = ("Comic Sans MS", 13), justify = "center", width = 7)
person4_c.config(bg = "#050005", fg = "#7e086c")
person4_c.place(x = 617, y = 410)

labelQuestionKey3 = tk.Label(fr3, text = "Enter your password", font = ("Comic Sans MS", 13))
labelQuestionKey3.config(fg = "#7e086c")
labelQuestionKey3.place(x = 805, y = 60)

labelPlayerBCM3 = tk.Label(fr3, text = "Welcome, ", font = ("Comic Sans MS", 11))
labelPlayerBCM3.config(fg = "#eba5f1", bg = "#050005")
labelPlayerBCM3.place(x = 780, y = 20)

imageCryptographicMachine3 = tk.Button(fr3, image = cryptoMachineImage, command = lambda:bc_decription_machine())
imageCryptographicMachine3.place(x = 730, y = 260)

closeMachineButton3 = tk.Button(fr3, text = "Close the BirdCipher Cryptographic Machine", font = ("Comic Sans MS", 12), command = lambda:closeMachine())
closeMachineButton3.place(x = 250, y = 460)
closeMachineButton3.config(fg = "#7e086c")

# ---------------------------

ramsonBird_message = tk.Text(fr0a, font = ("Comic Sans MS", 10), width = 72, height = 4)
ramsonBird_message.config(bg = '#050005', fg = '#FFFFFF', padx = 30)
ramsonBird_message.place(x = 60, y = 40)

labelPlayerBCM4 = tk.Label(fr0a, text = "Welcome,", font = ("Comic Sans MS", 11))
labelPlayerBCM4.config(fg = "#eba5f1", bg = "#050005")
labelPlayerBCM4.place(x = 780, y = 20)

labelQuestionKey4 = tk.Label(fr0a, text = "Enter your password", font = ("Comic Sans MS", 13))
labelQuestionKey4.config(fg = "#7e086c")
labelQuestionKey4.place(x = 805, y = 60)

ramsonBird_password = tk.Entry(fr0a, textvariable=password_for_ramson, font = ("Comic Sans MS", 13), justify = "center")
ramsonBird_password.config(bg = '#050005', fg = '#7e086c')
ramsonBird_password.place(x = 790, y = 100)

ramsonBird_directory = tk.Button(fr0a, image = directory_browser, font = ("Comic Sans MS", 8), command = lambda:selectDirectory())
ramsonBird_directory.config(fg = '#1af017')
ramsonBird_directory.place(x = 800, y = 150)
	
ramsonBird_instructions = tk.Button(fr0a, image = ramson_instructions, font = ("Comic Sans MS", 8), command = lambda:listen_decrypt_text())
ramsonBird_instructions.config(fg = '#1af017')
ramsonBird_instructions.place(x = 930, y = 150)

ramsonBird_Image = tk.Label(fr0a, image = ramson_image)
ramsonBird_Image.config(bg = '#20011c')
ramsonBird_Image.place(x = 60, y = 280)

ramsonBirdMessageTitle = tk.Label(fr0a, text = "Enter your message for identifying the ramson action", font = ("Comic Sans MS", 12))
ramsonBirdMessageTitle.config(fg = "#7e086c")
ramsonBirdMessageTitle.place(x = 70, y = 8)

ramsonKeyTitle = tk.Label(fr0a, text = "Key for Fernet algorithm")
ramsonKeyTitle.config(font = ("Comic Sans MS", 12), fg = "#7e086c")
ramsonKeyTitle.place(x = 65, y = 120)

ramsonKey = tk.Label(fr0a, text = "", font = ("Comic Sans MS", 10), width = 80)
ramsonKey.config(bg = "#050005", fg = "#FFFFFF")
ramsonKey.place(x = 60, y = 150)

ramsonDirectoryTitle = tk.Label(fr0a, text = "You have chosen the directory: ")
ramsonDirectoryTitle.config(font = ("Comic Sans MS", 12), fg = "#7e086c")
ramsonDirectoryTitle.place(x = 65, y = 180)
	
ramsonDirectoryUrl = tk.Label(fr0a, text = "", font = ("Comic Sans MS", 10), width = 80)
ramsonDirectoryUrl.config(bg = '#050005', fg = '#FFFFFF')
ramsonDirectoryUrl.place(x = 60, y = 210, height = 30)

buttonReceiver = tk.Button(fr0a, image = receiver_ramson_image, command = lambda:receiver_ramson_actv())
buttonReceiver.place(x = 570, y = 280)

entry_receiver_ramson = tk.Entry(fr0a, textvariable = receiver_var, font = ("Comic Sans MS", 13), justify = "center", width = 13)
entry_receiver_ramson.config(bg = "#050005", fg = "#7e086c")
entry_receiver_ramson.place(x = 570, y = 430)

packet_entry = tk.Entry(fr0a, textvariable = packet, font = ('Comic Sans MS', 11), justify = 'center', width = 6)
packet_entry.place(x = 650, y = 465)
packet_entry.config(bg = '#050005', fg = '#7e086c')

packet_label = tk.Label(fr0a, text = 'Packet No. ', font = ('Comic Sans MS', 11))
packet_label.place(x = 570, y = 465)
packet_label.config(fg = '#7e086c')

generateKeyRamson = tk.Button(fr0a, image = generateRamsonKey_de, command = lambda:generate_key_ramson())
generateKeyRamson.place(x = 330, y = 280)

bringKeyRamson = tk.Button(fr0a, image = bringRamsonKey_de, command = lambda:bring_key_ramson())
bringKeyRamson.place(x = 330, y = 390)

encryptFilesButton = tk.Button(fr0a, image = decryptFilesImage, command = lambda:encrypt_files_ramson_funct())
encryptFilesButton.place(x = 830, y = 260)

decryptFilesButton = tk.Button(fr0a, image = encryptFilesImage, command = lambda:decrypt_files_ramson_funct())
decryptFilesButton.place(x = 830, y = 380)




#decrypt.protocol("WM_DELETE_WINDOW", lambda: None)

decrypt.mainloop()

