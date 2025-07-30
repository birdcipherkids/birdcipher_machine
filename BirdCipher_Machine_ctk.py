import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import customtkinter
import pygame
import moviepy.editor
import time
from playsound import playsound
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidSignature
import pyperclip
import psycopg2
import os
import pyhibp
from pyhibp import pwnedpasswords as pw
import requests
import json
import webbrowser

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
from Videos_Awareness import *



books_pt = 0
keys_pt = 0
swords_pt = 0
caduceus_pt = 0
lives = 5
counter_social_eng = -1
directory = ''
directoryHash = ''
directoryDigitalSignature = ''
directoryFindKeysDS = ''
directoryVirusTotal = ''
username_db = ''
key_ramson = ''
login_check = False
no_video = 0
English_mode = True
Spanish_mode = False
Chinese_mode = False
private_key_user = ''
public_key_user = ''
public_key_user_string = ''
hash_file_DS = ''
signature = ''
option_sign_choose = True
option_verify_choose = False
count_breach_list = -1
arrow_breaches_asc = True
arrow_breaches_desc = False
eye_password_active = True

# ----------------------------------------------- Functions -------------------------------------------------------------------

## ---------------------------------------------- Login tab -------------------------------------------------------------------

def login_user():

	global username_db
	global login_check
	global English_mode
	global Spanish_mode
	global books_pt
	global keys_pt
	global swords_pt
	global caduceus_pt

	wdatos = bytes(password_dbc.get(), 'utf-8')
	h = hashlib.new(algoritmo, wdatos)
	hash2 = HASH.generaHash(h)

	miConexion1 = psycopg2.connect(host = 'bps57o4k0svfjp9fi4vv-postgresql.services.clever-cloud.com', port = 50013, 
	user = 'u8kpoxoaaxlswsvwrn12', dbname = 'bps57o4k0svfjp9fi4vv', password = 'AgCdmPuBEd0gAhai93vqWI2qoIz85G')
		
	miCursor1 = miConexion1.cursor()

	sql1 = 'select * from users where username = (%s)'
	sql1_data = (username_dbc.get(), )

	sql2 = 'insert into users(username, password, position, books, keys, swords, caduceus) values(%s,%s,%s,%s,%s,%s,%s)'
	sql2_data = (username_dbc.get(), hash2, position_dbc.get(), 1, 0, 0, 0)

	miCursor1.execute(sql1, sql1_data)
	dlt1 = miCursor1.fetchall()

	if len(dlt1) == 0 and username_dbc.get() != '' and password_dbc.get() != '':

		miCursor1.execute(sql2, sql2_data)
		miCursor1.execute(sql1, sql1_data)
		dlt2 = miCursor1.fetchall()
		hash256_passw_label.configure(text = hash2)
		username_db = dlt2[0][1]
		books_pt = dlt2[0][4]
		Book_score.configure(text = books_pt)
		keys_pt = dlt2[0][5]
		swords_pt = dlt2[0][6]
		caduceus_pt = dlt2[0][7]
		login_check = True
		#print(username_db)
		playsound('Audios/bambu_click.mp3')
		time.sleep(2)

		if English_mode:

			labelPlayerBCM.config(text = 'Welcome, {}'.format(username_dbc.get()))
			labelPlayerBCM2.config(text = 'Welcome, {}'.format(username_dbc.get()))
			labelPlayerBCM3.config(text = 'Welcome, {}'.format(username_dbc.get()))
			labelPlayerBCM4.config(text = 'Welcome, {}'.format(username_dbc.get()))
			labelPlayerLoginHashing.configure(text = 'Welcome, {}'.format(username_dbc.get()))
			playsound('Audios/NewUserCreated.mp3')


		elif Spanish_mode:

			labelPlayerBCM.config(text = 'Bienvenido, {}'.format(username_dbc.get()))
			labelPlayerBCM2.config(text = 'Bienvenido, {}'.format(username_dbc.get()))
			labelPlayerBCM3.config(text = 'Bienvenido, {}'.format(username_dbc.get()))
			labelPlayerBCM4.config(text = 'Bienvenido, {}'.format(username_dbc.get()))
			labelPlayerLoginHashing.configure(text = 'Bienvenido, {}'.format(username_dbc.get()))
			playsound('Audios/NuevoUsuarioCreado.mp3')



	elif len(dlt1) > 0 and hash2 == dlt1[0][2]:

		hash256_passw_label.configure(text = dlt1[0][2])
		username_db = dlt1[0][1]
		books_pt = dlt1[0][4]
		Book_score.configure(text = books_pt)
		keys_pt = dlt1[0][5]
		swords_pt = dlt1[0][6]
		caduceus_pt = dlt1[0][7]
		login_check = True
		#print(username_db)
		playsound('Audios/bambu_click.mp3')
		time.sleep(2)
		

		if English_mode:

			labelPlayerBCM.config(text = 'Welcome, {}'.format(username_dbc.get()))
			labelPlayerBCM2.config(text = 'Welcome, {}'.format(username_dbc.get()))
			labelPlayerBCM3.config(text = 'Welcome, {}'.format(username_dbc.get()))
			labelPlayerBCM4.config(text = 'Welcome, {}'.format(username_dbc.get()))
			labelPlayerLoginHashing.configure(text = 'Welcome, {}'.format(username_dbc.get()))
			playsound('Audios/CorrectLogin.mp3')

		elif Spanish_mode:

			labelPlayerBCM.config(text = 'Bienvenido, {}'.format(username_dbc.get()))
			labelPlayerBCM2.config(text = 'Bienvenido, {}'.format(username_dbc.get()))
			labelPlayerBCM3.config(text = 'Bienvenido, {}'.format(username_dbc.get()))
			labelPlayerBCM4.config(text = 'Bienvenido, {}'.format(username_dbc.get()))
			labelPlayerLoginHashing.configure(text = 'Bienvenido, {}'.format(username_dbc.get()))
			playsound('Audios/CorrectoLogin.mp3')



	elif len(dlt1) > 0 and hash2 != dlt1[0][2]:

		if English_mode:

			playsound('Audios/Incorrect_password.mp3')

		elif Spanish_mode:

			playsound('Audios/ContrasenaIncorrectaVI.mp3')

	elif username_dbc.get() == '' or password_dbc.get() == '':

		if English_mode:

			playsound('Audios/Enter_credencials.mp3')

		elif Spanish_mode:

			playsound('Audios/DebesIngresarCredenciales.mp3')

	miConexion1.commit()
	miConexion1.close()


def copyHashLogin():

	wdatos = bytes(password_dbc.get(), 'utf-8')
	h = hashlib.new(algoritmo, wdatos)
	hash2 = HASH.generaHash(h)

	playsound('Audios/bambu_click.mp3')

	if Spanish_mode:
		playsound('Audios/HashCopiadoLogin.mp3')

	elif English_mode:
		playsound('Audios/HashCopiedLogin.mp3')
	
	pyperclip.copy(hash2)


# -------------------------------------------------------------------------------------------------------------


def selectDirectory():

	global directory

	directory = filedialog.askdirectory(title = 'Open directory')
	ramsonDirectoryUrl.config(text = directory)
	print(directory)

	if English_mode:

		playsound('Audios/bambu_click.mp3')
		playsound('Audios/Directory_correctly_defined.mp3')

	elif Spanish_mode:

		playsound('Audios/bambu_click.mp3')
		playsound('Audios/DirectorioDefinido.mp3')

	elif Chinese_mode:

		playsound('Audios/bambu_click.mp3')
		playsound('Audios/Directory_correctly_defined_zh.mp3')

def selectDirectoryHash():

	global directoryHash

	directoryHash = filedialog.askopenfilename(title = 'Open file')
	archive_url.set(directoryHash)

def selectDirectoryDigitalSignature():

	global directoryDigitalSignature
	global hash_file_DS

	directoryDigitalSignature = filedialog.askopenfilename(title = 'Open file to sign or verify')
	url_file_label_DS.config(text = directoryDigitalSignature)
	hash_file_DS = hash_file_birdcipher(directoryDigitalSignature, 'sha256')
	hash_file_label_DS.config(text = hash_file_DS)
	hash_file_DS = hash_file_DS.encode()

	#playsound('Audios/bambu_click.mp3')

def selectDirectoryOpenFindKeysDS():

	global directoryFindKeysDS

	directoryFindKeysDS = filedialog.askdirectory(title = 'Open directory')
	directory_label_DS.config(text = directoryFindKeysDS)
	#playsound('Audios/bambu_click.mp3')


def selectDirectoryVirusTotal():

	global directoryVirusTotal
	
	directoryVirusTotal = filedialog.askopenfilename(title = 'Open file to upload in Virus Total')
	urlUploadFile.config(text = archive_upload_vt.set(directoryVirusTotal))
	hash_file_label_vt.set(hash_file_birdcipher(directoryVirusTotal, 'sha256'))
	#hashLabelVirusTotal.config(text = hash_file_label_vt.set(hashForFileVT))
	#playsound('bambu_click.mp3')

def generate_key_ramson():

	global key_ramson

	key_ramson = Fernet.generate_key()
	ramsonKey.config(text = key_ramson)
	playsound('Audios/bambu_click.mp3')
	playsound('Audios/LLaveGenerada.mp3')

def bring_key_ramson():

	global key_ramson

	wdatos = bytes(password_for_ramson.get(), 'utf-8')
	h = hashlib.new(algoritmo, wdatos)
	hash2 = HASH.generaHash(h)

	miConexion13 = psycopg2.connect(host = 'bps57o4k0svfjp9fi4vv-postgresql.services.clever-cloud.com', port = 50013, 
	user = 'u8kpoxoaaxlswsvwrn12', dbname = 'bps57o4k0svfjp9fi4vv', password = 'AgCdmPuBEd0gAhai93vqWI2qoIz85G')
		
	miCursor13 = miConexion13.cursor()

	sql_verf_hash_ramson = 'select * from users where username = (%s)'
	sql_verf_hash_data_ramson = (username_db,)
	miCursor13.execute(sql_verf_hash_ramson, sql_verf_hash_data_ramson)
	dlt453 = miCursor13.fetchall()

	if dlt453[0][5] >= 0 and hash2 == dlt453[0][2]:

		if target_receiver_ramson != '':

			sql_bring_key_ramson = 'select * from ramson_bird where (client = (%s) and server = (%s) and packet = (%s))'
			sql_bring_key_data_ramson = (target_receiver_ramson, username_db, packet.get())
			miCursor13.execute(sql_bring_key_ramson, sql_bring_key_data_ramson)
			dlt456 = miCursor13.fetchall()
			key_ramson = dlt456[0][4]
			ramsonKey.config(text = key_ramson)
			playsound('Audios/bambu_click.mp3')
			playsound('Audios/LlaveRecuperada.mp3')

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

	global directory
	global username_db
	global login_check


	wdatos = bytes(password_for_ramson.get(), 'utf-8')
	h = hashlib.new(algoritmo, wdatos)
	hash2 = HASH.generaHash(h)

	miConexion12 = psycopg2.connect(host = 'bps57o4k0svfjp9fi4vv-postgresql.services.clever-cloud.com', port = 50013, 
	user = 'u8kpoxoaaxlswsvwrn12', dbname = 'bps57o4k0svfjp9fi4vv', password = 'AgCdmPuBEd0gAhai93vqWI2qoIz85G')
	
	miCursor12 = miConexion12.cursor()

	sql_verf_hash_ramson = 'select * from users where username = (%s)'
	sql_verf_hash_data_ramson = (username_db,)
	miCursor12.execute(sql_verf_hash_ramson, sql_verf_hash_data_ramson)
	dlt5 = miCursor12.fetchall()

	if login_check == True and dlt5[0][5] >= 0 and hash2 == dlt5[0][2]:

		print(dlt5[0][2])
		print(dlt5[0][5])

		if target_receiver_ramson != '':

			sql_ramson_verf = 'select * from ramson_bird where (client = (%s) and server = (%s) and packet = (%s))'
			sql_ramson_verf_data = (username_db, target_receiver_ramson, packet.get())
			miCursor12.execute(sql_ramson_verf, sql_ramson_verf_data)
			df20 = miCursor12.fetchall()
			df12_test = True
			print('Ok')

			if len(df20) == 0 and df12_test == True:

				if directory != '' and ramsonBird_message.get("1.0", "end-1c") != '' and packet.get() != 0:

					sql1234 = 'insert into ramson_bird(client, password, server, key_c, description, packet) values(%s,%s,%s,%s,%s,%s)'
					datos_sql1234 = (username_db, hash2, target_receiver_ramson, key_ramson.decode(), ramsonBird_message.get('1.0', 'end-1c'), packet.get())
					miCursor12.execute(sql1234, datos_sql1234)
					archivos = directory
					items = os.listdir(archivos)
					archivos2 = [archivos + '/' + x for x in items]
					execution_encrypt_files(archivos2, key_ramson)
					print(key_ramson)

					playsound('Audios/bambu_click.mp3')
					playsound('Audios/ArchivosEncriptadosExitosamente.mp3')

				elif directory == '' or ramsonBird_message.get('1.0', 'end-1c') == '' or packet.get() == 0:

					playsound('Audios/cartoon121.mp3')


			elif len(df20) > 0 and df12_test == True:

				if directory != '' and ramsonBird_message.get("1.0", "end-1c") != '' and packet.get() != 0:

					sql1235 = 'update ramson_bird set (client, password, server, key_c, description, packet) = (%s,%s,%s,%s,%s,%s) where (client = (%s) and server = (%s) and packet = (%s))'
					datos_sql1235 = (username_db, hash2, target_receiver_ramson, key_ramson.decode(), ramsonBird_message.get('1.0', 'end-1c'), packet.get(), username_db, target_receiver_ramson, packet.get())
					miCursor12.execute(sql1235, datos_sql1235)
					archivos = directory
					items = os.listdir(archivos)
					archivos2 = [archivos + '/' + x for x in items]
					execution_encrypt_files(archivos2, key_ramson)
					print(key_ramson)

					playsound('Audios/bambu_click.mp3')
					playsound('Audios/ArchivosEncriptadosExitosamente.mp3')

				elif directory == '' or ramsonBird_message.get('1.0', 'end-1c') == '' or packet.get() == 0:

					playsound('Audios/cartoon121.mp3')


		elif target_receiver_ramson == '':

			playsound('Audios/RecipientUsername.mp3')
			df12_test = False


	elif login_check == False:

		playsound('Audios/IniciarSesionUtilizarFuncion.mp3')


	# if dlt5[0][5] >= 1 and hash2 != dlt5[0][3]:

	# 	playsound('Audios/WrongPass.mp3')

	# elif dlt5[0][5] < 1:

	# 	playsound('Audios/AuthorizationSendMssg.mp3')





	miConexion12.commit()
	miConexion12.close()


def decrypt_files_ramson_funct():

	global directory
	global username_db
	global login_check

	wdatos = bytes(password_for_ramson.get(), 'utf-8')
	h = hashlib.new(algoritmo, wdatos)
	hash2 = HASH.generaHash(h)

	miConexion122 = psycopg2.connect(host = 'bps57o4k0svfjp9fi4vv-postgresql.services.clever-cloud.com', port = 50013, 
	user = 'u8kpoxoaaxlswsvwrn12', dbname = 'bps57o4k0svfjp9fi4vv', password = 'AgCdmPuBEd0gAhai93vqWI2qoIz85G')
		
	miCursor122 = miConexion122.cursor()

	sql_verf_hash_ramson = 'select * from users where username = (%s)'
	sql_verf_hash_data_ramson = (username_db,)
	miCursor122.execute(sql_verf_hash_ramson, sql_verf_hash_data_ramson)
	dlt909 = miCursor122.fetchall()

	if login_check == True and dlt909[0][5] >= 0 and hash2 == dlt909[0][2]:

		if target_receiver_ramson != '':

			sql_ramson_verf = 'select * from ramson_bird where (client = (%s) and server = (%s) and packet = (%s))'
			sql_ramson_verf_data = (target_receiver_ramson, username_db, packet.get())
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
				playsound('Audios/bambu_click.mp3')
				playsound('Audios/ArchivosDesencriptadosExitosamente.mp3')

			elif len(df202) == 0:

				playsound('Audios/cartoon121.mp3')

	elif login_check == False:

		playsound('Audios/IniciarSesionUtilizarFuncion.mp3')

	miConexion122.commit()
	miConexion122.close()



def send_message():

	global username_db
	global key_encryption
	global token
	global target_person
	global login_check

	bdatos = bytes(passw_em.get(), 'utf-8')
	h = hashlib.new(algoritmo, bdatos)
	hash2 = HASH.generaHash(h)

	miConexion2 = psycopg2.connect(host = 'bps57o4k0svfjp9fi4vv-postgresql.services.clever-cloud.com', port = 50013, 
	user = 'u8kpoxoaaxlswsvwrn12', dbname = 'bps57o4k0svfjp9fi4vv', password = 'AgCdmPuBEd0gAhai93vqWI2qoIz85G')
		
	miCursor2 = miConexion2.cursor()

	sql_verf_hash = 'select * from users where username = (%s)'
	sql_verf_hash_data = (username_db,)
	miCursor2.execute(sql_verf_hash, sql_verf_hash_data)
	dlt5 = miCursor2.fetchall()

	if login_check == True and dlt5[0][5] >= 0 and hash2 == dlt5[0][2]:

		if target_person != '':

			sql_verf_server = 'select * from encryptedMessages where (username = (%s) and server = (%s))'
			sql_verf_server_data = (username_db, target_person)
			miCursor2.execute(sql_verf_server, sql_verf_server_data)
			df1 = miCursor2.fetchall()
			df1_test = True

			if len(df1) == 0 and df1_test == True:

				if token != '' and key_encryption != '':

					#key_encryption = key_encryption.decode()
					sql110 = 'insert into encryptedMessages(username, password, server, actual_message, key_b) values(%s,%s,%s,%s,%s)'
					datos_sql110 = (username_db, hash2, target_person, token.decode(), key_encryption.decode())
					miCursor2.execute(sql110, datos_sql110)
					playsound('Audios/bambu_click.mp3')
					#playsound('message_sent_success.mp3')

				# elif token == '' or key_encryption == '':

				# 	playsound('StepsForSending.mp3')

			elif len(df1) > 0 and df1_test == True:

				if token != '' and key_encryption != '':

					sql111 = 'update encryptedMessages set (username, password, server, actual_message, key_b) = (%s,%s,%s,%s,%s) where (nickname = (%s) and server = (%s))'
					datasql111 = (username_db, hash2, target_person, token.decode(), key_encryption.decode(), username_db, target_person)
					miCursor2.execute(sql111, datasql111)
					playsound('Audios/bambu_click.mp3')
					#playsound('Audios/message_sent_success.mp3')

				# elif token == '' or key_encryption == '':

				# 	playsound('Audios/StepsForSending.mp3')

		# elif target_person == '':

		# 	playsound('Audios/RecipientUsername.mp3')
		# 	df = -1
		# 	df1_test = False


	# elif dlt5[0][5] >= 0 and hash2 != dlt5[0][3]:

	# 	playsound('Audios/WrongPass.mp3')

	# elif dlt5[0][5] < 10:

	# 	playsound('Audios/AuthorizationSendMssg.mp3')


	miConexion2.commit()
	miConexion2.close()

	
def displayCiphertext():

	global username_db
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

	sql33 = 'select * from users where username = (%s)'
	datasql33 = (username_db,)

	sql330 = 'select * from encryptedMessages where server = (%s) and username = (%s)'
	datasql330 = (username_db, target_person_decrypt)

	miCursor3.execute(sql33, datasql33)
	dlt6 = miCursor3.fetchall()

	if hash3 == dlt6[0][2]:

		if target_person_decrypt != '':

			miCursor3.execute(sql330, datasql330)
			dlt7 = miCursor3.fetchall()

		elif target_person_decrypt == '':

			playsound('Audios/perder_incorrecto_no_valido.mp3')
			playsound('Audios/activatePersonFirst_toReceive.mp3')

		if len(dlt7) > 0:

			message_sent_decrypt = dlt7[0][4]
			key_sent_decrypt = dlt7[0][5]

			cipher_text3.insert(tk.END, dlt7[0][4])
			cipher_text3.config(font = ("Comic Sans MS", 10))
				
			key_fernet_text2.config(text = dlt7[0][5], justify = 'center', wraplength = 700, font = ('Comic Sans MS', 10))
			playsound('Audios/bambu_click.mp3')

	elif hash3 != dlt6[0][3]:

		playsound('Audios/WrongPass.mp3')


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

	sql555 = 'select * from encryptedMessages where server = (%s) and username = (%s)'
	datasql555 = (username_db, target_person_decrypt)

	miCursor3.execute(sql555, datasql555)
	dlt555 = miCursor3.fetchall()

	a = dlt555[0][4].encode()
	b = dlt555[0][5].encode()
	k = Fernet(b)
	token2 = k.decrypt(a)
	token2 = token2.decode()
	cipher_text2_encrp2.insert(tk.END, token2)
	cipher_text2_encrp2.config(font = ("Comic Sans MS", 10))
	playsound('Audios/bambu_click.mp3')

	miConexion3.commit()
	miConexion3.close()



def fernet_key_gen():

	global key_encryption
	global key_encryption_test

	key_encryption = Fernet.generate_key()
		
	key_fernet_text.config(text = key_encryption)
	#clipboard.copy(key_encryption)
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
		#clipboard.copy(token)

	elif key_encryption_test == False:

		playsound('Audios/MustGenerateKey.mp3')


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
			
		playsound('Audios/WrongKey.mp3')

	elif chances_decrypt > 3:

		playsound('Audios/chances_decrypt.mp3')

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

	if English_mode:

		playsound('Audios/Bye.mp3')

	elif Spanish_mode:

		playsound('Audios/HastaLuego.mp3')
	
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
		playsound('Audios/bambu_click.mp3')
		#playsound('Audios/activatedPersonA.mp3')

	elif person1_var.get() == '':

		playsound('Audios/EnterUsername.mp3')


def person2_actv():

	global target_person

	if person2_var.get() != '':

		person1_activated = False
		person2_activated = True
		person3_activated = False
		person4_activated = False
		target_person = person2_var.get()
		playsound('Audios/bambu_click.mp3')
		#playsound('activatedPersonA.mp3')

	elif person2_var.get() == '':

		playsound('Audios/EnterUsername.mp3')

def person3_actv():

	global target_person

	if person3_var.get() != '':

		person1_activated = False
		person2_activated = False
		person3_activated = True
		person4_activated = False
		target_person = person3_var.get()
		playsound('Audios/bambu_click.mp3')
		#playsound('Audios/activatedPersonA.mp3')

	elif person3_var.get() == '':

		playsound('Audios/EnterUsername.mp3')

def person4_actv():

	global target_person

	if person4_var.get() != '':

		person1_activated = False
		person2_activated = False
		person3_activated = False
		person4_activated = True
		target_person = person4_var.get()
		playsound('Audios/bambu_click.mp3')
		#playsound('Audios/activatedPersonA.mp3')

	elif person4_var.get() == '':

		playsound('Audios/EnterUsername.mp3')


def person1c_actv():

	global target_person_decrypt

	if person1c_var.get() != '':

		person1c_activated = True
		person2c_activated = False
		person3c_activated = False
		person4c_activated = False
		target_person_decrypt = person1c_var.get()
		playsound('Audios/bambu_click.mp3')
		#playsound('Audios/activatedPersonB.mp3')

	elif person1c_var.get() == '':

		playsound('Audios/activatePersonReceiveMessages.mp3')

def person2c_actv():

	global target_person_decrypt

	if person2c_var.get() != '':

		person1c_activated = False
		person2c_activated = True
		person3c_activated = False
		person4c_activated = False
		target_person_decrypt = person2c_var.get()
		playsound('Audios/button_click.mp3')
		playsound('Audios/activatedPersonB.mp3')

	elif person2c_var.get() == '':

		playsound('Audios/activatePersonReceiveMessages.mp3')

def person3c_actv():

	global target_person_decrypt

	if person3c_var.get() != '':

		person1c_activated = False
		person2c_activated = False
		person3c_activated = True
		person4c_activated = False
		target_person_decrypt = person3c_var.get()
		playsound('Audios/button_click.mp3')
		playsound('Audios/activatedPersonB.mp3')

	elif person3c_var.get() == '':

		playsound('Audios/activatePersonReceiveMessages.mp3')

def person4c_actv():

	global target_person_decrypt

	if person4c_var.get() != '':

		person1c_activated = False
		person2c_activated = False
		person3c_activated = False
		person4c_activated = True
		target_person_decrypt = person4c_var.get()
		playsound('Audios/button_click.mp3')
		playsound('Audios/activatedPersonB.mp3')

	elif person4c_var.get() == '':

		playsound('Audios/activatePersonReceiveMessages.mp3')


def receiver_ramson_actv():

	global target_receiver_ramson

	if receiver_var.get() != '':

		target_receiver_ramson = receiver_var.get()
		playsound('Audios/bambu_click.mp3')
		playsound('Audios/UsuarioArchivosEncriptadosExitoso.mp3')

	elif receiver_var.get() == '':

		playsound('Audios/PrimeroNombreDestinatario.mp3')


def change_video_number_asc():

	global no_video

	no_video = no_video + 1

def change_video_number_desc():

	global no_video

	if no_video > 0:

		no_video = no_video - 1

	else:

		playsound('Audios/avanzar_lista_ciberawareness.mp3')


def play_video_social_eng():

	global no_video

	pygame.init()
	video = moviepy.editor.VideoFileClip(videos_awareness[no_video], target_resolution=(350,650))
	video.preview()
	pygame.quit()

def change_spanish_mode():

	global Spanish_mode
	global English_mode
	global Chinese_mode

	Spanish_mode = True
	English_mode = False
	Chinese_mode = False

def change_english_mode():

	global Spanish_mode
	global English_mode
	global Chinese_mode

	English_mode = True
	Spanish_mode = False
	Chinese_mode = False

def change_chinese_mode():

	global English_mode
	global Chinese_mode
	global Spanish_mode

	Chinese_mode = True
	English_mode = False
	Spanish_mode = False

def translator():

	global Spanish_mode
	global English_mode
	global Chinese_mode

	if Spanish_mode == True:

		playsound('Audios/Espanol.mp3')
		# english.config(fg = '#7e086c', bg = 'white')
		# spanish.config(bg = '#3b0332', fg = 'white')
		# chinese.config(fg = '#7e086c', bg = 'white')
		login_label.configure(text = 'Inicia sesión en BirdCipher Machine', font = ("Times New Roman", 22))
		username_label.configure(text = 'Usuario', font = ("Times New Roman", 20))
		password_label.configure(text = 'Contraseña', font = ("Times New Roman", 20))
		position_label.configure(text = 'Posición', font = ("Times New Roman", 20))
		send_login_data.configure(text = 'Enviar datos', font = ("Times New Roman", 15))
		notebk._segmented_button._buttons_dict['Login'].configure(text='Inicio')
		notebk._segmented_button._buttons_dict['Education'].configure(text='Educación')
		#notebk._segmented_button._buttons_dict['Password Checking'].configure(text='Chequeo de contraseña')
		hash256_passw.configure(text = 'El hash de tu contraseña (SHA 265) es:', font = ("Times New Roman", 20))
		hash256passw_copy_btt.configure(text = 'Copiar hash al portapapeles', font = ("Times New Roman", 15))
		close_machine_from_login.configure(text = 'Cierra la maquina BirdCipher', font = ("Times New Roman", 30))
		closeBCM_awareness.config(text = 'Cierra la Máquina BirdCipher', font = ("Comic Sans MS", 14))
		answer_button_social_eng.config(text = 'Enviar respuesta', font = ("Comic Sans MS", 10))
		enter_password_label.config(text = 'Ingresa tu contraseña', font = ("Comic Sans MS", 14))
		result_check_label.config(text = 'Reporte de resultados', font = ("Comic Sans MS", 14))
		times_label.config(text = 'No. veces usada antes', font = ("Comic Sans MS", 13))
		notebk.add(digital_signature, text = 'Firma digital')
		closeBCM_checkpass.config(text = 'Cierre la Maquina Criptográfica BirdCipher', font = ("Comic Sans MS", 14))
		labelTextHashing.config(text = 'Ingrese el texto para crear hash:', font = ("Comic Sans MS", 14))
		labelPlayerLoginHashing.config(text = 'Bienvenido, ', font = ("Comic Sans MS", 14))
		labelHashEntry.config(text = 'El hash de tu mensaje/archivo es: ')
		labelArchive.config(text = 'La ruta a tu archivo es: ', font = ("Comic Sans MS", 14))
		notebk.add(fr, text = "Criptografía")
		titleBirdCipherMachine.config(text = 'Ingresa el texto a encriptar (Texto plano)', font = ("Comic Sans MS", 14))
		titleBirdCipherMachine2.config(text = 'Tu mensaje encriptado (texto cifrado) es: ', font = ("Comic Sans MS", 14))
		labelQuestionKey.config(text = 'Ingresa tu contraseña', font = ("Comic Sans MS", 14))
		labelPlayerBCM.config(text = 'Bienvenido, ', font = ("Comic Sans MS", 14))
		closeMachineButton.config(text = 'Cierra la Maquina Criptográfica BirdCipher', font = ("Comic Sans MS", 12))
		titleBirdCipherMachine20.config(text = 'BirdCipher Machine: una herramienta para garantizar la confidencialidad de tus mensajes', font = ("Comic Sans MS", 12))
		notebk.add(fr2, text = " Cifrado")
		key_fernet_label.config(text = 'Llave para el algoritmo Fernet', font = ("Comic Sans MS", 12))
		encrypted_label.config(text = 'Tu mensaje encriptado es:', font = ("Comic Sans MS", 12))
		labelPlayerBCM2.config(text = 'Bienvenido, ', font = ("Comic Sans MS", 11))
		labelQuestionKey2.config(text = 'Ingresa tu contraseña', font = ("Comic Sans MS", 13))
		closeMachineButton2.config(text = 'Cierra la Maquina Criptográfica BirdCipher', font = ("Comic Sans MS", 12))
		notebk.add(fr3, text = " Descifrado")
		titleBirdCipherMachine3.config(text = 'Máquina de descifrado BirdCipher', font = ("Comic Sans MS", 12))
		key_fernet_label2.config(text = 'Llave para el Algoritmo Fernet', font = ("Comic Sans MS", 12))
		encrypted_label2.config(text = 'Tu mensaje desencriptado es: ', font = ("Comic Sans MS", 12))
		labelQuestionKey3.config(text = 'Ingresa tu contraseña', font = ("Comic Sans MS", 13))
		labelPlayerBCM3.config(text = 'Bienvenido, ', font = ("Comic Sans MS", 11))
		closeMachineButton3.config(text = 'Cierra la Máquina Criptográfica BirdCipher', font = ("Comic Sans MS", 12))
		notebk.add(fr0a, text = 'RamsonBird')
		ramsonBirdMessageTitle.config(text = 'Ingresa tu mensaje para identificar la acción de encriptado de archivos', font = ("Comic Sans MS", 12))
		ramsonKeyTitle.config(text = 'Llave para el Algoritmo Fernet', font = ("Comic Sans MS", 12))
		ramsonDirectoryTitle.config(text = 'Has escogido el directorio: ', font = ("Comic Sans MS", 12))
		packet_label.config(text = 'Paquete No.', font = ("Comic Sans MS", 11))
		labelQuestionKey4.config(text = 'Ingresa tu contraseña', font = ("Comic Sans MS", 13))
		labelPlayerBCM4.config(text = 'Bienvenido, ', font = ("Comic Sans MS", 11))
		titleVirusTotal.config(text = 'SUBE TU ARCHIVO A VIRUS TOTAL', font = ('Comic Sans MS', 15))
		hashFileLabel.config(text = 'El hash (sha 256) de tu archivo es:', font = ('Comic Sans MS', 11))
		results_vt.config(text = 'ESTADÍSTICAS DEL ÚLTIMO ANÁLISIS', font = ('Comic Sans MS', 11))
		results_vt.place(x = 115, y = 330)
		explanation_vt.config(text = 'Número de reportes de antivirus por categoría', font = ('Comic Sans MS', 10))
		explanation_vt.place(x = 123, y = 355)
		last_analysis_results_label.config(text = 'RESULTADOS DEL ÚLTIMO ANÁLISIS', font = ('Comic Sans MS', 15))
		last_analysis_results_label.place(x = 630, y = 20)
		category_vt.config(text = 'Categoría', font = ('Comic Sans MS', 13))
		engine_update_vt.config(text = 'Actualización', font = ('Comic Sans MS', 13))
		result_vt.config(text = 'Resultado', font = ('Comic Sans MS', 13))
		result_vt.place(x = 905, y = 70)
		tactics_label_capa.config(text = 'TACTICAS DETECTADAS POR CAPA', font = ('Comic Sans MS', 17))
		tactics_label_capa.place(x = 340, y = 5)
		tactics_label_capa1.config(text = 'Táctica', font = ('Comic Sans MS', 14))
		tactics_label_capa2.config(text = 'Táctica', font = ('Comic Sans MS', 14))
		descriptions_label_capa1.config(text = 'Descripción', font = ('Comic Sans MS', 14))
		descriptions_label_capa2.config(text = 'Descripción', font = ('Comic Sans MS', 14))
		techniques_capa_label.config(text = 'Técnicas', font = ('Comic Sans MS', 14))
		tactics_label_cape.config(text = 'TÁCTICAS DETECTADAS POR CAPE SANDBOX', font = ('Comic Sans MS', 17))
		tactics_label_cape.place(x = 250, y = 5)
		tactics_label_cape1.config(text = 'Táctica', font = ('Comic Sans MS', 14))
		tactics_label_cape2.config(text = 'Táctica', font = ('Comic Sans MS', 14))
		descriptions_label_cape1.config(text = 'Descripción', font = ('Comic Sans MS', 14))
		descriptions_label_cape2.config(text = 'Descripción', font = ('Comic Sans MS', 14))
		techniques_cape_label.config(text = 'Técnicas', font = ('Comic Sans MS', 14))
		tactics_label_zen.config(text = 'TÁCTICAS DETECTADAS POR ZENBOX', font = ('Comic Sans MS', 17))
		tactics_label_zen1.config(text = 'Táctica', font = ('Comic Sans MS', 14))
		tactics_label_zen2.config(text = 'Táctica', font = ('Comic Sans MS', 14))
		descriptions_label_zen1.config(text = 'Descripción', font = ('Comic Sans MS', 14))
		descriptions_label_zen2.config(text = 'Descripción', font = ('Comic Sans MS', 14))
		techniques_zen_label.config(text = 'Técnicas', font = ('Comic Sans MS', 14))
		upload_file_label_DS.config(text = 'CARGA TU DOCUMENTO A LA HERRAMIENTA DE FIRMA DIGITAL', font = ('Comic Sans MS', 11))
		hash_file_ds_label.config(text = 'El hash (sha 256) de tu archivo es: ')
		create_key_pair_label.config(text = 'Crear par de llaves')
		bring_key_pair_label.config(text = 'Cargar par de llaves')
		create_key_pair_label.place(x = 525, y = 190)
		bring_key_pair_label.place(x = 780, y = 190)
		bring_directory_DS.config(text = 'Defina el directorio para guardar/buscar llaves')
		file_hash_ciphertext_title.config(text = 'Resultados de la firma digital')
		img_social_eng_label.config(image = firewall_humano)
		password_checking_button.config(image = chequeoContraseña)
		digital_signature_button.config(image = firma_digital_logo)
		logoBrowseDirectoriesHash.config(image = busqueda_directorio)
		urlUploadLogo.config(image = busqueda_directorio_vt)
		private_key_button_cr.config(image = llave_privada_logo)
		private_key_button_br.config(image = llave_privada_logo)
		public_key_button_cr.config(image = llave_publica_logo)
		public_key_button_br.config(image = llave_publica_logo)
		browse_ds_button.config(image = buscar_ds_logo)
		directory_browse_DS.config(image = buscar_ds_logo)
		verify_integrity_button.config(image = verificar_integridad_logo)
		non_repudiation_button.config(image = no_repudio_logo)
		instructions_ds_button.config(image = instrucciones_ds_logo)
		digital_signature_button.place(x = 30, y = 20)
		instructions_ds_button.place(x = 30, y = 380)
		non_repudiation_button.place(x = 178, y = 380)
		



	elif English_mode == True:

		playsound('Audios/English_mode.mp3')
		#english.config(bg = '#3b0332', fg = 'white')
		#spanish.config(fg = '#7e086c', bg = 'white')
		#chinese.config(fg = '#7e086c', bg = 'white')
		login_label.configure(text = 'Log in to BirdCipher Machine!!', font = ("Times New Roman", 26))
		username_label.configure(text = 'Username', font = ("Times New Roman", 20))
		password_label.configure(text = 'Password', font = ("Times New Roman", 20))
		position_label.configure(text = 'Position', font = ("Times New Roman", 26))
		send_login_data.config(text = 'Send data', font = ("Comic Sans MS", 9))
		notebk.add(hr, text = "Login")
		notebk.add(fr0, text = 'Human Firewall')
		hash256_passw.config(text = 'Your password hash (SHA 265) is:', font = ("Comic Sans MS", 12))
		hash256passw_copy_btt.config(text = 'Copy hash to clipboard', font = ("Comic Sans MS", 9))
		close_machine_from_login.config(text = '  Close the BirdCipher Machine  ', font = ("Comic Sans MS", 14))
		closeBCM_awareness.config(text = 'Close the BirdCipher Machine', font = ("Comic Sans MS", 14))
		answer_button_social_eng.config(text = 'Send answer', font = ("Comic Sans MS", 10))
		enter_password_label.config(text = 'Enter your password', font = ("Comic Sans MS", 14))
		result_check_label.config(text = 'Results report', font = ("Comic Sans MS", 14))
		times_label.config(text = 'Times used before: ', font = ("Comic Sans MS", 14))
		notebk.add(passcheck, text = 'Password Checking')
		notebk.add(digital_signature, text = 'Digital signature')
		closeBCM_checkpass.config(text = 'Close the BirdCipher Cryptographic Machine', font = ("Comic Sans MS", 14))
		labelTextHashing.config(text = 'Enter the text to hash:', font = ("Comic Sans MS", 14))
		labelPlayerLoginHashing.config(text = 'Welcome, ', font = ("Comic Sans MS", 14))
		labelHashEntry.config(text = 'The hash of your message/file is: ', font = ("Comic Sans MS", 14))
		labelArchive.config(text = 'The URL of your file is: ', font = ("Comic Sans MS", 14))
		notebk.add(fr, text = "Cryptography")
		titleBirdCipherMachine.config(text = 'Enter the message to encrypt (Plaintext)', font = ("Comic Sans MS", 14))
		titleBirdCipherMachine2.config(text = 'Your encrypted message (Ciphertext) is: ', font = ("Comic Sans MS", 14))
		labelQuestionKey.config(text = 'Enter your password', font = ("Comic Sans MS", 14))
		labelPlayerBCM.config(text = 'Welcome, ', font = ("Comic Sans MS", 14))
		closeMachineButton.config(text = 'Close the BirdCipher Cryptographic Machine', font = ("Comic Sans MS", 12))
		titleBirdCipherMachine20.config(text = 'BirdCipher Encryption Machine: a tool to guarantee the confidentiality of your messages', font = ("Comic Sans MS", 12))
		notebk.add(fr2, text = "Encryption")
		key_fernet_label.config(text = 'Key for Fernet Algorithm', font = ("Comic Sans MS", 12))
		encrypted_label.config(text = 'Your encrypted message is:', font = ("Comic Sans MS", 12))
		labelPlayerBCM2.config(text = 'Welcome, ', font = ("Comic Sans MS", 11))
		labelQuestionKey2.config(text = 'Enter your password', font = ("Comic Sans MS", 13))
		closeMachineButton2.config(text = 'Close the BirdCipher Cryptographic Machine', font = ("Comic Sans MS", 12))
		notebk.add(fr3, text = "Decryption")
		titleBirdCipherMachine3.config(text = 'BirdCipher Decryption Machine', font = ("Comic Sans MS", 12))
		key_fernet_label2.config(text = 'Key for Fernet Algorithm', font = ("Comic Sans MS", 12))
		encrypted_label2.config(text = 'Your decrypted message is: ', font = ("Comic Sans MS", 12))
		labelQuestionKey3.config(text = 'Enter your password', font = ("Comic Sans MS", 13))
		labelPlayerBCM3.config(text = 'Welcome, ', font = ("Comic Sans MS", 11))
		closeMachineButton3.config(text = 'Close the BirdCipher Cryptographic Machine', font = ("Comic Sans MS", 12))
		notebk.add(fr0a, text = 'RamsonBird')
		ramsonBirdMessageTitle.config(text = 'Enter your message for identifying the ramson action', font = ("Comic Sans MS", 12))
		ramsonKeyTitle.config(text = 'Key for Fernet Algorithm', font = ("Comic Sans MS", 12))
		ramsonDirectoryTitle.config(text = 'You have chosen the directory:', font = ("Comic Sans MS", 12))
		packet_label.config(text = 'Packet No.', font = ("Comic Sans MS", 11))
		labelQuestionKey4.config(text = 'Enter your password', font = ("Comic Sans MS", 13))
		labelPlayerBCM4.config(text = 'Welcome, ', font = ("Comic Sans MS", 11))
		titleVirusTotal.config(text = 'UPLOAD YOUR FILE TO VIRUS TOTAL', font = ('Comic Sans MS', 15))
		hashFileLabel.config(text = 'The hash (sha 256) of your file is:', font = ('Comic Sans MS', 11))
		results_vt.config(text = 'LAST ANALYSIS STATS', font = ('Comic Sans MS', 12))
		results_vt.place(x = 160, y = 330)
		explanation_vt.config(text = 'Number of antivirus reports per category', font = ('Comic Sans MS', 10))
		last_analysis_results_label.config(text = 'LAST ANALYSIS RESULTS', font = ('Comic Sans MS', 15))
		last_analysis_results_label.place(x = 700, y = 10)
		category_vt.config(text = 'Category', font = ('Comic Sans MS', 13))
		engine_update_vt.config(text = 'Engine update', font = ('Comic Sans MS', 13))
		result_vt.config(text = 'Result', font = ('Comic Sans MS', 13))
		result_vt.place(x = 920, y = 70)
		tactics_label_capa.config(text = 'TACTICS DETECTED BY CAPA', font = ('Comic Sans MS', 17))
		tactics_label_capa.place(x = 380, y = 5)
		tactics_label_capa1.config(text = 'Tactic', font = ('Comic Sans MS', 14))
		tactics_label_capa2.config(text = 'Tactic', font = ('Comic Sans MS', 14))
		descriptions_label_capa1.config(text = 'Description', font = ('Comic Sans MS', 14))
		descriptions_label_capa2.config(text = 'Description', font = ('Comic Sans MS', 14))
		techniques_capa_label.config(text = 'Techniques', font = ('Comic Sans MS', 14))
		tactics_label_cape.config(text = 'TACTICS DETECTED BY CAPE SANDBOX', font = ('Comic Sans MS', 17))
		tactics_label_cape.place(x = 300, y = 5)
		tactics_label_cape1.config(text = 'Tactic', font = ('Comic Sans MS', 14))
		tactics_label_cape2.config(text = 'Tactic', font = ('Comic Sans MS', 14))
		descriptions_label_cape1.config(text = 'Description', font = ('Comic Sans MS', 14))
		descriptions_label_cape2.config(text = 'Description', font = ('Comic Sans MS', 14))
		techniques_cape_label.config(text = 'Techniques', font = ('Comic Sans MS', 14))
		tactics_label_zen.config(text = 'TACTICS DETECTED BY ZENBOX', font = ('Comic Sans MS', 17))
		tactics_label_zen1.config(text = 'Tactic', font = ('Comic Sans MS', 14))
		tactics_label_zen2.config(text = 'Tactic', font = ('Comic Sans MS', 14))
		descriptions_label_zen1.config(text = 'Description', font = ('Comic Sans MS', 14))
		descriptions_label_zen2.config(text = 'Description', font = ('Comic Sans MS', 14))
		techniques_zen_label.config(text = 'Techniques', font = ('Comic Sans MS', 14))
		upload_file_label_DS.config(text = 'UPLOAD YOUR FILE TO THE DIGITAL SIGNATURE TOOL', font = ('Comic Sans MS', 13))
		hash_file_ds_label.config(text = 'The hash (sha 256) of your file is: ')
		create_key_pair_label.config(text = 'Create key pair')
		bring_key_pair_label.config(text = 'Bring key pair')
		create_key_pair_label.place(x = 540, y = 190)
		bring_key_pair_label.place(x = 800, y = 190)
		bring_directory_DS.config(text = 'Define the directory for keys saving/searching')
		file_hash_ciphertext_title.config(text = 'Digital signature results')
		img_social_eng_label.config(image = cyberaware)
		password_checking_button.config(image = password_checking_logo)
		digital_signature_button.config(image = digital_signature_logo)
		logoBrowseDirectoriesHash.config(image = directory_browser)
		urlUploadLogo.config(image = directory_browser1)
		private_key_button_cr.config(image = private_key_logo)
		private_key_button_br.config(image = private_key_logo)
		public_key_button_cr.config(image = public_key_logo)
		public_key_button_br.config(image = public_key_logo)
		browse_ds_button.config(image = browse_ds_logo)
		directory_browse_DS.config(image = browse_ds_logo)
		verify_integrity_button.config(image = verify_integrity_logo)
		non_repudiation_button.config(image = non_repudiation_logo)
		instructions_ds_button.config(image = instructions_ds_logo)
		digital_signature_button.place(x = 20, y = 20)
		instructions_ds_button.place(x = 20, y = 380)
		non_repudiation_button.place(x = 168, y = 380)
		author_button.config(image = author_logo)




	elif Chinese_mode == True:

		playsound('Audios/Zhong_wen.mp3')
		english.config(fg = '#7e086c', bg = 'white')
		spanish.config(fg = '#7e086c', bg = 'white')
		chinese.config(bg = '#3b0332', fg = 'white')
		login_label.config(text = '登录 BirdCipher Machine', font = ('Kaiti', 20))
		username_label.config(text = '用户名', font = ('Kaiti', 18))
		password_label.config(text = '密码', font = ('Kaiti', 18))
		position_label.config(text = '角色', font = ("Kaiti", 18))
		send_login_data.config(text = '发送数据', font = ("Kaiti", 15))
		notebk.add(hr, text = " 登录")



def eye_password():

	global eye_password_active

	if eye_password_active:

		eye_password_active = False
		password_entry.configure(show = '')
		print(eye_password_active)

	elif eye_password_active == False:

		eye_password_active = True
		password_entry.configure(show = '*')
		print(eye_password_active)



# ---------------------------------------------------------------------------------------------------------------------------

## --------------------------------------------- Graphical User Interface ---------------------------------------------------

### ----------------------------------------------------- Basic -------------------------------------------------------------





decrypt = customtkinter.CTk()

decrypt.title("BirdCipher Cryptographic Machine")
decrypt.geometry('1100x590')
decrypt.resizable(0, 0)
customtkinter.set_appearance_mode("dark")

username_dbc = tk.StringVar()
password_dbc = tk.StringVar()
position_dbc = tk.StringVar()
password_user_classic = tk.StringVar()
packet = tk.IntVar()
player_message_encrypt = tk.StringVar()
passw_em = tk.StringVar()
password_for_decrypt = tk.StringVar()
password_for_ramson = tk.StringVar()
private_key_name_cr = tk.StringVar()
public_key_name_cr = tk.StringVar()
private_key_name_br = tk.StringVar()
public_key_name_br = tk.StringVar()
author_name_variable = tk.StringVar()
signature_name_variable = tk.StringVar()


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

encrypt_buttonImg = tk.PhotoImage(file = "Images/Encrypt-logo1.png")
decrypt_buttonImg = tk.PhotoImage(file = "Images/Decrypt-logo1.png")
directory_browser = tk.PhotoImage(file = 'Images/Browse directories1.png')
directory_browser1 = tk.PhotoImage(file = 'Images/Browse-logo1.png')
busqueda_directorio = tk.PhotoImage(file = 'Images/Buscar directorio.png')
busqueda_directorio_vt = tk.PhotoImage(file = 'Images/Buscar.png')
ramson_instructions = tk.PhotoImage(file = 'Images/Instructions.png')
generateRamsonKey_de = tk.PhotoImage(file = 'Images/Generate RamsonBird Key.png')
bringRamsonKey_de = tk.PhotoImage(file = 'Images/Bring RamsonBird key.png')
encryptFilesImage = tk.PhotoImage(file = 'Images/Decrypt files.png')
decryptFilesImage = tk.PhotoImage(file = 'Images/Encrypt files.png')
bc_logo_loginImage = tk.PhotoImage(file = 'Images/BirdCipher Machine-logoLogin-white1.png')
hashingImage = tk.PhotoImage(file = 'Images/Hashing-logo-white1.png')
closeLog = tk.PhotoImage(file = 'Images/CloseLog1.png')
arrow_asc = tk.PhotoImage(file = 'Images/arrow_asc.png')
arrow_des = tk.PhotoImage(file = 'Images/arrow_desc.png')
cyberaware = tk.PhotoImage(file = 'Images/Cyber Awareness.png')
firewall_humano = tk.PhotoImage(file = 'Images/Firewall Humano.png')
chequeoContraseña = tk.PhotoImage(file = 'Images/Chequeo de contraseña.png')
Swords = tk.PhotoImage(file = 'Images/Swords.png')
Keys_aware = tk.PhotoImage(file = 'Images/Llave_fin.png')
Caduceus_aware = tk.PhotoImage(file = 'Images/Caduceus_fin.png')
Book_aware = tk.PhotoImage(file = 'Images/Book_fin.png')
digital_signature_logo = tk.PhotoImage(file = 'Images/Digital Signature.png')
firma_digital_logo = tk.PhotoImage(file = 'Images/Firma Digital.png')
sign_document_logo = tk.PhotoImage(file = 'Images/Sign document.png')
non_repudiation_logo = tk.PhotoImage(file = 'Images/Non-repudiation.png')
no_repudio_logo = tk.PhotoImage(file = 'Images/No Repudio.png')
verify_integrity_logo = tk.PhotoImage(file = 'Images/Verify Integrity.png')
verificar_integridad_logo = tk.PhotoImage(file = 'Images/Verificar integridad.png')
instructions_ds_logo = tk.PhotoImage(file = 'Images/InstructionsDS.png')
instrucciones_ds_logo = tk.PhotoImage(file = 'Images/Instrucciones.png')
browse_ds_logo = tk.PhotoImage(file = 'Images/Browse_ds1.png')
private_key_logo = tk.PhotoImage(file = 'Images/private.png')
public_key_logo = tk.PhotoImage(file = 'Images/public.png')
llave_privada_logo = tk.PhotoImage(file = 'Images/Privada.png')
llave_publica_logo = tk.PhotoImage(file = 'Images/Publica.png')
buscar_ds_logo = tk.PhotoImage(file = 'Images/Buscar-ds.png')
author_logo = tk.PhotoImage(file = 'Images/Author.png')
autor_logo = tk.PhotoImage(file = 'Images/Autor.png')
firmar_documento_logo = tk.PhotoImage(file = 'Images/Firmar documento.png')
button_examine_url_test = tk.PhotoImage(file = 'Images/Examine-logo2.png')
virus_total_logo = tk.PhotoImage(file = 'Images/VirusTotal_Logo1.png')
algorithm_logo = tk.PhotoImage(file = 'Images/algorithm.png')
arrow_breaches_asc_logo = tk.PhotoImage(file = 'Images/arrow_breaches_asc_fn.png')
arrow_breaches_desc_logo = tk.PhotoImage(file = 'Images/arrow_breaches_desc_fn.png')
data_breaches_logo = tk.PhotoImage(file = 'Images/Data breaches.png')
blue_team_logo = tk.PhotoImage(file = 'Images/Blue Team-logo-white1.png')
red_team_logo = tk.PhotoImage(file = 'Images/Red Team-logo-white1.png')
ideas_red_logo = tk.PhotoImage(file = 'Images/Ideas-red.png')
ideas_blue_logo = tk.PhotoImage(file = 'Images/Ideas-blue.png')
presentacion_blue_logo = tk.PhotoImage(file = 'Images/Presentacion-blue.png')
presentation_blue_logo = tk.PhotoImage(file = 'Images/Presentation-blue.png')
presentation_red_logo = tk.PhotoImage(file = 'Images/Presentation-red.png')
presentacion_red_logo = tk.PhotoImage(file = 'Images/Presentacion-red.png')
birdcipher_ssh_logo = tk.PhotoImage(file = 'Images/BirdCipher SSH_log.png')
cryptanalysis_logo = tk.PhotoImage(file = 'Images/Cryptanalysis.png')
eye_password_logo = tk.PhotoImage(file = 'Images/eye1.png')

notebk = customtkinter.CTkTabview(master=decrypt)
notebk.configure(width = 1150, height = 580, segmented_button_selected_color = '#260223')
notebk.pack(padx=10, pady=10)
#notebk.config(font = ("Comic Sans MS", 14))

hr = notebk.add("Login")
fr0 = notebk.add("Education")
passcheck = notebk.add("Password Test")
hashing = notebk.add("Hashing")
fr = notebk.add("Cryptography")
fr2 = notebk.add("Encryption")
fr3 = notebk.add("Decryption")
digital_signature = notebk.add("Digital Signature")
pki = notebk.add("PKI")
fr0a = notebk.add("RamsonBird")
scan_tab = notebk.add('Scan')
url_test_ntk = notebk.add("URL Test")
web_scrapping_tab = notebk.add('Scrapping')
virusTotal = notebk.add("Virus Total")
#capa_tab = notebk.add("CAPA")
cape_sandbox_tab = notebk.add("CAPE")
zenbox_tab = notebk.add("Zenbox")
notebk.set('Login')



### -------------------------------------------- Login Section ---------------------------------------------------------------


login_label = customtkinter.CTkLabel(hr, text = "Log in to BirdCipher Machine", font = ("Times New Roman", 26), fg_color = "transparent")
login_label.grid(row = 0, column = 0, columnspan = 3, padx = (30,0), pady = (10,0))

username_label = customtkinter.CTkLabel(hr, text = "Username", font = ("Times New Roman", 20), fg_color = "transparent")
username_label.grid(row = 1, column = 0, columnspan = 1, padx = (50,0), sticky = 's')

username_entry = customtkinter.CTkEntry(hr, textvariable = username_dbc, font = ("Times New Roman", 20), justify = 'center')
username_entry.configure(width = 260)
username_entry.grid(row = 2, column = 0, columnspan = 3, padx = (0,25))

password_label = customtkinter.CTkLabel(hr, text = "Password", font = ("Times New Roman", 20), fg_color = "transparent")
password_label.grid(row = 3, column = 0, columnspan = 1, padx = (50,0), sticky = 's')

password_entry = customtkinter.CTkEntry(hr, textvariable = password_dbc, font = ("Times New Roman", 18), justify = 'center')
password_entry.configure(width = 260, show = '*')
password_entry.grid(row = 4, column = 0, columnspan = 3, padx = (0,25))

password_mask_button = customtkinter.CTkButton(hr, image = eye_password_logo, text = '', command = lambda:eye_password())
password_mask_button.configure(width = 5, fg_color = 'transparent', hover_color = '#2D2D38')
password_mask_button.grid(row = 4, column = 2, padx = (100,0))

position_label = customtkinter.CTkLabel(hr, text = "Position", font = ("Times New Roman", 20), fg_color = "transparent")
position_label.grid(row = 5, column = 0, columnspan = 1, padx = (50,0), sticky = 's')

position_entry = customtkinter.CTkEntry(hr, textvariable = position_dbc, font = ("Times New Roman", 20), justify = 'center')
position_entry.configure(width = 260)
position_entry.grid(row = 6, column = 0, columnspan = 3, padx = (0,25))

send_login_data = customtkinter.CTkButton(hr, text = 'Send login data', command = lambda:login_user())
send_login_data.configure(fg_color = '#3e043a', hover_color = '#260223', corner_radius = 5, font = ("Times New Roman", 15))
send_login_data.grid(row = 7, column = 0, columnspan = 3, sticky = 'e', padx = (0,70))

hash256_passw = customtkinter.CTkLabel(hr, text = "Your password hash (SHA 256) is:", font = ("Times New Roman", 20), fg_color = "transparent")
hash256_passw.grid(row = 9, column = 0, columnspan = 3, sticky = 's')

hash256_passw_label = customtkinter.CTkLabel(hr, text = '', font = ("Times New Roman", 13), fg_color = "black")
hash256_passw_label.configure(width = 450, corner_radius = 5)
hash256_passw_label.grid(row = 10, column = 0, columnspan = 4, padx = (10,0), sticky = 'sw')

hash256passw_copy_btt = customtkinter.CTkButton(hr, text = 'Copy hash to clipboard', command = lambda:copyHashLogin())
hash256passw_copy_btt.configure(fg_color = '#3e043a', hover_color = '#260223', corner_radius = 5, font = ("Times New Roman", 15))
hash256passw_copy_btt.grid(row = 10, column = 3, sticky = 'se', padx = (100,0))

close_machine_from_login = customtkinter.CTkButton(hr, text = '  Close the BirdCipher Machine  ', command = lambda:closeMachine())
close_machine_from_login.configure(fg_color = '#3e043a', hover_color = '#260223', corner_radius = 5, font = ("Times New Roman", 30))
close_machine_from_login.grid(row = 10, column = 4, padx = (20,10), sticky = 's')

bc_logo_login = customtkinter.CTkButton(hr, image = bc_logo_loginImage, text = '', command = lambda:login_user())
bc_logo_login.configure(fg_color = '#3e043a', hover_color = '#260223', corner_radius = 10)
bc_logo_login.grid(row = 0, column = 3, rowspan = 9, columnspan = 2, padx = (60,0), pady = (20,0), sticky = 's')

english = customtkinter.CTkButton(hr, text = 'English', command = lambda:[change_english_mode(), translator()])
english.configure(fg_color = '#3e043a', hover_color = '#260223', corner_radius = 5, font = ("Times New Roman", 22), width = 40)
english.grid(row = 8, column = 0)

spanish = customtkinter.CTkButton(hr, text = 'Español', command = lambda:[change_spanish_mode(), translator()])
spanish.configure(fg_color = '#3e043a', hover_color = '#260223', corner_radius = 5, font = ("Times New Roman", 22), width = 40)
spanish.grid(row = 8, column = 1)

chinese = customtkinter.CTkButton(hr, text = '中文', command = lambda:[change_chinese_mode(), translator()])
chinese.configure(fg_color = '#3e043a', hover_color = '#260223', corner_radius = 5, font = ("Kaiti", 24), width = 40)
chinese.grid(row = 8, column = 2)

# ---------------------------------------------------------------------------------------------------------------------------


### --------------------------------------------- Cybersecurity awareness section -------------------------------------------


def play_social_eng_audio():

	playsound(social_eng_audio[index_social_eng_choose])


def send_answer_social_eng():

	global feathers

	if varOption.get() == correct_answers_social_eng[index_social_eng_choose]:

		playsound('Audios/wonFeather.mp3')
		feathers = feathers + 1
		updatePlayer_feathers()
		labelFeathers.config(text = feathers)
		answer_button_social_eng.config(state = 'disabled')

	elif varOption.get() != correct_answers_social_eng[index_social_eng_choose]:

		playsound('Audios/lostFeather.mp3')
		answer_button_social_eng.config(state = 'disabled')


def red_team_function():

	global Spanish_mode
	global English_mode
	global Chinese_mode

	
	def OpenDWVideo():

		url = 'https://www.youtube.com/watch?v=vnxFgddu4Co'
		webbrowser.open_new(url)

	red_team_window = customtkinter.CTkToplevel(decrypt)
	red_team_window.title('Human Firewall Red Team')
	red_team_window.geometry('400x220')
	red_team_window.focus_set()
	red_team_window.grab_set()

	ideas_red_button = customtkinter.CTkButton(red_team_window, image = ideas_red_logo, text = '', command = lambda:OpenDWVideo())
	ideas_red_button.configure(fg_color = 'white', hover_color = '#efc9cc', corner_radius = 10)
	ideas_red_button.grid(row = 0, column = 0, padx = (30,10), pady = (30,20))

	presentation_red_button = customtkinter.CTkButton(red_team_window, image = presentation_red_logo, text = '')
	presentation_red_button.configure(fg_color = 'white', hover_color = '#efc9cc', corner_radius = 10)
	presentation_red_button.grid(row = 0, column = 1, padx = (10,10), pady = (30,20))

	if Spanish_mode == True:

		red_team_window.title('Equipo Rojo del Firewall Humano')
		presentation_red_button.configure(image = presentacion_red_logo)

	elif English_mode == True:

		red_team_window.title('Human Firewall Red Team')
		presentation_red_button.configure(image = presentation_red_logo)

	

def blue_team_function():

	global Spanish_mode
	global English_mode
	global Chinese_mode

	def OpenHackingBrainVideo():

		url = 'https://www.youtube.com/watch?v=eaXT2YerTzo'
		webbrowser.open_new(url)

	
	blue_team_window = customtkinter.CTkToplevel(decrypt)
	blue_team_window.title('Human Firewall Blue Team')
	blue_team_window.geometry('390x220')
	blue_team_window.focus_set()
	blue_team_window.grab_set()

	ideas_blue_button = customtkinter.CTkButton(blue_team_window, image = ideas_blue_logo, text = '', command = lambda:OpenHackingBrainVideo())
	ideas_blue_button.configure(fg_color = 'white', hover_color = '#c9d0ef', corner_radius = 10)
	ideas_blue_button.grid(row = 0, column = 0, padx = (30,10), pady = (30,20))

	presentation_blue_button = customtkinter.CTkButton(blue_team_window, image = presentation_blue_logo, text = '', command = lambda:OpenHackingBrainVideo())
	presentation_blue_button.configure(fg_color = 'white', hover_color = '#c9d0ef', corner_radius = 10)
	presentation_blue_button.grid(row = 0, column = 1, padx = (10,10), pady = (30,20))

	
	if Spanish_mode == True:

		blue_team_window.title('Equipo Azul del Firewall Humano')
		presentation_blue_button.configure(image = presentacion_blue_logo)

	elif English_mode == True:

		blue_team_window.title('Human Firewall Blue Team')
		presentation_blue_button.configure(image = presentation_blue_logo)




counter_social_eng = counter_social_eng + 1
index_social_eng = list(range(44))
index_social_eng_choose = index_social_eng[counter_social_eng]
img_social_eng = tk.PhotoImage(file = imagenes_ing_social[index_social_eng_choose])
varOption = tk.IntVar()

img_social_eng_label = customtkinter.CTkButton(fr0, image = cyberaware, text = '', command = lambda:play_video_social_eng())
img_social_eng_label.configure(fg_color = '#3e043a', hover_color = '#260223', corner_radius = 10)
img_social_eng_label.grid(row = 0, column = 0, columnspan = 5, rowspan = 7, pady = (10,15), padx = (30,30))

rad_button1 = customtkinter.CTkCheckBox(fr0, text = tests_ing_social[index_social_eng_choose][0], 
	 variable = varOption, onvalue = 1, offvalue = 5)
rad_button1.grid(row = 0, column = 5, columnspan = 4, sticky = 'w', pady = (10,0))
rad_button1.configure(font = ('Times New Roman', 16), fg_color = '#3e043a', width = 10, height = 10, checkbox_width = 20, checkbox_height = 20)

rad_button2 = customtkinter.CTkCheckBox(fr0, text = tests_ing_social[index_social_eng_choose][1], 
	 variable = varOption, onvalue = 2, offvalue = 6)
rad_button2.grid(row = 1, column = 5, columnspan = 4, sticky = 'w')
rad_button2.configure(font = ('Times New Roman', 16), fg_color = '#3e043a', checkbox_width = 20, checkbox_height = 20)

rad_button3 = customtkinter.CTkCheckBox(fr0, text = tests_ing_social[index_social_eng_choose][2], 
	 variable = varOption, onvalue = 3, offvalue = 7)
rad_button3.grid(row = 2, column = 5, columnspan = 4, sticky = 'w')
rad_button3.configure(font = ('Times New Roman', 16), fg_color = '#3e043a', checkbox_width = 20, checkbox_height = 20)

rad_button4 = customtkinter.CTkCheckBox(fr0, text = tests_ing_social[index_social_eng_choose][3], 
	 variable = varOption, onvalue = 4, offvalue = 8)
rad_button4.grid(row = 3, column = 5, columnspan = 4, sticky = 'w')
rad_button4.configure(font = ('Times New Roman', 16), fg_color = '#3e043a', checkbox_width = 20, checkbox_height = 20)

answer_button_social_eng = customtkinter.CTkButton(fr0, text = 'Send answer', command = lambda:send_answer_social_eng())
answer_button_social_eng.configure(fg_color = '#3e043a', hover_color = '#260223', corner_radius = 10, font = ('Times New Roman', 16))
answer_button_social_eng.grid(row = 4, column = 5, columnspan = 4, sticky = 'e')

number_video = customtkinter.CTkButton(fr0, image = arrow_asc, text = '', command = lambda:change_video_number_asc())
number_video.configure(fg_color = 'white', hover_color = '#ecc9ef', corner_radius = 8, width = 40)
number_video.grid(row = 7, column = 4)

number_video2 = customtkinter.CTkButton(fr0, image = arrow_des, text = '', command = lambda:change_video_number_desc())
number_video2.configure(fg_color = 'white', hover_color = '#ecc9ef', corner_radius = 8, width = 40)
number_video2.grid(row = 7, column = 3)

swords_insig = customtkinter.CTkButton(fr0, image = Swords, text = '')
swords_insig.configure(fg_color = 'white', hover_color = '#ecc9ef', corner_radius = 5, width = 40)
swords_insig.grid(row = 5, column = 7)

swords_score = customtkinter.CTkLabel(fr0, text = '', font = ("Times New Roman", 11), fg_color = "black")
swords_score.configure(width = 95, corner_radius = 5)
swords_score.grid(row = 6, column = 7)

Llave_final = customtkinter.CTkButton(fr0, image = Keys_aware, text = '')
Llave_final.configure(fg_color = 'white', hover_color = '#ecc9ef', corner_radius = 5, width = 40)
Llave_final.grid(row = 5, column = 6)

Llave_score = customtkinter.CTkLabel(fr0, text = '', font = ("Times New Roman", 11), fg_color = "black")
Llave_score.configure(width = 80, corner_radius = 5)
Llave_score.grid(row = 6, column = 6)

Caduceus_final = customtkinter.CTkButton(fr0, image = Caduceus_aware, text = '')
Caduceus_final.configure(fg_color = 'white', hover_color = '#ecc9ef', corner_radius = 5, width = 40)
Caduceus_final.grid(row = 5, column = 8)

Caduceus_score = customtkinter.CTkLabel(fr0, text = '', font = ("Times New Roman", 11), fg_color = "black")
Caduceus_score.configure(width = 100, corner_radius = 5)
Caduceus_score.grid(row = 6, column = 8)

Book_final = customtkinter.CTkButton(fr0, image = Book_aware, text = '')
Book_final.configure(fg_color = 'white', hover_color = '#ecc9ef', corner_radius = 5, width = 40)
Book_final.grid(row = 5, column = 5)

Book_score = customtkinter.CTkLabel(fr0, text = '', font = ("Times New Roman", 11), fg_color = "black")
Book_score.configure(width = 100, corner_radius = 5)
Book_score.grid(row = 6, column = 5)

blue_team_button = customtkinter.CTkButton(fr0, image = blue_team_logo, text = '', command = lambda:blue_team_function())
blue_team_button.configure(corner_radius = 8, width = 40, fg_color = '#086e91', hover_color = '#053e52')
blue_team_button.grid(row = 7, column = 1)

red_team_button = customtkinter.CTkButton(fr0, image = red_team_logo, text = '', command = lambda:red_team_function())
red_team_button.configure(fg_color = '#c6061e', hover_color = '#6f0512', corner_radius = 8, width = 40)
red_team_button.grid(row = 7, column = 2)

birdcipher_ssh_button = customtkinter.CTkButton(fr0, image = birdcipher_ssh_logo, text = '')
birdcipher_ssh_button.configure(fg_color = '#3e043a', hover_color = '#260223', corner_radius = 10, width = 20)
birdcipher_ssh_button.grid(row = 7, column = 0)

closeBCM_awareness = customtkinter.CTkButton(fr0, text = 'Close the BirdCipher Machine', command = lambda:closeMachine())
closeBCM_awareness.configure(fg_color = '#3e043a', hover_color = '#260223', corner_radius = 5, font = ('Times New Roman', 30))
closeBCM_awareness.grid(row = 7, column = 5, columnspan = 4, padx = (80,0))


# --------------------------------------------------------------------------------------------------------------------------


### ----------------------------------------- Password Checking Section ----------------------------------------------------


def evaluate_password():

	global login_check

	if login_check == True:

		specials = "!#$%&()*+,-./:;<=>?@[\\]^_`{|}~¡"
		mayusculas = 'ABCDEFGHIJKLMNÑOPQRSTUVWXYZ'
		minusculas = 'abcdefghijklmnñopqrstuvwxyz'
		numeros = '1234567890'

		password_to_evaluate = password_user_entry.get()
		evaluation = [False, False, False, False]
		evaluation_audios_es = ['Audios/caracter_especial.mp3', 'Audios/letra_mayuscula.mp3', 'Audios/letra_minuscula.mp3', 
		'Audios/numero_contrasena.mp3']

		for i in password_to_evaluate:

			if i in specials:

				evaluation[0] = True
		
			if i in mayusculas:

				evaluation[1] = True

			if i in minusculas:

				evaluation[2] = True

			if i in numeros:

				evaluation[3] = True


		count_lack = 4
		x = 0

		while x < 4:

			if evaluation[x] == False:

				time.sleep(1)
				playsound(evaluation_audios_es[x])
				print(evaluation_audios_es[x])

			else:

				count_lack = count_lack - 1

			x = x + 1

		if count_lack == 0:

			playsound('Audios/buen_trabajo.mp3')
			time.sleep(2)



def check_password():

	global login_check

	# Required: A descriptive user agent must be set describing the application consuming
	#   the HIBP API
	pyhibp.set_user_agent(ua="Awesome application/0.0.1 (An awesome description)")

	# Check a password to see if it has been disclosed in a public breach corpus
	resp = pw.is_password_breached(password = password_user_entry.get())

	if resp and login_check == True:

		result_check.delete('0.0', 'end')
		result_check.insert('0.0', 'Password breached! \n\nThis password was used the \nfollowing time(s) before: \n\nThe Have I Been Pwned Portal recommends that you change \nor improve your password')
		result_check.configure(text_color = '#ef1d13')
		time_breached.delete('0.0', 'end')
		time_breached.insert('0.0', resp)
		#time_breached.config(fg = '#ef1d13')
		playsound('Audios/bambu_click.mp3')
		playsound('Audios/ContrasenaInsegura.mp3')
		time.sleep(2)
		playsound('Audios/ImprovePass.mp3')
		time.sleep(4)

	elif resp == False and login_check == True:

		result_check.delete('0.0', 'end')
		result_check.insert('0.0', 'Secure password! \n\nThis password was used the \nfollowing time(s) before: \n\nThe Have I Been Pwned Portal recommends that you can use \nyour password safely')
		result_check.configure(text_color = '#7ed2ef')
		time_breached.delete('0.0', 'end')
		time_breached.insert('0.0', resp)
		time_breached.configure(font = ('Times New Roman', 60), padx = 60)
		playsound('Audios/bambu_click.mp3')
		playsound('Audios/ContrasenaSegura.mp3')
		time.sleep(2)
		playsound('Audios/SafePass.mp3')
		time.sleep(4)

	elif login_check == False:

		playsound('Audios/IniciarSesionUtilizarFuncion.mp3')


def passchecking_explanation():

	playsound('Audios/explicacion_passwordHIBP.mp3')
	playsound('Audios/passcheck_explant.mp3')


def hibp_breaches_info():

	global count_breach_list
	global arrow_breaches_asc
	global arrow_breaches_desc

	def switch_breaches_asc():

		global arrow_breaches_asc
		global arrow_breaches_desc

		arrow_breaches_asc = True
		arrow_breaches_desc = False

	def switch_breaches_desc():

		global arrow_breaches_asc
		global arrow_breaches_desc

		arrow_breaches_desc = True
		arrow_breaches_asc = False


	def hibp_breaches_list():

		global count_breach_list
		global arrow_breaches_asc
		global arrow_breaches_desc

		if arrow_breaches_asc:

			count_breach_list = count_breach_list + 1

		elif arrow_breaches_desc == True and count_breach_list > 0:

			count_breach_list = count_breach_list - 1

		elif arrow_breaches_desc == True and count_breach_list <= 0:

			print('You must advance')


		pyhibp.set_user_agent(ua = 'Awesome application/0.0.1 (An awesome description)')
		resp = pyhibp.get_all_breaches()

		playsound('Audios/bambu_click.mp3')
		hibp_breaches_text.delete(1.0, tk.END)
		hibp_breaches_text.insert(tk.END, 'Service name: {} \n'.format(resp[count_breach_list]['Name']))
		hibp_breaches_text.insert(tk.END, 'Domain: {} \n'.format(resp[count_breach_list]['Domain']))
		hibp_breaches_text.insert(tk.END, 'Breach date: {} \n'.format(resp[count_breach_list]['BreachDate']))
		hibp_breaches_text.insert(tk.END, 'Pwn account: {} \n'.format(resp[count_breach_list]['PwnCount']))
		hibp_breaches_text.insert(tk.END, '\n')
		hibp_breaches_text.insert(tk.END, 'Pwn data type: {} \n'.format(resp[count_breach_list]['DataClasses']))
		hibp_breaches_text.insert(tk.END, '\n')
		hibp_breaches_text.insert(tk.END, 'Description: {} \n '.format(resp[count_breach_list]['Description']))


	hibp_breaches_window = customtkinter.CTkToplevel(decrypt)
	hibp_breaches_window.title('Data breaches reports by Have I Been Pwned')
	hibp_breaches_window.geometry('450x550')
	hibp_breaches_window.focus_set()
	hibp_breaches_window.grab_set()

	hibp_breaches_title = customtkinter.CTkLabel(hibp_breaches_window, text = 'DATA BREACHES INFO', 
		font = ("Times New Roman", 20), fg_color = "transparent")
	hibp_breaches_title.grid(row = 0, column = 0, columnspan = 3, pady = (40,10))

	hibp_breaches_text = customtkinter.CTkTextbox(hibp_breaches_window, width = 390, height = 350, padx = 15)
	hibp_breaches_text.configure(font = ("Times New Roman", 18), wrap = 'word', corner_radius = 5)
	hibp_breaches_text.grid(row = 1, column = 0, columnspan = 3, padx = (30,0))

	hibp_breaches_query_asc = customtkinter.CTkButton(hibp_breaches_window, image = arrow_breaches_asc_logo, 
		text = '', command = lambda:[switch_breaches_asc(), hibp_breaches_list()])
	hibp_breaches_query_asc.configure(fg_color = 'white', hover_color = '#b4bae5', corner_radius = 5, width = 20)
	hibp_breaches_query_asc.grid(row = 2, column = 1)

	hibp_breaches_query_desc = customtkinter.CTkButton(hibp_breaches_window, image = arrow_breaches_desc_logo, 
		text = '', command = lambda:[switch_breaches_desc(), hibp_breaches_list()])
	hibp_breaches_query_desc.configure(fg_color = 'white', hover_color = '#b4bae5', corner_radius = 5, width = 20)
	hibp_breaches_query_desc.grid(row = 2, column = 0, padx = (50,10))

	data_breaches_image = customtkinter.CTkLabel(hibp_breaches_window, image = data_breaches_logo, text = '', fg_color = "transparent")
	data_breaches_image.grid(row = 2, column = 2)


def password_vault():

	def length_label(value):

		slider_label.configure(text = int(value))
		value_slider = slider.get()
		print(int(value_slider))

	passvault_window = customtkinter.CTkToplevel(decrypt)
	passvault_window.title('BirdCipher Password Vault')
	passvault_window.geometry('450x550')
	passvault_window.focus_set()
	passvault_window.grab_set()

	password_gen_title = customtkinter.CTkLabel(passvault_window, text = 'Your password is: ', font = ('Times New Roman', 22))
	password_gen_title.grid(row = 0, column = 0, columnspan = 3, pady = (20,10))

	password_gen_field = customtkinter.CTkLabel(passvault_window, text = '', font = ('Times New Roman', 16))
	password_gen_field.configure(fg_color = 'black', width = 350, corner_radius = 7)
	password_gen_field.grid(row = 1, column = 0, columnspan = 3, padx = (20,0), pady = (10,20))

	slider_title = customtkinter.CTkLabel(passvault_window, text = 'Define the length of your password ', font = ('Times New Roman', 18))
	slider_title.grid(row = 2, column = 0, padx = (30,0), pady = (10,10))

	slider = customtkinter.CTkSlider(passvault_window, from_ = 10, to = 30, command = length_label)
	slider.configure(number_of_steps=30, width = 350, height = 20)
	slider.grid(row = 3, column = 0, columnspan = 2, padx = (20,10), pady = (10,20))

	slider_label = customtkinter.CTkLabel(passvault_window, text = '20', font = ('Times New Roman', 30))
	slider_label.grid(row = 3, column = 2, pady = (10,20))

	uppercase_chkbx = customtkinter.CTkCheckBox(passvault_window, text = 'Upper case', font = ('Times New Roman', 14))
	uppercase_chkbx.configure(checkbox_width = 20, checkbox_height = 20)
	uppercase_chkbx.grid(row = 4, column = 0, padx = (10,0))

	lowercase_chkbx = customtkinter.CTkCheckBox(passvault_window, text = 'Lower case', font = ('Times New Roman', 14))
	lowercase_chkbx.configure(checkbox_width = 20, checkbox_height = 20)
	lowercase_chkbx.grid(row = 4, column = 1, padx = (10,0))



	
password_checking_logo = tk.PhotoImage(file = 'Images/Password checking-logo-white1.png')
hibp1_logo = tk.PhotoImage(file = 'Images/hibp1.png')
hibp_info_logo = tk.PhotoImage(file = 'Images/Password Check Info-logo-white1.png')
padlock_image = tk.PhotoImage(file = 'Images/Candado4a.png')
password_user_entry = tk.StringVar()

password_checking_button = customtkinter.CTkButton(passcheck, image = password_checking_logo, text = '', command = lambda:[check_password(), evaluate_password()])
password_checking_button.configure(fg_color = '#067297', hover_color = '#044257', corner_radius = 10)
password_checking_button.grid(row = 0, column = 2, rowspan = 5, columnspan = 2, padx = (50,0), pady = (30,0), sticky = 'n')

hibp_logo = customtkinter.CTkButton(passcheck, image = hibp1_logo, text = '', command = lambda:hibp_breaches_info())
hibp_logo.configure(fg_color = '#067297', hover_color = '#044257', corner_radius = 5)
hibp_logo.grid(row = 5, column = 2, rowspan = 2, sticky = 'n', padx = (50,10))

hibp_info = customtkinter.CTkButton(passcheck, image = hibp_info_logo, text = '', command = lambda:passchecking_explanation())
hibp_info.configure(fg_color = '#067297', hover_color = '#044257', corner_radius = 5, width = 30)
hibp_info.grid(row = 5, column = 3)

enter_password_label = customtkinter.CTkLabel(passcheck, text = 'Enter your password or e-mail', font = ("Times New Roman", 20), fg_color = "transparent")
enter_password_label.grid(row = 0, column = 0, padx = (30,20), pady = (40,0),sticky = 's')

enter_password_entry = customtkinter.CTkEntry(passcheck, textvariable = password_user_entry, font = ("Times New Roman", 20), justify = 'center')
enter_password_entry.configure(width = 300)
enter_password_entry.grid(row = 1, column = 0, padx = (30,20), pady = (10,0), sticky = 'n')

result_check_label = customtkinter.CTkLabel(passcheck, text = 'Results report', font = ("Times New Roman", 20), fg_color = "transparent")
result_check_label.grid(row = 2, column = 0, pady = (0,10), sticky = 's')

result_check = customtkinter.CTkTextbox(passcheck, width = 300, height = 210, padx = 15)
result_check.configure(font = ("Times New Roman", 20), wrap = 'word', corner_radius = 5)
result_check.grid(row = 3, column = 0, rowspan = 2, sticky = 'n')

times_label = customtkinter.CTkLabel(passcheck, text = 'Times used before:', font = ("Times New Roman", 20), fg_color = "transparent")
times_label.grid(row = 3, column = 1, sticky = 'n', pady = (10,0))

time_breached = customtkinter.CTkTextbox(passcheck, font = ("Times New Roman", 50))
time_breached.grid(row = 4, column = 1, sticky = 'n')
time_breached.configure(width = 180, height = 150, corner_radius = 5, wrap = 'word', padx = 10, pady = 50)

padlock = customtkinter.CTkButton(passcheck, image = padlock_image, text = '', command = lambda:password_vault())
padlock.configure(fg_color = 'transparent', hover_color = '#242222', corner_radius = 10)
padlock.grid(row = 0, column = 1, rowspan = 3, sticky = 'n', pady = (10,0))

closeBCM_checkpass = customtkinter.CTkButton(passcheck, text = 'Close the BirdCipher Cryptographic Machine', command = lambda:closeMachine())
closeBCM_checkpass.configure(fg_color = '#067297', hover_color = '#044257', corner_radius = 5, font = ("Times New Roman", 25))
closeBCM_checkpass.grid(row = 5, column = 0, columnspan = 2, pady = (20,0))

# --------------------------------------------------------------------------------------------------------------------------


### ------------------------------------------------- Hashing section ------------------------------------------------------

def hashingExecution():

	global algorithm_hashing
	global login_check

	archive_url_funct = archive_url.get()

	if archive_url_funct == '' and login_check == True:

		wbdatos = bytes(textToHashing.get('1.0', 'end-1c'), 'utf-8')
		hd = hashlib.new(algorithm_hashing[hashOption.get()], wbdatos)
		hash200 = HASH.generaHash(hd)
		playsound('Audios/bambu_click.mp3')
		labelHashResult.configure(text = hash200)

	elif archive_url_funct != '' and login_check == True:

		hashForFile = hash_file_birdcipher(archive_url_funct, algorithm_hashing[hashOption.get()])
		playsound('Audios/bambu_click.mp3')
		labelHashResult.configure(text = hashForFile)

	elif login_check == False:

		playsound('Audios/IniciarSesionUtilizarFuncion.mp3')



hashOption = tk.IntVar()
archive_url = tk.StringVar()
algorithm_hashing = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'shake_128', 'shake_256']


hashing_logo = customtkinter.CTkButton(hashing, image = hashingImage, text = '', command = lambda:hashingExecution())
hashing_logo.configure(fg_color = '#48044d', hover_color = '#300234', corner_radius = 10)
hashing_logo.grid(row = 0, column = 0, rowspan = 7, padx = (20,30), pady = (20,20))

labelPlayerLoginHashing = customtkinter.CTkLabel(hashing, text = 'Welcome, ', font = ("Times New Roman", 20), fg_color = "black")
labelPlayerLoginHashing.configure(corner_radius = 5, width = 40)
labelPlayerLoginHashing.grid(row = 0, column = 1, columnspan = 3, sticky = 'w')

labelTextHashing = customtkinter.CTkLabel(hashing, text = 'Enter the text to hash', font = ("Times New Roman", 20))
labelTextHashing.grid(row = 1, column = 1, columnspan = 2, padx = (10,0), sticky = 'sw')

textToHashing = customtkinter.CTkTextbox(hashing, width = 530, height = 130, padx = 15)
textToHashing.configure(font = ("Times New Roman", 18), wrap = 'word', corner_radius = 5)
textToHashing.grid(row = 2, column = 1, columnspan = 7, padx = (0,40))

labelHashEntry = customtkinter.CTkLabel(hashing, text = 'The hash of your message/file is:', font = ("Times New Roman", 25))
labelHashEntry.grid(row = 7, column = 0, sticky = 'nw', padx = (20,0))

labelHashResult = customtkinter.CTkLabel(hashing, text = '', font = ("Times New Roman", 15))
labelHashResult.configure(width = 930, fg_color = 'black', corner_radius = 5)
labelHashResult.grid(row = 8, column = 0, columnspan = 6, sticky = 'w', padx = (20,0))

logoBrowseDirectoriesHash = customtkinter.CTkButton(hashing, image = directory_browser, text = '', command = lambda:selectDirectoryHash())
logoBrowseDirectoriesHash.configure(fg_color = 'white', hover_color = '#ecace7', corner_radius = 6, width = 5)
logoBrowseDirectoriesHash.grid(row = 5, column = 5, rowspan = 2, sticky = 's', pady = (0,10))

labelArchive = customtkinter.CTkLabel(hashing, text = 'The URL of your file is:', font = ("Times New Roman", 20))
labelArchive.configure(fg_color = 'transparent')
labelArchive.grid(row = 5, column = 1, columnspan = 2, sticky = 'sw')

archiveURLShow = customtkinter.CTkEntry(hashing, textvariable = archive_url, font = ("Times New Roman", 13), justify = 'center')
archiveURLShow.configure(width = 440)
archiveURLShow.grid(row = 6, column = 1, columnspan = 5, sticky = 'nw')

algorithmHash = customtkinter.CTkLabel(hashing, text = 'Available algorithms', font = ("Times New Roman", 20))
algorithmHash.configure(fg_color = 'transparent')
algorithmHash.grid(row = 3, column = 1, columnspan = 2, sticky = 'sw')

rad_button_md5 = customtkinter.CTkRadioButton(hashing, text = "md5", variable = hashOption, value = 0)
rad_button_md5.configure(font = ('Times New Roman', 18), fg_color = '#e889e1', border_width_unchecked = 2, border_width_checked = 3,
	radiobutton_width = 15, radiobutton_height = 15)
rad_button_md5.grid(row = 4, column = 1, sticky = 'e')

rad_button_sha224 = customtkinter.CTkRadioButton(hashing, text = "sha224", variable = hashOption, value = 2)
rad_button_sha224.configure(font = ('Times New Roman', 18), fg_color = '#e889e1', radiobutton_width = 15, radiobutton_height = 15,
	border_width_checked = 3, border_width_unchecked = 2)
rad_button_sha224.grid(row = 4, column = 2)

rad_button_sha256 = customtkinter.CTkRadioButton(hashing, text = "sha256", variable = hashOption, value = 3)
rad_button_sha256.configure(font = ('Times New Roman', 18), fg_color = '#e889e1', radiobutton_width = 15, radiobutton_height = 15,
	border_width_checked = 3, border_width_unchecked = 2)
rad_button_sha256.grid(row = 4, column = 3)

rad_button_sha384 = customtkinter.CTkRadioButton(hashing, text = "sha384", variable = hashOption, value = 4)
rad_button_sha384.configure(font = ('Times New Roman', 18), fg_color = '#e889e1', radiobutton_width = 15, radiobutton_height = 15,
	border_width_checked = 3, border_width_unchecked = 2)
rad_button_sha384.grid(row = 4, column = 4)

rad_button_sha512 = customtkinter.CTkRadioButton(hashing, text = "sha512", variable = hashOption, value = 5)
rad_button_sha512.configure(font = ('Times New Roman', 18), fg_color = '#e889e1', radiobutton_width = 15, radiobutton_height = 15,
	border_width_checked = 3, border_width_unchecked = 2)
rad_button_sha512.grid(row = 4, column = 5)

copy_hash = customtkinter.CTkButton(hashing, text = 'Copy hash', command = lambda:closeMachine())
copy_hash.configure(fg_color = '#48044d', hover_color = '#300234', corner_radius = 5, width = 5, font = ("Times New Roman", 13))
copy_hash.place(x = 980, y = 490)

closeBCM_hashing = customtkinter.CTkButton(hashing, image = closeLog, text = '', command = lambda:closeMachine())
closeBCM_hashing.configure(fg_color = 'white', hover_color = '#e4aee9', corner_radius = 10, width = 10)
closeBCM_hashing.grid(row = 0, column = 5, columnspan = 2)

# -------------------------------------------------------------------------------------------------------------------------


### ---------------------------------------------- Digital Signature section -----------------------------------------------


def private_key_generator():

	global private_key_user
	global directoryFindKeysDS

	print(directoryFindKeysDS)

	private_key_user = rsa.generate_private_key(
		public_exponent = 65537,
		key_size = 2048,
		backend = default_backend()
		)

	print(private_key_user)

	pem_private_key_user = private_key_user.private_bytes(
		encoding = serialization.Encoding.PEM,
		format = serialization.PrivateFormat.PKCS8,
		encryption_algorithm = serialization.NoEncryption()
		)

	with open(directoryFindKeysDS + '/' + private_key_name_cr.get(), 'wb') as f:

		f.write(pem_private_key_user)

	print('Done')


def public_key_generator():

	global private_key_user
	global public_key_user
	global directoryFindKeysDS
	global public_key_user_string

	public_key_user = private_key_user.public_key()
	print(public_key_user)

	pem_public_key_user = public_key_user.public_bytes(
		encoding = serialization.Encoding.PEM,
		format = serialization.PublicFormat.SubjectPublicKeyInfo
		)

	with open(directoryFindKeysDS + '/' + public_key_name_cr.get(), 'wb') as f:

		f.write(pem_public_key_user)

	public_key_user_string = pem_public_key_user.decode('utf-8')


def private_key_reader():

	global directoryFindKeysDS
	global private_key_user

	with open(directoryFindKeysDS + '/' + private_key_name_br.get(), 'rb') as key_file:

		private_key_user = serialization.load_pem_private_key(

			key_file.read(),
			password = None,
			backend = default_backend()
			)

	print(private_key_user)

def public_key_reader():

	global directoryFindKeysDS
	global private_key_user
	global public_key_user
	global public_key_user_string

	# public_key_user = private_key_user.public_key()
	# print(public_key_user)

	# pem_public_key_user = public_key_user.public_bytes(
	# 	encoding = serialization.Encoding.PEM,
	# 	format = serialization.PublicFormat.SubjectPublicKeyInfo
	# 	)

	with open(directoryFindKeysDS + '/' + public_key_name_br.get(), 'rb') as f:

		public_key_user = serialization.load_pem_public_key(

			f.read(),
			backend = default_backend()

			)


	public_pem_bytes = public_key_user.public_bytes(
    	encoding=serialization.Encoding.PEM,
    	format=serialization.PublicFormat.SubjectPublicKeyInfo)

	public_key_user_string = public_pem_bytes.decode('utf-8')




	# 	f.write(pem_public_key_user)

	print('Public key generated')
	print(public_key_user)




def sign_document_function():

	global hash_file_DS
	global private_key_user
	global signature

	signature = private_key_user.sign(

		hash_file_DS,
		padding.PSS(
			mgf = padding.MGF1(hashes.SHA256()),
			salt_length = padding.PSS.MAX_LENGTH
			),
		hashes.SHA256()
		) 

	file_hash_ciphertext_label.delete('1.0', tk.END)
	file_hash_ciphertext_label.insert(tk.END, signature)

	with open(directoryFindKeysDS + '/' + signature_name_variable.get(), 'wb') as j:

		j.write(signature)


def verify_function():

	global signature
	global hash_file_DS
	global public_key_user

	if signature == '':

		with open(directoryFindKeysDS + '/' + signature_name_variable.get(), 'rb') as l:

			signature = l.read()

	try:

		verification = public_key_user.verify(

			signature,
			hash_file_DS,
			padding.PSS(
			
				mgf = padding.MGF1(hashes.SHA256()),
				salt_length = padding.PSS.MAX_LENGTH
				),
			hashes.SHA256()

			)

		file_hash_ciphertext_label.delete('1.0', tk.END)

		if verification is None:

			file_hash_ciphertext_label.insert(tk.END, 'Verification is OK')

	except InvalidSignature:

		file_hash_ciphertext_label.insert(tk.END, 'Verification failed')


def option_sign():

	global option_sign_choose
	global option_verify_choose
	global username_db

	option_sign_choose = True
	option_verify_choose = False
	author_name_variable.set(username_db)


def option_verify():

	global option_sign_choose
	global option_verify_choose

	option_verify_choose = True
	option_sign_choose = False




def manage_signature():

	global public_key_user
	global option_sign_choose
	global option_verify_choose


	if option_sign_choose:

		miConexion1000 = psycopg2.connect(host = 'bps57o4k0svfjp9fi4vv-postgresql.services.clever-cloud.com', port = 50013, 
		user = 'u8kpoxoaaxlswsvwrn12', dbname = 'bps57o4k0svfjp9fi4vv', password = 'AgCdmPuBEd0gAhai93vqWI2qoIz85G')

		miCursor1000 = miConexion1000.cursor()

		sql2000 = 'insert into digital_signature(author, public_key) values(%s,%s)'
		sql2000_data = (author_name_variable.get(), public_key_user_string)

		miCursor1000.execute(sql2000, sql2000_data)

		miConexion1000.commit()
		miConexion1000.close()

	elif option_verify_choose:

		miConexion3000 = psycopg2.connect(host = 'bps57o4k0svfjp9fi4vv-postgresql.services.clever-cloud.com', port = 50013, 
		user = 'u8kpoxoaaxlswsvwrn12', dbname = 'bps57o4k0svfjp9fi4vv', password = 'AgCdmPuBEd0gAhai93vqWI2qoIz85G')

		miCursor3000 = miConexion3000.cursor()

		sql3000 = 'select * from digital_signature where author = (%s)'
		sql3000_data = (author_name_variable.get(), )

		miCursor3000.execute(sql3000, sql3000_data)
		dlt3000 = miCursor3000.fetchall()

		public_key_user_temp = dlt3000[0][2]
		public_key_user_temp2 = public_key_user_temp.encode('utf-8')

		with open(directoryFindKeysDS + '/' + public_key_name_br.get(), 'wb') as f:

			f.write(public_key_user_temp2)

		# pem_encoded_public_key = public_key_user_temp2.public_bytes(
    	# 	encoding=serialization.Encoding.PEM,
    	# 	format=serialization.PublicFormat.SubjectPublicKeyInfo)

		# public_key_user = pem_encoded_public_key
		# public_key_name_br.set('public.pem')
		#public_key_name_label_br.config()
		




		miConexion3000.commit()
		miConexion3000.close()




def person_non_repudiation():

	global English_mode
	global Spanish_mode

	person_registry = tk.Toplevel(decrypt)
	person_registry.title('Person')
	person_registry.geometry('550x400')

	author_button = tk.Button(person_registry, command = lambda:manage_signature())
	author_button.config(bg = '#040339')
	author_button.place(x = 20, y = 20)

	author_name_title = tk.Label(person_registry)
	author_name_title.config(font = ('Comic Sans MS', 13), fg = '#040339')
	author_name_title.place(x = 30, y = 260)

	author_name_label = tk.Entry(person_registry, textvariable = author_name_variable, width = 22)
	author_name_label.config(font = ('Comic Sans MS', 11), fg = '#9daee1', bg = '#050005', justify = 'center')
	author_name_label.place(x = 20, y = 290)

	signature_name_title = tk.Label(person_registry)
	signature_name_title.config(font = ('Comic Sans MS', 13), fg = '#040339')
	signature_name_title.place(x = 30, y = 320)

	signature_name_label = tk.Entry(person_registry, textvariable = signature_name_variable, width = 22)
	signature_name_label.config(font = ('Comic Sans MS', 11), fg = '#9daee1', bg = '#050005', justify = 'center')
	signature_name_label.place(x = 20, y = 350)

	option_sign_document = tk.Button(person_registry, command = lambda:option_sign())
	option_sign_document.place(x = 250, y = 30)
	option_sign_document.config(font = ('Comic Sans MS', 11), fg = '#040339')

	option_verify_document = tk.Button(person_registry, command = lambda:option_verify())
	option_verify_document.place(x = 250, y = 80)
	option_verify_document.config(font = ('Comic Sans MS', 11), fg = '#040339')

	sign_document_button = tk.Button(person_registry, image = sign_document_logo, command = lambda:sign_document_function())
	sign_document_button.place(x = 385, y = 267)

	
	if English_mode:

		author_button.config(image = author_logo)
		author_name_title.config(text = 'Username')
		signature_name_title.config(text = 'Signature file name')
		signature_name_title.place(x = 30, y = 320)
		option_sign_document.config(text = 'Sign document mode')
		option_verify_document.config(text = 'Verify document mode')
		sign_document_button.config(image = sign_document_logo)
		sign_document_button.place(x = 385, y = 267)


	elif Spanish_mode:

		author_button.config(image = autor_logo)
		author_name_title.config(text = 'Usuario')
		signature_name_title.config(text = 'Archivo de firma digital')
		signature_name_title.place(x = 20, y = 320)
		option_sign_document.config(text = 'Modo firma digital de documento')
		option_verify_document.config(text = 'Modo verificación de firma digital')
		sign_document_button.config(image = firmar_documento_logo)
		sign_document_button.place(x = 385, y = 250)




digital_signature_button = tk.Button(digital_signature, image = digital_signature_logo, command = lambda:person_non_repudiation())
digital_signature_button.config(bg = '#040339')
digital_signature_button.place(x = 20, y = 20)

instructions_ds_button = tk.Button(digital_signature, image = instructions_ds_logo)
instructions_ds_button.place(x = 20, y = 380)

non_repudiation_button = tk.Button(digital_signature, image = non_repudiation_logo, command = lambda:person_non_repudiation())
non_repudiation_button.place(x = 168, y = 380)

verify_integrity_button = tk.Button(digital_signature, image = verify_integrity_logo, command = lambda:verify_function())
verify_integrity_button.place(x = 315, y = 380)

upload_file_label_DS = tk.Label(digital_signature, text = 'UPLOAD YOUR FILE TO THE DIGITAL SIGNATURE TOOL')
upload_file_label_DS.config(font = ('Comic Sans MS', 13), fg = '#040339')
upload_file_label_DS.place(x = 510, y = 20)

url_file_label_DS = tk.Label(digital_signature, width = 57)
url_file_label_DS.config(font = ('Comic Sans MS', 8), fg = '#9daee1', bg = '#050005', justify = 'center')
url_file_label_DS.place(x = 520, y = 70)

browse_ds_button = tk.Button(digital_signature, image = browse_ds_logo, command = lambda:selectDirectoryDigitalSignature())
browse_ds_button.place(x = 940, y = 55)

hash_file_ds_label = tk.Label(digital_signature, text = 'The hash (sha 256) of your file is: ')
hash_file_ds_label.config(font = ('Comic Sans MS', 11), fg = '#040339')
hash_file_ds_label.place(x = 520, y = 120)

hash_file_label_DS = tk.Label(digital_signature, width = 63)
hash_file_label_DS.config(font = ('Comic Sans MS', 8), fg = '#9daee1', bg = '#050005', justify = 'center')
hash_file_label_DS.place(x = 520, y = 150)

create_key_pair_label = tk.Label(digital_signature, text = 'Create key pair')
create_key_pair_label.config(font = ('Comic Sans MS', 12), fg = '#040339')
create_key_pair_label.place(x = 540, y = 190)

bring_key_pair_label = tk.Label(digital_signature, text = 'Bring key pair')
bring_key_pair_label.config(font = ('Comic Sans MS', 12), fg = '#040339')
bring_key_pair_label.place(x = 800, y = 190)

private_key_name_label_cr = tk.Entry(digital_signature, textvariable = private_key_name_cr, width = 15)
private_key_name_label_cr.config(font = ('Comic Sans MS', 12), fg = '#9daee1', bg = '#050005', justify = 'center')
private_key_name_label_cr.place(x = 520, y = 220)

private_key_button_cr = tk.Button(digital_signature, image = private_key_logo, command = lambda:private_key_generator())
private_key_button_cr.place(x = 690, y = 202)

public_key_name_label_cr = tk.Entry(digital_signature, textvariable = public_key_name_cr, width = 15)
public_key_name_label_cr.config(font = ('Comic Sans MS', 12), fg = '#9daee1', bg = '#050005', justify = 'center')
public_key_name_label_cr.place(x = 520, y = 300)

public_key_button_cr = tk.Button(digital_signature, image = public_key_logo, command = lambda:public_key_generator())
public_key_button_cr.place(x = 690, y = 282)

private_key_name_label_br = tk.Entry(digital_signature, textvariable = private_key_name_br, width = 15)
private_key_name_label_br.config(font = ('Comic Sans MS', 12), fg = '#9daee1', bg = '#050005', justify = 'center')
private_key_name_label_br.place(x = 780, y = 220)

private_key_button_br = tk.Button(digital_signature, image = private_key_logo, command = lambda:private_key_reader())
private_key_button_br.place(x = 950, y = 202)

public_key_name_label_br = tk.Entry(digital_signature, textvariable = public_key_name_br, width = 15)
public_key_name_label_br.config(font = ('Comic Sans MS', 12), fg = '#9daee1', bg = '#050005', justify = 'center')
public_key_name_label_br.place(x = 780, y = 300)

public_key_button_br = tk.Button(digital_signature, image = public_key_logo, command = lambda:public_key_reader())
public_key_button_br.place(x = 950, y = 282)

bring_directory_DS = tk.Label(digital_signature, text = 'Define the directory for keys saving/searching')
bring_directory_DS.config(font = ('Comic Sans MS', 14), fg = '#040339')
bring_directory_DS.place(x = 520, y = 360)

directory_label_DS = tk.Label(digital_signature, width = 59)
directory_label_DS.config(bg = '#050005', fg = '#9daee1')
directory_label_DS.place(x = 520, y = 390)

directory_browse_DS = tk.Button(digital_signature, image = browse_ds_logo, command = lambda:selectDirectoryOpenFindKeysDS())
directory_browse_DS.place(x = 950, y = 370)

file_hash_ciphertext_title = tk.Label(digital_signature, text = 'Digital Signature Results')
file_hash_ciphertext_title.config(font = ('Comic Sans MS', 13), fg = '#040339')
file_hash_ciphertext_title.place(x = 530, y = 415)

file_hash_ciphertext_label = tk.Text(digital_signature, width = 50, height = 3, padx = 10)
file_hash_ciphertext_label.config(font = ('Comic Sans MS', 11), fg = '#9daee1', bg = '#050005')
file_hash_ciphertext_label.place(x = 520, y = 445)




### ---------------------------------------------- Classic cryptography section -------------------------------------------- 


mode_classic = ''
translate = ''
keyApply = 0
keyApply_transLinear = 0
translate_tl = ''
translation = ''

keyCaesarAnswer = tk.IntVar()
keyLinearTranspostAnswer = tk.IntVar()
keyInverseTranspostAnswer = tk.IntVar()

ddatos = bytes(password_user_classic.get(), 'utf-8')
u = hashlib.new(algoritmo, ddatos)
hash4 = HASH.generaHash(u)



def reverse_adjust():

	global translation
	global login_check

	if login_check == True:

		translation = reverse_cipher_apl(plaintext.get("1.0", "end-1c"))
		ciphertext.delete(1.0, tk.END)
		playsound('Audios/bambu_click.mp3')
		ciphertext.insert(tk.END, translation)

	else:

		playsound('Audios/IniciarSesionUtilizarFuncion.mp3')

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
	global login_check

	if mode_classic == 'e':

		message_apply = plaintext.get('1.0', 'end-1c')

	elif mode_classic == 'd':

		message_apply = ciphertext.get('1.0', 'end-1c')

	elif mode_classic == '':

		playsound('Audios/Encriptar_o_desencriptar.mp3')


	if mode_classic != '':

		keyApply = keyCaesarAnswer.get()

		if keyApply != 0 and login_check == True:

			translation = getTranslatedMessage(mode_classic, message_apply, keyCaesarAnswer.get())

			# ciphertext.delete(1.0, tk.END)
			# ciphertext.insert(tk.END, translate)

			if mode_classic == 'e':

				ciphertext.delete(1.0, tk.END)
				#playsound('Audios/bambu_click.mp3')
				ciphertext.insert(tk.END, translation)

			elif mode_classic == 'd':

				plaintext.delete(1.0, tk.END)
				playsound('Audios/bambu_click.mp3')
				plaintext.insert(tk.END, translation)


		elif keyApply == 0:

			playsound('Audios/DebesDefinirLlave.mp3')

		elif login_check == False:

			playsound('Audios/IniciarSesionUtilizarFuncion.mp3')


def TranspositionApply():

	global mode_classic
	global translation
	global keyApply_transLinear
	global login_check
		

	if mode_classic == 'e':

		message_apply_tl = plaintext.get('1.0', 'end-1c')
		#print(len(message_apply_tl))

	elif mode_classic == 'd':

		message_apply_tl = ciphertext.get('1.0', 'end-1c')

	elif mode_classic == '':

		playsound('Audios/Encriptar_o_desencriptar.mp3')

	if mode_classic == 'e':

		keyApply_transLinear = keyLinearTranspostAnswer.get()

		if keyApply_transLinear != 0 and login_check == True:

			translation = encryptMessageTransLinear(keyApply_transLinear, message_apply_tl)

			ciphertext.delete(1.0, tk.END)
			playsound('Audios/bambu_click.mp3')
			ciphertext.insert(tk.END, translation)

		elif keyApply_transLinear == 0:

			playsound('Audios/DebesDefinirLlave.mp3')

		elif login_check == False:

			playsound('Audios/IniciarSesionUtilizarFuncion.mp3')

	if mode_classic == 'd':

		keyApply_transLinear = keyLinearTranspostAnswer.get()

		if keyApply_transLinear != 0 and login_check == True:

			translation = decryptMessages(keyApply_transLinear, message_apply_tl)
			plaintext.delete(1.0, tk.END)
			playsound('Audios/bambu_click.mp3')
			plaintext.insert(tk.END, translation)

		elif keyApply_transLinear == 0:

			playsound('Audios/DebesDefinirLlave.mp3')

		elif login_check == False:

			playsound('Audios/IniciarSesionUtilizarFuncion.mp3')


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

		playsound('Audios/Hello.mp3')

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

nicknameCuad = tk.Entry(fr, textvariable=password_user_classic, font = ("Comic Sans MS", 13), justify = "center")
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
	
imagen_caesar_cipher = tk.PhotoImage(file = 'Images/Imagen_caesar.png')
imageCaesar = tk.PhotoImage(file = "Images/Caesar Cipher-logo1.png")
imageReverse = tk.PhotoImage(file = "Images/Reverse Cipher-logo1.png")
imageLinearTransposition = tk.PhotoImage(file = "Images/Linear Transposition -logo1.png")
imageInverseTransposition = tk.PhotoImage(file = "Images/Inverse Transposition -logo1.png")
imageLives = tk.PhotoImage(file = "Images/Lives-logo1.png")
cryptoMachineImage = tk.PhotoImage(file = "Images/Cryptographic Machine-logo1.png")
ramson_image = tk.PhotoImage(file = 'Images/RamsonBird_MachineImage.png')

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
labelQuestionKey.place(x = 800, y = 50)

labelPlayerBCM = tk.Label(fr, text = "Welcome, ", font = ("Comic Sans MS", 11))
labelPlayerBCM.config(fg = "#eba5f1", bg = "#050005")
labelPlayerBCM.place(x = 780, y = 10)

imageCryptographicMachine = tk.Button(fr, image = cryptanalysis_logo, command = lambda:copyText())
imageCryptographicMachine.config(bg = '#2f022b')
imageCryptographicMachine.place(x = 790, y = 260)

closeMachineButton = tk.Button(fr, text = "Close the BirdCipher Cryptographic Machine", font = ("Comic Sans MS", 12), command = lambda:closeMachine())
closeMachineButton.place(x = 700, y = 475)
closeMachineButton.config(fg = "#7e086c")


# ----------------------------------------------------------------------------------------------------------------------------



### ------------------------------------------------ Message encryption section -----------------------------------------------


def algorithm_selection():

	algorithm_select = tk.Toplevel(decrypt)
	algorithm_select.title('Encryption Algorithm selection')
	algorithm_select.geometry('400x300')

	
encryption_machine_logo = tk.PhotoImage(file = "Images/Send Encrypted Message-logo.png")
generate_key_image = tk.PhotoImage(file = "Images/Generate Key-logo.png")
encrypt_message_image = tk.PhotoImage(file = "Images/Encrypt Message-logo1.png")
person1_image = tk.PhotoImage(file = 'Images/Person1.png')
person2_image = tk.PhotoImage(file = 'Images/Person2.png')
person3_image = tk.PhotoImage(file = 'Images/Person3.png')
person4_image = tk.PhotoImage(file = 'Images/Person4.png')
receiver_ramson_image = tk.PhotoImage(file = 'Images/PersonRansom-logo1.png')

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
scrollVetrn2.place(x = 710, y = 210, height = 79)

nicknameCuad2 = tk.Entry(fr2, textvariable = passw_em, font = ("Comic Sans MS", 13), justify = "center")
nicknameCuad2.config(bg = '#050005', fg = '#7e086c')
nicknameCuad2.place(x = 790, y = 100)
	
fernet_key_button = tk.Button(fr2, image = generate_key_image, font = ("Comic Sans MS", 8), command = lambda:fernet_key_gen())
fernet_key_button.config(fg = '#7e086c')
fernet_key_button.place(x = 800, y = 150)
	
fernet_encryption_message = tk.Button(fr2, image = encrypt_message_image, font = ("Comic Sans MS", 8), command = lambda:fernet_encryption_function())
fernet_encryption_message.config(fg = '#1af017')
fernet_encryption_message.place(x = 900, y = 150)

algorithm_button = tk.Button(fr2, image = algorithm_logo, command = lambda:algorithm_selection())
algorithm_button.place(x = 50, y = 310)
algorithm_button.config(bg = '#3f0322')

titleBirdCipherMachine20 = tk.Label(fr2, text = "BirdCipher Encryption Machine: a tool to guarantee the confidentiality of your messages", font = ("Comic Sans MS", 12))
titleBirdCipherMachine20.config(fg = "#7e086c")
titleBirdCipherMachine20.place(x = 70, y = 8)

buttonPerson1a = tk.Button(fr2, image = person1_image, command = lambda:person1_actv())
buttonPerson1a.place(x = 270, y = 310)

buttonPerson2a = tk.Button(fr2, image = person2_image, command = lambda:person2_actv())
buttonPerson2a.place(x = 370, y = 310)

buttonPerson3a = tk.Button(fr2, image = person3_image, command = lambda:person3_actv())
buttonPerson3a.place(x= 470, y = 310)

buttonPerson4a = tk.Button(fr2, image = person4_image, command = lambda:person4_actv())
buttonPerson4a.place(x = 570, y = 310)

# labelPoints2 = tk.Label(fr2, font = ("Comic Sans MS", 13), justify = "center", width = 6)
# labelPoints2.config(bg = "#050005", fg = "#7e086c")
# labelPoints2.place(x = 212, y = 410)

person1 = tk.Entry(fr2, textvariable = person1_var, font = ("Comic Sans MS", 10), justify = "center", width = 10)
person1.config(bg = "#050005", fg = "#efc2ee")
person1.place(x = 270, y = 410)

person2 = tk.Entry(fr2, textvariable = person2_var, font = ("Comic Sans MS", 10), justify = "center", width = 10)
person2.config(bg = "#050005", fg = "#efc2ee")
person2.place(x = 370, y = 410)

person3 = tk.Entry(fr2, textvariable = person3_var, font = ("Comic Sans MS", 10), justify = "center", width = 10)
person3.config(bg = "#050005", fg = "#efc2ee")
person3.place(x = 470, y = 410)

person4 = tk.Entry(fr2, textvariable = person4_var, font = ("Comic Sans MS", 10), justify = "center", width = 10)
person4.config(bg = "#050005", fg = "#efc2ee")
person4.place(x = 570, y = 410)

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
closeMachineButton2.place(x = 290, y = 460)
closeMachineButton2.config(fg = "#7e086c")

# ---------------------------------------------------------------------------------------------------------------------------


### ------------------------------------------- Message decryption section --------------------------------------------------


cipher_text3 = tk.Text(fr3, font = ("Comic Sans MS", 10), width = 79, height = 4)
cipher_text3.config(bg = '#050005', fg = '#FFFFFF', padx = 8)
cipher_text3.place(x = 60, y = 40)

scrollVetrn3 = tk.Scrollbar(fr3, command = cipher_text3.yview)
scrollVetrn3.place(x = 710, y = 40, height = 75)

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
	
cipher_text2_encrp2 = tk.Text(fr3, font = ("Comic Sans MS", 10), width = 79)
cipher_text2_encrp2.config(bg = '#050005', fg = '#FFFFFF', padx = 8)
cipher_text2_encrp2.place(x = 60, y = 210, height = 80)

scrollVetrn4 = tk.Scrollbar(fr3, command = cipher_text2_encrp2.yview)
scrollVetrn4.place(x = 710, y = 210, height = 80)

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

labelPoints3 = tk.Label(fr3, font = ("Comic Sans MS", 13), justify = "center", width = 6)
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

# ---------------------------------------------------------------------------------------------------------------------------



### ----------------------------------------------- RamsonBird Section -------------------------------------------------------


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
buttonReceiver.place(x = 577, y = 280)

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

# -----------------------------------------------------------------------------------------------------------------------------

### ---------------------------------------------- Virus Total URL Test section -----------------------------------------------

url_for_test = tk.StringVar()

def url_test_function():

	ldatos = bytes(url_for_test.get(), 'utf-8')
	h = hashlib.new(algoritmo, ldatos)
	hash2000 = HASH.generaHash(h)
	url_hash_display.config(text = hash2000)

	url = "https://www.virustotal.com/api/v3/urls/" + hash2000

	headers = {
    "accept": "application/json",
    "x-apikey": "9aa1e017d10d318069b654469cd2826d4111eff92d2479f660a60318d8f2b10c"
	}

	response = requests.get(url, headers=headers)

	data = json.loads(response.text)

	category_webpage.config(text = data['data']['attributes']['categories']['Forcepoint ThreatSeeker'])
	malicious_stat_url_test.config(text = data['data']['attributes']['last_analysis_stats']['malicious'])
	malicious_stat_url_test.config(bg = '#050005', justify = 'center', width = 4, height = 2, font = ('Comic Sans MS', 28))
	malicious_label_url_test = tk.Label(url_test_ntk, text = 'Malicious')
	malicious_label_url_test.config(font = ('Comic Sans MS', 11), fg = '#7a0684')
	malicious_label_url_test.place(x = 70, y = 490)
	suspicious_stat_url_test.config(text = data['data']['attributes']['last_analysis_stats']['suspicious'])
	suspicious_stat_url_test.config(bg = '#050005', justify = 'center', width = 4, height = 2, font = ('Comic Sans MS', 28))
	suspicious_label_url_test = tk.Label(url_test_ntk, text = 'Suspicious')
	suspicious_label_url_test.config(font = ('Comic Sans MS', 11), fg = '#7a0684')
	suspicious_label_url_test.place(x = 210, y = 490)
	undetected_stat_url_test.config(text = data['data']['attributes']['last_analysis_stats']['harmless'])
	undetected_stat_url_test.config(bg = '#050005', justify = 'center', width = 4, height = 2, font = ('Comic Sans MS', 28))
	undetected_label_url_test = tk.Label(url_test_ntk, text = 'Harmless')
	undetected_label_url_test.config(font = ('Comic Sans MS', 11), fg = '#7a0684')
	undetected_label_url_test.place(x = 362, y = 490)
	description_html_meta_content = data['data']['attributes']['html_meta']['description']
	description_html_meta.delete("1.0", tk.END)
	description_html_meta.insert(tk.END, description_html_meta_content)





url_test_title = tk.Label(url_test_ntk, text = 'CHECK THE SECURITY OF THE WEBSITES YOU BROWSE', font = ("Comic Sans MS", 14))
url_test_title.config(fg = '#7e086c')
url_test_title.place(x = 20, y = 10)

url_test_label = tk.Label(url_test_ntk, text = 'Enter the website URL', font = ("Comic Sans MS", 12))
url_test_label.config(fg = '#7e086c')
url_test_label.place(x = 50, y = 50)

url_test_entry = tk.Entry(url_test_ntk, textvariable = url_for_test, font = ('Comic Sans MS', 12), width = 45)
url_test_entry.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
url_test_entry.place(x = 50, y = 80)

examine_button_url_test = tk.Button(url_test_ntk, image = button_examine_url_test, command = lambda:url_test_function())
examine_button_url_test.place(x = 525, y = 62)

url_hash_label = tk.Label(url_test_ntk, text = 'The hash (sha 256) of your URL is:', font = ("Comic Sans MS", 12))
url_hash_label.config(fg = '#7e086c')
url_hash_label.place(x = 50, y = 120)

url_hash_display = tk.Label(url_test_ntk, text = '', font = ('Comic Sans MS', 9), width = 64)
url_hash_display.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
url_hash_display.place(x = 50, y = 150)

category_webpage_label = tk.Label(url_test_ntk, text = 'Webpage category', font = ('Comic Sans MS', 12))
category_webpage_label.config(fg = '#7e086c')
category_webpage_label.place(x = 100, y = 205)

category_webpage = tk.Label(url_test_ntk, text = '', font = ('Comic Sans MS', 10), width = 25)
category_webpage.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
category_webpage.place(x = 60, y = 240)

results_url_test = tk.Label(url_test_ntk, text = 'LAST ANALYSIS STATS')
results_url_test.config(font = ('Comic Sans MS', 12), fg = '#7a0684')
results_url_test.place(x = 160, y = 330)

explanation_url_test = tk.Label(url_test_ntk, text = '(Number of engine reports per category)')
explanation_url_test.config(font = ('Comic Sans MS', 10), fg = '#7a0684')
explanation_url_test.place(x = 130, y = 355)

malicious_stat_url_test = tk.Label(url_test_ntk)
malicious_stat_url_test.config(fg = '#f7a6f1', justify = 'center', width = 4, height = 2)
malicious_stat_url_test.place(x = 60, y = 380)

suspicious_stat_url_test = tk.Label(url_test_ntk)
suspicious_stat_url_test.config(fg = '#f7a6f1', justify = 'center', width = 4, height = 2)
suspicious_stat_url_test.place(x = 200, y = 380)

undetected_stat_url_test = tk.Label(url_test_ntk)
undetected_stat_url_test.config(fg = '#f7a6f1', justify = 'center', width = 4, height = 2)
undetected_stat_url_test.place(x = 350, y = 380)

description_html_meta_label = tk.Label(url_test_ntk, text = 'Description', font = ('Comic Sans MS', 12))
description_html_meta_label.config(fg = '#7e086c')
description_html_meta_label.place(x = 400, y = 190)

scrollDescription_html_meta = ttk.Scrollbar(url_test_ntk, orient = tk.VERTICAL)
scrollDescription_html_meta.place(x = 570, y = 220, height = 90)

description_html_meta = tk.Text(url_test_ntk, font = ('Comic Sans MS', 9), wrap = tk.WORD, width = 35, height = 5, padx = 10)
description_html_meta.config(bg = '#050005', fg = '#f7a6f1')
description_html_meta.place(x = 300, y = 220)
scrollDescription_html_meta.config(command = description_html_meta.yview)

virus_total_logo_url_section = tk.Button(url_test_ntk, image = virus_total_logo, command = lambda:url_test_function())
virus_total_logo_url_section.place(x = 930, y = 10)





### ---------------------------------------------- Virus Total section -----------------------------------------------------

archive_upload_vt = tk.StringVar()
hash_file_label_vt = tk.StringVar()
formatUploadFile = tk.IntVar()
upload_file_image = tk.PhotoImage(file = 'Images/Upload file-logo1.png')
examine_file_image = tk.PhotoImage(file = 'Images/Examine-logo1.png')
mitre_image = tk.PhotoImage(file = 'Images/Mitre Attack-logo1.png')
formats_VT = []

def uploadFileVirusTotal():

	global directoryVirusTotal

	url = "https://www.virustotal.com/api/v3/files"

	files = { "file": (directoryVirusTotal, open(directoryVirusTotal, "rb"))}
	headers = {
    	"accept": "application/json",
    	"x-apikey": "9aa1e017d10d318069b654469cd2826d4111eff92d2479f660a60318d8f2b10c"
	}

	response = requests.post(url, files=files, headers=headers)
	datos_diccionario = json.loads(response.text)

	if datos_diccionario['data']['id'] != '':

		#playsound('Audios/bambu_click.mp3')
		#playsound('Audios/archivoSubidoSatisfactoriamenteVT.mp3')
		print('Done')


def examine_vt():

	url = "https://www.virustotal.com/api/v3/files/" + hash_file_label_vt.get()
	
	headers = {
    	"accept": "application/json",
    	"x-apikey": "9aa1e017d10d318069b654469cd2826d4111eff92d2479f660a60318d8f2b10c"
	}

	response = requests.get(url, headers=headers)
	data = json.loads(response.text)

	if data['data']['attributes']['last_analysis_stats']['malicious'] > 0:

		malicious_stat.config(fg = 'red')

	else:

		malicious_stat.config(fg = '#f7a6f1')


	malicious_stat.config(bg = '#050005', justify = 'center', width = 4, height = 2, font = ('Comic Sans MS', 28))
	malicious_stat.config(text = data['data']['attributes']['last_analysis_stats']['malicious'])
	suspicious_stat.config(bg = '#050005', fg = '#f7a6f1', justify = 'center', width = 4, height = 2, font = ('Comic Sans MS', 28))
	suspicious_stat.config(text = data['data']['attributes']['last_analysis_stats']['suspicious'])
	undetected_stat.config(bg = '#050005', fg = '#f7a6f1', justify = 'center', width = 4, height = 2, font = ('Comic Sans MS', 28))
	undetected_stat.config(text = data['data']['attributes']['last_analysis_stats']['undetected'])
	malicious_label = tk.Label(virusTotal, text = 'Malicious')
	malicious_label.config(font = ('Comic Sans MS', 11), fg = '#7a0684')
	malicious_label.place(x = 70, y = 490)
	suspicious_label = tk.Label(virusTotal, text = 'Suspicious')
	suspicious_label.config(font = ('Comic Sans MS', 11), fg = '#7a0684')
	suspicious_label.place(x = 210, y = 490)
	undetected_label = tk.Label(virusTotal, text = 'Undetected')
	undetected_label.config(font = ('Comic Sans MS', 11), fg = '#7a0684')
	undetected_label.place(x = 355, y = 490)
	Baidu_category.config(text = '')
	Baidu_update.config(text = '')
	Baidu_result.config(text = '')
	Tencent_category.config(text = '')
	Tencent_update.config(text = '')
	Tencent_result.config(text = '')
	Kaspersky_category.config(text = '')
	Kaspersky_update.config(text = '')
	Kaspersky_result.config(text = '')
	Avast_category.config(text = '')
	Avast_update.config(text = '')
	Avast_result.config(text = '')
	Fortinet_category.config(text = '')
	Fortinet_update.config(text = '')
	Fortinet_result.config(text = '')
	Microsoft_category.config(text = '')
	Microsoft_update.config(text = '')
	Microsoft_result.config(text = '')
	Avira_category.config(text = '')
	Avira_update.config(text = '')
	Avira_result.config(text = '')


	try:
		Baidu_category.config(text = data['data']['attributes']['last_analysis_results']['Baidu']['category'])
		Baidu_update.config(text = data['data']['attributes']['last_analysis_results']['Baidu']['engine_update'])
		Baidu_result.config(text = data['data']['attributes']['last_analysis_results']['Baidu']['result'])
		Tencent_category.config(text = data['data']['attributes']['last_analysis_results']['Tencent']['category'])
		Tencent_update.config(text = data['data']['attributes']['last_analysis_results']['Tencent']['engine_update'])
		Tencent_result.config(text = data['data']['attributes']['last_analysis_results']['Tencent']['result'])
		Kaspersky_category.config(text = data['data']['attributes']['last_analysis_results']['Kaspersky']['category'])
		Kaspersky_update.config(text = data['data']['attributes']['last_analysis_results']['Kaspersky']['engine_update'])
		Kaspersky_result.config(text = data['data']['attributes']['last_analysis_results']['Kaspersky']['result'])
		Avast_category.config(text = data['data']['attributes']['last_analysis_results']['Avast']['category'])
		Avast_update.config(text = data['data']['attributes']['last_analysis_results']['Avast']['engine_update'])
		Avast_result.config(text = data['data']['attributes']['last_analysis_results']['Avast']['result'])
		Fortinet_category.config(text = data['data']['attributes']['last_analysis_results']['Fortinet']['category'])
		Fortinet_update.config(text = data['data']['attributes']['last_analysis_results']['Fortinet']['engine_update'])
		Fortinet_result.config(text = data['data']['attributes']['last_analysis_results']['Fortinet']['result'])
		Microsoft_category.config(text = data['data']['attributes']['last_analysis_results']['Microsoft']['category'])
		Microsoft_update.config(text = data['data']['attributes']['last_analysis_results']['Microsoft']['engine_update'])
		Microsoft_result.config(text = data['data']['attributes']['last_analysis_results']['Microsoft']['result'])
		Avira_category.config(text = data['data']['attributes']['last_analysis_results']['Avira']['category'])
		Avira_update.config(text = data['data']['attributes']['last_analysis_results']['Avira']['engine_update'])
		Avira_result.config(text = data['data']['attributes']['last_analysis_results']['Avira']['result'])
		#playsound('bambu_click.mp3')

	except KeyError:

		print('espere')
		#playsound('Audios/Espere_ejecute_nuevamente.mp3')


titleVirusTotal = tk.Label(virusTotal, text = 'UPLOAD YOUR FILE TO VIRUS TOTAL')
titleVirusTotal.config(font = ('Comic Sans MS', 15), fg = '#7a0684')
titleVirusTotal.place(x = 70, y = 20)

urlUploadFile = tk.Entry(virusTotal, textvariable = archive_upload_vt, font = ('Comic Sans MS', 7), width = 75)
urlUploadFile.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
urlUploadFile.place(x = 30, y = 60)

urlUploadLogo = tk.Button(virusTotal, image = directory_browser1, command = lambda:selectDirectoryVirusTotal())
urlUploadLogo.place(x = 505, y = 37)

hashFileLabel = tk.Label(virusTotal, text = 'The hash (sha 256) of your file is:')
hashFileLabel.config(font = ('Comic Sans MS', 11), fg = '#7a0684')
hashFileLabel.place(x = 130, y = 110)

hashLabelVirusTotal = tk.Entry(virusTotal, textvariable = hash_file_label_vt)
hashLabelVirusTotal.config(bg = '#050005', fg = '#f7a6f1', justify = 'center', width = 75)
hashLabelVirusTotal.place(x = 30, y = 145)

upload_button = tk.Button(virusTotal, image = upload_file_image, command = lambda:uploadFileVirusTotal())
upload_button.place(x = 60, y = 200)

examine_button = tk.Button(virusTotal, image = examine_file_image, command = lambda:examine_vt())
examine_button.place(x = 200, y = 200)

mitre_button = tk.Button(virusTotal, image = mitre_image, command = lambda:[capeSandboxExecution(), zenboxExecution()])
mitre_button.place(x = 350, y = 200)

results_vt = tk.Label(virusTotal, text = 'LAST ANALYSIS STATS')
results_vt.config(font = ('Comic Sans MS', 12), fg = '#7a0684')
results_vt.place(x = 160, y = 330)

explanation_vt = tk.Label(virusTotal, text = '(Number of antivirus reports per category)')
explanation_vt.config(font = ('Comic Sans MS', 10), fg = '#7a0684')
explanation_vt.place(x = 130, y = 355)

malicious_stat = tk.Label(virusTotal)
malicious_stat.config(fg = '#f7a6f1', justify = 'center', width = 4, height = 2)
malicious_stat.place(x = 60, y = 380)

suspicious_stat = tk.Label(virusTotal)
suspicious_stat.config(fg = '#f7a6f1', justify = 'center', width = 4, height = 2)
suspicious_stat.place(x = 200, y = 380)

undetected_stat = tk.Label(virusTotal)
undetected_stat.config(fg = '#f7a6f1', justify = 'center', width = 4, height = 2)
undetected_stat.place(x = 350, y = 380)

last_analysis_results_label = tk.Label(virusTotal, text = 'LAST ANALYSIS RESULTS')
last_analysis_results_label.config(font = ('Comic Sans MS', 15), fg = '#7a0684')
last_analysis_results_label.place(x = 700, y = 10)

category_vt = tk.Label(virusTotal, text = 'Category')
category_vt.config(font = ('Comic Sans MS', 13), fg = '#7a0684')
category_vt.place(x = 650, y = 70)

result_vt = tk.Label(virusTotal, text = 'Result')
result_vt.config(font = ('Comic Sans MS', 13), fg = '#7a0684')
result_vt.place(x = 920, y = 70)

engine_update_vt = tk.Label(virusTotal, text = 'Engine update')
engine_update_vt.config(font = ('Comic Sans MS', 13), fg = '#7a0684')
engine_update_vt.place(x = 750, y = 70)

Baidu_label = tk.Label(virusTotal, text = 'Baidu')
Baidu_label.config(font = ('Comic Sans MS', 11), fg = '#7a0684')
Baidu_label.place(x = 550, y = 120)

Baidu_category = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 13)
Baidu_category.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Baidu_category.place(x = 640, y = 120)

Baidu_update = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 15)
Baidu_update.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Baidu_update.place(x = 755, y = 120)

Baidu_result = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 20)
Baidu_result.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Baidu_result.place(x = 880, y = 120)

Tencent_label = tk.Label(virusTotal, text = 'Tencent')
Tencent_label.config(font = ('Comic Sans MS', 11), fg = '#7a0684')
Tencent_label.place(x = 550, y = 180)

Tencent_category = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 13)
Tencent_category.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Tencent_category.place(x = 640, y = 180)

Tencent_update = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 15)
Tencent_update.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Tencent_update.place(x = 755, y = 180)

Tencent_result = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 20)
Tencent_result.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Tencent_result.place(x = 880, y = 180)

Kaspersky_label = tk.Label(virusTotal, text = 'Kaspersky')
Kaspersky_label.config(font = ('Comic Sans MS', 11), fg = '#7a0684')
Kaspersky_label.place(x = 550, y = 240)

Kaspersky_category = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 13)
Kaspersky_category.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Kaspersky_category.place(x = 640, y = 240)

Kaspersky_update = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 15)
Kaspersky_update.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Kaspersky_update.place(x = 755, y = 240)

Kaspersky_result = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 20)
Kaspersky_result.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Kaspersky_result.place(x = 880, y = 240)

Avast_label = tk.Label(virusTotal, text = 'Avast')
Avast_label.config(font = ('Comic Sans MS', 11), fg = '#7a0684')
Avast_label.place(x = 550, y = 300)

Avast_category = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 13)
Avast_category.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Avast_category.place(x = 640, y = 300)

Avast_update = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 15)
Avast_update.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Avast_update.place(x = 755, y = 300)

Avast_result = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 20)
Avast_result.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Avast_result.place(x = 880, y = 300)

Fortinet_label = tk.Label(virusTotal, text = 'Fortinet')
Fortinet_label.config(font = ('Comic Sans MS', 11), fg = '#7a0684')
Fortinet_label.place(x = 550, y = 360)

Fortinet_category = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 13)
Fortinet_category.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Fortinet_category.place(x = 640, y = 360)

Fortinet_update = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 15)
Fortinet_update.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Fortinet_update.place(x = 755, y = 360)

Fortinet_result = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 20)
Fortinet_result.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Fortinet_result.place(x = 880, y = 360)

Microsoft_label = tk.Label(virusTotal, text = 'Microsoft')
Microsoft_label.config(font = ('Comic Sans MS', 11), fg = '#7a0684')
Microsoft_label.place(x = 550, y = 420)

Microsoft_category = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 13)
Microsoft_category.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Microsoft_category.place(x = 640, y = 420)

Microsoft_update = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 15)
Microsoft_update.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Microsoft_update.place(x = 755, y = 420)

Microsoft_result = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 20)
Microsoft_result.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Microsoft_result.place(x = 880, y = 420)

Avira_label = tk.Label(virusTotal, text = 'Avira')
Avira_label.config(font = ('Comic Sans MS', 11), fg = '#7a0684')
Avira_label.place(x = 550, y = 480)

Avira_category = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 13)
Avira_category.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Avira_category.place(x = 640, y = 480)

Avira_update = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 15)
Avira_update.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Avira_update.place(x = 755, y = 480)

Avira_result = tk.Label(virusTotal, font = ('Comic Sans MS', 9), width = 20)
Avira_result.config(bg = '#050005', fg = '#f7a6f1', justify = 'center')
Avira_result.place(x = 880, y = 480)


# --------------------------------------------------------------------------------------------------------------------------


### -------------------------------------------------- CAPA Section -----------------------------------------------------------


# def capaExecution():

# 	url = 'https://www.virustotal.com/api/v3/files/' + hash_file_label_vt.get() + '/behaviour_mitre_trees'

# 	headers = {
#     	"accept": "application/json",
#     	"x-apikey": "9aa1e017d10d318069b654469cd2826d4111eff92d2479f660a60318d8f2b10c"
# 	}

# 	response = requests.get(url, headers=headers)
# 	data = json.loads(response.text)

	
# 	labels_capa_tactics = [tactic1_capa, tactic2_capa, tactic3_capa, tactic4_capa, tactic5_capa, tactic6_capa, tactic7_capa]
# 	capa_tactics_descriptions = [tactic1_capa_explan, tactic2_capa_explan, tactic3_capa_explan, tactic4_capa_explan,
# 	tactic5_capa_explan, tactic6_capa_explan, tactic7_capa_explan]

# 	x = 0
# 	y = 0

# 	tactic1_capa.config(text = '')
# 	tactic2_capa.config(text = '')
# 	tactic3_capa.config(text = '')
# 	tactic4_capa.config(text = '')
# 	tactic5_capa.config(text = '')
# 	tactic6_capa.config(text = '')
# 	tactic7_capa.config(text = '')
# 	tactic1_capa_explan.delete(1.0, tk.END)
# 	tactic2_capa_explan.delete(1.0, tk.END)
# 	tactic3_capa_explan.delete(1.0, tk.END)
# 	tactic4_capa_explan.delete(1.0, tk.END)
# 	tactic5_capa_explan.delete(1.0, tk.END)
# 	tactic6_capa_explan.delete(1.0, tk.END)
# 	tactic7_capa_explan.delete(1.0, tk.END)
# 	techniques_capa.delete(1.0, tk.END)

# 	try:

# 		while x < len(data['data']['CAPA']['tactics']):

# 			labels_capa_tactics[x].config(text = data['data']['CAPA']['tactics'][x]['name'])
# 			capa_tactics_descriptions[x].delete(1.0, tk.END)
# 			capa_tactics_descriptions[x].insert(tk.END, data['data']['CAPA']['tactics'][x]['id'] + ':  ' + 
# 				data['data']['CAPA']['tactics'][x]['description'])
# 			y = 0

# 			while y < len(data['data']['CAPA']['tactics'][x]['techniques']):

# 				techniques_capa.insert(tk.END, '[' + data['data']['CAPA']['tactics'][x]['id'] + ']  [' + 
# 				data['data']['CAPA']['tactics'][x]['techniques'][y]['id'] + ']:   ' +
# 				 data['data']['CAPA']['tactics'][x]['techniques'][y]['name'] + ' \n')
# 				y = y + 1

# 			x = x + 1
		

# 	except KeyError:

# 		print('No report')


	
# tactics_label_capa = tk.Label(capa_tab, text = 'TACTICS DETECTED BY CAPA')
# tactics_label_capa.config(font = ('Comic Sans MS', 17), fg = '#067297')
# tactics_label_capa.place(x = 380, y = 5)

# tactics_label_capa1 = tk.Label(capa_tab, text = 'Tactic')
# tactics_label_capa1.config(font = ('Comic Sans MS', 14), fg = '#067297')
# tactics_label_capa1.place(x = 100, y = 40)

# tactics_label_capa2 = tk.Label(capa_tab, text = 'Tactic')
# tactics_label_capa2.config(font = ('Comic Sans MS', 14), fg = '#067297')
# tactics_label_capa2.place(x = 600, y = 40)

# descriptions_label_capa1 = tk.Label(capa_tab, text = 'Description')
# descriptions_label_capa1.config(font = ('Comic Sans MS', 14), fg = '#067297')
# descriptions_label_capa1.place(x = 300, y = 40)

# descriptions_label_capa2 = tk.Label(capa_tab, text = 'Description')
# descriptions_label_capa2.config(font = ('Comic Sans MS', 14), fg = '#067297')
# descriptions_label_capa2.place(x = 820, y = 40)


# tactic1_capa = tk.Label(capa_tab, font = ('Comic Sans MS', 10), width = 24)
# tactic1_capa.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
# tactic1_capa.place(x = 40, y = 80)

# tactic1_capa_explan = tk.Text(capa_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
# tactic1_capa_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
# tactic1_capa_explan.place(x = 255, y = 80)

# tactic2_capa = tk.Label(capa_tab, font = ('Comic Sans MS', 10), width = 24)
# tactic2_capa.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
# tactic2_capa.place(x = 40, y = 160)

# tactic2_capa_explan = tk.Text(capa_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
# tactic2_capa_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
# tactic2_capa_explan.place(x = 255, y = 160)

# tactic3_capa = tk.Label(capa_tab, font = ('Comic Sans MS', 10), width = 24)
# tactic3_capa.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
# tactic3_capa.place(x = 40, y = 240)

# tactic3_capa_explan = tk.Text(capa_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
# tactic3_capa_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
# tactic3_capa_explan.place(x = 255, y = 240)

# tactic4_capa = tk.Label(capa_tab, font = ('Comic Sans MS', 10), width = 24)
# tactic4_capa.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
# tactic4_capa.place(x = 40, y = 320)

# tactic4_capa_explan = tk.Text(capa_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
# tactic4_capa_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
# tactic4_capa_explan.place(x = 255, y = 320)

# tactic5_capa = tk.Label(capa_tab, font = ('Comic Sans MS', 10), width = 24)
# tactic5_capa.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
# tactic5_capa.place(x = 40, y = 400)

# tactic5_capa_explan = tk.Text(capa_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
# tactic5_capa_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
# tactic5_capa_explan.place(x = 255, y = 400)

# tactic6_capa = tk.Label(capa_tab, font = ('Comic Sans MS', 10), width = 24)
# tactic6_capa.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
# tactic6_capa.place(x = 550, y = 80)

# tactic6_capa_explan = tk.Text(capa_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
# tactic6_capa_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
# tactic6_capa_explan.place(x = 765, y = 80)

# tactic7_capa = tk.Label(capa_tab, font = ('Comic Sans MS', 10), width = 24)
# tactic7_capa.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
# tactic7_capa.place(x = 550, y = 160)

# tactic7_capa_explan = tk.Text(capa_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
# tactic7_capa_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
# tactic7_capa_explan.place(x = 765, y = 160)

# techniques_capa_label = tk.Label(capa_tab, text = 'Techniques', font = ('Comic Sans MS', 14))
# techniques_capa_label.config(fg = '#067297')
# techniques_capa_label.place(x = 700, y = 230)

# techniques_capa = tk.Text(capa_tab, font = ('Comic Sans MS', 10), width = 50, height = 12)
# techniques_capa.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
# techniques_capa.place(x = 550, y = 270)

# scrollVetrn40 = ttk.Scrollbar(capa_tab, command = techniques_capa.yview)
# #cipher_text2['yscrollcommand'] = scrollVetrn.set()
# scrollVetrn40.place(x = 960, y = 270, height = 220)


# --------------------------------------------------- CAPE Sandbox section -----------------------------------------------------


def capeSandboxExecution():

	url2 = 'https://www.virustotal.com/api/v3/files/' + hash_file_label_vt.get() + '/behaviour_mitre_trees'

	headers2 = {
    	"accept": "application/json",
    	"x-apikey": "9aa1e017d10d318069b654469cd2826d4111eff92d2479f660a60318d8f2b10c"
	}

	response2 = requests.get(url2, headers=headers2)
	data2 = json.loads(response2.text)

	
	labels_cape_tactics = [tactic1_cape, tactic2_cape, tactic3_cape, tactic4_cape, tactic5_cape, tactic6_cape, tactic7_cape]
	cape_tactics_descriptions = [tactic1_cape_explan, tactic2_cape_explan, tactic3_cape_explan, tactic4_cape_explan,
	tactic5_cape_explan, tactic6_cape_explan, tactic7_cape_explan]

	x_cape = 0
	y_cape = 0

	tactic1_cape.config(text = '')
	tactic2_cape.config(text = '')
	tactic3_cape.config(text = '')
	tactic4_cape.config(text = '')
	tactic5_cape.config(text = '')
	tactic6_cape.config(text = '')
	tactic7_cape.config(text = '')
	tactic1_cape_explan.delete(1.0, tk.END)
	tactic2_cape_explan.delete(1.0, tk.END)
	tactic3_cape_explan.delete(1.0, tk.END)
	tactic4_cape_explan.delete(1.0, tk.END)
	tactic5_cape_explan.delete(1.0, tk.END)
	tactic6_cape_explan.delete(1.0, tk.END)
	tactic7_cape_explan.delete(1.0, tk.END)
	techniques_cape.delete(1.0, tk.END)

	try:

		while x_cape < len(data2['data']['CAPE Sandbox']['tactics']):

			labels_cape_tactics[x_cape].config(text = data2['data']['CAPE Sandbox']['tactics'][x_cape]['name'])
			cape_tactics_descriptions[x_cape].delete(1.0, tk.END)
			cape_tactics_descriptions[x_cape].insert(tk.END, data2['data']['CAPE Sandbox']['tactics'][x_cape]['id'] + ':  ' + 
				data2['data']['CAPE Sandbox']['tactics'][x_cape]['description'])
			y_cape = 0

			while y_cape < len(data2['data']['CAPE Sandbox']['tactics'][x_cape]['techniques']):

				techniques_cape.insert(tk.END, '[' + data2['data']['CAPE Sandbox']['tactics'][x_cape]['id'] + ']  [' + 
				data2['data']['CAPE Sandbox']['tactics'][x_cape]['techniques'][y_cape]['id'] + ']:   ' +
				 data2['data']['CAPE Sandbox']['tactics'][x_cape]['techniques'][y_cape]['name'] + ' \n')
				y_cape = y_cape + 1

			x_cape = x_cape + 1
		

	except KeyError:

		print('No report')


	
tactics_label_cape = tk.Label(cape_sandbox_tab, text = 'TACTICS DETECTED BY CAPE SANDBOX')
tactics_label_cape.config(font = ('Comic Sans MS', 17), fg = '#067297')
tactics_label_cape.place(x = 300, y = 5)

tactics_label_cape1 = tk.Label(cape_sandbox_tab, text = 'Tactic')
tactics_label_cape1.config(font = ('Comic Sans MS', 14), fg = '#067297')
tactics_label_cape1.place(x = 100, y = 40)

tactics_label_cape2 = tk.Label(cape_sandbox_tab, text = 'Tactic')
tactics_label_cape2.config(font = ('Comic Sans MS', 14), fg = '#067297')
tactics_label_cape2.place(x = 600, y = 40)

descriptions_label_cape1 = tk.Label(cape_sandbox_tab, text = 'Description')
descriptions_label_cape1.config(font = ('Comic Sans MS', 14), fg = '#067297')
descriptions_label_cape1.place(x = 300, y = 40)

descriptions_label_cape2 = tk.Label(cape_sandbox_tab, text = 'Description')
descriptions_label_cape2.config(font = ('Comic Sans MS', 14), fg = '#067297')
descriptions_label_cape2.place(x = 820, y = 40)


tactic1_cape = tk.Label(cape_sandbox_tab, font = ('Comic Sans MS', 10), width = 24)
tactic1_cape.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
tactic1_cape.place(x = 40, y = 80)

tactic1_cape_explan = tk.Text(cape_sandbox_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
tactic1_cape_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
tactic1_cape_explan.place(x = 255, y = 80)

tactic2_cape = tk.Label(cape_sandbox_tab, font = ('Comic Sans MS', 10), width = 24)
tactic2_cape.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
tactic2_cape.place(x = 40, y = 160)

tactic2_cape_explan = tk.Text(cape_sandbox_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
tactic2_cape_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
tactic2_cape_explan.place(x = 255, y = 160)

tactic3_cape = tk.Label(cape_sandbox_tab, font = ('Comic Sans MS', 10), width = 24)
tactic3_cape.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
tactic3_cape.place(x = 40, y = 240)

tactic3_cape_explan = tk.Text(cape_sandbox_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
tactic3_cape_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
tactic3_cape_explan.place(x = 255, y = 240)

tactic4_cape = tk.Label(cape_sandbox_tab, font = ('Comic Sans MS', 10), width = 24)
tactic4_cape.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
tactic4_cape.place(x = 40, y = 320)

tactic4_cape_explan = tk.Text(cape_sandbox_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
tactic4_cape_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
tactic4_cape_explan.place(x = 255, y = 320)

tactic5_cape = tk.Label(cape_sandbox_tab, font = ('Comic Sans MS', 10), width = 24)
tactic5_cape.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
tactic5_cape.place(x = 40, y = 400)

tactic5_cape_explan = tk.Text(cape_sandbox_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
tactic5_cape_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
tactic5_cape_explan.place(x = 255, y = 400)

tactic6_cape = tk.Label(cape_sandbox_tab, font = ('Comic Sans MS', 10), width = 24)
tactic6_cape.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
tactic6_cape.place(x = 550, y = 80)

tactic6_cape_explan = tk.Text(cape_sandbox_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
tactic6_cape_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
tactic6_cape_explan.place(x = 765, y = 80)

tactic7_cape = tk.Label(cape_sandbox_tab, font = ('Comic Sans MS', 10), width = 24)
tactic7_cape.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
tactic7_cape.place(x = 550, y = 160)

tactic7_cape_explan = tk.Text(cape_sandbox_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
tactic7_cape_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
tactic7_cape_explan.place(x = 765, y = 160)

techniques_cape_label = tk.Label(cape_sandbox_tab, text = 'Techniques', font = ('Comic Sans MS', 14))
techniques_cape_label.config(fg = '#067297')
techniques_cape_label.place(x = 700, y = 230)

techniques_cape = tk.Text(cape_sandbox_tab, font = ('Comic Sans MS', 10), width = 50, height = 12)
techniques_cape.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
techniques_cape.place(x = 550, y = 270)

scrollVetrn50 = ttk.Scrollbar(cape_sandbox_tab, command = techniques_cape.yview)
#cipher_text2['yscrollcommand'] = scrollVetrn.set()
scrollVetrn50.place(x = 960, y = 270, height = 220)


# -----------------------------------------------------------------------------------------------------------------------------



### ---------------------------------------------- Zenbox section --------------------------------------------------------------



def zenboxExecution():

	url3 = 'https://www.virustotal.com/api/v3/files/' + hash_file_label_vt.get() + '/behaviour_mitre_trees'

	headers3 = {
    	"accept": "application/json",
    	"x-apikey": "9aa1e017d10d318069b654469cd2826d4111eff92d2479f660a60318d8f2b10c"
	}

	response3 = requests.get(url3, headers=headers3)
	data3 = json.loads(response3.text)

	
	labels_zenbox_tactics = [tactic1_zen, tactic2_zen, tactic3_zen, tactic4_zen, tactic5_zen, tactic6_zen, tactic7_zen]
	zen_tactics_descriptions = [tactic1_zen_explan, tactic2_zen_explan, tactic3_zen_explan, tactic4_zen_explan,
	tactic5_zen_explan, tactic6_zen_explan, tactic7_zen_explan]

	x_zen = 0
	y_zen = 0

	tactic1_zen.config(text = '')
	tactic2_zen.config(text = '')
	tactic3_zen.config(text = '')
	tactic4_zen.config(text = '')
	tactic5_zen.config(text = '')
	tactic6_zen.config(text = '')
	tactic7_zen.config(text = '')
	tactic1_zen_explan.delete(1.0, tk.END)
	tactic2_zen_explan.delete(1.0, tk.END)
	tactic3_zen_explan.delete(1.0, tk.END)
	tactic4_zen_explan.delete(1.0, tk.END)
	tactic5_zen_explan.delete(1.0, tk.END)
	tactic6_zen_explan.delete(1.0, tk.END)
	tactic7_zen_explan.delete(1.0, tk.END)
	techniques_zen.delete(1.0, tk.END)

	try:

		while x_zen < len(data3['data']['Zenbox']['tactics']):

			labels_zenbox_tactics[x_zen].config(text = data3['data']['Zenbox']['tactics'][x_zen]['name'])
			zen_tactics_descriptions[x_zen].delete(1.0, tk.END)
			zen_tactics_descriptions[x_zen].insert(tk.END, data3['data']['Zenbox']['tactics'][x_zen]['id'] + ':  ' + 
				data3['data']['Zenbox']['tactics'][x_zen]['description'])
			y_zen = 0

			while y_zen < len(data3['data']['Zenbox']['tactics'][x_zen]['techniques']):

				techniques_zen.insert(tk.END, '[' + data3['data']['Zenbox']['tactics'][x_zen]['id'] + ']  [' + 
				data3['data']['Zenbox']['tactics'][x_zen]['techniques'][y_zen]['id'] + ']:   ' +
				 data3['data']['Zenbox']['tactics'][x_zen]['techniques'][y_zen]['name'] + ' \n')
				y_zen = y_zen + 1

			x_zen = x_zen + 1
		

	except KeyError:

		print('No report')


	
tactics_label_zen = tk.Label(zenbox_tab, text = 'TACTICS DETECTED BY ZENBOX')
tactics_label_zen.config(font = ('Comic Sans MS', 17), fg = '#067297')
tactics_label_zen.place(x = 300, y = 5)

tactics_label_zen1 = tk.Label(zenbox_tab, text = 'Tactic')
tactics_label_zen1.config(font = ('Comic Sans MS', 14), fg = '#067297')
tactics_label_zen1.place(x = 100, y = 40)

tactics_label_zen2 = tk.Label(zenbox_tab, text = 'Tactic')
tactics_label_zen2.config(font = ('Comic Sans MS', 14), fg = '#067297')
tactics_label_zen2.place(x = 600, y = 40)

descriptions_label_zen1 = tk.Label(zenbox_tab, text = 'Description')
descriptions_label_zen1.config(font = ('Comic Sans MS', 14), fg = '#067297')
descriptions_label_zen1.place(x = 300, y = 40)

descriptions_label_zen2 = tk.Label(zenbox_tab, text = 'Description')
descriptions_label_zen2.config(font = ('Comic Sans MS', 14), fg = '#067297')
descriptions_label_zen2.place(x = 820, y = 40)


tactic1_zen = tk.Label(zenbox_tab, font = ('Comic Sans MS', 10), width = 24)
tactic1_zen.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
tactic1_zen.place(x = 40, y = 80)

tactic1_zen_explan = tk.Text(zenbox_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
tactic1_zen_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
tactic1_zen_explan.place(x = 255, y = 80)

tactic2_zen = tk.Label(zenbox_tab, font = ('Comic Sans MS', 10), width = 24)
tactic2_zen.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
tactic2_zen.place(x = 40, y = 160)

tactic2_zen_explan = tk.Text(zenbox_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
tactic2_zen_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
tactic2_zen_explan.place(x = 255, y = 160)

tactic3_zen = tk.Label(zenbox_tab, font = ('Comic Sans MS', 10), width = 24)
tactic3_zen.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
tactic3_zen.place(x = 40, y = 240)

tactic3_zen_explan = tk.Text(zenbox_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
tactic3_zen_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
tactic3_zen_explan.place(x = 255, y = 240)

tactic4_zen = tk.Label(zenbox_tab, font = ('Comic Sans MS', 10), width = 24)
tactic4_zen.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
tactic4_zen.place(x = 40, y = 320)

tactic4_zen_explan = tk.Text(zenbox_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
tactic4_zen_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
tactic4_zen_explan.place(x = 255, y = 320)

tactic5_zen = tk.Label(zenbox_tab, font = ('Comic Sans MS', 10), width = 24)
tactic5_zen.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
tactic5_zen.place(x = 40, y = 400)

tactic5_zen_explan = tk.Text(zenbox_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
tactic5_zen_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
tactic5_zen_explan.place(x = 255, y = 400)

tactic6_zen = tk.Label(zenbox_tab, font = ('Comic Sans MS', 10), width = 24)
tactic6_zen.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
tactic6_zen.place(x = 550, y = 80)

tactic6_zen_explan = tk.Text(zenbox_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
tactic6_zen_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
tactic6_zen_explan.place(x = 765, y = 80)

tactic7_zen = tk.Label(zenbox_tab, font = ('Comic Sans MS', 10), width = 24)
tactic7_zen.config(bg = '#050005', fg = '#b6c7f9', justify = 'center')
tactic7_zen.place(x = 550, y = 160)

tactic7_zen_explan = tk.Text(zenbox_tab, font = ('Comic Sans MS', 10), width = 26, height = 3)
tactic7_zen_explan.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
tactic7_zen_explan.place(x = 765, y = 160)

techniques_zen_label = tk.Label(zenbox_tab, text = 'Techniques', font = ('Comic Sans MS', 14))
techniques_zen_label.config(fg = '#067297')
techniques_zen_label.place(x = 700, y = 230)

techniques_zen = tk.Text(zenbox_tab, font = ('Comic Sans MS', 10), width = 50, height = 12)
techniques_zen.config(bg = '#050005', fg = '#b6c7f9', padx = 10)
techniques_zen.place(x = 550, y = 270)

scrollVetrn70 = ttk.Scrollbar(zenbox_tab, command = techniques_zen.yview)
#cipher_text2['yscrollcommand'] = scrollVetrn.set()
scrollVetrn70.place(x = 960, y = 270, height = 220)

#decrypt.protocol("WM_DELETE_WINDOW", lambda: None)

decrypt.mainloop()


#### ---------------------------------------------- The End -------------------------------------------------------------------

