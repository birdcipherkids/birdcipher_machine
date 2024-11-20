#    Implementacion del algoritmo para el cifrado Cesar


def getTranslatedMessage(modeCaesar, message, keyCaesar):

	translated = ''

	if modeCaesar == 'd':

		keyCaesar = -keyCaesar
		
	for symbol in message:

		if symbol.isalpha():

			num = ord(symbol)
			num = num + keyCaesar

			if symbol.isupper():

				if num > ord('Z'):

					num = num - 26

				elif num < ord('A'):

					num = num + 26

			elif symbol.islower():

				if num > ord('z'):

					num = num - 26

				elif num < ord('a'):

					num = num + 26

			translated = translated + chr(num)

		else:

			translated = translated + symbol

	return translated

