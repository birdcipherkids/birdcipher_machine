# ---------------------------- Reverse cipher for the BirdCipher cryptographic machine



def reverse_cipher_apl(message):

	translated = ''

	i = len(message) - 1
	
	while i >= 0:

		translated = translated + message[i]
		i = i - 1

	return translated




