def encryptMessageTransLinear(key, message):

	cipherTextTransLinear = [''] * key

	for col in range(key):

		pointer = col

		while pointer < len(message):

			cipherTextTransLinear[col] = cipherTextTransLinear[col] + message[pointer]
			pointer = pointer + key

	return ''.join(cipherTextTransLinear)

