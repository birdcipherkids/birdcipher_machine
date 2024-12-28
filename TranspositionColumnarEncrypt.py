def TranspositionColumnarInverse(key, message):

	cipherTextTransInverse = [''] * key

	remaining_rows = len(message) // key

	for col in range(key):

		pointer = col

		if col % 2 != 0:

			while pointer < len(message):

				cipherTextTransInverse[col] = cipherTextTransInverse[col] + message[pointer]
				pointer = pointer + key

		elif col % 2 == 0:

			pointer = pointer + (remaining_rows * key)

			if pointer >= len(message):

				pointer = pointer - key

			while pointer >= col:

				cipherTextTransInverse[col] = cipherTextTransInverse[col] + message[pointer]
				pointer = pointer - key

	return ''.join(cipherTextTransInverse)

