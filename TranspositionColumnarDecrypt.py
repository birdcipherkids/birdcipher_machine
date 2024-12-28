import math

messag = input('Ingrese mensaje a encriptar: ')
keys = int(input('Ingrese llave: '))


def decryptMessagesInverse(key, message):

	numberOfColumns = math.ceil(len(message)/key)
	numberOfRows = key
	numberShadedBoxes = (numberOfColumns * numberOfRows) - len(message)

	plaintext = [''] * numberOfColumns

	
	

	for col in range(numberOfColumns):

		if col % 2 != 0:

			pointer = col
			row = 0

			while row < numberOfRows:

				plaintext[col] = plaintext[col] + message[pointer]
				pointer = pointer + numberOfColumns
				row = row + 1

		
		elif col % 2 == 0:

			pointer = col
			pointer = pointer + (numberOfColumns * (key - 1))
			row = numberOfRows

			while row > 0:

				plaintext[col] = plaintext[col] + message[pointer]
				pointer = pointer - numberOfColumns
				row = row - 1

			
	return ''.join(plaintext)

print(decryptMessagesInverse(keys, messag))








			


