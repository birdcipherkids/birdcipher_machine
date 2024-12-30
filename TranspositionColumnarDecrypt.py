import math

messag = input('Ingrese mensaje a encriptar: ')
keys = int(input('Ingrese llave: '))


def decryptMessagesInverse(key, message):

	numberOfColumns = math.ceil(len(message)/key)
	numberOfRows = key
	grid = numberOfColumns * numberOfRows
	numberShadedBoxes = (numberOfColumns * numberOfRows) - len(message)
	Fsb = numberOfRows - numberShadedBoxes

	plaintext = [''] * numberOfColumns

	
	for col in range(numberOfColumns):

		countCaracters = 0

		if col % 2 != 0 or col % 2 == 0:

			pointer = col
			row = 0

			while row < numberOfRows:

				if pointer < len(message) and col <= numberOfColumns - 1: 

					if row < Fsb and col < numberOfColumns - 1:

						plaintext[col] = plaintext[col] + message[pointer]
						pointer = pointer + numberOfColumns
						row = row + 1
					
					elif row >= Fsb and col < numberOfColumns - 1:

						plaintext[col] = plaintext[col] + message[pointer]
						pointer = pointer + numberOfColumns - 1
						row = row + 1

					elif row <= Fsb - 1 and col == numberOfColumns - 1:

						plaintext[col] = plaintext[col] + message[pointer]
						pointer = pointer + numberOfColumns
						row = row + 1

					elif row > Fsb - 1 and col == numberOfColumns - 1:

						break

				
				

					

				
					
				



				

		# elif col % 2 == 0:

		# 	pointer = col
		# 	pointer = pointer + (numberOfColumns * (key - 1))
		# 	row = numberOfRows

		# 	# elif numberShadedBoxes > 0:

		# 	# 	pointer = col
		# 	# 	pointer = pointer + (numberOfColumns * (key - 1)) - numberShadedBoxes

		# 	while row > 0:

		# 		if pointer >= col and countCaracters <= len(message):

		# 			plaintext[col] = plaintext[col] + message[pointer]
		# 			pointer = pointer - numberOfColumns
		# 			row = row - 1
		# 			countCaracters = countCaracters + 1

		# 		else:
		# 			break

	print(numberShadedBoxes)
	print(plaintext)		
	return ''.join(plaintext)



print(decryptMessagesInverse(keys, messag))





