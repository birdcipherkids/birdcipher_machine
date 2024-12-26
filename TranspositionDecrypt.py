import math

def decryptMessages(key, message):

	numberColumns = math.ceil(len(message)/key)
	numberRows = key
	numberShadedBoxes = (numberColumns * numberRows) - len(message)

	plaintext = [''] * numberColumns

	col = 0
	row = 0

	for symbol in message:

		plaintext[col] = plaintext[col] + symbol
		col = col + 1

		if (col == numberColumns) or (col == numberColumns - 1 and row >= numberRows - numberShadedBoxes):

			col = 0
			row = row + 1

	return ''.join(plaintext)

