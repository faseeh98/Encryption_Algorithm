from time import time  # Used to calculate execution time of instruction
from random import choice  # Used to select one of the six encryption algorithms
import math  # Used for RSA calculations


# Base class for all encryption types
class BaseEncryption:

    @property  # Getter for name of encryption type
    def name(self):
        return self.__name

    @name.setter  # setter for encryption type
    def name(self, x):
        if isinstance(x, str):  # ensures a string is passed
            self.__name = x  # sets name to encryption type
        else:
            self.__name = str(x)  # if it's not a string, convert to a string


# Caesar Encryption
class Ceaser(BaseEncryption):
    def __init__(self):
        self.name = 'ceaser'  # Calls @name.setter from BaseEncryption
        # Encryption key used for encrypting and decrypting caesar encryption. Offset for encrypting plaintext
        self.key = 3

    def __call__(self, text, mode):

        if mode == 'decrypt':  # To decrypt, algorithm will first encrypt the original text then reverse it to decrypt.
            cipher_text = ""  # This string will be added onto as the original text is ran through the encryption
            for i in range(len(msg)):  # for each letter/character in the original text
                # This uses the ASCII code of the space bar and converts it into the encrypted text
                if ord(msg[i]) == 32:  # The ASCII code for space bar is 32
                    # convert space bar ASCII code back to string representation and add it to the encrypted text
                    cipher_text += chr(ord(msg[i]))
# After the algorithm cycles past the letter 'z' (ASCII code 122), it must return to letter 'a' (ASCII Code 97)
                elif ord(msg[i]) + self.key > 122:
                    # subtracts ASCII code of 'z' and adds ASCII code 96 to return back to 'a'
                    cipher_text += chr(96 + ((ord(msg[i]) + self.key) - 122))
                # This serves the same purpose as code above except for capital letters (65-90)
                elif (ord(msg[i]) + self.key > 90) and (ord(msg[i]) <= 96):  # if > 'Z' and < 'a'
# push back 90 (end of capital letters) and add 64 (beginning of capital letters) to get speciied capital letter
                    cipher_text += chr(64 + ((ord(msg[i]) + self.key) - 90))  # Adds capital letter to encrypted text
                else:
                    cipher_text += chr(ord(msg[i]) + self.key)  # converts to string representation
            # For loop below will reverse the encryption algorithm applied above
            plain_text = ""  # This string will be added onto as the encrypted text is ran through decryption
            for i in range(len(cipher_text)):
                if ord(cipher_text[i]) == 32:
                    plain_text += chr(ord(cipher_text[i]))
                elif ((ord(cipher_text[i]) - self.key) < 97) and ((ord(cipher_text[i]) - self.key) > 90):
                    # subtract key from letter ASCII and add 26 to current number
                    plain_text += chr(((ord(cipher_text[i]) - self.key) + 26))
                elif (ord(cipher_text[i]) - self.key) < 65:
                    plain_text += chr(((ord(cipher_text[i]) - self.key) + 26))
                else:
                    plain_text += chr(ord(cipher_text[i]) - self.key)
            return plain_text

        elif mode == 'encrypt':  # if mode is set to encrypt, run encryption
            cipher_text = ""  # This string will be added onto as the original text is ran through the encryption
            for i in range(len(msg)):  # for each letter/character in the original text
                # This uses the ASCII code of the space bar and converts it into the encrypted text
                if ord(msg[i]) == 32:  # The ASCII code for space bar is 32
                    # convert space bar ASCII code back to string representation and add it to the encrypted text
                    cipher_text += chr(ord(msg[i]))
                # After the algorithm cycles past the letter 'z' (ASCII code 122), it must return to letter 'a' (ASCII Code 97)
                elif ord(msg[i]) + self.key > 122:
                    # subtracts ASCII code of 'z' and adds ASCII code 96 to return back to 'a'
                    cipher_text += chr(96 + ((ord(msg[i]) + self.key) - 122))
                # This serves the same purpose as code above except for capital letters (65-90)
                elif (ord(msg[i]) + self.key > 90) and (ord(msg[i]) <= 96):  # if > 'Z' and < 'a'
                    # push back 90 (end of capital letters) and add 64 (beginning of capital letters) to get speciied capital letter
                    cipher_text += chr(64 + ((ord(msg[i]) + self.key) - 90))  # Adds capital letter to encrypted text
                else:
                    cipher_text += chr(ord(msg[i]) + self.key)  # converts to string representation
            return cipher_text


# Substitution Encryption class
class Substitution(BaseEncryption):

    def __init__(self):
        self.name = 'substitution'  # calls @name.setter from BaseEncryption

    def __call__(self, text, mode):
        letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ '  # plaintext alphabet
        sub = 'zxywvtusronqmplkijhgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA '  # substitution alphabet

        if mode == 'encrypt':  # When encrypting...
            # substitute plaintext alphabet with substitution alphabet
            new_text = ''.join(sub[letters.index(x)] for x in text)
        elif mode == 'decrypt':  # When decrypting..
            # Substitute substitution alphabet with plaintext alphabet
            new_text = ''.join(letters[sub.index(x)] for x in text)
        return new_text


# Transposition Encryption class
class Transposition(BaseEncryption):  # Columnar Transposition

    def __init__(self):
        self.name = 'transposition'  # Calls @name.setter from BaseEncryption class
        self.key = 3  # Encryption key used for encrypting and decrypting text

    def encrypt(self, msg):
        ciphertext = [''] * self.key
        for col in range(self.key):  # col must be within range of encryption key
            pointer = col  # set pointer to column number
            while pointer < len(msg):  # as the column number is less than the length of the message...
                ciphertext[col] += msg[pointer]
                pointer += self.key  # Add the encryption key to the column number
        return ''.join(ciphertext)  # returns the cipher text as a string

    def decrypt(self, msg):
        # sets column number to the lowest value greater than or equal to the length of the message divided by the key
        col_n = math.ceil(len(msg) / self.key)
        row_n = self.key  # sets row number to the encryption key
        # creates the boxes for columnar transposition using column and row numbers minus the length of the message
        boxes = (col_n * row_n) - len(msg)

        plaintext = [''] * col_n

        col = 0  # starting value for column number
        row = 0  # starting value for row number

        for symbol in msg:
            plaintext[col] += symbol
            col += 1
            if (col == col_n) or (col == col_n - 1 and row >= row_n - boxes):
                col = 0
                row += 1

        return ''.join(plaintext)  # returns decrypted plaintext as a string

    def __call__(self, text, mode):  # triggered when an instance of the Transposition class is called

        if mode == 'encrypt':
            return self.encrypt(text)  # runs encryption method in this class if mode is encrypt
        elif mode == 'decrypt':
            return self.decrypt(text)  # runs decryption method in this class if mode is decrypt


# Product Encryption class
class Product(BaseEncryption):

    def __init__(self):
        self.name = 'product'  # calls @name.setter from BaseEncryption
        self.cypher1 = Substitution()  # initializes cypher 1 as an instance of the Substitution class
        self.cypher2 = Transposition()  # Initializes cypher 2 as an instance of the Transposition class

    def __call__(self, text, mode):  # triggered when an instance of the Product class is called
        if mode == 'encrypt':  # If the mode is set to encrypt...
            level1 = self.cypher1(text, 'encrypt')  # runs the first level of encryption - Substitution
            level2 = self.cypher2(level1, 'encrypt')  # runs the second level of encryption - Transposition
            return level2  # Return encrypted message
        elif mode == 'decrypt':  # If the mode is set to decrypt... (reverse of encryption procedure)
            level2 = self.cypher2(text, 'decrypt')  # runs the first level of decryption - Transposition
            level1 = self.cypher1(level2, 'decrypt')  # runs the second level of decryption - Substitution
            return level1  # Return decrypted message


# Play fair Encryption class
class Playfair(BaseEncryption):

    def __init__(self):
        self.name = 'playfair'  # calls @name.setter from BaseEncryption
        self.key = 'thisisarandomkey'  # encryption key used for encrypting and decrypting text

    def get_key_matrix(self, key):
        key += 'abcdefghijklmnopqrstuvwxyz0123456789 '
        keys = []  # list containing the key as well as the string above
        [keys.append(i) for i in key if i not in keys]
        return keys

    def encrypt(self, message):  # Apply play fair encryption algorithm
        key_matrix = self.get_key_matrix(self.key)  # calls method above to create KeyMatrix

        message = [i for i in message.lower() if i in key_matrix]
        i = 0
        digraphs = []  # encrypts pairs of letters - digraphs instead of single letters
        while i <= len(message) - 1:
            if i == len(message) - 1:
                if message[i] != 'z':  # if the letter z is not present in the message
                    digraphs.append(message[i] + 'z')  # append z to the digraphs as well as the message
                else:
                    digraphs.append(message[i] + 'x')  # if z is present, append x instead
                i += 1
            elif message[i] != message[i + 1]:
                digraphs.append(''.join(message[i:i + 2]))
                i += 2
            elif message[i] == message[i + 1]:
                if message[i] != 'x':
                    digraphs.append(message[i] + 'x')
                else:
                    digraphs.append(message[i] + 'z')
                i += 1

        encrypted_text = []  # list containing encrypted text
        for i in digraphs:  # matrix encryption manipulation
            row0 = key_matrix.index(i[0]) // 6
            col0 = key_matrix.index(i[0]) % 6
            row1 = key_matrix.index(i[1]) // 6
            col1 = key_matrix.index(i[1]) % 6
            if row0 == row1:
                col0 += 1
                col1 += 1
                if col0 > 5:
                    col0 -= 6
                if col1 > 5:
                    col1 -= 6
            elif col0 == col1:
                row0 += 1
                row1 += 1
                if row0 > 5:
                    row0 -= 6
                if row1 > 5:
                    row1 -= 6
            else:
                col0, col1 = col1, col0
            encrypted_text.append(key_matrix[row0 * 6 + col0] +
                                  key_matrix[row1 * 6 + col1])
        return ''.join(encrypted_text)

    def decrypt(self, secret_message):  # Apply play fair decryption algorithm
        key_matrix = self.get_key_matrix(self.key)  # calls method GetKeyMatrix to create KeyMatrix

        secret_message = [secret_message[i:i + 2]
                          for i in range(0, len(secret_message.lower()), 2)]
        message = []
        for i in secret_message:
            row0 = key_matrix.index(i[0]) // 6
            col0 = key_matrix.index(i[0]) % 6
            row1 = key_matrix.index(i[1]) // 6
            col1 = key_matrix.index(i[1]) % 6
            if row0 == row1:
                col0 -= 1
                col1 -= 1
                if col0 < 0:
                    col0 += 6
                if col1 < 0:
                    col1 += 6
            elif col0 == col1:
                row0 -= 1
                row1 -= 1
                if row0 < 0:
                    row0 += 6
                if row1 < 0:
                    row1 += 6
            else:
                col0, col1 = col1, col0
            message.append(key_matrix[row0 * 6 + col0] +
                           key_matrix[row1 * 6 + col1])
        return ''.join(message)

    def __call__(self, text, mode):
        if mode == 'encrypt':
            return self.encrypt(text)  # if mode is encrypt, run encryption method
        elif mode == 'decrypt':
            return self.decrypt(text)  # if mode is decrypt, run decryption method


# RSA Encryption class
class Rsa(BaseEncryption):

    def __init__(self):
        self.name = 'rsa'  # calls @name.setter from BaseEncryption

        #  first prime number (p)
        p = 20988936657440586486151264256610222593863921
        #  second prime number (q)
        q = 67280421310721

        # generates a key pair using the two prime numbers p and q
        self.public_key, self.private_key = self.generate_key_pair(p, q)

    def gcd(self, x, y):  # greatest common divisor
        return x if y == 0 else self.gcd(y, x % y)  # returns the gcd of y and x modulus y given y!=0

    def modinv(self, e, n):
        #  returns the modular inverse (d) using e * d mod n = 1
        def egcd(a, b):
            if a == 0:
                return b, 0, 1
            g, x, y = egcd(b % a, a)
            return g, y - (b // a) * x, x

        g, x, _ = egcd(e, n)
        return x % n

    def generate_key_pair(self, p, q):  # generates a public and private key pair using prime numbers p and q
        #  find modulus
        n = p * q

        #  public key = (n, e), where e is not a factor of n(their gcd is 1)
        #  and 1 < e < phi, phi = (p-1)(q-1)
        e, phi = 2, (p - 1) * (q - 1)
        while e < phi and self.gcd(e, phi) != 1:
            e += 1

        public_key = (n, e)
        private_key = (n, self.modinv(e, phi))
        return public_key, private_key

    def encrypt(self, msg):
        #  note: msg has to be numerical, or string converted to numerical
        #  cipher = (msg ^ e) mod n
        n, e = self.public_key
        #  cipher = (msg ** e) % n
        cipher = pow(msg, e, n)  # sets cipher to msg to the power of e modulus n
        return cipher

    def decrypt(self, cipher):
        #  plaintext = (cipher ^ d) mod n
        n, d = self.private_key

        if cipher > n:
            print('Choose larger prime numbers p and q')
            return 0

        #  plaintext = (cipher ** d) % n
        plaintext = pow(cipher, d, n)  # sets plaintext to msg to the power of d modulus n
        return plaintext

    def __call__(self, text, mode):

        if mode == 'encrypt':  # if the mode is encrypt...
            return str(self.encrypt(int(text)))  # run encryption of integer and return as a string

        elif mode == 'decrypt':
            return str(self.decrypt(int(text)))  # run decryption of integer and return as a string


# Message class - Parent class for child classes plaintext message as well as cypher text message class
class Message:

    def __init__(self, msg):  # initializer
        self.msg = msg

    @property  # Getter for .msg
    def msg(self):
        return self.__msg

    @property  # Getter for .time
    def time(self):
        return self.__time

    @property  # Getter for .method
    def method(self):
        return self.__method

    @msg.setter  # Setter for .msg
    def msg(self, x):
        if isinstance(x, str):  # Ensures message passed is a string
            self.__msg = x  # Setter
        else:  # If its not a string, convert it to string
            self.__msg = str(x)  # Setter

    @time.setter  # Setter for .time
    def time(self, x):
        if isinstance(x, float):  # time must be a float
            self.__time = x  # Setter
        else:
            raise Exception('Time in incorrect format')  # Exception handling for if is not a float

    @method.setter  # Setter for .method
    def method(self, x):
        self.__method = x  # Setter


# Plaintext message class - Child class of Parent Message class
class plaintextMsg(Message):

    # 6 algorithms of encryption - aka the method
    cyphers = {
        1: Ceaser,
        2: Substitution,
        3: Transposition,
        4: Product,
        5: Playfair,
        6: Rsa,
    }

    def encrypt(self):  # encryption method
        try:
            int(self.msg)  # Since RSA only accepts integers, if msg can be successfully converted to an int, run RSA
            num = 6
        # If an integer is not passed and a ValueError is raised, apply one of the 5 other encryption algorithms
        except ValueError:
            num = choice(range(1, 5))
        # sets the number selected between 1-6 and sets the appropriate algorithm to the method
        method_obj = self.cyphers[num]()

        start_time = time()  # Starting time before encrypting
        cypher = ciphertextMsg(method_obj(self.msg, 'encrypt'))  # Encrypt message
        cypher.time = time() - start_time  # time after encryption minus time before encryption = execution time
        cypher.method = method_obj

        return cypher


# Plaintext message class - Child class of Parent Message class
class ciphertextMsg(Message):

    def decrypt(self):  # decryption method
        start_time = time()  # Starting time before decrypting
        plaintext = plaintextMsg(self.method(self.msg, 'decrypt'))  # Decrypt message
        plaintext.time = time() - start_time  # time after decryption minus time before decryption
        return plaintext


if __name__ == '__main__':

    msgs = []  # empty list of cypher and plaintext message(s)

    while True:
        try:
            msg = input('Enter message to encrypt: ')  # User inputs message to encrypt/decrypt
            if
        except
        if msg in ['stop', 'Stop', 'STOP']:  # if user inputs stop, Stop or STOP, break program
            break
        original_msg = plaintextMsg(msg)  # Makes original message an instance of the plaintextMsg class
        cypher = original_msg.encrypt()  # encrypt original message and set it cypher
        plaintext = cypher.decrypt()  # decrypt cypher message and set it to plaintext
        msgs.append((cypher, plaintext))  # add cypher and plaintext to msgs list created above

    for cypher, plaintext in msgs:  # for each cypher and plaintext in the msgs list created and appended to above...
        print('\nCypher Text: {}'.format(cypher.msg))  # Encrypted text
        print('Plain Text: {}'.format(plaintext.msg))  # Original user text
        print('Encryption Time: {} seconds'.format(cypher.time))  # Time to encrypt
        print('Decryption Time: {} seconds'.format(plaintext.time))  # Time to decrypt
        print('Cypher Algorithm: {}\n'.format(cypher.method.name))  # Algorithm used
