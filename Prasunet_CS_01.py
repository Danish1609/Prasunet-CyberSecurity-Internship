print("==================================================================")
print("")
print("                 CAESAR CIPHER CRYPTOGRAPHY                       ")
print("")
print("==================================================================")
print("")
print(" a b c d e f g h i j  k  l  m  n  o  p   q  r  s  t  u  v  w  x  y  z")
print(" 0 1 2 3 4 5 6 7 8 9 10  11 12 13 14 15 16 17 18 19 20 21 22 23 24 25")
print("")
print("==================================================================\n")
print("")
print(" ------------ C A E S A R  C I P H E R  A L G O R I T H M ------------- \n")
print("A : Encrypt your text using Caesar method \n")
print("B : Decrypt your Caesar Encrypted text \n")

def get_valid_input(prompt):
    while True:
        try:
            value = int(input(prompt))
            return value
        except ValueError:
            print("Invalid input. Please enter a valid number.")

while True:
    option = input("\n Choose your option (A / B) ? : ")

    s = ""
    encrypt_list = []
    decrypt_list = []

    try:
        if option in ('A', 'a'):
            print("\n----------------ENCRYPT YOUR TEXT--------------\n")
            plain_text = input("\n Enter Plain-text / Original-text here : ")
            key = get_valid_input("\n Enter Encryption key here : ")
            for i in plain_text:
                x = ord(i) + key
                encrypt_list.append(chr(x))
            x_str = ''.join(encrypt_list)
            print("\n Encrypted text : ", x_str)

            decrypt_option = input("\n Do you want to decrypt the text? (Y/N) : ")
            if decrypt_option in ('Y', 'y'):
                option = 'B'
                cipher_text = x_str
            else:
                print("\n Exiting The System ! ")
                break

        if option in ('B', 'b'):
            print("\n ----------------LET'S SEE IF YOUR A VALID USER OR NOT--------------\n")
            if 'cipher_text' not in locals():
                cipher_text = input("Enter cipher-text/encrypted-text here : ")
            key = get_valid_input("Enter Decryption key here : ")
            for i in cipher_text:
                x = ord(i) - key
                decrypt_list.append(chr(x))
            y_str = ''.join(decrypt_list)
            print("Decrypted text : ", y_str)
            break

        else:
            print("Invalid option chosen. Please start again !")

    except Exception as e:
        print("Something is wrong here, please start again from the beginning. Error :", str(e))