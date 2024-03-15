# -*- coding: utf-8 -*-
"""
Created on Thu Feb 29 12:13:21 2024

@author: round
"""
#needed for alphabet encoder/decoder
alphabet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']


def alpha_encode(user_inp):
    encoded_msg = ""
    for i in range(len(user_inp)):
        #only proceeds if the element is in the alphabet
        if user_inp[i] in alphabet:
            #catchs z and turns to a
            if user_inp[i] == 'z':
                encoded_msg = encoded_msg + 'a'
            else:
                #finds the index of the specific element, adds one and then pulls that number from the alphabet list
                encoded_msg = encoded_msg + (alphabet[1 + alphabet.index(user_inp[i])])
        #if not in alphabet then just passes it through
        else:
            encoded_msg = encoded_msg + user_inp[i]
    print(encoded_msg)
    
def alpha_decode(inp):
    decoded_msg = ""
    for i in range(len(inp)):
        #only proceeds if the element is in the alphabet
        if inp[i] in alphabet:
            #turns a to z
            if inp[i] == 'a':
                decoded_msg = decoded_msg + 'z'
            else:
                #finds the index of the specific element, subtracts one and then pulls that number from the alphabet list
                decoded_msg = decoded_msg + (alphabet[alphabet.index(inp[i]) - 1])  
        #if not in alphabet then just passes it through
        else:
            decoded_msg = decoded_msg + inp[i]
    print(decoded_msg)



#-----------------------------------------------#



#just user interface stuff, temporary
run = True

while run == True:
    
    enc_or_dec = input("""Would you like to encode or decode?
                       type 'encode' to encode
                       type 'decode' to decode
                       type 'stop' to quit program
                       """)

    if enc_or_dec == "encode":
        user_inp = input("what text would you like to encode? :")
        alpha_encode(user_inp)
    elif enc_or_dec == "decode":
        user_inp = input("what text would you like to decode? :")
        alpha_decode(user_inp)
    elif enc_or_dec == "stop":
        run = False
    else:
        print("input not recognized")
                       

    
















    
        



