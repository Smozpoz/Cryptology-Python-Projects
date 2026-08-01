# Cryptology-Python-Projects
A compilation of python projects made for my cryptology class at DePaul.

## Table of Contents
1. [Shift Cipher](#shift-cipher)

## Shift Cipher
	shift.py - Implementation of a shift cipher:
	
	Description:
	
    - A shift cipher takes plaintext and moves each letter 'x' times to the
      right to create the ciphertext. For example, shifting 'A'
      once to the right results in the ciphertext 'B'. The key in this cipher
      is the number of shifts, so in the previous example the
      key equals '1'.
      
    - The key is symmetric, meaning it's used for both encryption and decryption.
      To decrypt, take the key and shift left by the number
      instead of right. For instance, in the previous example,
      to decrypt ciphertext 'B', shift it one to the left, resulting in 'A'.
      
    - When a letter reaches the end of the alphabet, it wraps to the beginning.
      For example, shifting 'Z' by two results in ciphertext 'B'. 
      This is also true for when decrypting; letters shifted past A wrap to Z.

 	Functions:
	
    encode(text)/decode(text):
      Used for reference to the ASCII values of 'text'
      (e.g. encode('hello') = [7, 4, 11, 11, 14]). Useful to visualize how
      the letters get shifted by the key value.
        
    shift(pt,k):
      The actual shift cipher function. Shifts 'pt', or plaintext, 'k' to the right.
      Implements the wrapping using modular arithmetic (i.e. % 26).
      
    breakshift(ct)
       - 
    
