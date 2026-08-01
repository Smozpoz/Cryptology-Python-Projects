import random
import pprint
#following code only uses lower-case letters
def encode(text):
    'encode text as list of ASCII values'

    text = text.lower()
    code_lst = [(ord(letter) - ord('a')) for letter in text if letter.isalpha()]
    return code_lst

def decode(code_lst):
    'decode code_lst of ASCII values to string'
    
    text = ''.join([chr(ord('a')+code) for code in code_lst])
    return text

def shift(pt,k):
    'shift plaintext pt by shift k'
    
    pt_lst = encode(pt)
    
    #shift each letter by 26, use mod 26 for wrap-around
    ct_lst = [(code+k) % 26 for code in pt_lst]
    return decode(ct_lst)

def breakshift(ct):
    'breaks a shift cipher using brute force and frequency analysis'

    frequency = {
        'a': 0.082, 'b': 0.015, 'c': 0.028, 'd': 0.043, 'e': 0.127,
        'f': 0.022, 'g': 0.020, 'h': 0.061, 'i': 0.070, 'j': 0.0016,
        'k': 0.0077, 'l': 0.040, 'm': 0.024, 'n': 0.067, 'o': 0.075,
        'p': 0.019, 'q': 0.0012, 'r': 0.060, 's': 0.063, 't': 0.091,
        'u': 0.028, 'v': 0.0098, 'w': 0.024, 'x': 0.0015, 'y': 0.020,
        'z': 0.00074
    }
    
    match = float("inf")
    bestShift = 0
    length = len(ct)
    
    for shft in range(26):
        temp = 0
        shifted = shift(ct,shft)
        count = {
            'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0, 'f': 0, 'g': 0,
            'h': 0, 'i': 0, 'j': 0, 'k': 0, 'l': 0, 'm': 0, 'n': 0,
            'o': 0, 'p': 0, 'q': 0, 'r': 0, 's': 0, 't': 0, 'u': 0,
            'v': 0, 'w': 0, 'x': 0, 'y': 0, 'z': 0
        }
        
        for ch in shifted:
            if ch in count:
                count[ch] += 1

        for ch, value in count.items():
            temp += abs((value / length) - frequency[ch])

        if (temp < match):
            match = temp
            bestShift = shft
     
    return (26 - bestShift) % 26

def prepare(t):
    return ''.join([l for l in t.lower() if l.isalpha()])

def test(a, b):
    'test breakshift'
    infile = open('bible.txt', 'r')
    pt = infile.read()
    infile.close()
    pt = prepare(pt)
    length = len(pt)

    stats = {}
    
    for i in range(a,b):
        correct = 0

        for j in range(1000):
            substr = random.randrange(0, length)
            numShift = random.randrange(1,25)
            shifted = shift(pt[substr:substr+i],numShift)

            if(numShift == breakshift(shifted)):
                correct += 1

        stats[i] = correct / 1000
    pprint.pprint(stats)

def test2(a, b):
    'test breakshift'
    infile = open('bible.txt', 'r')
    pt = infile.read()
    infile.close()
    pt = prepare(pt)
    length = len(pt)

    stats = {}
    
    for i in range(a,b):
        correct = 0

        for j in range(1000):
            substr = random.randrange(0, length)
            numShift = random.randrange(1,25)
            shifted = shift(pt[substr:substr+i],numShift)

            if(numShift == breakshift2(shifted)):
                correct += 1

        stats[i] = correct / 1000
    pprint.pprint(stats)

def breakshift2(ct):
    'breaks a shift cipher using brute force and frequency analysis'

    frequency = {
        'a': 0.082, 'b': 0.015, 'c': 0.028, 'd': 0.043, 'e': 0.127,
        'f': 0.022, 'g': 0.020, 'h': 0.061, 'i': 0.070, 'j': 0.0016,
        'k': 0.0077, 'l': 0.040, 'm': 0.024, 'n': 0.067, 'o': 0.075,
        'p': 0.019, 'q': 0.0012, 'r': 0.060, 's': 0.063, 't': 0.091,
        'u': 0.028, 'v': 0.0098, 'w': 0.024, 'x': 0.0015, 'y': 0.020,
        'z': 0.00074
    }
    
    match = float("inf")
    bestShift = 0
    length = len(ct)
    
    for shft in range(26):
        temp = 0
        shifted = shift(ct,shft)
        count = {
            'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0, 'f': 0, 'g': 0,
            'h': 0, 'i': 0, 'j': 0, 'k': 0, 'l': 0, 'm': 0, 'n': 0,
            'o': 0, 'p': 0, 'q': 0, 'r': 0, 's': 0, 't': 0, 'u': 0,
            'v': 0, 'w': 0, 'x': 0, 'y': 0, 'z': 0
        }
        
        for ch in shifted:
            if ch in count:
                count[ch] += 1

        for ch, value in count.items():
            temp += (abs((value / length) - frequency[ch])) ** 2

        if (temp < match):
            match = temp
            bestShift = shft
            
    return (26 - bestShift) % 26
