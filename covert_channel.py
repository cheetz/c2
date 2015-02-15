import zlib, base64
import random
import words_list


def decode_create_wordspace(key):
        cookie_count = 1
        words = []
        #f = open('words.txt','r')
	f = words_list.abcd()
        for zz in f:
                words.append(zz.strip())
        
        for y in words:
                y = y.strip()
                if y == key:
                        cookie = cookie_count
                        break
                cookie_count = cookie_count + 1
        
        alphabet = []
        cookie_count = 1
        for q in words:

                if (cookie_count >= cookie) and (cookie_count < (66 + cookie)):
                        alphabet.append(q.strip())
                cookie_count = cookie_count + 1
        #f.close()
        return alphabet


def decode_convert_base(str_input, alphabet):
        str_input = str_input.lower()
        alphabet_end = "."
        alphabet_end_double = ","
        alphabet_check = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/']
        revert = []
        if str_input.endswith(','):
                str_input = str_input.replace(',',' ,')
        if str_input.endswith('.'):
                str_input = str_input.replace('.',' .')
        str_list_arr = str_input.split(" ")
        for x in str_list_arr:
                counter = 0
                if x == alphabet_end:
                        revert.append('=')
                elif x == alphabet_end_double:
                        revert.append('==')
                else:
                        for y in alphabet:
                                if x == y:
                                        revert.append(alphabet_check[counter])
                                counter = counter + 1
        
        base64x = ''.join(revert)
	#print base64x
        return base64x


def decompress_decode(text):
	#make sure to delete the line below
	#a = open('logging.txt','a')
	#a.write(text)
        x = base64.b64decode(text)
        decrypt = zlib.decompress(x)
        return decrypt

def encode_create_wordspace(cookie):
    #f = open('words.txt','r')
    f = words_list.abcd()
    alphabet = []
    cookie_count = 1
    for q in f:
        if cookie_count == cookie:
                key = q.strip()
        if (cookie_count >= cookie) and (cookie_count < (66 + cookie)):
                alphabet.append(q.strip())
        cookie_count = cookie_count + 1
    return (alphabet,key)
        
def encode_convert_base(str_input, alphabet):
    alphabet_end = "."
    alphabet_end_double = ","
    alphabet_check = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/']
    revert = []
    
    for x in str_input:
        counter = 0
        
        for y in alphabet_check:
            if (y == x):
                revert.append(alphabet[counter])
            counter = counter + 1

    if str_input.endswith('=='):
        str_input = revert.append(',')
    elif str_input.endswith('='):
        str_input = revert.append('.')

    str_output = ' '.join(revert)
    if str_output.endswith(' .'):
        str_output = str_output.replace(' .', '.')
    elif str_output.endswith(' ,'):
        str_output = str_output.replace(' ,', ',')

    return str_output

def encode_compress_encode(text):
    s = zlib.compress(text)
    str_input = base64.b64encode(s)
    return str_input

def encode_string(text):
    cookie = random.randint(0,400)
    alphabet,key = encode_create_wordspace(cookie)
    
    str_input = encode_compress_encode(text)
    str_output = encode_convert_base(str_input, alphabet)
    str_output = key.capitalize() + " " + str_output
    return str_output

def decode_string(text):
    str_input = text.lower()
    str_key = str_input.split(' ',1)
    alphabet = decode_create_wordspace(str_key[0])

    str_input = str_key[1]
    str_input = decode_convert_base(str_input, alphabet)
    decrypt = decompress_decode(str_input)
    return decrypt
