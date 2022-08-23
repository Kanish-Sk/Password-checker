import requests
#This is module give response from the given url by using requests.get().
import hashlib
#This module is to use a hash function on a string, and encrypt it so that it is very difficult to decrypt it. 
import sys
 
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
    	#status code returns a number that indicates the status.
    	raise RuntimeError(f'Error fetcing: {res.status_code}, check the url')
    return res

def get_password_leaks_count(hashes, hash_to_check):
	#response.text returns the content of the response, in unicod
	#FEE1BB02B4C557EAE3F680F9AA73B448DF3:3
	hashes = (line.split(':') for line in hashes.text.splitlines())
	#split(seperator)  method splits a string into a list.
	# splitlines() method is used to split the lines at line boundaries.\n

	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    #sha1 is a algorithm.sha1() create a object for hash code
    #The encode() method encodes the string, using the specified encoding. If no encoding is specified, UTF-8 will be used.
    #without encode() we can't generate hash code.
    # UTF stands for “Unicode Transformation Format”, and the ‘8’ means that 8-bit values are used in the encoding.
    #In hash code all should be in uppercase and also a hexadecimal formate.
    first5_char, tail = sha1password[:5],sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

def main(args):
	for password in args:
		count = pwned_api_check(password)
		if count:
			print(f'{password} was found {count} time..You should change it')
		else:
		    print(f'{password} was NOT found..Thats good.')
	return 'All are done!'	

if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))
	#sys.exit() is print and exit the value in calling function return statement