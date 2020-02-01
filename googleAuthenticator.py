#!/usr/bin/python3

import hmac, base64, struct, hashlib, time, getpass, sys, pyperclip

def get_hotp_token(secret, intervals_no):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return h

def get_totp_token(secret):
    return get_hotp_token(secret, intervals_no=int(time.time())//30)

def get_code(raw_secret):
    mod=len(secret)%8
    padding = ""
    if mod==2:
        padding = "======"
    elif mod==4:
	    padding = "===="
    elif mod==5:
	    padding = "==="
    elif mod==7:
	    padding = "=="
    return '{:06d}'.format(get_totp_token(secret+padding))


if len(sys.argv)>1:
    with open(sys.argv[1], "r") as ins:
        for line in ins:
            line = line.strip()
            if not line:
                continue
            idx = line.find(' ')
            secret = line[:idx]
            comment = line[idx+1:]
            print(get_code(secret), comment)
else:
    secret=getpass.getpass("Enter your Google Authenticator secret: ").upper().replace(" ", "")
    code = get_code(secret)
    pyperclip.copy(code)
    print("copied to clipboard: ", code)

