pad = lambda BS, s: s + bytes((BS - len(s) % BS) * [BS - len(s) % BS])
unpad = lambda s: s[0:-s[-1]]
