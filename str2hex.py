#!/usr/bin/python3

import sys

if len(sys.argv) == 1:
    print('usage :\n\tstr2hex str')
    exit(0)
for i in sys.argv[1]:
    print("0x%x," % ord(i), end='')
print('\b ', flush=True)
print("")
