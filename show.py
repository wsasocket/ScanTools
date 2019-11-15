#!/usr/bin/python3
import sys


def main():
    version = """Cisco IOS Software, C3750 Software (C3750-ADVIPSERVICESK9-M), Version 12.2(55)SE5, RELEASE SOFTWARE (fc1)
Copyright (c) 1986-2007 by Cisco Systems, Inc.
Compiled Fri 20-Jul-07 01:58 by nachen
Image text-base: 0x00003000, data-base: 0x01400000

ROM: Bootstrap program is C3750 boot loader
BOOTLDR: C3750 Boot Loader (C3750-HBOOT-M) Version 12.2(25r)SEE4, RELEASE SOFTWARE (fc1)
"""
    versionXE = 'Cisco IOS Software, IOS-XE Software, Catalyst L3 Switch Software\
 (CAT3K_CAA-UNIVERSALK9-M), Version 03.03.00SE RELEASE SOFTWARE (fc1)'
    if len(sys.argv) > 1:
        if sys.argv[1] == 'version':
            print(versionXE)
        elif sys.argv[1] == 'vstack':
            print('Role:Client(SmartInstall enabled)\nVstack Director IP address:\n0.0.0.0')
        else:
            print(
                "Darwin localhost 17.5.0 Darwin Kernel Version 17.5.0: Mon Mar  5 22:24:32 PST 2018; root:xnu-4570.51.1~1/RELEASE_X86_64 x86_64")


if __name__ == '__main__':
    main()
