#!/usr/bin/python3

import os
from shutil import copyfile

import utils

SRC = '/Users/james/work/plugins'
DST = '/Users/james/work/tmp/'


def classify(root, fp):
    cmd = './find_dep.py {}'.format(os.path.join(root, fp))
    print(cmd)
    # print(os.path.split(fp)[1])
    result = os.popen(cmd)
    dep_inc = result.read()
    if 'ssh_authorization_init.nasl' in dep_inc and 'gather-package-list.nasl' in dep_inc:
        return 'SSH'

    if 'smb_authorization.nasl' in dep_inc:
        return 'SMB'

    if 'http_func.inc' in dep_inc and 'http_keepalive.inc' in dep_inc:
        return 'HTTP'

    if 'network_func.inc' in dep_inc:
        return 'REMOTE'

    return 'UNKNOW'


def main():
    g = utils.gen_get_file_path(SRC, suffix="nasl")
    for fp in g:
        root, fn = os.path.split(fp)
        # print(root)
        # print(fp)
        typestr = classify(root, fn)
        print("From:{}".format(fp))
        todir = os.path.join(DST, typestr)
        print("To:{}".format(todir))
        copyfile(fp, os.path.join(todir, fn))


if __name__ == '__main__':
    main()
