#!/usr/bin/python3
import os
import sys
from enum import Enum
from shutil import copyfile

SRC = '/root/projects/plugins'
DST = '/root/tmp'


class op_mode(Enum):
    DEL = 1
    NEW = 2
    MOD = 3


def classify(root, fp):
    cmd = './find_dep.py {}'.format(os.path.join(root, fp))
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


def get_file_st(line):
    o = [x.strip() for x in line.split(':')]
    op = op_mode.NEW
    if o[0] == 'modified':
        op = op_mode.MOD
    if o[0] == 'deleted':
        op = op_mode.DEL
    filename = o[1]
    if op == op_mode.DEL:
        fn, ext = os.path.splitext(filename)
        if ext == '.nasl' or ext == '.inc':
            filename = fn + '.asc'
    return op, filename


def operate_file(mode, file):
    if mode == op_mode.MOD:
        return file
    srcfile = os.path.join(SRC, file)
    dstfile = os.path.join(DST, file)
    if mode == op_mode.NEW:
        # if '/' in file:
        #    NASL_classify[classify(SRC,file)].append(file)
        if not os.path.exists(srcfile):
            print('%s Not found!' % srcfile)
            return None
        else:
            base_dir, _ = os.path.split(dstfile)
            if not os.path.isdir(base_dir):
                os.makedirs(base_dir)
            try:
                if COMMIT:
                    copyfile(srcfile, dstfile)
                # pass
            except IsADirectoryError as e:
                # print(e)
                return None
        return dstfile

    if mode == op_mode.DEL:
        try:
            if COMMIT:
                os.remove(srcfile)
            # pass
        except FileNotFoundError as e:
            # print(e)
            return None
        return srcfile
    return None


if '__main__' == __name__:
    COMMIT = False
    NASL_classify = {'SSH': [], 'SMB': [], 'HTTP': [], 'REMOTE': [], 'UNKNOW': []}
    if len(sys.argv) != 2:
        print("if you want Checkout files, pls add 'commit' option")
    elif 'commit' == sys.argv[1]:
        COMMIT = True

    data = sys.stdin.readlines()

    new_count = 0
    mod_count = 0
    del_count = 0
    for l in data:
        if l == '\n':
            continue
        l = l.strip()
        if ':' in l:
            op, file = get_file_st(l)
        else:
            file = l
            op = op_mode.NEW

        if op_mode.NEW == op:
            new_count += 1
        if op_mode.DEL == op:
            del_count += 1
        if op_mode.MOD == op:
            mod_count += 1

        f = operate_file(op, file)
        # print(op,'\t',file)
        if '/' not in file and op == op_mode.MOD:
            print('[!]{}'.format(file))

    # for k in NASL_classify.keys():
    #    print(k)
    #    for fp in NASL_classify[k]:
    #        print('\t{}'.format(fp))
    print('ENDLIST')
    print('+-------+-------+-------+')
    print('|  New  |  Mod  |  Del  |')
    print('+-------+-------+-------+')
    print('|  %4d |  %4d |  %4d |' % (new_count, mod_count, del_count))
    print('+-------+-------+-------+')
