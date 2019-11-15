#!/usr/local/bin/python3
"""比较两个inc文件内含有的函数数量及名称，方便新版本简脚本的替换"""

import os
import re
import sys

PATTERN_INC_FUNC = r'function\s+([\w_]+\s*\(\s*[\w _,]*\s*\))'


def get_standard_line():
    line = ''
    complete = False
    while True:
        if complete:
            buffer = yield line
            line = ''
            complete = False
        else:
            buffer = yield None

        try:
            str = buffer.decode()
        except:
            # dump_bytearray(byte_buf)
            # exit(0)
            line = ''
            complete = True
            continue

        if str.strip('\n\r\t ').startswith('#'):
            continue
        tmp = str.strip('\n\r\t ')
        pos1 = tmp.find(';')
        pos2 = tmp.find('#')
        if pos1 > 0 and pos2 > 0:
            if pos1 < pos2:
                tmp = tmp[:pos2]
                pos1, pos2 = 0, 0
        line += tmp.strip('\n\r\t ')
        if line.endswith(';'):
            complete = True


def get_func_def(line):
    p = re.compile(PATTERN_INC_FUNC)
    return p.findall(line)


def get_func_from_file(filename):
    if not os.path.exists(filename):
        print(filename)
        return None

    g = get_standard_line()
    g.send(None)
    dep = set()
    with open(filename, 'rb') as f:
        for l in f:
            line = g.send(l)
            if not line:
                continue

            if 'function' in line:
                _dep = get_func_def(line)
                for d in _dep:
                    dep.add(func_split(d)[0])
    return dep


def func_split(func_name):
    pattern = r'([\w_]+)'
    p = re.compile(pattern)
    r = p.findall(func_name)
    if r is None:
        print('Error: %s ' % func_name)
        exit(0)
    return r


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: ./cmpfunc.py func_name ')
        exit(0)

    inc_name = sys.argv[1]

    if not os.environ['OPENVAS_PLUGINS']:
        print('Pls export OPENVAS_PLUGINS variable!')
        exit(0)
    if not os.environ['SCANNER_PLUGINS']:
        print('Pls export SCANNER_PLUGINS variable!')
        exit(0)

    old_file = os.path.join(os.environ['SCANNER_PLUGINS'], inc_name)
    old_set = get_func_from_file(old_file)

    new_file = os.path.join(os.environ['OPENVAS_PLUGINS'], inc_name)
    new_set = get_func_from_file(new_file)
    old_count = len(old_set)
    new_count = len(new_set)
    discard_count = 0
    miss_count = 0
    print('%-40s|%-39s' % ('        new', '         old'))
    for f in new_set:
        print('-------------------------------------------------------------------------------')
        print('%-39s |' % f, end='')
        if f in old_set:
            print('%-39s' % f)
            old_set.remove(f)
        else:
            miss_count += 1
            print('\x1B[1;30;41m%-39s\x1B[0m' % '        Miss')

    if len(old_set) != 0:
        for f in old_set:
            print('-------------------------------------------------------------------------------')
            discard_count += 1
            print('\x1B[1;30;42m%-39s\x1B[0m | %-39s' % ('        Discard', f))
    print('-------------------------------------------------------------------------------')
    print('%02d function(s) in old inc ' % old_count)
    print('%02d function(s) in new inc ' % new_count)
    print('%02d function(s) create in new inc ' % miss_count)
    print('%02d function(s) drop in new inc ' % discard_count)
