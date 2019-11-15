#!/usr/local/bin/python3

import os
import re
import sys

import utils


def get_func_name(func_string):
    pattern = r'([\w_]+)'
    p = re.compile(pattern)
    r = p.findall(func_string)
    if r is None:
        print('Error: %s ' % func_name)
        exit(0)
    return r[0]


if __name__ == '__main__':

    if len(sys.argv) != 3:
        print('Usage: ./whereisfunc.py func_name path_to_plugins')
        exit(0)

    func_name = sys.argv[1]
    dirname = sys.argv[2]
    if not os.environ['OPENVAS_PLUGINS']:
        print('Pls export OPENVAS_PLUGINS variable!')
        exit(0)
    if not os.environ['SCANNER_PLUGINS']:
        print('Pls export SCANNER_PLUGINS variable!')
        exit(0)

    if os.environ['SCANNER_PLUGINS'] in dirname:
        dirname = os.environ['SCANNER_PLUGINS']
    elif os.environ['OPENVAS_PLUGINS'] in dirname:
        dirname = os.environ['OPENVAS_PLUGINS']
    else:
        print(func_name)
        exit(0)

    file_list = utils.gen_get_file_path(dirname, suffix='inc')
    for f in file_list:

        res = utils.get_specify_data_from_file(f, [utils.FUC])
        for n in res[utils.FUC]:
            if func_name == get_func_name(n):
                print("{0} -----> {1}".format(get_func_name(n), f))
