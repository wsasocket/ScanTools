#!/usr/bin/python3
"""
find Openvas scripts dependices
copy plugins all directory and files to ROOT_PATH
"""

import os
import sys

import utils.cvss


def usage():
    print('find_dep.py {NASL OR INC file}')
    print('nasl or inc file MUST BE full path')


if __name__ == '__main__':

    if len(sys.argv) == 1:
        usage()
        exit(0)
    arg = sys.argv[1]
    tag = False
    if os.path.isfile(arg):
        dirname, basename = os.path.split(arg)
        if dirname is None:
            usage()
            exit(0)
        fname, ext = os.path.splitext(basename)
        if ext not in ['.nasl', '.inc']:
            print("{0} is not a legal file".format(arg))
            exit(0)
    else:
        print("{0} is not a legal file".format(arg))
        exit(0)
    try:
        os.environ['OPENVAS_PLUGINS']
        os.environ['SCANNER_PLUGINS']
    except KeyError:
        print('Pls export OPENVAS_PLUGINS variable!')
        exit(0)

    if os.environ['OPENVAS_PLUGINS'] in dirname:
        tag = True

    data_set = {
        utils.DEP: set(),
        utils.INC: set(),
        utils.CVE: set(),
        utils.OID: set(),
        utils.CVSS: set()
    }
    items = utils.get_specify_data_from_file(
        arg, [utils.DEP, utils.INC, utils.CVE, utils.OID, utils.CVSS])

    for d in items[utils.DEP]:
        if 'find_service' in d or 'os_detection.nasl' in d:
            continue
        data_set[utils.DEP].add(d)

    for d in items[utils.INC]:
        data_set[utils.INC].add(d)

    # for d in items[utils.CVE]:
    #     data_set[utils.CVE].add(d)

    # for d in items[utils.OID]:
    #     data_set[utils.OID].add(d)

    file_list = set()

    while len(file_list) != len(data_set[utils.DEP]):
        file_list.update(data_set[utils.DEP])
        for script_file in file_list:
            if tag:
                _deps = utils.get_specify_data_from_file(
                    os.path.join(os.environ['OPENVAS_PLUGINS'], script_file),
                    [utils.DEP, utils.INC])
            else:
                _deps = utils.get_specify_data_from_file(
                    os.path.join(os.environ['SCANNER_PLUGINS'], script_file),
                    [utils.DEP, utils.INC])
            if _deps:
                if _deps[utils.DEP] is None:
                    continue
            else:
                print("Error: {}".format(script_file))
                continue
            for d in _deps[utils.INC]:
                data_set[utils.INC].add(d)

            for d in _deps[utils.DEP]:
                if 'find_service' in d or 'os_detection.nasl' in d:
                    continue
                data_set[utils.DEP].add(d)
    if len(items[utils.OID]) > 0:
        print("Script OID :%s" % items[utils.OID].pop())
    if len(items[utils.CVSS]) > 0:
        cvss = items[utils.CVSS].pop()
        print("Script CVSS_Vector :%s" % cvss)
        cvss_score = utils.cvss.cvss_base_calc(cvss)
        print("Script CVSS_Vector :%1.1f" % cvss_score)
    print("\t-------------------------")
    for i, v in enumerate(items[utils.CVE]):
        print("\t%03d|---> %s" % (i + 1, v))
    print("\t-------------------------")
    for i, f in enumerate(data_set[utils.DEP]):
        print("\t%03d|---> %s" % (i + 1, f))
    print("\t-------------------------")
    for i, v in enumerate(data_set[utils.INC]):
        print("\t%03d|---> %s" % (i + 1, v))
