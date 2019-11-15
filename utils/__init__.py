import os
import re
from functools import partial


class bcolors:
    # This module is just for beautifying output
    # bcolors.ENDC should be followed after using each
    # of the variables to revert back to original color

    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def get_specify_pattern_data(statement, pattern):
    """return regular express filtered data,just like function,dependence include"""
    if not isinstance(statement, str):
        return None
    p = re.compile(pattern)
    return p.findall(statement)


get_dependencie = partial(
    get_specify_pattern_data, pattern=r'([\w_\-]+\.nasl)')

get_include = partial(get_specify_pattern_data, pattern=r'([\w_\-]+\.inc)')

get_function = partial(
    get_specify_pattern_data,
    pattern=r'function\s+([\w_]+\s*\(\s*[\w _,]*\s*\))')

get_CVE = partial(get_specify_pattern_data, pattern=r'(CVE[\d-]+)')

get_oid = partial(get_specify_pattern_data, pattern=r'([\d\.]+)')

get_cvss = partial(get_specify_pattern_data, pattern=r'name:[,\s]*\"cvss_base_vector\"[,\s]*value:[,\s]*\"([\w:/]+)\"')

get_affected = partial(get_specify_pattern_data, pattern=r'name:[,\s]*\"affected\"[,\s]*value:[,\s]*\"(.+?)\"\)')

get_summary = partial(get_specify_pattern_data, pattern=r'name\s*:\s*\"summary\"[,\s]*value\s*:\s*\"(.+?)\"\)')

get_insight = partial(get_specify_pattern_data, pattern=r'name:[,\s]*\"insight\"[,\s]*value:[,\s]*\"(.+?)\"\)')

get_xref = partial(get_specify_pattern_data, pattern=r'name:[,\s]*\"URL\"[,\s]*value:[,\s]*\"(.+?)\"\)')

get_solution = partial(get_specify_pattern_data, pattern=r'name:[,\s]*\"solution\"[,\s]*value:[,\s]*\"(.+?)\"\)')

get_name = partial(get_specify_pattern_data, pattern=r'[\"|\'](.+?)[\"|\']')

get_version = partial(get_specify_pattern_data, pattern=r'\$Revision:\s*([\d\+\-T:]+)\s*\$')
# get_version = partial(get_specify_pattern_data,pattern=r'([\d\-T\+:]+)')
get_family = partial(get_specify_pattern_data, pattern=r'\"(.*?)\"')

DEP = 0
CVE = 1
OID = 2
INC = 3
FUC = 4
CVSS = 5
AFFECTED = 6
SUMMARY = 7
INSIGHT = 8
XREF = 9
SOLUTION = 10
VNAME = 11
VERSION = 12
FAMILY = 13
TAG = {
    DEP: 'script_dependencie', CVE: 'script_cve_id',
    OID: 'script_oid', INC: 'include',
    FUC: 'function', CVSS: 'script_tag',
    AFFECTED: 'script_tag', SUMMARY: 'script_tag',
    INSIGHT: 'script_tag', XREF: 'script_xref',
    SOLUTION: 'script_tag', VNAME: 'script_name',
    VERSION: 'script_version', FAMILY: 'script_family'}

PTR = {
    DEP: get_dependencie, CVE: get_CVE,
    OID: get_oid, INC: get_include,
    FUC: get_function, CVSS: get_cvss,
    AFFECTED: get_affected, SUMMARY: get_summary,
    INSIGHT: get_insight, XREF: get_xref,
    SOLUTION: get_solution, VNAME: get_name,
    VERSION: get_version, FAMILY: get_family}


def gen_get_file_path(path, suffix=None, deep=True):
    """ Generator for get script file from path, 
    deep means current dir or ergodic all dir and sub dir.
    default is ergodic all"""
    for dirpath, _, filenames in os.walk(path):
        for filename in filenames:
            if suffix is None:
                yield os.path.join(dirpath, filename)
            elif isinstance(suffix, list):
                for s in suffix:
                    if filename.endswith(s):
                        yield os.path.join(dirpath, filename)
            elif isinstance(suffix, str):
                if filename.endswith(suffix):
                    yield os.path.join(dirpath, filename)
        if not deep:
            raise (StopIteration)


def get_complex_path(root, filepath):
    """return subdir and filename"""
    x = filepath.find(root, 0)
    if x == 0:
        sub = filepath[len(root):]
        if sub.startswith(os.path.sep):
            h, t = os.path.split(sub)
            if h.startswith(os.path.sep):
                h = h[1:]
            if not h.endswith(os.path.sep):
                h = h + os.path.sep
            return h, t
    return None, None


def dump_bytearray(buffer):
    count = 1
    show = ''
    for c in buffer:

        if count % 16 == 1:
            print('%04X | ' % (count - 1), end='')

        print('%02X ' % c, end='')
        if 31 < c < 127:
            show += chr(c)
        else:
            show += '.'

        if count % 16 == 0:
            print(' | %s' % show)
            show = ''
        count += 1

    if show != '':
        count %= 16
        count = 16 - count
        while count > 0:
            print('%3c' % ' ', end='')
            count -= 1
        print('    | %s' % show)


def gen_get_standard_line():
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
            str = buffer.decode('ISO-8859-1')
        except UnicodeDecodeError:
            # dump_bytearray(buffer)
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


def get_specify_data_from_file(
        filename, tags=[DEP, CVE, OID, INC, FUC]):
    retData = dict()
    if not os.path.exists(filename):
        print("Error Not find {0}".format(filename))
        return None
    for i in tags:
        retData[i] = set()

    g = gen_get_standard_line()
    g.send(None)
    with open(filename, 'rb') as f:
        for l in f:
            line = g.send(l)
            if not line:
                continue
            for t in tags:
                if TAG[t] in line:
                    _dep = PTR[t](line)
                    for d in _dep:
                        retData[t].add(d)
    return retData
