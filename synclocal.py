import os
import sys
from hashlib import md5
from shutil import copyfile

# openvas update plugins dir
SRC = '/var/lib/openvas/plugins'
# git dir for plugins
DST = '/root/projects/plugins'


def file_cmp(src_file, dst_file):
    """ Return True for there are NO differents between files"""
    md5_1 = md5()
    with open(src_file, 'rb') as f:
        for line in f:
            md5_1.update(line)
    src_hash = md5_1.digest()
    md5_2 = md5()
    with open(dst_file, 'rb') as f:
        for line in f:
            md5_2.update(line)
    dst_hash = md5_2.digest()

    return dst_hash == src_hash


def gen_get_file_path(path, suffix=None):
    """ Generator for get script file from path,return absolute full path"""
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


def get_sub_path(root, fullpathname):
    if not fullpathname.startswith(root):
        return None

    pos = len(root.split('/'))
    f = fullpathname.split('/')
    sub_path = ''
    for i in f[pos:]:
        sub_path = os.path.join(sub_path, i)
    return sub_path


if __name__ == '__main__':
    bCommit = False
    if len(sys.argv) == 2:
        if sys.argv[1] == 'commit':
            bCommit = True

    # find deleted file in dst dir
    file_list = gen_get_file_path(DST, ['inc', 'nasl'])
    for fp in file_list:
        fullpath, scriptname = os.path.split(fp)
        sub_path = get_sub_path(DST, fullpath)
        fpp = os.path.join(SRC, sub_path)
        fpp = os.path.join(fpp, scriptname)
        if not os.path.exists(fpp):
            if bCommit:
                try:
                    os.remove(fp)
                except Exception as e:
                    print('\x1B[1;37;41m %s \x1B[0m' % e)
                    exit(1)
                print('\x1B[1;31;40m[-]\x1B[0m %s \x1B[1;37;42m OK \x1B[0m' % os.path.join(sub_path, scriptname))
            else:
                print('deleted:    %s' % os.path.join(sub_path, scriptname))

    # copy new file and modified file to dst dir
    file_list = gen_get_file_path(SRC, ['inc', 'nasl'])

    for fp in file_list:
        fullpath, scriptname = os.path.split(fp)
        sub_path = get_sub_path(SRC, fullpath)
        fpp = os.path.join(DST, sub_path)
        fpp = os.path.join(fpp, scriptname)

        if not os.path.isfile(fpp):
            #  copy new file
            try:
                fpath, fname = os.path.split(fpp)  # 分离文件名和路径
                if not os.path.exists(fpath):
                    os.makedirs(fpath)
                if bCommit:
                    copyfile(fp, fpp)
                    print('\x1B[1;32;40m[+]\x1B[0m %s \x1B[1;37;42m OK \x1B[0m' % os.path.join(sub_path, scriptname))
                else:
                    print('new file:    %s ' % os.path.join(sub_path, scriptname))
            except Exception as e:
                print('\x1B[5;37;41m %s \x1B[0m' % e)
                exit(1)
            continue

        if not file_cmp(fp, fpp):
            # copy modify file
            try:
                fpath, fname = os.path.split(fpp)  # 分离文件名和路径
                if not os.path.exists(fpath):
                    os.makedirs(fpath)
                if bCommit:
                    copyfile(fp, fpp)
                    print('\x1B[1;35;40m[=]\x1B[0m %s \x1B[1;37;42m OK \x1B[0m' % os.path.join(sub_path, scriptname))
                else:
                    print('modified:    %s ' % os.path.join(sub_path, scriptname))
            except Exception as e:
                print('\x1B[5;37;41m %s \x1B[0m' % e)
                exit(1)
