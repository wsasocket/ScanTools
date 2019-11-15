import os
import re

import utils

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'
SRC = os.path.join(os.environ['HOME'], 'tmp')
DST = os.path.join(os.environ['HOME'], 'updateperweek')
OLD_PLUGINS = os.path.join(os.environ['HOME'], 'work/plugins/plugins')
OMIT_LIST = [
    'ssh_func.inc', 'revisions-lib.inc', 'gather-package-list.nasl',
    'policy_functions.inc'
]
pattern_a_v = 'get_app_version_and_location'
pattern_m = 'security_message'
pattern_log = 'log_message'
__specify_func__ = [pattern_a_v, pattern_m, pattern_log]
job_dic = dict()
dep_list = list()


def modify_version(src, dst):
    fout = open(dst, 'w')
    with open(src, 'r') as fp:
        for line in fp:
            if 'script_version' in line:
                print(line)
                if 'Revision' not in line:
                    # process xxxx-xx-xxTyy:yy:yy+YYYY style
                    v = re.search('([\d:\-T\+]+)', line)
                    if v:
                        # print(v.group(1))
                        line = '  script_version("$Revision: {} $");\n'.format(v.group(1))
            fout.write(line)
    fout.close()


def grep_first(nasl):
    '''
    find which nasl file should be ommitted
    '''
    # 不再依赖之前的文件分类清单，只要不是SSH/package都处理
    data = utils.get_specify_data_from_file(nasl, tags=[utils.INC, utils.DEP])

    funcs = list(data[utils.INC]) if data[utils.INC] is not None else None
    deps = list(data[utils.DEP]) if data[utils.DEP] is not None else None
    total = list()
    if funcs:
        total.extend(funcs)
    if deps:
        total.extend(deps)
    # print(total)
    # even file do not need modified,but detected file should be copy!
    path, name = os.path.split(nasl)
    for item in OMIT_LIST:
        if item in total:
            print(WARNING, 'Omitted because of:', item, ENDC)
            if os.path.samefile(path, SRC):
                # detect file
                dep_list.append(name)
                print(FAIL, 'Detect File should be Ommited because of:', dep_list, ENDC)
            return None
    if os.path.samefile(path, SRC):
        # shutil.copy(nasl,os.path.join(DST,name))
        modify_version(nasl, os.path.join(DST, name))
        print(WARNING, 'Detect File copied', ENDC)
    return nasl


def grep_second(nasl):
    flag = False
    data = utils.get_specify_data_from_file(nasl, tags=[utils.DEP])
    deps = list(data[utils.DEP]) if data[utils.DEP] is not None else None
    for d in deps:
        if d in dep_list:
            print(FAIL, 'Omitted Because of dependence file is ommitted:', d, ENDC)
            return flag

    count = 0
    with open(nasl, 'r') as fp:
        for line in fp:
            count += 1
            if pattern_a_v in line:
                # print(WARNING, 'Replace get_app_version_and_location', ENDC)
                job_dic[nasl].append(count)
                flag = True
            if pattern_m in line:
                # print(WARNING, 'Replace security_message', ENDC)
                job_dic[nasl].append(count)
                flag = True
            if pattern_log in line:
                # print(WARNING, 'Replace log_message', ENDC)
                job_dic[nasl].append(count)
                flag = True
    return flag


def replace_av(nasl):
    g = utils.gen_get_standard_line()
    g.send(None)
    should_be_replace = {
        pattern_a_v: list(),
        pattern_m: list(),
        pattern_log: list()
    }
    # first term to collect lines to be replace info
    with open(nasl, 'rb') as fp:
        for l in fp:
            if not l:
                break
            line = g.send(l)
            if not line:
                continue
            else:
                for func in __specify_func__:
                    if func in line:
                        should_be_replace[func].append(line)
    # parse get_version_and_localtion
    pattern_parameter = r'(([\w\d_]+)\s?=\s?get_app_version_and_location\s?\((.*?)\))'
    re_parameter = re.compile(pattern_parameter)
    parameter = ''
    all_line = ''
    var_info = ''

    # get info from collections
    # suppose only one get_app_version_and_location() function i r'(([\w\d_]+)\s?=\s?get_app_version_and_location\s?\((.*?)\))'n one nasl
    for line in should_be_replace[pattern_a_v]:
        try:
            parameter = re_parameter.findall(line)
            all_line = parameter[0][0]
            var_info = parameter[0][1]
            # print('var：',var_info)
            # print('line:',all_line)
            paramaters = [p.strip() for p in parameter[0][2].split(',') if 'exit_no_version' not in p]
            # print('para',paramaters)
        except Exception as e:
            print(e)
            return
    # now we have get return value of func and parameter list of func
    pattern_ver = r'(([\w\d_]+)\s{0,5}=\s{0,5}' + var_info + r'\[\s?[\'|\"]version[\'|\"]\s?\]\s?;)'
    pattern_path = r'(([\w\d_]+)\s{0,5}=\s{0,5}' + var_info + r'\[\s?[\'|\"]location[\'|\"]\s?\]\s?;)'

    p_v = re.compile(pattern_ver)
    p_p = re.compile(pattern_path)

    g = utils.gen_get_standard_line()
    g.send(None)
    # find var name
    version = str()
    location = str()
    version_line = str()
    location_line = str()
    # Second term to get version and location var name
    with open(nasl, 'rb') as fp:
        for l in fp:
            if not l:
                break
            line = g.send(l)
            if not line:
                continue
            else:
                if var_info in line:
                    # print('filter var:',line)
                    r = p_v.findall(line)
                    # print('find ver:',r)
                    if r:
                        version = r[0][1]
                        version_line = r[0][0]
                    r = p_p.findall(line)
                    # print('find loc:',r)
                    if r:
                        location = r[0][1]
                        location_line = r[0][0]
    # if version:
    #     print(version)
    # if location:
    #     print(location)
    # now version and location parameter var_info is ready
    target_file = os.path.join(DST, os.path.split(nasl)[1])
    out = open(target_file, 'w')
    count = 0
    # Third term to replace all
    with open(nasl, 'r') as fp:
        for line in fp:
            count += 1
            # line =line.strip()
            if 'script_version' in line:
                if 'Revision' not in line:
                    # process xxxx-xx-xxTyy:yy:yy+YYYY style
                    v = re.search('([\d:\-T\+]+)', line)
                    if v:
                        line = '  script_version("$Revision: {} $");\n'.format(v.group(1))
            if 'security_message' in line:
                line = line.replace('security_message', 'security_hole')
                if count in job_dic[nasl]:
                    job_dic[nasl].remove(count)
                    print(OKBLUE, 'Replace security_message OK', ENDC)
                else:
                    print('Error')
            if 'log_message' in line:
                line = line.replace('log_message', 'security_hole')
                if count in job_dic[nasl]:
                    job_dic[nasl].remove(count)
                    print(OKBLUE, 'Replace log_message OK', ENDC)
                else:
                    print('Error')
            # replace  get_app_version_and_location       
            if 'get_app_version_and_location' in line:
                if count in job_dic[nasl]:
                    job_dic[nasl].remove(count)
                    print(OKBLUE, 'Replace get_app_version_and_location OK', ENDC)

                new_line = version + ' = get_app_version('
                for i in paramaters:
                    new_line += i
                    new_line += ','
                new_line = new_line[:-1]
                new_line += ')'

                line = line.replace(all_line, new_line)

            if p_v.findall(line):
                print(OKBLUE, '\tvariable version found', ENDC)
                line = line.replace(version_line, '\n')
            if p_p.findall(line):
                print(OKBLUE, '\tvariable location found', ENDC)
                line = line.replace(location_line, location + ' = \'/\';\n')
            out.write(line)
    if len(job_dic[nasl]) != 0:
        print(FAIL, job_dic[nasl], ENDC)
    else:
        job_dic.pop(nasl)
    out.close()


def main():
    for nasl in utils.gen_get_file_path(SRC, suffix='nasl'):
        print(
            '\n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\nProcess:',
            nasl)
        nasl = grep_first(nasl)
        if nasl:
            job_dic[nasl] = list()
            if grep_second(nasl):
                replace_av(nasl)


if __name__ == '__main__':
    main()
