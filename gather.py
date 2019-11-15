#!/usr/bin/python3
# http://cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-201804-315

import json
import os

import utils
from utils.cvss import cvss_base_calc
from utils.trans import GoogleTranslate

SRC = os.path.join(os.environ['HOME'], 'updateperweek')

payload_templete = {
    'action':
        'UpdatePckManager',
    'method':
        'chgPluginInfo',
    'data': [{
        'oid': '',
        'name': '',
        'ename': '',
        'version': '',
        'family': '25',
        'category': '4',
        'riskLevel': '',
        'scriptName': '',
        'description': '',
        'resolvent': '',
        'cve': '',
        'cnvd': '',
        'cnnvd': '',
        'cncve': '',
        'bugtraq': '',
        'av': '',
        'ac': '',
        'au': '',
        'c': '',
        'i': '',
        'a': '',
        'baseScore': '',
        'port': '',
        'service': '',
        'dependencies': '',
        'pos': '0',
        'updater': 'peim'
    }],
    'type':
        'rpc',
    'tid':
        30
}


def main():
    work_list = set()
    nasl_list = utils.gen_get_file_path(SRC, suffix='.nasl')
    output = open('result.txt', 'w')
    count = 0
    for fp in nasl_list:
        work_list.add(os.path.split(fp)[1])

    lo = 0
    count = len(work_list)
    print(count)
    nasl_list = utils.gen_get_file_path(SRC, suffix='.nasl')
    # testlist=['/Users/james/work/updateperweek/secpod_asterisk_detect.nasl']
    High_risk = dict()
    for fp in nasl_list:
        fn = os.path.split(fp)[1]
        if fn in work_list:
            work_list.remove(fn)
            # print(fn,len(work_list))
        else:
            continue

        lo += 1
        print('[%03d/%03d] %s' % (lo, count, fp))
        data = utils.get_specify_data_from_file(
            fp,
            tags=[
                utils.CVE, utils.AFFECTED, utils.SUMMARY, utils.INSIGHT,
                utils.XREF, utils.DEP, utils.CVSS, utils.SOLUTION, utils.VNAME,
                utils.OID, utils.VERSION, utils.FAMILY
            ])

        deps = list(data[utils.DEP]) if data[utils.DEP] is not None else None
        cve = list(data[utils.CVE]) if data[utils.CVE] is not None else None
        affected = list(
            data[utils.AFFECTED]) if data[utils.AFFECTED] is not None else None
        summary = list(
            data[utils.SUMMARY]) if data[utils.SUMMARY] is not None else None
        insight = list(
            data[utils.INSIGHT]) if len(data[utils.INSIGHT]) > 0 else None
        xref = list(data[utils.XREF]) if len(data[utils.XREF]) > 0 else None
        solution = list(
            data[utils.SOLUTION]) if len(data[utils.SOLUTION]) > 0 else None
        cvss = list(data[utils.CVSS]) if data[utils.CVSS] is not None else None
        name = list(
            data[utils.VNAME]) if data[utils.VNAME] is not None else None
        oid = list(data[utils.OID]) if data[utils.OID] is not None else None
        version = list(
            data[utils.VERSION]) if data[utils.VERSION] is not None else None
        family = list(data[utils.FAMILY]) if data[utils.FAMILY] is not None else None

        payload = payload_templete
        payload['data'][0]['scriptName'] = os.path.split(fp)[1]
        try:
            payload['data'][0]['oid'] = oid[0]
        except IndexError as e:
            print(e, fp)
            exit(0)
        payload['data'][0]['version'] = version[0]
        if name:
            if len(name[0]) > 10:
                payload['data'][0]['ename'] = name[0]
                payload['data'][0]['name'] = GoogleTranslate(name[0])
            else:
                payload['data'][0]['ename'] = name[0]
                payload['data'][0]['name'] = name[0]
        else:
            print(os.path.split(fp)[1], 'name field is empty')
            exit(0)
        score = cvss_base_calc(cvss[0])
        if score == -1:
            print(os.path.split(fp)[1], 'CVSS Score Calculate Fail')
            exit(0)

        payload['data'][0]['baseScore'] = str(score)
        risklevel = '信息'
        if score == 10.0:
            risklevel = '紧急'
        if 7.0 <= score < 10.0:
            risklevel = '高级'
        if 4.0 <= score < 7.0:
            risklevel = '中级'
        if 0.0 < score < 4.0:
            risklevel = '低级'
        payload['data'][0]['riskLevel'] = risklevel
        for item in cvss[0].split('/'):
            k, v = item.split(':')
            payload['data'][0][k.lower()] = v

        tmp = str()
        if summary:
            tmp += summary[0]
            tmp += '\n'
        if affected:
            tmp += affected[0]
            tmp += '\n'
        if insight:
            tmp += insight[0]
            tmp += '\n'
        if xref:
            tmp += '\n'
            tmp += xref[0]
        if tmp == '':
            print(os.path.split(fp)[1], 'Description Collect Fail')
            exit(0)

        payload['data'][0]['description'] = GoogleTranslate(tmp)
        if payload['data'][0]['description'] == None:
            print(fp, 'Description Translate Fail')
            exit(0)
        tmp = ''
        if not solution:
            tmp = '无'
        else:
            tmp = GoogleTranslate(solution[0])
        if tmp == '':
            print(fp, 'Solution Collect Fail')
        payload['data'][0]['resolvent'] = tmp
        tmp = ''
        if cve:
            for c in cve:
                tmp += c
                tmp += ','
        if tmp.endswith(','):
            payload['data'][0]['cve'] = tmp[:-1]
        else:
            payload['data'][0]['cve'] = ''
        if score == 10.0 and cve:
            High_risk[os.path.split(fp)[1]] = payload['data'][0]['cve']

        if 'detect' not in os.path.split(
                fp)[1] and payload['data'][0]['cve'] == '':
            print(os.path.split(fp)[1], "NOT FOUND CVE")
        tmp = ''
        if deps:
            for d in deps:
                tmp += d
                tmp += ','
        if tmp.endswith(','):
            payload['data'][0]['dependencies'] = tmp[:-1]
        else:
            payload['data'][0]['dependencies'] = ''
        if payload['data'][0]['dependencies'] == '':
            print(os.path.split(fp)[1], "NOT FOUND dependencies")

        if family:
            if 'Windows' in family[0]:
                payload['data'][0]['family'] = 27
            if 'remotely' in family[0]:
                payload['data'][0]['family'] = 11
            if 'General' in family[0]:
                payload['data'][0]['family'] = 12
            if 'SNMP' in family[0]:
                payload['data'][0]['family'] = 20
            if 'Service' in family[0]:
                payload['data'][0]['family'] = 21
            if 'General' in family[0]:
                payload['data'][0]['family'] = 12
            if 'Malware' in family[0]:
                payload['data'][0]['family'] = 13
            if 'Accounts' in family[0]:
                payload['data'][0]['family'] = 6

            else:
                print(family[0])

        output.write(json.dumps(payload))
        output.write('\n')
        continue
    output.close()
    print('-----------------------------------------')
    for k in High_risk.keys():
        print(k, High_risk[k])


if __name__ == '__main__':
    main()
