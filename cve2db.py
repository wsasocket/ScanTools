import os
import sqlite3

import utils

home = os.environ['HOME']


def init_db():
    try:
        os.remove(os.path.join(home, 'cve.db'))
    except FileNotFoundError:
        pass

    try:
        conn = sqlite3.connect(os.path.join(home, 'cve.db'))
        cur = conn.cursor()
        print('Init sqlite3 database')
        Create_SQL = [
            'CREATE TABLE OpenVAS_V9 (ID INTEGER PRIMARY KEY AUTOINCREMENT ,CVE TEXT NOT NULL,NASL TEXT NOT NULL);',
            'CREATE TABLE OpenVAS_V3 (ID INTEGER PRIMARY KEY AUTOINCREMENT ,CVE TEXT NOT NULL,NASL TEXT NOT NULL);']
        cur.execute(Create_SQL[0])
        cur.execute(Create_SQL[1])
        conn.commit()

    finally:
        conn.close()


def build_db():
    conn = sqlite3.connect(os.path.join(home, 'cve.db'))
    cur = conn.cursor()
    file_list = utils.gen_get_file_path(path=os.path.join(home, 'work/plugins'), suffix='nasl')

    for fp in file_list:
        item = utils.get_specify_data_from_file(fp, [utils.CVE])
        if item[utils.CVE]:
            for CVE in list(item[utils.CVE]):
                SQL = 'INSERT INTO OpenVAS_V3(CVE,NASL) VALUES(\"{}\",\"{}\")'.format(CVE, os.path.split(fp)[1])
                print(SQL)
                cur.execute(SQL)
            conn.commit()

    file_list = utils.gen_get_file_path(path=os.path.join(home, 'work/openvas/plugins'), suffix='nasl')

    for fp in file_list:
        item = utils.get_specify_data_from_file(fp, [utils.CVE])
        if item[utils.CVE]:
            for CVE in list(item[utils.CVE]):
                SQL = 'INSERT INTO OpenVAS_V9(CVE,NASL) VALUES(\"{}\",\"{}\")'.format(CVE, os.path.split(fp)[1])
                print(SQL)
                cur.execute(SQL)
            conn.commit()

    conn.close()


def cmp_db():
    conn = sqlite3.connect(os.path.join(home, 'cve.db'))
    cur = conn.cursor()
    SQL = 'SELECT DISTINCT CVE FROM OpenVAS_V3;'
    cur.execute(SQL)
    rs = cur.fetchall()
    SQL = 'SELECT CVE FROM OpenVAS_V9 WHERE CVE=\"{}\";'
    cve_not_found = 0
    for cve in rs:
        cur.execute(SQL.format(cve[0]))
        if not cur.fetchall():
            print('CVE:{} Not Found!'.format(cve[0]))
            cve_not_found += 1
    print('{} CVE not found'.format(cve_not_found))


def main():
    # +---------+----------+
    # | V9      |  V3      |
    # +---------+----------+
    # | 141580  |    21758 |
    # | 33455   |    13631 |
    # +---------+----------+
    # init_db()
    # build_db()
    cmp_db()


if __name__ == '__main__':
    main()
