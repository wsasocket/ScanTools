#!/usr/bin/python3
import re
import time

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException


class browser(object):

    def __init__(self):
        pattern = "(CNNVD-[\d]+-[\d]+)"
        self.re_CNNVD = re.compile(pattern)
        self.driver = webdriver.Chrome(port=9515)

    def close(self):
        self.driver.quit()

    def get_CNNVD(self, cve):

        self.driver.get('http://cnnvd.org.cn/web/vulnerability/querylist.tag')
        try:
            item = self.driver.find_element_by_id('qcvCnnvdid')
        except NoSuchElementException as e:
            print('cnnvd.org.cn changed!!!')
            exit(0)
        self.driver.find_element_by_id('qcvCnnvdid').click()
        self.driver.find_element_by_id('qcvCnnvdid').send_keys(cve)

        self.driver.find_element_by_class_name('bd_b').click()
        try:
            item = self.driver.find_element_by_id('vulner_0')
        except NoSuchElementException as e:
            # driver.quit()
            return None
        if item:
            # driver.quit()
            return self.re_CNNVD.findall(item.text)[0]


bo = browser()
for i in ['CVE-2018-9158', 'CVE-2018-1141', 'CVE-2018-1302', 'CVE-2018-1301', 'CVE-2018-1283']:
    time.sleep(5)
    print(i, bo.get_CNNVD(i))
# bo.close()
# exit(1)
