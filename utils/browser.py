#!/usr/bin/python3

import re

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException


class browser(object):
    def __init__(self):
        pattern = "(CNNVD-[\d]+-[\d]+)"
        self.re_CNNVD = re.compile(pattern)
        option = webdriver.ChromeOptions()
        option.add_argument('headless')
        self.driver = webdriver.Chrome(options=option)

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
