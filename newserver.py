import json
import os
import re
import socketserver
import sys
import threading
from urllib.parse import unquote

import utils


# 最后修改2018-04-11
# 最后修改2018-04-12
#   增加TCP链接只需要获取Banner类型服务器，与其他的区别在于，客户端只要链接，服务器就返回Banner
#   其他需要等待客户端的请求后才给予响应
# 最后修改2018-04-18
#   将TCP和UDP的数据全部改进成二进制格式，提高了通用性
#   对请求的方式进行了判断，也完成了相应的函数
# 最后修改2018-04-25
#   修改返回的头信息及格式，保证识别的正确性
#   合并了相同的处理方法，使程序更加简洁
#   在json文件中可以使用正则表达式对请求进行识别
#   在json文件中使用$$作为可识别可替换的变量
# 最后修改2018-05-08
#   修改了解析参数全局化的问题
#   增加了对于参数中含有正则的识别匹配问题
# 最后修改2018-05-09
#   对TCP方式下的问/答进行了完整的匹配


class Cfg(object):
    _instance_lock = threading.Lock()
    __hasLoad = False
    __data = dict()
    __server_id = -1
    __default_header = """HTTP/1.1 {code} OK\r\n{tag}\r\nContent-Type: text/html; charset=utf-8\r\nConnection: keep-alive\r\n\r\n{content}"""
    __default_404 = """HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\nConnection: keep-alive\r\n{tag}\r\n\r\n\
    <html><title>{name}</title><body><h2>404 : Not Found</h2><br><h4>You are requesting a page that does not exist!</h4></body></html>"""

    def __init__(self, json_path='./fakeserver.json'):
        if not self.__hasLoad:
            self.load_cfg(json_path)
            self.__hasLoad = True

    def __new__(cls, *args, **kwargs):
        if not hasattr(Cfg, "_instance"):
            with Cfg._instance_lock:
                if not hasattr(Cfg, "_instance"):
                    Cfg._instance = object.__new__(cls)
        return Cfg._instance

    def load_cfg(self, path):
        if not self.__hasLoad:
            try:
                with open(path, 'r') as fp:
                    self.__data = json.load(fp)
                self.__hasLoad = True
            except json.decoder.JSONDecodeError as e:
                print('Load json Fail because:\x1B[5;37;40m {}\x1B[0m '.format(
                    e))
                exit(0)
            except FileNotFoundError as e:
                print(
                    'Can Not Find json File:\x1B[5;37;40m {}\x1B[0m at current directory'.
                        format(path))
                exit(0)
            current_path, _ = os.path.split(path)
            # 增加其他json配置文件，id可以随便写，会统一编号
            # 主要是防止配置文件过大，不方便修改
            other_json_file = utils.gen_get_file_path(
                current_path, suffix='json', deep=False)
            for json_file in other_json_file:
                if json_file == path:
                    continue
                try:
                    with open(json_file, 'r') as fp:
                        json_data = json.load(fp)

                    max_id = 0
                    for i in self.__data['Servers']:
                        max_id = i['id'] if max_id < i['id'] else max_id

                    max_id += 1
                    for item in json_data['Servers']:
                        item['id'] = max_id
                        self.__data['Servers'].append(item)
                        max_id += 1
                    self.__hasLoad = True
                except json.decoder.JSONDecodeError as e:
                    print('Load json Fail because:\x1B[5;37;40m {}\x1B[0m '.
                          format(e))
                    continue

    def set_server_id(self, index):
        if self.__server_id == -1 and self.__hasLoad:
            max_value = len(self.__data['Servers'])
            if index < max_value and index >= 0:
                self.__server_id = index
        else:
            raise (ValueError)

    def get_server_port(self):
        if self.__hasLoad:
            for i in self.__data['Servers']:
                if i['id'] == self.__server_id:
                    return i['PORT']
        return None

    def get_server_type(self):
        if self.__hasLoad:
            for i in self.__data['Servers']:
                if i['id'] == self.__server_id:
                    return i['Type']
        return None

    def get_server_name(self):
        if self.__hasLoad:
            for i in self.__data['Servers']:
                if i['id'] == self.__server_id:
                    return i['Name']
        return None

    def describe(self):
        if self.__hasLoad:
            for i in self.__data['Servers']:
                print(i['id'], i['Type'], '\t', i['Name'])
        else:
            print('Load config first!')

    def rexp_check(self, pattern, value):
        if pattern is None:
            return None
            # 正常URL
        if pattern.startswith('/'):
            if pattern == value:
                return value
            # 正则表达式
        if pattern.startswith('r'):
            p = re.compile(pattern[1:])
            r = p.findall(value)
            if r:
                return r
            else:
                return None
        return None

    def getHttpResponseHeader(self):
        if self.__hasLoad:
            for i in self.__data['Servers']:
                if i['id'] == self.__server_id and i['Type'] == 'HDR':
                    return self.__default_404.format(
                        tag=i['Tag'], name=i['Name'])
        return None

    def getHttpResponse(self, url, method):
        if self.__hasLoad:
            for i in self.__data['Servers']:
                if i['id'] == self.__server_id and i['Type'] == 'URL':
                    for u in i['URLS']:
                        if u['Method'] != method:
                            continue
                        tmp_url = self.rexp_check(u['URL'], url)
                        if tmp_url:
                            print(
                                "\x1B[5;33;40mHint :{}\x1B[0m".format(tmp_url))
                            return self.__default_header.format(
                                tag=i['Tag'],
                                content=u['Content'],
                                code=u['Code'] if 'Code' in u.keys() else 200)
                    return self.__default_404.format(
                        tag=i['Tag'], name=i['Name'])

    def ask_data_match(self, pattern, data):
        if pattern == "":
            return True
        array = lambda ss: bytearray([int(x.strip(), base=16) for x in ss.split(',') if x != ''])

        for i in pattern.split('|'):
            pice = i.split(':')
            offset = int(pice[0], base=16)
            match_pattern = array(pice[1])
            count = 0
            for p in match_pattern:
                try:
                    if p != data[offset + count]:
                        return False
                    count += 1
                except IndexError:
                    return False
        return True

    def getRawResponse(self, ask):
        if self.__hasLoad:
            array = lambda ss: bytearray([int(x.strip(), base=16) for x in ss.split(',') if x != ''])
            for i in self.__data['Servers']:
                if i['id'] == self.__server_id and (i['Type'] == 'TCP'
                                                    or i['Type'] == 'UDP'):
                    for d in i['DATA']:
                        if self.ask_data_match(d['Ask'], ask):
                            return array(d['Reply'])

    def getBanner(self):
        if self.__hasLoad:
            for i in self.__data['Servers']:
                if i['id'] == self.__server_id and i['Type'] == 'TBA':
                    for d in i['DATA']:
                        return d['Reply']


class StaticHttpHandler(socketserver.BaseRequestHandler):
    configure = Cfg()
    param = dict()

    def parseHeader(self, binHeader):
        try:
            strHeader = binHeader.decode()
        except UnicodeDecodeError:
            return None, None, None
        method = str()
        url = str()

        pattern_url = r'(GET|PUT|POST) ([^ \r\n?]*)'
        p = re.compile(pattern_url)
        l = p.findall(strHeader)
        if l:
            if len(l[0]) >= 2:
                method = l[0][0]
                url = l[0][1]
            else:
                return None, None, None

        query = dict()

        pattern = r'\?([\w\d_=&#%-]+) '
        p = re.compile(pattern)
        l = p.findall(strHeader)
        try:
            if l:
                for i in unquote(l[0]).split('&'):
                    k, v = i.split('=')
                    query[k] = v
        except ValueError:
            pass

        pattern = r'\r\n\r\n([\w\d_=&#\[\]]+)'
        p = re.compile(pattern)
        l = p.findall(strHeader)
        try:
            if l:
                for i in unquote(l[0]).split('&'):
                    k, v = i.split('=')
                    query[k] = v
        except ValueError:
            pass

        return method, url, query

    def replace_result(self, res, param):
        pattern = r'\$([\w\d_#\[\]]+)\$'
        p = re.compile(pattern)
        l = p.findall(res)
        if not l:
            return res
        for i in l:
            if i not in param.keys():
                return res
        for i in l:
            tmp = '$' + i + '$'
            res = res.replace(tmp, param[i])
        return res

    def handle(self):
        method = str()
        url = str()

        self.data = self.request.recv(1024).strip()
        if self.configure.get_server_type() == 'HDR':
            res = self.configure.getHttpResponseHeader()
            print("RESPONSE:{}".format(res))
        elif self.configure.get_server_type() == 'URL':
            method, url, localparam = self.parseHeader(self.data)
            if localparam is not None:
                for i in localparam.keys():
                    self.param[i] = localparam[i]
            if method and url:
                res = self.replace_result(
                    self.configure.getHttpResponse(url, method), self.param)
                if '404' not in res:
                    print("\x1B[0;32;40m")
                    print('Method : {}'.format(method))
                    print('URL : {}'.format(url))
                    print('Parameter : {}'.format(self.param))
                    print("\x1B[0m")
                    print("\x1B[0;36;40mResponse:")
                    print(res)
                    print("\x1B[0m")
            else:
                print('Unknow request')
                return

        else:
            print("Server Type Error")
            return

        self.request.sendall(res.encode())


class FakeTCPHandler(socketserver.BaseRequestHandler):
    configure = Cfg()

    def str2bin(self, response):
        res_len = len(response)
        if res_len % 2 != 0:
            return None
        l = bytearray()
        for i in range(2, res_len, 2):
            l.append(int(response[i:i + 2], base=16))
        return l

    def handle(self):
        if self.configure.get_server_type() == 'TBA':  # TCP Banner
            conn = self.request
            conn.sendall(self.configure.getBanner().encode())
        else:
            self.data = self.request.recv(1024).strip()
            print("Receive:")
            utils.dump_bytearray(self.data)
            res = self.configure.getRawResponse(self.data)
            if res is not None:
                print("Response:")
                utils.dump_bytearray(res)
                self.request.sendall(res)


class FakeUDPHandler(socketserver.BaseRequestHandler):
    configure = Cfg()

    def handle(self):
        buffer = self.request[0]
        socket = self.request[1]
        res = self.configure.getRawResponse(buffer)
        if res is not None:
            utils.dump_bytearray(res)
            socket.sendto(res, self.client_address)


def main():
    ip = '0.0.0.0'
    fake_id = None
    if len(sys.argv) == 2:
        ip = sys.argv[1]
    if len(sys.argv) == 3:
        ip = sys.argv[1]
        fake_id = sys.argv[2]

    cfg = Cfg()
    if fake_id is None:
        print(
            "Fake Server for Debug Openvas Scripts<version 0.4 build 20180428>"
        )
        cfg.describe()
        print("Select which server do you need:", end='')
        fake_id = input()
    cfg.set_server_id(int(fake_id))
    print('Running {} at port:{}'.format(cfg.get_server_name(),
                                         cfg.get_server_port()))

    if cfg.get_server_type() == 'HDR' or cfg.get_server_type() == 'URL':
        with socketserver.TCPServer((ip, cfg.get_server_port()),
                                    StaticHttpHandler) as server:
            server.serve_forever()

    if cfg.get_server_type() == 'TCP' or cfg.get_server_type() == 'TBA':
        with socketserver.TCPServer((ip, cfg.get_server_port()),
                                    FakeTCPHandler) as server:
            server.serve_forever()

    if cfg.get_server_type() == 'UDP':
        with socketserver.UDPServer((ip, cfg.get_server_port()),
                                    FakeUDPHandler) as server:
            server.serve_forever()


if __name__ == '__main__':
    main()
