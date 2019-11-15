import codecs
import re
import socketserver

import utils


class snmp_protocal_simulater(object):

    def __init__(self):
        self._hex = codecs.lookup('hex')
        self.command_id = b'\x00'
        self.session_id = b'\x00'
        self.request = bytearray()

    def parse_command(self, request):
        '''30 29 020101 0406 7075626c6963 a01c 0204 32835b7f 0201 00 0201 00 30 0e 30 0c 0608 2b06010201010100 0500'''
        '''30 29 020101 0406 7075626c6963 a01c 0204 32835b80 0201 00 0201 00 30 0e 30 0c 0608 2b06010201010200 0500'''
        self.request = self._hex.encode(request)[0]
        # print(self.request)
        pattern = rb'0204([a-z0-9]{8})02'
        p = re.compile(pattern)
        r = p.findall(self.request)
        if not r:
            self.session_id = b'\x00'
            self.command_id = -1
            return
        self.session_id = r[0]
        flag = [b'2b06010201010100',
                b'2b06010201010200',
                b'2b06010201010300',
                b'2b06010201010400',
                b'2b06010201010500',
                b'2b06010201010600',
                b'2b06010201010700',
                b'2b060106031001020103010d6e6f74436f6e66696755736572',
                b'2b060106031001020103020d6e6f74436f6e66696755736572',
                b'2b060106031001020103']
        index = 0
        self.command_id = -1
        for index in range(len(flag)):
            if flag[index] in self.request:
                self.command_id = index
                break

        if self.command_id >= 0:
            print('cmd', self.command_id)
            print('session', self.session_id)
        else:
            print('cmd parse:', r)
            self.session_id = b'\x00'
            self.command_id = -1
            utils.dump_bytearray(self._hex.decode(self.request)[0])
            pattern = rb'2b06([0-9a-z]+)0500'
            p = re.compile(pattern)
            r = p.findall(self.request)
            if not r:
                return
            oid = '1.3.6'
            cc = self._hex.decode(r[0])
            print(cc[0])
            for i in cc[0]:
                oid += ".%d" % i
            print('OID=', oid)

    def build_response(self):
        response = [
            b'307902010104067075626c6963a26c020432835b7f020100020100305e305c06082b0601020101010004504c696e7578206c6f63616c686f737420322e362e33322d3433312e656c362e7838365f363420233120534d5020467269204e6f762032322030333a31353a3039205554432032303133207838365f3634',
            b'303302010104067075626c6963a226020432835b800201000201003018301606082b06010201010200060a2b06010401090102020a',
            b'302c02010104067075626c6963a21f020432835b810201000201003011300f06082b06010201010300430302b35d',
            b'306402010104067075626c6963a257020432835b820201000201003049304706082b06010201010400043b526f6f74203c726f6f74406c6f63616c686f73743e2028636f6e666967757265202f6574632f736e6d702f736e6d702e6c6f63616c2e636f6e6629',
            b'303202010104067075626c6963a225020432835b830201000201003017301506082b0601020101050004096c6f63616c686f7374',
            b'304c02010104067075626c6963a23f020432835b840201000201003031302f06082b060102010106000423556e6b6e6f776e202865646974202f6574632f736e6d702f736e6d70642e636f6e6629',
            b'302902010104067075626c6963a21c020432835b85020100020100300e300c06082b060102010107008100',
            # -----------------extend---------------
            b'304802010104067075626c6963a23b02047cac7e84020100020100302d302b06192b060106031001020103020d6e6f74436f6e66696755736572040e6e6f74436f6e66696747726f7570',
            b'303b02010104067075626c6963a22e02047cac7e850201000201003020301e06192b060106031001020104010d6e6f74436f6e66696755736572020104',
            b'304802010104067075626c6963a23b02047cac7e83020100020100302d302b06192b060106031001020103010d6e6f74436f6e66696755736572040e6e6f74436f6e66696747726f7570'
        ]
        line = bytearray()
        if self.command_id == -1 and self.session_id == b'\x00':
            print('parameter error,No response build')
            return None
        cmd = self.command_id
        pattern = rb'0204([0-9a-z]{8})02'
        p = re.compile(pattern)
        s = b'0204' + self.session_id + b'02'
        line = re.sub(p, s, response[cmd])
        return self._hex.decode(line)[0]


class FakeUDPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        buffer = self.request[0]
        socket = self.request[1]
        snmp = snmp_protocal_simulater()
        if buffer:
            print("Receive:")
            utils.dump_bytearray(buffer)

            snmp.parse_command(buffer)
            response = snmp.build_response()
            if response is not None:
                print("Send to :")
                utils.dump_bytearray(response)
                socket.sendto(response, self.client_address)


def main():
    with socketserver.UDPServer(('0.0.0.0', 161), FakeUDPHandler) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
