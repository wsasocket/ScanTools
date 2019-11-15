import sys

import requests

# Tks for  https://blog.csdn.net/yingshukun/article/details/53470424
# pip3 install requests
# pip3 install PyExecJS
try:
    import execjs
except:
    sys.path.append('/usr/local/lib/python3.6/site-packages')
finally:
    import execjs


class Py4Js():
    def __init__(self):
        self.ctx = execjs.compile(""" 
        function TL(a) { 
        var k = ""; 
        var b = 406644; 
        var b1 = 3293161072; 
         
        var jd = "."; 
        var $b = "+-a^+6"; 
        var Zb = "+-3^+b+-f"; 
     
        for (var e = [], f = 0, g = 0; g < a.length; g++) { 
            var m = a.charCodeAt(g); 
            128 > m ? e[f++] = m : (2048 > m ? e[f++] = m >> 6 | 192 : (55296 == (m & 64512) && g + 1 < a.length && 56320 == (a.charCodeAt(g + 1) & 64512) ? (m = 65536 + ((m & 1023) << 10) + (a.charCodeAt(++g) & 1023), 
            e[f++] = m >> 18 | 240, 
            e[f++] = m >> 12 & 63 | 128) : e[f++] = m >> 12 | 224, 
            e[f++] = m >> 6 & 63 | 128), 
            e[f++] = m & 63 | 128) 
        } 
        a = b; 
        for (f = 0; f < e.length; f++) a += e[f], 
        a = RL(a, $b); 
        a = RL(a, Zb); 
        a ^= b1 || 0; 
        0 > a && (a = (a & 2147483647) + 2147483648); 
        a %= 1E6; 
        return a.toString() + jd + (a ^ b) 
    }; 
     
    function RL(a, b) { 
        var t = "a"; 
        var Yb = "+"; 
        for (var c = 0; c < b.length - 2; c += 3) { 
            var d = b.charAt(c + 2), 
            d = d >= t ? d.charCodeAt(0) - 87 : Number(d), 
            d = b.charAt(c + 1) == Yb ? a >>> d: a << d; 
            a = b.charAt(c) == Yb ? a + d & 4294967295 : a ^ d 
        } 
        return a 
    } 
    """)

    def getTk(self, text):
        return self.ctx.call("TL", text)


def translate(tk, content):
    if len(content) > 4891:
        print("翻译的长度超过限制！！！")
        return None

    param = {'tk': tk, 'q': content}

    result = requests.get(
        """http://translate.google.cn/translate_a/single?client=t&sl=en 
        &tl=zh-CN&hl=zh-CN&dt=at&dt=bd&dt=ex&dt=ld&dt=md&dt=qca&dt=rw&dt=rm&dt=ss 
        &dt=t&ie=UTF-8&oe=UTF-8&clearbtn=1&otf=1&pc=1&srcrom=0&ssel=0&tsel=0&kc=2""",
        params=param)

    # 返回的结果为Json，解析为一个嵌套列表
    text = result.json()
    part = len(text[0])
    res = str()
    for index in range(part - 1):
        res += text[0][index][0]
    return res


def GoogleTranslate(content):
    js = Py4Js()

    # content = """In Apache httpd 2.4.0 to 2.4.29, the expression specified in\
    #  <FilesMatch> could match '$' to a newline character in a malicious filename, \
    #  rather than matching only the end of the filename. This could be exploited \
    #  in environments where uploads of some files are are externally blocked, \
    #  but only by matching the trailing portion of the filename."""
    #     content = 'Run Windows update and update the malware\
    #   protection engine to the latest version available. Typically, no action is\
    #   required as the built-in mechanism for the automatic detection and deployment\
    #   of updates will apply the update itself.'
    tk = js.getTk(content)
    return translate(tk, content)
