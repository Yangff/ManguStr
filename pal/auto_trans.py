import json

j = json.load(open("TRANS.json", "r"))

import re

r = re.compile(r'[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uff66-\uff9f「]')

import translators as ts
import time
skip = 0

cached = {
}

post = {
}


cnt = 0

import urllib
import random
import hashlib
from urllib.request import urlopen

def youdao_translate(text,fromLang='ja',toLang='zh-CHS'):
    appKey = '{your app key here}'
    secretKey = '{your secret here}'
 
    myurl = 'http://openapi.youdao.com/api'
    q = text
    salt = random.randint(1, 65536)
 
    sign = appKey+q+str(salt)+secretKey
    m1 = hashlib.md5()
    m1.update(sign.encode('utf-8'))
    sign = m1.hexdigest()
    myurl = myurl+'?appKey='+appKey+'&q='+urllib.parse.quote(q)+'&from='+fromLang+'&to='+toLang+'&salt='+str(salt)+'&sign='+sign
 
    httpClient = urlopen(myurl)
    try:
        response = json.loads(httpClient.read().decode())
        return response["translation"]
    finally:
        if httpClient:
            httpClient.close()


def save(j):
    extract = open("TRANS.json", "w")
    extract.write(json.dumps(j,ensure_ascii=False,indent=2))
    extract.close()

for i in j:
    if r.search(i["context"]):
        if not ("trans" in i) or (i["context"].find('」') != -1 and i["trans"].find("”") == -1):
            if (i["context"] in cached):
                i["trans"] = cached[i["context"]]
            else:
                if i['context'].find('・') != -1:
                    def xtrans(s):
                        if not (s in cached):
                            cached[s] = youdao_translate(s)[0]
                        return cached[s]
                    i["trans"] = '・'.join([xtrans(x) for x in i['context'].split('・')])
                else:
                    try:
                        i["trans"] = youdao_translate(i["context"])[0]
                        if not i["trans"] or (i["context"].find('」') != -1 and i["trans"].find("”") == -1):
                            i["trans"] = ts.baidu(i["context"], from_language='jp', to_language='zh')
                    except:
                        i["trans"] = ts.baidu(i["context"], from_language='jp', to_language='zh')
                for x,y in post.items():
                    i["trans"] = i["trans"].replace(x,y)
            cached[i["context"]] = i["trans"]
            print("{0} to {1}".format(i["context"], i["trans"]))
            cnt = cnt + 1
            if cnt == 100:
                cnt = 0
                save(j)
            time.sleep(0.01)
        else:
            if isinstance(i["trans"], list):
                print("fix list")
                i["trans"] = i["trans"][0]
            cached[i["context"]] = i["trans"]
    else:
        i["trans"] = i["context"]
            

save(j)