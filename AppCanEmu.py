#!/usr/bin/env python3
#和AppCan.py的区别就是，AppCanEmu.py文件实现了Android本地模拟器来加载so文件进行加解密，AppCan.py文件实现了加解密算法来进行解密
import logging
import sys
import posixpath
import shutil
import re

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

import os
from libs.modules.BaseModule import BaseModule
from libs.ExAndroidNativeEmu.androidemu.java.classes.array import Array
from libs.ExAndroidNativeEmu.androidemu.java.classes.string import String
from libs.ExAndroidNativeEmu.androidemu.emulator import Emulator
from libs.ExAndroidNativeEmu.androidemu.java.java_class_def import JavaClassDef
from libs.ExAndroidNativeEmu.androidemu.java.java_method_def import java_method_def

logging.basicConfig(stream=sys.stdout, format="%(levelname)s: %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

'''
Reference:
1) http://www.appcan.cn/
'''

class desutility(metaclass=JavaClassDef, jvm_name='org/zywx/wbpalmstar/acedes/DESUtility'):
    @java_method_def(name='nativeHtmlDecode', signature='([BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;', native=True)
    def nativeHtmlDecode(self):
        pass

def isEncrypted(enfile):
    flag = False
    with open(enfile, "rb") as f:
        read_data = f.read()
        length = len(read_data)
        a = read_data[(length-17):]   #此时读取的是bytes，要将bytes转换为str，才能进行字符串比较
        if a == "3G2WIN Safe Guard".encode("UTF-8"):
            flag = True
    f.close()
    return flag

def init_emulator(libpath):
    emulator = Emulator(
        vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs"), config_path=posixpath.join(posixpath.dirname(__file__), "default.json")
    )

    lib_appcanmodule = emulator.load_library(libpath)
    emulator.java_classloader.add_class(desutility)
    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    ret = emulator.call_symbol(lib_appcanmodule, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)
    return emulator


class AppCan(BaseModule):

    def transmit(self, value):
        key = value.replace("-", "")
        l = list(key)
        l.reverse()         #反转字符串，如"abc"变为"cba"
        result = "".join(l)
        #print(result)

        v6 = ['d', 'b', 'e', 'a', 'f', 'c']
        v7 = ['2', '4', '0', '9', '7', '1', '5', '8', '3', '6']
        v0 = []
        ll = list(result)
        i = 0
        for c in ll:
            cc = ord(c)
            if cc >= 97 and cc <= 102:
                v0.append(v6[cc-97])
            elif cc >= 48 and cc <= 57:
                v0.append(v7[cc-48])
            else:
                v0.append(ll[i])
            i = i + 1
            if i == 8 or i == 12 or i == 16 or i ==20:
                v0.append('-')
        #print("".join(v0))
        return "".join(v0)


    def extractKey(self, key, configfile):
        if key != "":
            return key

        value = ""      #store appkey from file "/res/values/strings.xml"
        t = ET.ElementTree(file=configfile)
        for elem in t.iter(tag='string'):
            appid = elem.attrib['name']
            if appid == "appkey" :
                value = elem.text
        #print(value)
        key = self.transmit(value)   #读取appkey之后将其进行转换
        return key


    def decryptFile(self, emulator, enfile, key):
        filename = os.path.splitext(os.path.split(enfile)[1])[0]  #refer https://www.cnblogs.com/panfb/p/9546035.html
        #print(filename)
        with open(enfile, "rb") as f:
            data = f.read()
        cipherlen = len(data)-0x111
        data2 = data.hex()
        data = bytearray(bytes.fromhex(data2))
        arr = Array(data)
        filename2 = String(filename)
        print(filename2)
        key2 = String(key)
        print(key2)
        cipherlen2 = String(cipherlen.__str__())
        print(cipherlen2)
        y = desutility()
        ret1 = y.nativeHtmlDecode(emulator, arr, filename2, cipherlen2, key2)  #ret1是java.class.string类型，如果值，需要调用get_py_string()
        print(ret1.get_py_string())
        return ret1.get_py_string()


    def doSigCheck(self):
        if self.host_os == "android":
            return self._find_main_activity("org.zywx.wbpalmstar.engine.LoadingActivity")
        elif self.host_os == "ios":
            log.error("not support yet.")
            return False
        return False


    def doExtract(self, working_folder):

        extract_folder = self._format_working_folder(working_folder)

        if os.access(extract_folder, os.R_OK):
            shutil.rmtree(extract_folder)
        os.makedirs(extract_folder, exist_ok = True)
        tmp_folder = os.path.join(extract_folder, "tmp")
        os.makedirs(tmp_folder, exist_ok=True)
        self._apktool(tmp_folder)

        emulator = init_emulator(os.path.join(tmp_folder, "lib/armeabi-v7a/libappcan.so"))

        configfile=os.path.join(tmp_folder, "res/values/strings.xml")
        launch_path = ""
        encryptflag = 0  #0:unknown  1:encrypt
        key = ""

        for dirpath, dirnames, ifilenames in os.walk(tmp_folder):
            if dirpath.find("assets/widget") != -1:   # store web resource  and f != "assets/widget/config.xml"
                for fs in ifilenames:
                    f = os.path.join(dirpath, fs)
                    encryptflag = isEncrypted(f)

                    # if f.endswith("ui-color.css"):
                    #     print("ha")

                    matchObj = re.match(r'(.*)assets/widget/(.*)', f, re.S)
                    newRP = matchObj.group(2)

                    tf = os.path.join(extract_folder, newRP)
                    if not os.access(os.path.dirname(tf), os.R_OK):
                        os.makedirs(os.path.dirname(tf))

                    with open(tf, "wb") as fwh:  #output the plain
                        if encryptflag:             #encrypt
                            key = self.extractKey(key, configfile)
                            fwh.write(self.decryptFile(emulator, f, key).encode("UTF-8"))      #the plain after decrypted
                        else:
                            # ugly coding
                            fp = open(f, "rb")
                            c = fp.read()
                            fp.close()
                            fwh.write(c)                                     #no encrypt

                    if f.endswith("assets/widget/config.xml"):
                        encryptflag = isEncrypted(f)
                        if encryptflag:             # encrypted
                            key = self.extractKey(key, configfile)
                            plain = self.decryptFile(emulator, f, key)
                        else:                       # no encrypt
                            # ugly coding
                            fp = open(f, "rb")
                            plain = fp.read()
                            fp.close()
                        results = re.findall('(?<=<)content.*(?=>)', plain)
                        for r_con in results:
                            src = re.findall('(?<=src=").*(?=")', r_con)
                            if len(src) == 1:
                                launch_path = src[0]
                                break
                #print(launch_path)
        self._dump_info(extract_folder, launch_path)     #store the home page

        # clean env
        shutil.rmtree(tmp_folder)
        return extract_folder, launch_path


def main():
    f = "./test_case/AppCan/apphe.apk"    #后续会将当前脚本路径与之相拼接，得到最终detect_file路径
    appcan = AppCan(f, "android")
    if appcan.doSigCheck():
        logging.info("AppCan signature Match")
        extract_folder, launch_path = appcan.doExtract("working_folder")
        log.info("{} is extracted to {}, the start page is {}".format(f, extract_folder, launch_path))

    return

if __name__ == "__main__":
    sys.exit(main())
