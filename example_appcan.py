import logging
import posixpath
import sys
import os
import subprocess
import shutil
import traceback

from unicorn import UC_HOOK_CODE, UcError
from unicorn.arm_const import *

from androidemu.java.classes.array import Array
from androidemu.java.classes.string import String

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
import androidemu.utils.debug_utils
from androidemu.utils.chain_log import ChainLogger

# Configure logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
)

logger = logging.getLogger(__name__)


class desutility(metaclass=JavaClassDef, jvm_name='org/zywx/wbpalmstar/acedes/DESUtility'):
    @java_method_def(name='nativeHtmlDecode', signature='([BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;', native=True)
    def nativeHtmlDecode(self):
        pass


class XGorgen(metaclass=JavaClassDef, jvm_name='com/ss/sys/ces/a'):
    def __init__(self):
        pass

    @java_method_def(name='leviathan', signature='(I[B)[B', native=True)
    def leviathan(self, mu):
        pass

    def extractKey(self, configfile):
        value = ""      #store appkey from file "/res/values/strings.xml"
        t = ET.ElementTree(file=configfile)
        for elem in t.iter(tag='string'):
            appid = elem.attrib['name']
            if appid == "appkey" :
                value = elem.text
        #print(value)
        key = self.transmit(value)   #读取appkey之后将其进行转换
        return key

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

    def test(self):
        pass

# Initialize emulator
emulator = Emulator(
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)

lib_appcanmodule = emulator.load_library("tests/bin/libappcan.so")
lib_hellomodule = emulator.load_library("tests/bin/libhello.so")
emulator.java_classloader.add_class(desutility)


# Show loaded modules.
logger.info("Loaded modules:")
for module in emulator.modules:
    logger.info("[0x%x] %s" % (module.base, module.filename))


def _apktool(extract_folder):
    proc = subprocess.Popen("java -jar '{}' d '{}' -f -o '{}'".format(os.path.join(os.getcwd(), "tools/apktool_2.4.0.jar"), os.path.join(os.getcwd(), "tools/apphe.apk"), extract_folder), shell=True, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    r = (proc.communicate()[0]).decode()
    #log.info(r)
    return

'''
##libhello.so中静态注册的getplain2()函数调用
try:
    data = bytearray(bytes.fromhex('acde74a94e6b493a3399fa'))
    arr = Array(data)
    filename2 = String('config')
    print(filename2)
    key2 = String('11234-78328')
    print(key2)
    cipherlen2 = String('659')
    print("[0x%x]"%(lib_hellomodule.find_symbol('Java_com_test_NativeCaller_getplain2')))
    ##reference: androidemu/java/helpers/native_method.py, it calls method 'call_native()' in androidemu/emulator.py
    result = emulator.call_native(lib_hellomodule.find_symbol('Java_com_test_NativeCaller_getplain2'), emulator.java_vm.jni_env.address_ptr, 0xFA, arr, filename2, cipherlen2, key2)
    print(result.get_py_string())
except UcError as e:
    print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
    #可通过异常打印调用栈
    #e = Exception()
    traceback.print_exc(e)
    raise
'''

##libappcan.so中动态注册的解密函数调用,以apphe.apk中assets/widget/config.xml为例进行解密
try:
    tmp_folder = os.path.join(os.getcwd(), "tmp")
    os.makedirs(tmp_folder, exist_ok=True)
    _apktool(tmp_folder)
    print(tmp_folder)
    configfile = os.path.join(tmp_folder, "res/values/strings.xml")
    print(configfile)
    x = XGorgen()
    key = x.extractKey(configfile)
    filename = "config"
    with open(os.path.join(tmp_folder, "assets/widget/config.xml"), "rb") as f:
        data = f.read()
    cipherlen = len(data)-0x111

    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    ret = emulator.call_symbol(lib_appcanmodule, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)
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
    shutil.rmtree(tmp_folder)
except UcError as e:
    print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
    raise


