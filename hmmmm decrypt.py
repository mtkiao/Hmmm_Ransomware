import os
import tkinter
import psutil
import win32api
import win32con
from tkinter import filedialog
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

class Main:
    def __init__(self) -> None:
        ...
    
    def getFiles(self, path) -> list:
        allFiles = []
        for root, dirs, files in os.walk(os.path.realpath(path)):
            for file in files:
                file_path = os.path.realpath(os.path.join(root, file))
                allFiles.append(file_path)

        return allFiles

    def start(self) -> None: 
        window = tkinter.Tk()
        window.title("Hmmmm Decryptor")

        self.label = tkinter.Label(window, text="Enter the private key(321.yek) path:")
        self.label.grid(column=0, row=0)

        self.entry = tkinter.Entry(window, width=50)
        self.entry.grid(column=0, row=1)

        self.pathChoose = tkinter.Button(window, text="Choose prative key", command = lambda: self.choosePath())
        self.pathChoose.grid(column=1, row=1)

        self.label2 = tkinter.Label(window, text="Enter the path to the folder with encrypted files:")
        self.label2.grid(column=0, row=2)

        self.entry2 = tkinter.Entry(window, width=50)
        self.entry2.grid(column=0, row=3)

        self.pathChoose2 = tkinter.Button(window, text="Choose folder", command = lambda: self.chooseEnPath())
        self.pathChoose2.grid(column=1, row=3)

        self.button = tkinter.Button(window, text="Decrypt", command = lambda: self.decrypt())
        self.button.grid(column=0, row=4)


        window.mainloop()

    def checkFile(self, file) -> bool:
        if file[-6:] == ".Hmmmm": return True

        return False

    def choosePath(self) -> None:
        key = filedialog.askopenfile()
        if not key == None:
            self.entry.delete(0, tkinter.END)
            self.entry.insert(0, key.name)

    def chooseEnPath(self) -> None:
        path = filedialog.askdirectory()
        if not path == None:
            self.entry2.delete(0, tkinter.END)
            self.entry2.insert(0, path)

    def deFile(self, path, privateKey) -> bool:
        with open(path, "rb") as f:
            encSessionKey = f.read(privateKey.size_in_bytes())
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read(-1)

        cipherRSA = PKCS1_OAEP.new(privateKey)
        sessionKey = cipherRSA.decrypt(encSessionKey)

        cipherAES = AES.new(sessionKey, AES.MODE_EAX, nonce)
        data = cipherAES.decrypt_and_verify(ciphertext, tag)

        try:
            with open(path, "w") as f:
                f.write(data.decode("utf-8"))
        except:
            try:
                with open(path, "wb") as f:
                    f.write(data)
            except Exception as e:
                messagebox.showerror("Error", f"Can't decrypt: {path}!")

        os.rename(path, path[:-6])

    def removeViruses(self):
        userPath = os.path.realpath(os.getenv("appdata").replace("\AppData\Roaming", ""))
        pathlist = [
            "C:\\Windows\\Fonts\\de de de de de de.exe",
            "C:\\Windows\\Offline Web Pages\\cxk.exe",
            "C:\\Windows\\why so many websites report that.exe",
            os.path.realpath(f"{userPath}\\Desktop\\WHY.exe"),
            f"{userPath}\\AppData\\SYSTEM32.exe",
        ]
        for i in pathlist:
            if os.path.exists(i):
                try:
                    os.remove(i)
                except:
                    ...

        key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, 'nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\ERAWTFOS'[::-1], 0, win32con.KEY_ALL_ACCESS)
        win32api.RegDeleteValue(key, "mosnar eht yap ot wonk uoy yhw"[::-1])

    def killVieruses(self):
        userPath = os.path.realpath(os.getenv("appdata").replace("\AppData\Roaming", ""))
        pathlist = [
            "C:\\Windows\\Fonts\\de de de de de de.exe".lower(),
            "C:\\Windows\\Offline Web Pages\\cxk.exe".lower(),
            "C:\\Windows\\why so many websites report that.exe".lower(),
            os.path.realpath(f"{userPath}\\Desktop\\WHY.exe").lower(),
            f"{userPath}\\AppData\\SYSTEM32.exe".lower(),
        ]

        for i in psutil.process_iter():
            try:
                if f"{i.exe().lower()}\\{i.name().lower()}" in pathlist:
                    i.kill()
            except:
                ...


    def decrypt(self) -> None:
        if self.entry.get() == "": return messagebox.showerror("Error", "Please choose private key!")
        if self.entry2.get() == "": return messagebox.showerror("Error", "Please choose folder!")
        if not os.path.exists(self.entry.get()): return messagebox.showerror("Error", "Please choose effective private key!")
        if not os.path.exists(self.entry2.get()): return messagebox.showerror("Error", "Please choose effective folder!")
        try: self.privateKey = RSA.import_key(open(self.entry.get()).read(), passphrase="boon si oaiktm"[::-1])
        except: return messagebox.showerror("Error", "Please choose effective private key!")

        if not self.privateKey.has_private(): return messagebox.showerror("Error", "Please choose effective private key!")
        
        self.files = self.getFiles(self.entry2.get())
        for file in self.files:
            if not self.checkFile(file): continue
            try:
                self.deFile(file, self.privateKey)
            except:
                messagebox.showerror("Error", f"Can't decrypt {file}")
        
        try:
            self.killVieruses()
            self.removeViruses()
        except:
            ...

        messagebox.showinfo("Success", "All files have been decrypted!")

if __name__ == "__main__":
    main = Main()
    main.start()