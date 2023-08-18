from tkinter import *
from PIL import ImageTk, Image
from tkinter import messagebox
import base64
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

window = Tk()
window.title("Secret Notes")
window.minsize(width=400,height=610)
window.config(padx=30,pady=30)

def save_and_encrypt():
    title = my_entry1.get()
    message = text.get("1.0", END)
    secret = my_entry2.get()

    if title == "" or message == "" or secret == "":
        messagebox.showinfo(title="Error",message="Please enter all information")
    else:
        encrypted_message = encode(secret,message)
        try:
            with open("my_secret.txt","a") as hidden_file:
                hidden_file.write(f"\n{title}\n{encrypted_message}")
        except FileNotFoundError:
            with open("my_secret.txt""w") as hidden_file:
                hidden_file.write(f"\n{title}\n{encrypted_message}")
        finally:
            my_entry1.delete(0, END)
            text.delete("1.0", END)
            my_entry2.delete(0,END)

def decrypt():
    message_encrypted = text.get("1.0", END)
    secret = my_entry2.get()
    if message_encrypted == "" or secret == "":
        messagebox.showinfo(title="Error",message="Please enter all information!")
    else:
        try:
            message_decrypted = decode(secret,message_encrypted)
            text.delete("1.0", END)
            text.insert("1.0",message_decrypted)
        except:
            messagebox.showinfo(title="Error!",message="Please enter encrypted text!")

img = Image.open("topsecret.png")
photo = ImageTk.PhotoImage(img)
lab = Label(image=photo).pack()

my_label1 = Label(text="Enter your title")
my_label1.pack()

my_entry1 = Entry(width=20)
my_entry1.pack()

my_label2 = Label(text="Enter your secret")
my_label2.pack()

text = Text(width=30,height=20)
text.pack()


my_label3 = Label(text="Enter master key")
my_label3.pack()

my_entry2 = Entry(width=20)
my_entry2.pack()

my_button1 = Button(text="Save & Encrypt",command=save_and_encrypt)
my_button1.pack()

my_button2 = Button(text="Decrypt",command=decrypt)
my_button2.pack()















window.mainloop()