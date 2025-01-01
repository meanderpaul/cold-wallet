import os
import json
import tkinter as tk
import ttkbootstrap as ttk
from tkinter import messagebox
from cryptography.fernet import Fernet
from eth_account import Account
from bitcoinlib.wallets import Wallet

WALLET_FILE = "wallet_info.enc"
PIN_FILE = "pin.enc"

class WalletGUI:
    def __init__(self, on_generate_address, view_keys):
        self.on_generate_address = on_generate_address
        self.view_keys = view_keys
        self.pin_window = None
        self.wallet_window = None

    def apply_theme(self, window):
        style = ttk.Style(window)
        available_themes = style.theme_names()
        print("Available themes:", available_themes)
        
        theme_name = "superhero"  # Desired theme
        if theme_name in available_themes:
            style.theme_use(theme_name)
        else:
            print(f"Theme '{theme_name}' is not available. Default theme will be used.")
            style.theme_use("default")
        
        style.configure('TButton', font=('Helvetica', 12), background='gray', foreground='white')
        window.configure(bg='black')
        window.tk.call('tk', 'scaling', 1.25)

    def open_wallet_window(self, wallet_info, key):
        if self.wallet_window and self.wallet_window.winfo_exists():
            self.wallet_window.destroy()

        self.wallet_window = ttk.Window()
        self.apply_theme(self.wallet_window)
        self.wallet_window.title("USB Wallet Information")
        self.wallet_window.geometry("600x400")
        self.wallet_window.resizable(True, True)

        wallet_frame = ttk.Frame(self.wallet_window, padding=(20, 10))
        wallet_frame.pack(fill="both", expand=True)

        ttk.Label(wallet_frame, text="Wallet Information", font=("Helvetica", 16, "bold"), bootstyle="primary").grid(row=0, column=0, columnspan=3, pady=10)
        row = 1
        for crypto, info in wallet_info.items():
            ttk.Label(wallet_frame, text=f"{crypto.capitalize()} Address:", font=("Helvetica", 12), bootstyle="info").grid(row=row, column=0, sticky="e", pady=5, padx=10)
            ttk.Label(wallet_frame, text=info["wallet"], font=("Helvetica", 12), bootstyle="default").grid(row=row, column=1, sticky="w", pady=5)
            row += 1

        ttk.Label(wallet_frame, text="Select Cryptocurrency:", font=("Helvetica", 12), bootstyle="info").grid(row=row, column=0, sticky="e", pady=5, padx=10)
        self.crypto_options = ["bitcoin", "ethereum", "xrp", "shiba_inu"]
        self.selected_crypto = tk.StringVar(value=self.crypto_options[0])
        ttk.Combobox(wallet_frame, textvariable=self.selected_crypto, values=self.crypto_options, state="readonly").grid(row=row, column=1, sticky="w", pady=5)
        ttk.Button(wallet_frame, text="View Keys", command=lambda: self.view_keys(self.selected_crypto.get()), bootstyle="info-outline").grid(row=row, column=2, sticky="w", pady=5, padx=5)
        row += 1
        ttk.Button(wallet_frame, text="Generate New Address", command=lambda: self.on_generate_address(wallet_frame, self.selected_crypto.get()), bootstyle="success-outline").grid(row=row, column=0, columnspan=3, pady=20)

    def show_pin_window(self, on_pin_entry, pin=None):
        if self.pin_window and self.pin_window.winfo_exists():
            return

        self.pin_window = ttk.Window()
        self.apply_theme(self.pin_window)
        self.pin_window.title("USB Wallet - PIN Entry")
        self.pin_window.geometry("400x200")
        ttk.Label(self.pin_window, text="Enter your PIN:", bootstyle="primary").pack(pady=10)

        self.pin_entry = ttk.Entry(self.pin_window, show='*', bootstyle="primary")
        self.pin_entry.pack(pady=10)

        if pin is None:
            ttk.Label(self.pin_window, text="Confirm your PIN:", bootstyle="primary").pack(pady=10)
            self.pin_confirm_entry = ttk.Entry(self.pin_window, show='*', bootstyle="primary")
            self.pin_confirm_entry.pack(pady=10)

        self.pin_entry.bind("<Return>", on_pin_entry)
        if pin is None:
            self.pin_confirm_entry.bind("<Return>", on_pin_entry)
        ttk.Button(self.pin_window, text="Submit PIN", command=on_pin_entry, bootstyle="success-outline").pack(pady=10)

def load_key():
    if os.path.exists("secret.key"):
        return open("secret.key", "rb").read()
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    return key

def encrypt(data, key):
    return Fernet(key).encrypt(data.encode())

def decrypt(data, key):
    return Fernet(key).decrypt(data).decode()

def get_pin(key):
    return decrypt(open(PIN_FILE, "rb").read(), key) if os.path.exists(PIN_FILE) else None

def set_pin(new_pin, key):
    with open(PIN_FILE, "wb") as pin_file:
        pin_file.write(encrypt(new_pin, key))

def verify_pin(stored_pin, entered_pin):
    if entered_pin == stored_pin:
        return True
    messagebox.showerror("Error", "Incorrect PIN.")
    return False

def load_wallet_info(key):
    if os.path.exists(WALLET_FILE):
        return json.loads(decrypt(open(WALLET_FILE, "rb").read(), key))
    return {
        "bitcoin": {"wallet": "bitcoin_wallet_address", "private_key": "bitcoin_private_key", "balance": 0.0},
        "ethereum": {"wallet": "ethereum_wallet_address", "private_key": "ethereum_private_key", "balance": 0.0},
        "xrp": {"wallet": "xrp_wallet_address", "private_key": "xrp_private_key", "balance": 0.0},
        "shiba_inu": {"wallet": "shiba_wallet_address", "private_key": "shiba_private_key", "balance": 0.0}
    }

def save_wallet_info(wallet_info, key):
    with open(WALLET_FILE, "wb") as wallet_file:
        wallet_file.write(encrypt(json.dumps(wallet_info), key))

def generate_new_address(crypto_type):
    if crypto_type == "ethereum":
        account = Account.create()
        return account.address, account.key.hex()
    wallet = Wallet.create(f'USBWallet_{crypto_type}')
    key = wallet.new_key()
    return key.address, key.private_hex

def on_pin_entry(event=None):
    stored_pin = get_pin(key)
    entered_pin = gui.pin_entry.get()
    if stored_pin:
        if verify_pin(stored_pin, entered_pin):
            gui.pin_window.destroy()
            gui.open_wallet_window(load_wallet_info(key), key)
    else:
        confirm_pin = gui.pin_confirm_entry.get()
        if entered_pin == confirm_pin:
            set_pin(entered_pin, key)
            messagebox.showinfo("Success", "New PIN set successfully.")
            gui.pin_window.destroy()
            gui.open_wallet_window(load_wallet_info(key), key)
        else:
            messagebox.showerror("Error", "PINs do not match. Try again.")

def view_keys(crypto_type):
    wallet_info = load_wallet_info(key)
    if crypto_type in wallet_info:
        pub_key = wallet_info[crypto_type]["wallet"]
        priv_key = wallet_info[crypto_type]["private_key"]
        messagebox.showinfo(f"{crypto_type.capitalize()} Keys", f"Public Key: {pub_key}\nPrivate Key: {priv_key}")
    else:
        messagebox.showerror("Error", f"No keys found for {crypto_type.capitalize()}.")

def on_generate_address(wallet_frame, crypto_type):
    wallet_info = load_wallet_info(key)
    new_address, private_key = generate_new_address(crypto_type)
    wallet_info[crypto_type]["wallet"] = new_address
    wallet_info[crypto_type]["private_key"] = private_key
    save_wallet_info(wallet_info, key)
    gui.open_wallet_window(wallet_info, key)

if __name__ == "__main__":
    key = load_key()
    pin = get_pin(key)
    root = tk.Tk()
    root.withdraw()
    gui = WalletGUI(on_generate_address, view_keys)
    gui.show_pin_window(on_pin_entry, pin)
    root.mainloop()
