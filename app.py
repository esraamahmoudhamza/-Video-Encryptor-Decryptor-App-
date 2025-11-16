# app.py
# Video Encryptor / Decryptor with CustomTkinter UI
# Shows encrypted files list so user can decrypt easily.
# All comments and UI strings are in English only.

import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import secrets
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import sys
from pathlib import Path
from functools import partial

# -----------------------
# Configuration
# -----------------------
ENC_FOLDER = Path.cwd() / "encrypted_files"
ENC_FOLDER.mkdir(exist_ok=True)

# -----------------------
# Crypto helper functions
# -----------------------

def derive_fernet_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """Derive a 32-byte key for Fernet from password and salt"""
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key)

def encrypt_file(file_path: str, password: str) -> str:
    """
    Encrypt the file and save it to the encrypted_files folder.
    File format: salt(16 bytes) || ciphertext
    Returns path to encrypted file.
    """
    salt = secrets.token_bytes(16)
    key = derive_fernet_key(password, salt)
    fernet = Fernet(key)

    with open(file_path, "rb") as f:
        plaintext = f.read()

    ciphertext = fernet.encrypt(plaintext)
    out_path = ENC_FOLDER / (Path(file_path).name + ".enc")

    with open(out_path, "wb") as f:
        f.write(salt)
        f.write(ciphertext)

    return str(out_path)

def decrypt_file(enc_path: str, password: str) -> str | None:
    """
    Decrypt file saved in the encrypted_files folder (or any .enc).
    Returns path to decrypted file or None if failure.
    """
    with open(enc_path, "rb") as f:
        salt = f.read(16)
        ciphertext = f.read()

    key = derive_fernet_key(password, salt)
    fernet = Fernet(key)
    try:
        plaintext = fernet.decrypt(ciphertext)
    except Exception:
        return None

    base = enc_path
    if base.endswith(".enc"):
        base = base[:-4]
    dirname, fname = os.path.split(base)
    name, ext = os.path.splitext(fname)
    out_name = f"{name}_dec{ext or '.mp4'}"
    out_path = os.path.join(dirname, out_name)

    with open(out_path, "wb") as f:
        f.write(plaintext)

    return out_path

# -----------------------
# GUI Application Class
# -----------------------

class VideoEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Video Encryptor")
        self.root.geometry("760x420")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        # Main frame (avoid unsupported kwargs like padding)
        self.frame = ctk.CTkFrame(self.root, corner_radius=10)
        self.frame.pack(fill="both", expand=True, padx=16, pady=16)

        # Left side: controls
        left = ctk.CTkFrame(self.frame)
        left.grid(row=0, column=0, sticky="nsew", padx=(0,12), pady=6)
        # Right side: encrypted files list
        right = ctk.CTkFrame(self.frame)
        right.grid(row=0, column=1, sticky="nsew", pady=6)

        self.frame.grid_columnconfigure(0, weight=0)
        self.frame.grid_columnconfigure(1, weight=1)
        self.frame.grid_rowconfigure(0, weight=1)

        # --- Left: controls ---
        ctk.CTkLabel(left, text="Select video or encrypted file:", anchor="w").pack(pady=(12,6), padx=8)
        self.file_entry = ctk.CTkEntry(left, width=420)
        self.file_entry.pack(padx=8)
        self.browse_btn = ctk.CTkButton(left, text="Browse...", command=self.browse_file)
        self.browse_btn.pack(padx=8, pady=(8,12))

        ctk.CTkLabel(left, text="Password:", anchor="w").pack(pady=(6,4), padx=8)
        self.password_entry = ctk.CTkEntry(left, placeholder_text="Enter password", show="*")
        self.password_entry.pack(padx=8, pady=(0,12))

        # Buttons row
        btn_row = ctk.CTkFrame(left)
        btn_row.pack(padx=8, pady=(6,12), fill="x")
        self.play_btn = ctk.CTkButton(btn_row, text="Play Video", command=self.play_video, fg_color="#f0ad4e")
        self.play_btn.grid(row=0, column=0, padx=6, pady=6)
        self.encrypt_btn = ctk.CTkButton(btn_row, text="Encrypt -> save to encrypted_files", command=self.encrypt_action, fg_color="#28a745")
        self.encrypt_btn.grid(row=0, column=1, padx=6, pady=6)
        self.decrypt_btn = ctk.CTkButton(btn_row, text="Decrypt (from path above)", command=self.decrypt_action, fg_color="#007bff")
        self.decrypt_btn.grid(row=0, column=2, padx=6, pady=6)

        # status
        self.status = ctk.CTkLabel(left, text="Ready", anchor="w")
        self.status.pack(padx=8, pady=(6,4))

        # --- Right: encrypted files list ---
        ctk.CTkLabel(right, text="Encrypted files (in ./encrypted_files):", anchor="w").pack(pady=(12,6), padx=8)
        self.scroll_frame = ctk.CTkScrollableFrame(right, width=340, height=300)
        self.scroll_frame.pack(padx=8, pady=(0,8), fill="both", expand=True)
        # refresh button
        self.refresh_btn = ctk.CTkButton(right, text="Refresh list", command=self.refresh_enc_list)
        self.refresh_btn.pack(padx=8, pady=(0,12))

        # fill initial list
        self.refresh_enc_list()

    # ---------------- GUI Functions ----------------

    def browse_file(self):
        """Open file dialog and put selected path into entry (allow .enc selection too)."""
        path = filedialog.askopenfilename(
            title="Select video or encrypted file",
            filetypes=[("Video files", "*.mp4 *.mov *.avi *.mkv *.flv *.wmv"),
                       ("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        if path:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, path)

    def play_video(self):
        """Play the file shown in file_entry using system default player (if a normal video)."""
        path = self.file_entry.get()
        if not path or not os.path.exists(path):
            messagebox.showwarning("Warning", "Please select a valid file first.")
            return
        # if it's an encrypted file, prompt user to decrypt first
        if path.endswith(".enc"):
            messagebox.showinfo("Encrypted file", "This is an encrypted file. Decrypt it first to play.")
            return
        try:
            if os.name == "nt":
                os.startfile(path)
            elif os.name == "posix":
                if sys.platform == "darwin":
                    os.system(f'open "{path}"')
                else:
                    os.system(f'xdg-open "{path}"')
            else:
                messagebox.showinfo("Info", "Unsupported OS for playback")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open video: {e}")

    def encrypt_action(self):
        """Encrypt the selected video and save .enc into encrypted_files folder."""
        path = self.file_entry.get()
        password = self.password_entry.get()
        if not path or not os.path.exists(path):
            messagebox.showwarning("Warning", "Please select a valid video to encrypt.")
            return
        if path.endswith(".enc"):
            messagebox.showwarning("Warning", "Selected file is already encrypted.")
            return
        if not password:
            messagebox.showwarning("Warning", "Please enter a password for encryption.")
            return

        try:
            self._set_status("Encrypting...")
            out = encrypt_file(path, password)
            self._set_status("Encryption complete.")
            messagebox.showinfo("Done", f"Encrypted file saved:\n{out}")
            self.refresh_enc_list()
            # put the encrypted file path in entry for convenience
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, out)
        except Exception as e:
            self._set_status("Encryption failed.")
            messagebox.showerror("Encryption Error", f"An error occurred:\n{e}")

    def decrypt_action(self):
        """Decrypt the path in the file_entry (must be .enc) using provided password."""
        path = self.file_entry.get()
        password = self.password_entry.get()
        if not path or not os.path.exists(path):
            messagebox.showwarning("Warning", "Please select an encrypted file to decrypt.")
            return
        if not path.endswith(".enc"):
            messagebox.showwarning("Warning", "Please choose a .enc file to decrypt (use the list or Browse).")
            return
        if not password:
            messagebox.showwarning("Warning", "Please enter the password used for encryption.")
            return

        try:
            self._set_status("Decrypting...")
            out = decrypt_file(path, password)
            if out:
                self._set_status("Decryption complete.")
                messagebox.showinfo("Done", f"Decrypted file saved:\n{out}")
                # place decrypted path into entry so user can play it
                self.file_entry.delete(0, "end")
                self.file_entry.insert(0, out)
            else:
                self._set_status("Decryption failed.")
                messagebox.showerror("Failed", "Password incorrect or file invalid.")
        except Exception as e:
            self._set_status("Decryption error.")
            messagebox.showerror("Decryption Error", f"An error occurred:\n{e}")

    def refresh_enc_list(self):
        """Rebuild the encrypted files list UI from the encrypted_files folder."""
        # clear current children in scroll_frame
        for child in self.scroll_frame.winfo_children():
            child.destroy()

        enc_files = sorted(ENC_FOLDER.glob("*.enc"))
        if not enc_files:
            lbl = ctk.CTkLabel(self.scroll_frame, text="No encrypted files found.", anchor="w")
            lbl.pack(fill="x", padx=6, pady=6)
            return

        for p in enc_files:
            row = ctk.CTkFrame(self.scroll_frame)
            row.pack(fill="x", pady=6, padx=6)
            name_lbl = ctk.CTkLabel(row, text=p.name, anchor="w")
            name_lbl.pack(side="left", fill="x", expand=True, padx=(6,10))
            open_btn = ctk.CTkButton(row, text="Select", width=80, command=partial(self._select_enc, str(p)))
            open_btn.pack(side="right", padx=6)
            dec_btn = ctk.CTkButton(row, text="Decrypt", width=80, fg_color="#007bff", command=partial(self._decrypt_from_list, str(p)))
            dec_btn.pack(side="right", padx=6)

    def _select_enc(self, enc_path):
        """Put selected encrypted file path into the file_entry."""
        self.file_entry.delete(0, "end")
        self.file_entry.insert(0, enc_path)

    def _decrypt_from_list(self, enc_path):
        """Decrypt a file chosen from the list — prompt for password if none entered."""
        pwd = self.password_entry.get()
        if not pwd:
            # ask user for password input (simple dialog)
            pwd = ctk.simpledialog.askstring("Password", "Enter password to decrypt:", show="*") if hasattr(ctk, "simpledialog") else None
            if not pwd:
                return
        # set the path into entry and call decrypt_action logic
        self.file_entry.delete(0, "end")
        self.file_entry.insert(0, enc_path)
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, pwd)
        self.decrypt_action()

    def _set_status(self, text):
        self.status.configure(text=text)

# -----------------------
# Run the app
# -----------------------
if __name__ == "__main__":
    root = ctk.CTk()
    app = VideoEncryptorApp(root)
    root.mainloop()
