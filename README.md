# 🔒 Video Encryptor / Decryptor App 🐍

A robust and user-friendly desktop application built with **Python** and **CustomTkinter** for encrypting and decrypting video files (or any file) with a strong password.

## ✨ Features

* **Strong Cryptography:** Utilizes the `cryptography` library with **Fernet** encryption, deriving the key from the user's password using **PBKDF2HMAC-SHA256** and a unique salt for maximum security.
* **Modern GUI:** A clean, dark-themed user interface built with the **CustomTkinter** library.
* **Encrypted File Management:** Automatically saves encrypted files (`.enc` extension) to a dedicated `encrypted_files` folder and displays them in a scrollable list for easy access.
* **One-Click Decrypt:** Select a file from the list or browse one, enter the password, and decrypt the video back to its original format.
* **Cross-Platform Playback:** Includes basic system commands to attempt playing the decrypted video instantly (Windows, macOS, Linux supported).


### How to Use

1.  **To Encrypt:**
    * Click **"Browse..."** and select the video file you wish to protect (e.g., `my_private_course.mp4`).
    * Enter a **strong password** in the password field.
    * Click **"Encrypt -> save to encrypted_files"**. A new `.enc` file will appear in the list on the right.

2.  **To Decrypt:**
    * Select the encrypted file from the list (or browse to it).
    * Enter the **correct password**.
    * Click **"Decrypt"**. The original video file (e.g., `my_private_course_dec.mp4`) will be saved in the same directory and the path will be shown in the entry field.

## 🛠️ Built With

* [Python](https://www.python.org/)
* [CustomTkinter](https://customtkinter.tomschimansky.com/) - For the modern, responsive GUI.
* [Cryptography](https://cryptography.io/en/latest/) - For secure, standard encryption/decryption.

## 🔗 Follow Me

Stay connected for more cool projects & tutorials 🚀

* 📸 [Instagram](https://www.instagram.com/esraa_codes)
* 🎵 [TikTok](https://www.tiktok.com/@esraa.codes)
* ▶️ [YouTube](https://www.youtube.com/@EsraaCodes)
* 🌐 [GitHub](https://github.com/esraamahmoudhamza)


## ⭐ Support

If you like this project:
⭐ **Star the repo** — it helps a lot!
📢 **Share it** with friends & devs
📺 **Subscribe** on YouTube for more awesome builds 🚀

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
