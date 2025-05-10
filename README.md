# Kriptografi_File_Dokumen
Kode Python ini merupakan aplikasi GUI enkripsi dan dekripsi file menggunakan AES (Advanced Encryption Standard) dengan antarmuka berbasis PyQt5. Fungsionalitas utamanya adalah mengenkripsi dan mendekripsi file .docx, .xlsx, .pdf, dan .txt, serta menampilkan preview isi file sebelum dan sesudah proses.
📦 1. Import Library
Kode ini mengimpor:

GUI: PyQt5.QtWidgets (membuat antarmuka pengguna)

Kriptografi: cryptography untuk AES CBC, padding, dan key derivation

File Handling: docx, openpyxl, PyPDF2 untuk membaca isi file

Misc: os, sys, secrets, base64 untuk dukungan sistem dan enkripsi

🧱 2. Class FileEncryptorApp
Merupakan komponen utama GUI, mewarisi dari QWidget. Fitur utama:

🖼️ init_ui(self)
Mengatur tampilan antarmuka:

Label instruksi

Tombol: pilih file, enkripsi, dekripsi

Area preview file (QTextEdit)

📂 select_file(self)
Membuka dialog pemilihan file

Mendukung: .docx, .xlsx, .pdf, .txt, .enc

Menyimpan path file yang dipilih, mengaktifkan tombol sesuai jenis file

👁️ preview_file(self)
Menampilkan isi file dalam bentuk:

Word (.docx): semua paragraf

Excel (.xlsx): 10 baris pertama

PDF: 5 halaman pertama

Text (.txt): 1000 karakter pertama

Encrypted (.enc): 500 byte pertama dalam bentuk hex

🔒 encrypt_file(self)
Membaca isi file

Menghasilkan salt dan kunci dari password (PBKDF2HMAC)

Enkripsi data menggunakan AES-CBC dan padding PKCS7

Menyimpan hasil: salt + iv + encrypted_data ke file .enc

Menampilkan pratinjau hex dan notifikasi sukses

🔓 decrypt_file(self)
Membaca file .enc

Ekstraksi: salt, iv, encrypted_data

Derivasi kunci dengan salt dan password

Dekripsi menggunakan AES-CBC

Menyimpan ke file baru _decrypted

Menampilkan hasilnya

👁️‍🗨️ preview_decrypted_file(self)
Seperti preview_file(), tapi untuk hasil dekripsi

🔐 3. Fungsi Kriptografi
derive_key(self, password, salt)
Membuat kunci 256-bit dengan PBKDF2HMAC, SHA-256, dan salt

aes_encrypt(self, data, key)
Menambahkan padding → enkripsi dengan AES-CBC → hasil: encrypted_data, iv

aes_decrypt(self, encrypted_data, key, iv)
Dekripsi AES-CBC → hapus padding → kembalikan data asli

