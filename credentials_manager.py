import base64
import hashlib
import os
import secrets
import sqlite3
import string
import tempfile
import shutil
from datetime import datetime
from io import BytesIO
import qrcode
import py7zr
import pyotp
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class CredentialsManager:
    # Initialize the CredentialsManager class with default values
    def __init__(self, db_folder='databases', in_memory=True):
        # Set default attributes for the database
        self.db_folder = db_folder
        self.db_path = None
        self.db_file_name = None
        self.temp_db_path = None
        self.archive_path = None
        self.create_database_folder(self.db_folder)
        self.conn = None
        self.cursor = None
        self.key = None
        self.salt = None
        self.totp = None
        self.two_factor_enabled = False
        self.key_2fa = None
        self.in_memory = in_memory
        self.in_memory_db = None
        self.user_password = None
        self.user_name = None
        self.archive_name = f'{self.user_name}.7z'

    # Function to create and populate the in-memory database
    def create_and_populate_in_memory_database(self, db_name):
        # Create an in-memory SQLite3 connection
        self.conn = sqlite3.connect(':memory:')
        conn = self.conn
        cursor = conn.cursor()
        # Create a new table for users
        cursor.execute(
            'CREATE TABLE users (id INTEGER PRIMARY KEY, website TEXT, email TEXT, username TEXT, password TEXT, notes TEXT);'
            )
        conn.commit()
        # Save the in-memory database to a BytesIO object
        self.in_memory_db = BytesIO()
        for line in conn.iterdump():
            self.in_memory_db.write(line.encode('utf-8'))
        self.in_memory_db.seek(0)

    # Function to load the database from the in-memory database
    def load_database_from_memory(self):
        # Check if 2-factor authentication is enabled
        if self.two_factor_enabled:
            decrypted_content = self.decrypt_database_file()
            if decrypted_content is not None:
                conn = sqlite3.connect(':memory:')
                conn.executescript(decrypted_content)
            else:
                return
        # If 2-factor authentication is not enabled, load the database from the in-memory database
        else:
            self.in_memory_db.seek(0)
            conn = sqlite3.connect(':memory:')
            conn.executescript(self.in_memory_db.read().decode('utf-8'))
        self.conn = conn
        self.cursor = conn.cursor()

    # Function to get the secret key from the in-memory database
    def get_secret_key_from_in_memory_db(self):
        secret_key_file_name = os.path.basename(os.path.splitext(self.
            db_file_name)[0] + '.secret')
        in_memory_db_content = self.in_memory_db
        if secret_key_file_name.encode() in in_memory_db_content:
            secret_key = in_memory_db_content.split(secret_key_file_name + ': '
                )[1].split('\n')[0]
            return secret_key.encode()
        else:
            return None

    # Function to compress the database into a 7z archive
    def compress_database(self):
        with tempfile.NamedTemporaryFile(delete=False) as temp_db_file:
            temp_db_path = temp_db_file.name
            temp_db_file.write(self.in_memory_db)

        # Compress the database, handling existing archives
        if os.path.exists(self.archive_path):
            temp_dir = tempfile.mkdtemp()
            with py7zr.SevenZipFile(self.archive_path, 'r', password=self.
                user_password) as archive:
                archive.extractall(temp_dir)
            os.remove(self.archive_path)
            with py7zr.SevenZipFile(self.archive_path, 'w', password=self.
                user_password) as archive:
                # Iterate through files and add them to the archive
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if file != os.path.basename(self.db_path):
                            archive.write(file_path, os.path.relpath(
                                file_path, temp_dir))
                        else:
                            os.remove(file_path)
                archive.write(temp_db_path, os.path.basename(self.db_path))
                secret_key_file_name = os.path.splitext(self.db_file_name)[0
                    ] + '.secret'
                secret_key = self.get_secret_key_from_in_memory_db()
                if secret_key:
                    archive.writestr(secret_key_file_name, secret_key)
            shutil.rmtree(temp_dir)
        else:
            # Create a new archive and add the database
            with py7zr.SevenZipFile(self.archive_path, 'w', password=self.
                user_password) as archive:
                archive.write(temp_db_path, os.path.basename(self.db_path))
                secret_key_file_name = os.path.splitext(self.db_file_name)[0
                    ] + '.secret'
                secret_key = self.get_secret_key_from_in_memory_db()
                if secret_key:
                    archive.writestr(secret_key_file_name, secret_key)
        os.remove(temp_db_path)

    # Function to extract the database from a 7z archive
    def extract_database(self):
        with py7zr.SevenZipFile(self.archive_path, mode='r', password=self.
            user_password) as archive:
            file_data = archive.read(self.db_file_name)
            if self.db_file_name in file_data:
                self.in_memory_db = file_data[self.db_file_name]
                self.load_database_from_memory()
            else:
                raise ValueError(
                    f"Database '{self.db_file_name}' not found in the archive."
                    )

    # Function to list all databases in the 7z archive
    def list_databases(self):
        with py7zr.SevenZipFile(self.archive_path, mode='r', password=self.
            user_password) as archive:
            databases = archive.getnames()
        return databases

    # Static method to create a folder for the databases
    @staticmethod
    def create_database_folder(folder_path):
        os.makedirs(folder_path, exist_ok=True)

    # Function to set the database path and check for two-factor authentication
    def set_db_path(self, db_path):
        self.db_path = db_path
        self.check_two_factor_enabled()
        if self.two_factor_enabled:
            temp_db_file_path = os.path.splitext(db_path)[0] + '.db'
            if os.path.exists(temp_db_file_path):
                self.temp_db_path = temp_db_file_path
                self.decrypt_database_file()
            else:
                self.temp_db_path = ':memory:'
        else:
            self.temp_db_path = db_path
        self.conn = self.create_db_connection()

    # Function to check if two-factor authentication is enabled
    def check_two_factor_enabled(self):
        secret_key_file_name = os.path.basename(os.path.splitext(self.
            db_file_name)[0] + '.secret')
        if os.path.exists(self.archive_path):
            with py7zr.SevenZipFile(self.archive_path, 'r', password=self.
                user_password) as archive:
                if secret_key_file_name in archive.getnames():
                    secret_key = archive.read(secret_key_file_name)
                    secret_key = secret_key[secret_key_file_name]
                    self.initialize_totp(secret_key)
                    self.two_factor_enabled = True
                else:
                    self.two_factor_enabled = False
        else:
            self.two_factor_enabled = False

    # Function to create a database connection
    def create_db_connection(self):
        if self.in_memory or not os.path.exists(self.temp_db_path):
            conn = sqlite3.connect('file::memory:?cache=shared', uri=True,
                check_same_thread=False)
            if os.path.exists(self.temp_db_path):
                with open(self.temp_db_path, 'rb') as f:
                    decrypted_content = f.read()
                    conn.executescript(decrypted_content.decode('utf-8'))
        else:
            conn = sqlite3.connect(self.db_path)
        return conn

    # Function to create a new table for storing credentials
    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS credentials
                       (id INTEGER PRIMARY KEY AUTOINCREMENT, website TEXT, email TEXT, username TEXT, password TEXT, notes TEXT, date_saved TEXT)"""
            )
        self.conn.commit()

    # Function to generate a key for encryption using the password and salt
    def generate_key(self, password, salt):
        password = password.encode('utf-8')
        self.salt = salt
        self.key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
        return base64.urlsafe_b64encode(self.key)

    # Function to encrypt text using the key
    def encrypt_text(self, text, key):
        fernet = Fernet(key)
        if isinstance(text, bytes):
            return fernet.encrypt(text)
        else:
            return fernet.encrypt(text.encode('utf-8'))

    # Function to decrypt text using the key
    def decrypt_text(self, text, key):
        fernet = Fernet(key)
        return fernet.decrypt(text).decode('utf-8')

    # Function to generate a random password of a specified length
    def generate_random_password(self, length=12):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        return password

    # Function to add new encrypted credentials to the database
    def add_new_credentials(self, key, credentials):
        encrypted_credentials = [self.encrypt_text(cred, key) for cred in
            credentials]
        self.save_encrypted_credentials(encrypted_credentials)
        if self.two_factor_enabled:
            self.update_encrypted_database_file()
        else:
            self.update_unencrypted_database_file()

    # Function to save the encrypted credentials to the database
    def save_encrypted_credentials(self, encrypted_credentials):
        current_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor = self.conn.cursor()
        cursor.execute(
            'INSERT INTO credentials (website, email, username, password, notes, date_saved) VALUES (?, ?, ?, ?, ?, ?)'
            , (*encrypted_credentials, current_date))
        self.conn.commit()

    # Function to read and decrypt stored credentials using the key
    def read_and_decrypt_credentials(self, key):
        cursor = self.conn.cursor()
        cursor.execute(
            'SELECT id, website, email, username, password, notes, date_saved FROM credentials'
            )
        encrypted_rows = cursor.fetchall()
        decrypted_rows = []
        for row in encrypted_rows:
            decrypted_row = [row[0]]
            decrypted_row.extend([self.decrypt_text(encrypted_data, key) for
                encrypted_data in row[1:-1]])
            decrypted_row.append(row[-1])
            decrypted_rows.append(decrypted_row)
        return decrypted_rows

    # Function to search for credentials based on search terms
    def search_credentials(self, key, search_terms):
        results = []
        for search_term in search_terms:
            search_term = search_term.lower()
            decrypted_credentials = self.read_and_decrypt_credentials(key)
            matching_creds = [cred for cred in decrypted_credentials if any
                (search_term in str(field).lower() for field in cred[1:])]
            results.extend(matching_creds)
        unique_results = []
        for result in results:
            if result not in unique_results:
                unique_results.append(result)
        return unique_results

    # Function to verify if the entered key can decrypt the stored credentials
    def verify_existing_credentials(self, key):
        try:
            self.read_and_decrypt_credentials(key)
            return True
        except Exception:
            return False

    # Function to verify if the entered password is correct
    def verify_password(self, password):
        entered_key = self.generate_key(password, self.salt)
        return self.verify_existing_credentials(entered_key)

    # Function to delete a credential from the database using its ID
    def delete_credential_from_database(self, credential_id):
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM credentials WHERE id = ?', (credential_id,)
            )
        self.conn.commit()

    # Function to generate a random TOTP secret key
    def generate_totp_secret_key(self):
        return pyotp.random_base32()

    # Function to initialize TOTP with the given secret key
    def initialize_totp(self, secret_key):
        try:
            secret_key = secret_key.getvalue()
        except:
            pass
        self.key_2fa = secret_key
        self.totp = pyotp.TOTP(secret_key)

    # Function to verify if the given TOTP matches the generated one
    def verify_totp(self, otp):
        try:
            secret_bytes = otp.getvalue()
        except:
            secret_bytes = otp
        return self.totp.verify(secret_bytes) if self.totp else False

    # Function to save the TOTP secret key to a file
    def save_secret_key_to_file(self, secret_key):
        secret_key_file_name = os.path.basename(os.path.splitext(self.
            db_file_name)[0] + '.secret')
        if os.path.exists(self.archive_path):
            with py7zr.SevenZipFile(self.archive_path, 'a', password=self.
                user_password) as archive:
                archive.writestr(secret_key.encode(), secret_key_file_name)

    # Function to enable two-factor authentication
    def enable_two_factor(self):
        secret_key = self.get_secret_key_from_in_memory_db()
        if secret_key:
            self.initialize_totp(secret_key)
            self.two_factor_enabled = True
        else:
            secret_key = self.generate_totp_secret_key()
            self.save_secret_key_to_file(secret_key)
            self.initialize_totp(secret_key)
            self.two_factor_enabled = True

    # Function to encrypt data with the given key
    @staticmethod
    def encrypt_data(data, key):
        try:
            key = key.encode('utf-8')
        except:
            pass
        backend = default_backend()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_data = base64.b64encode(iv + ciphertext)
        return encrypted_data

    # Function to decrypt encrypted data using the given key
    @staticmethod
    def decrypt_data(encrypted_data, key):
        backend = default_backend()
        decoded_data = base64.b64decode(encrypted_data)
        iv, encrypted_data = decoded_data[:16], decoded_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize(
            )
        unpadder = padding.PKCS7(128).unpadder()
        try:
            unpadded_data = unpadder.update(decrypted_data
                ) + unpadder.finalize()
        except ValueError:
            return None
        return unpadded_data

    # Function to encrypt the entire database file
    def encrypt_database_file(self):
        key = self.key_2fa
        if not self.two_factor_enabled:
            return
        temp_db = sqlite3.connect(':memory:')
        with self.conn:
            self.conn.backup(temp_db)
        temp_db.commit()
        with BytesIO() as content:
            for line in temp_db.iterdump():
                content.write(f'{line}\n'.encode('utf-8'))
            encrypted_content = self.encrypt_data(content.getvalue(), key)
            self.in_memory_db = encrypted_content
            self.compress_database()

    # Function to decrypt the entire database file
    def decrypt_database_file(self):
        key = self.key_2fa
        if not self.two_factor_enabled:
            return
        with py7zr.SevenZipFile(self.archive_path, 'r', password=self.
            user_password) as archive:
            encrypted_content = archive.read(self.db_file_name)
            encrypted_content = encrypted_content[self.db_file_name].getvalue()
        decrypted_content = self.decrypt_data(encrypted_content, key)
        temp_db = sqlite3.connect(':memory:')
        temp_db.executescript(decrypted_content.decode('utf-8'))
        temp_db.commit()
        self.conn = temp_db
        if self.two_factor_enabled:
            return decrypted_content.decode('utf-8')
        else:
            return None

    # Function to update the encrypted database file
    def update_encrypted_database_file(self):
        if not self.two_factor_enabled:
            return
        try:
            self.encrypt_database_file()
        except FileNotFoundError:
            pass

    # Function to update the unencrypted database file
    def update_unencrypted_database_file(self):
        if self.two_factor_enabled:
            return
        temp_db = sqlite3.connect(':memory:')
        with self.conn:
            self.conn.backup(temp_db)
        temp_db.commit()
        with BytesIO() as content:
            for line in temp_db.iterdump():
                content.write(f'{line}\n'.encode('utf-8'))
            self.in_memory_db = content.getvalue()
            self.compress_database()

    # Function to close the database connection
    def close_connection(self):
        if self.conn is not None:
            if self.in_memory and self.two_factor_enabled:
                data_to_encrypt = '\n'.join(self.conn.iterdump())
                if data_to_encrypt:
                    encrypted_content = self.encrypt_data(data_to_encrypt.
                        encode('utf-8'), self.key_2fa)
                    with open(self.db_path, 'wb') as f:
                        f.write(encrypted_content)
                self.conn.commit()
            self.conn.close()
            self.conn = None

    # Function to generate a QR code for the TOTP secret key
    def generate_qr_code(self, provisioning_uri):
        qr = qrcode.QRCode()
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white')
        img_data = BytesIO()
        img.save(img_data, format='PNG')
        img_data.seek(0)
        return img_data

    # Function get existing databases in the 7z archive
    def get_existing_databases(self, folder_path):
        archive_name = f'{self.user_name}.7z'
        archive_path = os.path.join(folder_path, archive_name)
        if os.path.exists(archive_path):
            self.archive_path = archive_path
            databases = self.list_databases()
        else:
            databases = []
        return databases

    # Function to delete a database from the 7z archive
    def delete_database(self, db_name):
        with tempfile.TemporaryDirectory() as temp_dir:
            with py7zr.SevenZipFile(self.archive_path, mode='r', password=
                self.user_password) as archive:
                archive.extractall(path=temp_dir)
            db_path = os.path.join(temp_dir, db_name)
            if os.path.exists(db_path):
                os.remove(db_path)
            else:
                raise ValueError('Database not found in the archive.')
            secret_file_path = os.path.join(temp_dir,
                f'{os.path.splitext(db_name)[0]}.secret')
            if os.path.exists(secret_file_path):
                os.remove(secret_file_path)
            os.remove(self.archive_path)
            with py7zr.SevenZipFile(self.archive_path, mode='w', password=
                self.user_password) as new_archive:
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        new_archive.write(file_path, os.path.relpath(
                            file_path, temp_dir))