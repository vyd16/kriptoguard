import os
import struct
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# Constants
CHUNK_SIZE = 65536  # 64 KB chunks
MAGIC_FILE = b"KGF1"
MAGIC_TEXT = b"KGT1"

def derive_key(password: str = None, salt: bytes = None, keyfile_data: bytes = None) -> tuple[bytes, bytes]:
    """
    Derives a 256-bit AES key from a password (using PBKDF2) and/or a key file.
    Returns (key, salt).
    """
    if not password and not keyfile_data:
        raise ValueError("Password atau file kunci (.key) harus disediakan.")

    pwd_key = None
    derived_salt = salt

    # 1. Derive key from password if provided
    if password:
        if not derived_salt:
            derived_salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=derived_salt,
            iterations=100000
        )
        pwd_key = kdf.derive(password.encode('utf-8'))

    # 2. Derive key from keyfile if provided
    kf_key = None
    if keyfile_data:
        # Hash the keyfile data to ensure it is exactly 32 bytes
        kf_key = hashlib.sha256(keyfile_data).digest()

    # 3. Combine keys if both are provided
    if pwd_key and kf_key:
        final_key = hashlib.sha256(pwd_key + kf_key).digest()
    elif pwd_key:
        final_key = pwd_key
    else:
        final_key = kf_key

    return final_key, derived_salt

def encrypt_file_stream(input_path: str, output_path: str, password: str = None, keyfile_data: bytes = None):
    """
    Encrypts a file chunk-by-chunk using AES-256-GCM.
    Supports streaming for unlimited file size.
    """
    # Determine mode byte:
    # Bit 0 (value 1): Password used
    # Bit 1 (value 2): Keyfile used
    mode = 0
    if password:
        mode |= 1
    if keyfile_data:
        mode |= 2

    # Derive key and salt
    key, salt = derive_key(password, None, keyfile_data)
    aesgcm = AESGCM(key)

    with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        # 1. Write Magic Bytes
        outfile.write(MAGIC_FILE)
        # 2. Write Mode Byte
        outfile.write(bytes([mode]))
        # 3. Write Salt (16 bytes) if password used
        if password:
            outfile.write(salt)

        # 4. Read ahead and encrypt in chunks
        chunk = infile.read(CHUNK_SIZE)
        while chunk:
            next_chunk = infile.read(CHUNK_SIZE)
            is_last = len(next_chunk) == 0
            
            # Last chunk flag: 1 if last chunk, 0 otherwise
            flag = b"\x01" if is_last else b"\x00"
            outfile.write(flag)

            # Generate random 12-byte nonce
            nonce = os.urandom(12)
            outfile.write(nonce)

            # Encrypt current chunk
            ciphertext = aesgcm.encrypt(nonce, chunk, None)
            
            # Write ciphertext length (4 bytes, big-endian)
            outfile.write(struct.pack(">I", len(ciphertext)))
            # Write ciphertext + tag
            outfile.write(ciphertext)

            chunk = next_chunk

def decrypt_file_stream(input_path: str, output_path: str, password: str = None, keyfile_data: bytes = None):
    """
    Decrypts a file chunk-by-chunk using AES-256-GCM.
    Raises ValueError on incorrect key, password, tampering, or truncation.
    """
    with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        # 1. Verify Magic Bytes
        magic = infile.read(4)
        if magic != MAGIC_FILE:
            raise ValueError("Format file tidak dikenali. Ini bukan file KriptoGuard yang valid.")

        # 2. Read Mode Byte
        mode_byte = infile.read(1)
        if not mode_byte:
            raise ValueError("File rusak: Metadata mode tidak lengkap.")
        mode = mode_byte[0]

        has_password = bool(mode & 1)
        has_keyfile = bool(mode & 2)

        if has_password and not password:
            raise ValueError("File ini dienkripsi menggunakan password. Harap masukkan password.")
        if has_keyfile and not keyfile_data:
            raise ValueError("File ini dienkripsi menggunakan file kunci (.key). Harap unggah file kunci Anda.")

        # 3. Read Salt if password was used
        salt = None
        if has_password:
            salt = infile.read(16)
            if len(salt) < 16:
                raise ValueError("File rusak: Data salt tidak lengkap.")

        # Derive key
        try:
            key, _ = derive_key(password, salt, keyfile_data)
        except Exception as e:
            raise ValueError(f"Gagal memproses kunci: {str(e)}")

        aesgcm = AESGCM(key)

        # 4. Decrypt chunks
        while True:
            # Read last chunk flag
            flag_byte = infile.read(1)
            if not flag_byte:
                raise ValueError("File terpotong atau tidak lengkap: tidak ditemukan flag akhir.")
            flag = flag_byte[0]

            if flag not in (0, 1):
                raise ValueError("File terpotong atau rusak: flag chunk tidak valid.")

            # Read nonce
            nonce = infile.read(12)
            if len(nonce) < 12:
                raise ValueError("File terpotong atau rusak: data nonce tidak lengkap.")

            # Read ciphertext length
            len_bytes = infile.read(4)
            if len(len_bytes) < 4:
                raise ValueError("File terpotong atau rusak: ukuran ciphertext tidak lengkap.")
            length = struct.unpack(">I", len_bytes)[0]

            # Read ciphertext + tag
            ciphertext = infile.read(length)
            if len(ciphertext) < length:
                raise ValueError("File terpotong atau rusak: data ciphertext tidak lengkap.")

            # Decrypt
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            except InvalidTag:
                raise ValueError("Gagal mendekripsi: Kata sandi salah, file kunci tidak cocok, atau file telah dimodifikasi.")

            outfile.write(plaintext)

            # Check if this was the last chunk
            if flag == 1:
                # Ensure no trailing data exists
                extra = infile.read(1)
                if extra:
                    raise ValueError("Peringatan keamanan: Data tambahan terdeteksi setelah akhir file resmi (kemungkinan sabotase).")
                break

def encrypt_text(text: str, password: str = None, keyfile_data: bytes = None) -> bytes:
    """
    Encrypts text and returns binary packet.
    """
    text_bytes = text.encode('utf-8')
    mode = 0
    if password:
        mode |= 1
    if keyfile_data:
        mode |= 2

    key, salt = derive_key(password, None, keyfile_data)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, text_bytes, None)

    # Assemble packet
    packet = bytearray()
    packet.extend(MAGIC_TEXT)
    packet.append(mode)
    if password:
        packet.extend(salt)
    packet.extend(nonce)
    packet.extend(ciphertext)

    return bytes(packet)

def decrypt_text(encrypted_bytes: bytes, password: str = None, keyfile_data: bytes = None) -> str:
    """
    Decrypts binary text packet and returns string.
    """
    if len(encrypted_bytes) < 5:
        raise ValueError("Data terenkripsi terlalu pendek.")

    # 1. Verify Magic
    magic = encrypted_bytes[:4]
    if magic != MAGIC_TEXT:
        raise ValueError("Format teks tidak dikenali sebagai KriptoGuard yang valid.")

    # 2. Read Mode
    mode = encrypted_bytes[4]
    has_password = bool(mode & 1)
    has_keyfile = bool(mode & 2)

    if has_password and not password:
        raise ValueError("Pesan ini dienkripsi menggunakan password. Harap masukkan password.")
    if has_keyfile and not keyfile_data:
        raise ValueError("Pesan ini dienkripsi menggunakan file kunci (.key). Harap unggah file kunci Anda.")

    offset = 5

    # 3. Read Salt if password was used
    salt = None
    if has_password:
        if len(encrypted_bytes) < offset + 16:
            raise ValueError("Data terenkripsi rusak (salt tidak lengkap).")
        salt = encrypted_bytes[offset:offset+16]
        offset += 16

    # Derive key
    key, _ = derive_key(password, salt, keyfile_data)
    aesgcm = AESGCM(key)

    # 4. Read Nonce
    if len(encrypted_bytes) < offset + 12:
        raise ValueError("Data terenkripsi rusak (nonce tidak lengkap).")
    nonce = encrypted_bytes[offset:offset+12]
    offset += 12

    # 5. Read Ciphertext
    ciphertext = encrypted_bytes[offset:]

    # Decrypt
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Gagal mendekripsi: Kata sandi salah, file kunci tidak cocok, atau teks telah dimodifikasi.")

    return plaintext.decode('utf-8')
