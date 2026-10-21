import hashlib
import json
import os
import secrets
import shutil
import struct
import subprocess
import sys
import tarfile
import threading
import unicodedata

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD

    DND_AVAILABLE = True
except ImportError:
    DND_AVAILABLE = False


APP_NAME = "Tenna's File Encrypter"
ENC_EXT = ".encrypted"

MAGIC = b"TFE2"
ARGON_ITERATIONS = 3
ARGON_LOG_MEMORY = 18
ARGON_LANES = 4
CHUNK_SIZE = 1024 * 1024
TAG_SIZE = 16

HEADER_FMT = ">4sBBB32s7sI"
HEADER_LEN = struct.calcsize(HEADER_FMT)

PASSWORD_ALPHABET = (
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*-_=+?"
)


class NotEncryptedFileError(Exception):
    pass


class WrongPasswordError(Exception):
    pass


class CorruptFileError(Exception):
    pass


class VerificationError(Exception):
    pass


class FolderNotAllowedError(Exception):
    pass


def generate_password(length=20):
    return "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(length))


def get_desktop_dir():
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", wintypes.DWORD),
                    ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8),
                ]

            desktop_id = GUID(
                0xB4BFCC3A, 0xDB2C, 0x424C,
                (ctypes.c_ubyte * 8)(0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41),
            )
            buf = ctypes.c_wchar_p()
            result = ctypes.windll.shell32.SHGetKnownFolderPath(
                ctypes.byref(desktop_id), 0, None, ctypes.byref(buf)
            )
            if result == 0:
                path = buf.value
                ctypes.windll.ole32.CoTaskMemFree(buf)
                if path and os.path.isdir(path):
                    return path
        except Exception:
            pass
    candidate = os.path.join(home, "Desktop")
    return candidate if os.path.isdir(candidate) else home


def unique_path(directory, filename):
    base, ext = os.path.splitext(filename)
    candidate = os.path.join(directory, filename)
    n = 1
    while os.path.exists(candidate) or os.path.exists(candidate + ".part"):
        candidate = os.path.join(directory, f"{base} ({n}){ext}")
        n += 1
    return candidate


def safe_filename(name):
    name = os.path.basename(str(name).replace("\\", "/"))
    name = "".join(c for c in name if ord(c) >= 32 and c not in '<>:"/\\|?*')
    name = name.rstrip(" .")
    return name or "decrypted_item"


def _inside(child, parent):
    try:
        child = os.path.normcase(os.path.realpath(child))
        parent = os.path.normcase(os.path.realpath(parent))
        return os.path.commonpath([child, parent]) == parent
    except ValueError:
        return False


def folder_is_allowed(path, desktop):
    path = os.path.realpath(path)
    if os.path.dirname(path) == path:
        return False
    for protected in (desktop, os.path.expanduser("~")):
        if _inside(protected, path):
            return False
    for var in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
        system_dir = os.environ.get(var)
        if system_dir and _inside(path, system_dir):
            return False
    return True


def _derive_key(password, salt, iterations, log_memory, lanes):
    pw = unicodedata.normalize("NFKC", password).encode("utf-8")
    return Argon2id(
        salt=salt, length=32, iterations=iterations,
        lanes=lanes, memory_cost=2 ** log_memory,
    ).derive(pw)


def _nonce(prefix, counter, final):
    return prefix + counter.to_bytes(4, "big") + (b"\x01" if final else b"\x00")


def _parse_header(raw):
    if len(raw) != HEADER_LEN:
        raise NotEncryptedFileError()
    magic, iterations, log_memory, lanes, salt, prefix, chunk = struct.unpack(HEADER_FMT, raw)
    if (
        magic != MAGIC
        or not 1 <= iterations <= 10
        or not 12 <= log_memory <= 20
        or not 1 <= lanes <= 16
        or not 4096 <= chunk <= 16 * 1024 * 1024
    ):
        raise NotEncryptedFileError()
    return iterations, log_memory, lanes, salt, prefix, chunk


def is_encrypted_file(path):
    try:
        with open(path, "rb") as f:
            _parse_header(f.read(HEADER_LEN))
        return True
    except Exception:
        return False


def _is_link(path):
    return os.path.islink(path) or getattr(os.path, "isjunction", lambda p: False)(path)


def _raise(error):
    raise error


def _scan_folder(folder):
    entries, skipped, total = [], [], 0
    for current, dirnames, filenames in os.walk(folder, onerror=_raise):
        dirnames.sort()
        filenames.sort()
        rel = os.path.relpath(current, folder)
        prefix = "" if rel == "." else rel.replace(os.sep, "/") + "/"
        kept = []
        for name in dirnames:
            full = os.path.join(current, name)
            if _is_link(full):
                skipped.append(full)
            else:
                kept.append(name)
                entries.append((prefix + name, full, True, 0))
        dirnames[:] = kept
        for name in filenames:
            full = os.path.join(current, name)
            if _is_link(full) or not os.path.isfile(full):
                skipped.append(full)
                continue
            size = os.path.getsize(full)
            entries.append((prefix + name, full, False, size))
            total += size
    return entries, skipped, total


class _ProgressFile:
    def __init__(self, f, on_read):
        self._f = f
        self._on_read = on_read

    def read(self, size=-1):
        data = self._f.read(size)
        self._on_read(len(data))
        return data


class _HashWriter:
    def __init__(self):
        self._hash = hashlib.sha256()

    def write(self, data):
        self._hash.update(data)
        return len(data)

    def digest(self):
        return self._hash.digest()


def build_tar(folder, writer, progress=None):
    entries, skipped, total = _scan_folder(folder)
    done = 0

    def on_read(count):
        nonlocal done
        done += count
        if progress:
            progress(min(done / max(total, 1), 1.0))

    with tarfile.open(fileobj=writer, mode="w|", format=tarfile.PAX_FORMAT) as tar:
        for arcname, full, is_dir, size in entries:
            info = tarfile.TarInfo(arcname)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            if is_dir:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.mtime = 0
                tar.addfile(info)
            else:
                info.size = size
                info.mode = 0o644
                info.mtime = int(os.path.getmtime(full))
                with open(full, "rb") as f:
                    tar.addfile(info, _ProgressFile(f, on_read))
    return skipped


class _PlainReader:
    def __init__(self, chunks):
        self._chunks = iter(chunks)
        self._buffer = b""

    def read(self, size=-1):
        if size is None or size < 0:
            data = self._buffer + b"".join(self._chunks)
            self._buffer = b""
            return data
        while len(self._buffer) < size:
            try:
                self._buffer += next(self._chunks)
            except StopIteration:
                break
        data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data


def _extract_tar_stream(reader, dest):
    root = os.path.realpath(dest)
    try:
        with tarfile.open(fileobj=reader, mode="r|") as tar:
            for member in tar:
                parts = [
                    p for p in member.name.replace("\\", "/").split("/") if p not in ("", ".")
                ]
                if not parts or ".." in parts:
                    raise CorruptFileError()
                if os.name == "nt" and any(":" in p for p in parts):
                    raise CorruptFileError()
                target = os.path.realpath(os.path.join(root, *parts))
                if target == root or not _inside(target, root):
                    raise CorruptFileError()
                if member.isdir():
                    os.makedirs(target, exist_ok=True)
                elif member.isfile():
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    source = tar.extractfile(member)
                    with open(target, "wb") as out:
                        shutil.copyfileobj(source, out, CHUNK_SIZE)
                    try:
                        os.utime(target, (member.mtime, member.mtime))
                    except (OSError, OverflowError, ValueError):
                        pass
    except tarfile.TarError:
        raise CorruptFileError()


class _ChunkEncryptor:
    def __init__(self, fout, aes, prefix, header):
        self._fout = fout
        self._aes = aes
        self._prefix = prefix
        self._header = header
        self._buffer = bytearray()
        self._counter = 1

    def write(self, data):
        self._buffer += data
        while len(self._buffer) > CHUNK_SIZE:
            self._emit(bytes(self._buffer[:CHUNK_SIZE]), False)
            del self._buffer[:CHUNK_SIZE]
        return len(data)

    def finish(self):
        self._emit(bytes(self._buffer), True)
        self._buffer.clear()

    def _emit(self, chunk, final):
        nonce = _nonce(self._prefix, self._counter, final)
        self._fout.write(self._aes.encrypt(nonce, chunk, self._header))
        self._counter += 1


def _write_encrypted(out_path, password, meta, produce):
    tmp_path = out_path + ".part"
    salt = os.urandom(32)
    prefix = os.urandom(7)
    header = struct.pack(
        HEADER_FMT, MAGIC, ARGON_ITERATIONS, ARGON_LOG_MEMORY, ARGON_LANES,
        salt, prefix, CHUNK_SIZE,
    )
    key = _derive_key(password, salt, ARGON_ITERATIONS, ARGON_LOG_MEMORY, ARGON_LANES)
    aes = AESGCM(key)
    try:
        with open(tmp_path, "wb") as fout:
            fout.write(header)
            meta_ct = aes.encrypt(
                _nonce(prefix, 0, False), json.dumps(meta).encode("utf-8"), header
            )
            fout.write(struct.pack(">H", len(meta_ct)))
            fout.write(meta_ct)
            encryptor = _ChunkEncryptor(fout, aes, prefix, header)
            produce(encryptor)
            encryptor.finish()
            fout.flush()
            os.fsync(fout.fileno())
        os.replace(tmp_path, out_path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def encrypt_path(src_path, out_dir, password, progress=None):
    src_path = os.path.abspath(src_path)
    is_dir = os.path.isdir(src_path)
    if is_dir and not folder_is_allowed(src_path, out_dir):
        raise FolderNotAllowedError()
    name = os.path.basename(src_path.rstrip("\\/")) or "folder"
    out_path = unique_path(out_dir, name + ENC_EXT)
    meta = {"name": name, "kind": "dir" if is_dir else "file"}

    def produce(encryptor):
        if is_dir:
            build_tar(src_path, encryptor, progress)
            return
        total = max(os.path.getsize(src_path), 1)
        done = 0
        with open(src_path, "rb") as fin:
            while True:
                block = fin.read(CHUNK_SIZE)
                if not block:
                    break
                encryptor.write(block)
                done += len(block)
                if progress:
                    progress(done / total)

    _write_encrypted(out_path, password, meta, produce)
    return out_path


def _decrypt_stream(src_path, password, progress=None):
    total = max(os.path.getsize(src_path), 1)
    with open(src_path, "rb") as fin:
        header = fin.read(HEADER_LEN)
        iterations, log_memory, lanes, salt, prefix, chunk = _parse_header(header)
        aes = AESGCM(_derive_key(password, salt, iterations, log_memory, lanes))

        raw_len = fin.read(2)
        if len(raw_len) != 2:
            raise CorruptFileError()
        (meta_len,) = struct.unpack(">H", raw_len)
        meta_ct = fin.read(meta_len)
        if meta_len < TAG_SIZE or len(meta_ct) != meta_len:
            raise CorruptFileError()
        try:
            meta = aes.decrypt(_nonce(prefix, 0, False), meta_ct, header)
        except InvalidTag:
            raise WrongPasswordError()
        try:
            info = json.loads(meta.decode("utf-8"))
            name = safe_filename(info["name"])
            kind = info["kind"]
            if kind not in ("file", "dir"):
                raise ValueError()
        except Exception:
            raise CorruptFileError()

        yield {"name": name, "kind": kind}

        enc_chunk = chunk + TAG_SIZE
        counter = 1
        current = fin.read(enc_chunk)
        if not current:
            raise CorruptFileError()
        while True:
            following = fin.read(enc_chunk)
            final = not following
            try:
                plain = aes.decrypt(_nonce(prefix, counter, final), current, header)
            except InvalidTag:
                raise CorruptFileError()
            if progress:
                progress(min(fin.tell() / total, 1.0))
            yield plain
            if final:
                break
            current = following
            counter += 1


def decrypt_path(src_path, out_dir, password, progress=None):
    stream = _decrypt_stream(src_path, password, progress)
    meta = next(stream)
    out_path = unique_path(out_dir, meta["name"])
    tmp_path = out_path + ".part"
    try:
        if meta["kind"] == "dir":
            os.makedirs(tmp_path)
            _extract_tar_stream(_PlainReader(stream), tmp_path)
            for _ in stream:
                pass
        else:
            with open(tmp_path, "wb") as fout:
                for plain in stream:
                    fout.write(plain)
                fout.flush()
                os.fsync(fout.fileno())
        os.replace(tmp_path, out_path)
    except BaseException:
        if os.path.isdir(tmp_path):
            shutil.rmtree(tmp_path, ignore_errors=True)
        elif os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise
    return out_path


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(block)
    return h.digest()


def delete_original_if_verified(src_path, enc_path, password, progress=None):
    try:
        stream = _decrypt_stream(enc_path, password, progress)
        meta = next(stream)
        h = hashlib.sha256()
        for plain in stream:
            h.update(plain)
    except (NotEncryptedFileError, WrongPasswordError, CorruptFileError):
        raise VerificationError()
    if os.path.isdir(src_path):
        if meta["kind"] != "dir":
            raise VerificationError()
        hasher = _HashWriter()
        skipped = build_tar(src_path, hasher)
        if hasher.digest() != h.digest():
            raise VerificationError()
        if skipped:
            raise OSError("the folder contains links that were not included in the encrypted copy")
        shutil.rmtree(src_path)
    else:
        if meta["kind"] != "file" or h.digest() != _sha256_file(src_path):
            raise VerificationError()
        os.remove(src_path)


STRINGS = {
    "en": {
        "nav_home": "Home",
        "nav_encrypt": "Encrypt",
        "nav_decrypt": "Decrypt",
        "home_encrypt_sub": "Protect files and folders with a password",
        "home_decrypt_sub": "Restore files and folders you encrypted",
        "btn_encrypt": "Encrypt",
        "btn_decrypt": "Decrypt",
        "title_encrypt": "Encrypt a File or Folder",
        "title_decrypt": "Decrypt a File or Folder",
        "drop_encrypt": "Drag & drop a file or folder here",
        "drop_decrypt": "Drag & drop an encrypted file here",
        "drop_click": "Click to browse",
        "select_file": "Select File",
        "select_folder": "Select Folder",
        "delete_original": "Delete the original after encryption",
        "pick_file": "Select a file to encrypt",
        "pick_folder": "Select a folder to encrypt",
        "pick_decrypt": "Select an encrypted file",
        "filetype_enc": "Encrypted files",
        "filetype_all": "All files",
        "err_not_found": "The selected item could not be found.",
        "err_folder_decrypt": "Please select an encrypted file, not a folder.",
        "err_not_ours": "This file was not encrypted with Tenna's File Encrypter.",
        "err_folder_not_allowed": (
            "This folder cannot be encrypted because it contains your Desktop or your "
            "user folder, or is a system folder. Please choose another folder."
        ),
        "set_password": "Set a Password",
        "enter_password": "Enter Password",
        "file_label": "File: {name}",
        "folder_label": "Folder: {name}",
        "auto_password": "Generate a secure password for me",
        "password": "Password",
        "confirm_password": "Confirm password",
        "show_password": "Show password",
        "back": "\u2190 Back",
        "action_encrypt": "Encrypt",
        "action_decrypt": "Decrypt",
        "err_empty_password": "Please enter a password.",
        "err_mismatch": "Passwords do not match.",
        "err_enter_password": "Please enter the password.",
        "warn_title": "Important",
        "warn_generated": (
            "Write down the password generated for you by the program and keep it "
            "in a safe place. Otherwise, you may not be able to access this file again."
        ),
        "warn_typed": (
            "Write down the password you entered and keep it in a safe place. "
            "Otherwise, you may not be able to access the file you are about to "
            "encrypt again."
        ),
        "your_password": "Your password:",
        "copy": "Copy",
        "copied": "Copied!",
        "cancel": "Cancel",
        "confirm": "Confirm",
        "working_encrypt": "Encrypting...",
        "working_decrypt": "Decrypting...",
        "wait_close": "Please wait until the process is finished.",
        "done": "Process completed.\n\nSaved to your Desktop as:\n{name}",
        "original_deleted": "\n\nThe original was deleted.",
        "original_not_deleted": "\n\nThe original could not be deleted:\n{error}",
        "verify_failed": (
            "The encrypted copy could not be verified, so it was discarded and "
            "your original was kept. Please try again."
        ),
        "wrong_password": "Wrong password, please try again.",
        "corrupt": "This file is damaged or has been modified, so it cannot be decrypted.",
        "error": "Something went wrong:\n{error}",
    },
    "tr": {
        "nav_home": "Ana Sayfa",
        "nav_encrypt": "Şifrele",
        "nav_decrypt": "Çöz",
        "home_encrypt_sub": "Dosya ve klasörlerinizi şifreyle koruyun",
        "home_decrypt_sub": "Şifrelediğiniz dosya ve klasörleri geri açın",
        "btn_encrypt": "Şifrele",
        "btn_decrypt": "Çöz",
        "title_encrypt": "Dosya veya Klasör Şifrele",
        "title_decrypt": "Dosya veya Klasör Çöz",
        "drop_encrypt": "Bir dosyayı veya klasörü buraya sürükleyip bırakın",
        "drop_decrypt": "Şifreli dosyayı buraya sürükleyip bırakın",
        "drop_click": "Seçmek için tıklayın",
        "select_file": "Dosya Seç",
        "select_folder": "Klasör Seç",
        "delete_original": "Şifreledikten sonra orijinali sil",
        "pick_file": "Şifrelenecek dosyayı seçin",
        "pick_folder": "Şifrelenecek klasörü seçin",
        "pick_decrypt": "Şifreli dosyayı seçin",
        "filetype_enc": "Şifreli dosyalar",
        "filetype_all": "Tüm dosyalar",
        "err_not_found": "Seçilen öğe bulunamadı.",
        "err_folder_decrypt": "Lütfen klasör değil, şifreli bir dosya seçin.",
        "err_not_ours": "Bu dosya Tenna's File Encrypter ile şifrelenmemiş.",
        "err_folder_not_allowed": (
            "Bu klasör Masaüstünüzü ya da kullanıcı klasörünüzü içerdiği veya bir sistem "
            "klasörü olduğu için şifrelenemez. Lütfen başka bir klasör seçin."
        ),
        "set_password": "Şifre Belirle",
        "enter_password": "Şifreyi Girin",
        "file_label": "Dosya: {name}",
        "folder_label": "Klasör: {name}",
        "auto_password": "Benim için güvenli bir şifre oluştur",
        "password": "Şifre",
        "confirm_password": "Şifreyi tekrar yazın",
        "show_password": "Şifreyi göster",
        "back": "\u2190 Geri",
        "action_encrypt": "Şifrele",
        "action_decrypt": "Çöz",
        "err_empty_password": "Lütfen bir şifre girin.",
        "err_mismatch": "Şifreler eşleşmiyor.",
        "err_enter_password": "Lütfen şifreyi girin.",
        "warn_title": "Önemli",
        "warn_generated": (
            "Programın sizin için oluşturduğu şifreyi not edin ve güvenli bir şekilde "
            "muhafaza edin, yoksa bu dosyaya bir daha erişemeyebilirsiniz."
        ),
        "warn_typed": (
            "Yazdığınız şifreyi bir yere not edin ve güvenli bir şekilde muhafaza edin, "
            "yoksa şifreleyeceğiniz dosyaya bir daha erişemeyebilirsiniz."
        ),
        "your_password": "Şifreniz:",
        "copy": "Kopyala",
        "copied": "Kopyalandı!",
        "cancel": "İptal",
        "confirm": "Onayla",
        "working_encrypt": "Şifreleniyor...",
        "working_decrypt": "Çözülüyor...",
        "wait_close": "Lütfen işlem bitene kadar bekleyin.",
        "done": "İşlem tamamlandı.\n\nMasaüstünüze şu adla kaydedildi:\n{name}",
        "original_deleted": "\n\nOrijinal silindi.",
        "original_not_deleted": "\n\nOrijinal silinemedi:\n{error}",
        "verify_failed": (
            "Şifreli kopya doğrulanamadı, bu yüzden silindi ve orijinaliniz korundu. "
            "Lütfen tekrar deneyin."
        ),
        "wrong_password": "Şifre yanlış, tekrar deneyin.",
        "corrupt": "Bu dosya bozulmuş ya da değiştirilmiş, bu yüzden çözülemiyor.",
        "error": "Bir şeyler ters gitti:\n{error}",
    },
    "de": {
        "nav_home": "Startseite",
        "nav_encrypt": "Verschlüsseln",
        "nav_decrypt": "Entschlüsseln",
        "home_encrypt_sub": "Schützen Sie Dateien und Ordner mit einem Passwort",
        "home_decrypt_sub": "Stellen Sie verschlüsselte Dateien und Ordner wieder her",
        "btn_encrypt": "Verschlüsseln",
        "btn_decrypt": "Entschlüsseln",
        "title_encrypt": "Datei oder Ordner verschlüsseln",
        "title_decrypt": "Datei oder Ordner entschlüsseln",
        "drop_encrypt": "Datei oder Ordner hierher ziehen und ablegen",
        "drop_decrypt": "Verschlüsselte Datei hierher ziehen und ablegen",
        "drop_click": "Zum Auswählen klicken",
        "select_file": "Datei auswählen",
        "select_folder": "Ordner auswählen",
        "delete_original": "Original nach dem Verschlüsseln löschen",
        "pick_file": "Datei zum Verschlüsseln auswählen",
        "pick_folder": "Ordner zum Verschlüsseln auswählen",
        "pick_decrypt": "Verschlüsselte Datei auswählen",
        "filetype_enc": "Verschlüsselte Dateien",
        "filetype_all": "Alle Dateien",
        "err_not_found": "Das ausgewählte Element wurde nicht gefunden.",
        "err_folder_decrypt": "Bitte wählen Sie eine verschlüsselte Datei aus, keinen Ordner.",
        "err_not_ours": "Diese Datei wurde nicht mit Tenna's File Encrypter verschlüsselt.",
        "err_folder_not_allowed": (
            "Dieser Ordner kann nicht verschlüsselt werden, weil er Ihren Desktop oder "
            "Ihren Benutzerordner enthält oder ein Systemordner ist. Bitte wählen Sie "
            "einen anderen Ordner."
        ),
        "set_password": "Passwort festlegen",
        "enter_password": "Passwort eingeben",
        "file_label": "Datei: {name}",
        "folder_label": "Ordner: {name}",
        "auto_password": "Sicheres Passwort für mich erstellen",
        "password": "Passwort",
        "confirm_password": "Passwort bestätigen",
        "show_password": "Passwort anzeigen",
        "back": "\u2190 Zurück",
        "action_encrypt": "Verschlüsseln",
        "action_decrypt": "Entschlüsseln",
        "err_empty_password": "Bitte geben Sie ein Passwort ein.",
        "err_mismatch": "Die Passwörter stimmen nicht überein.",
        "err_enter_password": "Bitte geben Sie das Passwort ein.",
        "warn_title": "Wichtig",
        "warn_generated": (
            "Notieren Sie sich das vom Programm erstellte Passwort und bewahren Sie es "
            "sicher auf. Andernfalls können Sie möglicherweise nicht mehr auf diese "
            "Datei zugreifen."
        ),
        "warn_typed": (
            "Notieren Sie sich das eingegebene Passwort und bewahren Sie es sicher auf. "
            "Andernfalls können Sie möglicherweise nicht mehr auf die Datei zugreifen, "
            "die Sie gleich verschlüsseln."
        ),
        "your_password": "Ihr Passwort:",
        "copy": "Kopieren",
        "copied": "Kopiert!",
        "cancel": "Abbrechen",
        "confirm": "Bestätigen",
        "working_encrypt": "Verschlüsselung läuft...",
        "working_decrypt": "Entschlüsselung läuft...",
        "wait_close": "Bitte warten Sie, bis der Vorgang abgeschlossen ist.",
        "done": "Vorgang abgeschlossen.\n\nAuf Ihrem Desktop gespeichert als:\n{name}",
        "original_deleted": "\n\nDas Original wurde gelöscht.",
        "original_not_deleted": "\n\nDas Original konnte nicht gelöscht werden:\n{error}",
        "verify_failed": (
            "Die verschlüsselte Kopie konnte nicht überprüft werden. Sie wurde verworfen "
            "und Ihr Original wurde behalten. Bitte versuchen Sie es erneut."
        ),
        "wrong_password": "Falsches Passwort, bitte versuchen Sie es erneut.",
        "corrupt": "Diese Datei ist beschädigt oder wurde verändert und kann nicht entschlüsselt werden.",
        "error": "Etwas ist schiefgelaufen:\n{error}",
    },
    "fr": {
        "nav_home": "Accueil",
        "nav_encrypt": "Chiffrer",
        "nav_decrypt": "Déchiffrer",
        "home_encrypt_sub": "Protégez vos fichiers et dossiers avec un mot de passe",
        "home_decrypt_sub": "Restaurez vos fichiers et dossiers chiffrés",
        "btn_encrypt": "Chiffrer",
        "btn_decrypt": "Déchiffrer",
        "title_encrypt": "Chiffrer un fichier ou un dossier",
        "title_decrypt": "Déchiffrer un fichier ou un dossier",
        "drop_encrypt": "Glissez-déposez un fichier ou un dossier ici",
        "drop_decrypt": "Glissez-déposez un fichier chiffré ici",
        "drop_click": "Cliquez pour parcourir",
        "select_file": "Choisir un fichier",
        "select_folder": "Choisir un dossier",
        "delete_original": "Supprimer l'original après le chiffrement",
        "pick_file": "Sélectionnez un fichier à chiffrer",
        "pick_folder": "Sélectionnez un dossier à chiffrer",
        "pick_decrypt": "Sélectionnez un fichier chiffré",
        "filetype_enc": "Fichiers chiffrés",
        "filetype_all": "Tous les fichiers",
        "err_not_found": "L'élément sélectionné est introuvable.",
        "err_folder_decrypt": "Veuillez sélectionner un fichier chiffré, pas un dossier.",
        "err_not_ours": "Ce fichier n'a pas été chiffré avec Tenna's File Encrypter.",
        "err_folder_not_allowed": (
            "Ce dossier ne peut pas être chiffré, car il contient votre Bureau ou votre "
            "dossier utilisateur, ou c'est un dossier système. Veuillez choisir un autre "
            "dossier."
        ),
        "set_password": "Définir un mot de passe",
        "enter_password": "Saisir le mot de passe",
        "file_label": "Fichier : {name}",
        "folder_label": "Dossier : {name}",
        "auto_password": "Générer un mot de passe sécurisé pour moi",
        "password": "Mot de passe",
        "confirm_password": "Confirmer le mot de passe",
        "show_password": "Afficher le mot de passe",
        "back": "\u2190 Retour",
        "action_encrypt": "Chiffrer",
        "action_decrypt": "Déchiffrer",
        "err_empty_password": "Veuillez saisir un mot de passe.",
        "err_mismatch": "Les mots de passe ne correspondent pas.",
        "err_enter_password": "Veuillez saisir le mot de passe.",
        "warn_title": "Important",
        "warn_generated": (
            "Notez le mot de passe généré par le programme et conservez-le en lieu sûr. "
            "Sinon, vous risquez de ne plus pouvoir accéder à ce fichier."
        ),
        "warn_typed": (
            "Notez le mot de passe que vous avez saisi et conservez-le en lieu sûr. "
            "Sinon, vous risquez de ne plus pouvoir accéder au fichier que vous allez "
            "chiffrer."
        ),
        "your_password": "Votre mot de passe :",
        "copy": "Copier",
        "copied": "Copié !",
        "cancel": "Annuler",
        "confirm": "Confirmer",
        "working_encrypt": "Chiffrement en cours...",
        "working_decrypt": "Déchiffrement en cours...",
        "wait_close": "Veuillez patienter jusqu'à la fin de l'opération.",
        "done": "Opération terminée.\n\nEnregistré sur votre Bureau sous :\n{name}",
        "original_deleted": "\n\nL'original a été supprimé.",
        "original_not_deleted": "\n\nImpossible de supprimer l'original :\n{error}",
        "verify_failed": (
            "La copie chiffrée n'a pas pu être vérifiée ; elle a été supprimée et votre "
            "original a été conservé. Veuillez réessayer."
        ),
        "wrong_password": "Mot de passe incorrect, veuillez réessayer.",
        "corrupt": "Ce fichier est endommagé ou a été modifié ; il ne peut pas être déchiffré.",
        "error": "Une erreur s'est produite :\n{error}",
    },
    "zh": {
        "nav_home": "主页",
        "nav_encrypt": "加密",
        "nav_decrypt": "解密",
        "home_encrypt_sub": "使用密码保护文件和文件夹",
        "home_decrypt_sub": "恢复已加密的文件和文件夹",
        "btn_encrypt": "加密",
        "btn_decrypt": "解密",
        "title_encrypt": "加密文件或文件夹",
        "title_decrypt": "解密文件或文件夹",
        "drop_encrypt": "将文件或文件夹拖放到此处",
        "drop_decrypt": "将加密文件拖放到此处",
        "drop_click": "点击浏览",
        "select_file": "选择文件",
        "select_folder": "选择文件夹",
        "delete_original": "加密后删除原文件",
        "pick_file": "选择要加密的文件",
        "pick_folder": "选择要加密的文件夹",
        "pick_decrypt": "选择加密文件",
        "filetype_enc": "加密文件",
        "filetype_all": "所有文件",
        "err_not_found": "找不到所选项目。",
        "err_folder_decrypt": "请选择加密文件，而不是文件夹。",
        "err_not_ours": "此文件不是用 Tenna's File Encrypter 加密的。",
        "err_folder_not_allowed": (
            "无法加密此文件夹，因为它包含您的桌面或用户文件夹，或者是系统文件夹。"
            "请选择其他文件夹。"
        ),
        "set_password": "设置密码",
        "enter_password": "输入密码",
        "file_label": "文件：{name}",
        "folder_label": "文件夹：{name}",
        "auto_password": "为我生成安全密码",
        "password": "密码",
        "confirm_password": "确认密码",
        "show_password": "显示密码",
        "back": "\u2190 返回",
        "action_encrypt": "加密",
        "action_decrypt": "解密",
        "err_empty_password": "请输入密码。",
        "err_mismatch": "两次输入的密码不一致。",
        "err_enter_password": "请输入密码。",
        "warn_title": "重要提示",
        "warn_generated": "请记下程序为您生成的密码并妥善保管，否则您可能无法再访问此文件。",
        "warn_typed": "请记下您输入的密码并妥善保管，否则您可能无法再访问即将加密的文件。",
        "your_password": "您的密码：",
        "copy": "复制",
        "copied": "已复制！",
        "cancel": "取消",
        "confirm": "确认",
        "working_encrypt": "正在加密...",
        "working_decrypt": "正在解密...",
        "wait_close": "请等待操作完成。",
        "done": "操作完成。\n\n已保存到桌面，名称为：\n{name}",
        "original_deleted": "\n\n原文件已删除。",
        "original_not_deleted": "\n\n无法删除原文件：\n{error}",
        "verify_failed": "无法验证加密副本，因此已将其丢弃，您的原文件已保留。请重试。",
        "wrong_password": "密码错误，请重试。",
        "corrupt": "此文件已损坏或被修改，无法解密。",
        "error": "出了点问题：\n{error}",
    },
}

LANGUAGES = {
    "en": "English",
    "tr": "Türkçe",
    "de": "Deutsch",
    "fr": "Français",
    "zh": "中文",
}
FONTS = {"zh": "Microsoft YaHei UI"}
DEFAULT_FONT = "Segoe UI"

PALETTES = {
    "dark": {
        "topbar": "#171a21", "bg": "#1b2838", "sidebar": "#16202d", "panel": "#22364b",
        "panel_hover": "#2a475e", "border": "#35506a", "entry": "#101822",
        "fg": "#c7d5e0", "bright": "#ffffff", "muted": "#8f98a0", "accent": "#66c0f4",
        "green": "#5c9a2a", "green_hover": "#6cb436", "on_green": "#ffffff",
        "button": "#2f5470", "button_hover": "#3c6a8c", "nav_active": "#2a475e",
        "error": "#ff6b6b", "warn": "#ffcc66",
    },
    "light": {
        "topbar": "#dce3eb", "bg": "#eef2f6", "sidebar": "#e3e9f0", "panel": "#ffffff",
        "panel_hover": "#e6f0fa", "border": "#c3cfdb", "entry": "#ffffff",
        "fg": "#1b2838", "bright": "#0e1621", "muted": "#5d6b79", "accent": "#1a73b5",
        "green": "#4c8c1f", "green_hover": "#5ba126", "on_green": "#ffffff",
        "button": "#cfdbe8", "button_hover": "#bdd0e3", "nav_active": "#ffffff",
        "error": "#c62828", "warn": "#b36b00",
    },
}


def detect_theme():
    try:
        if sys.platform == "win32":
            import winreg

            key_path = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            return "light" if value else "dark"
        if sys.platform == "darwin":
            result = subprocess.run(
                ["defaults", "read", "-g", "AppleInterfaceStyle"],
                capture_output=True, text=True, timeout=2,
            )
            return "dark" if "dark" in result.stdout.lower() else "light"
    except Exception:
        pass
    return "dark"


class ConfirmDialog(tk.Toplevel):
    def __init__(self, app, message, secret=None):
        super().__init__(app.root)
        self.app = app
        self.result = False
        p = app.p
        self.title(app.t("warn_title"))
        self.configure(bg=p["bg"])
        self.resizable(False, False)
        self.transient(app.root)

        body = tk.Frame(self, bg=p["bg"])
        body.pack(padx=30, pady=26)

        app.label(body, "\u26a0  " + app.t("warn_title"), 14, True, "warn").pack(anchor="w")
        app.label(
            body, message, 11, wraplength=420, justify="left"
        ).pack(anchor="w", pady=(12, 6))

        if secret:
            app.label(body, app.t("your_password"), 10, color="muted").pack(
                anchor="w", pady=(10, 3)
            )
            row = tk.Frame(body, bg=p["bg"])
            row.pack(fill="x")
            var = tk.StringVar(value=secret)
            entry = tk.Entry(
                row, textvariable=var, state="readonly", readonlybackground=p["entry"],
                fg=p["bright"], relief="flat", font=("Consolas", 13, "bold"),
                highlightthickness=1, highlightbackground=p["accent"],
            )
            entry.pack(side="left", fill="x", expand=True, ipady=7)
            self.copy_btn = app.button(row, app.t("copy"), lambda: self._copy(secret))
            self.copy_btn.pack(side="left", padx=(8, 0))

        buttons = tk.Frame(body, bg=p["bg"])
        buttons.pack(fill="x", pady=(24, 0))
        app.button(buttons, app.t("cancel"), self._cancel).pack(side="left")
        app.button(buttons, app.t("confirm"), self._confirm, "primary").pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.update_idletasks()
        parent = app.root
        x = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.wait_visibility()
        self.grab_set()
        self.focus_set()
        self.wait_window(self)

    def _copy(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.copy_btn.config(text=self.app.t("copied"))

    def _confirm(self):
        self.result = True
        self.destroy()

    def _cancel(self):
        self.result = False
        self.destroy()


class App:
    def __init__(self):
        self.root = TkinterDnD.Tk() if DND_AVAILABLE else tk.Tk()
        self.root.title(APP_NAME)
        self.root.resizable(False, False)
        width, height = 880, 580
        x = (self.root.winfo_screenwidth() - width) // 2
        y = (self.root.winfo_screenheight() - height) // 3
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.lang = "en"
        self.theme = detect_theme()
        self.p = PALETTES[self.theme]
        self.font = DEFAULT_FONT
        self.view = "home"
        self.mode = None
        self.path = None
        self.error = None
        self.error_label = None
        self.busy = False
        self.dialog_open = False
        self.progress_value = 0.0
        self.work_result = None
        self.entry1 = None
        self.entry2 = None
        self.bar = None
        self.pct = None
        self.container = None

        self.delete_var = tk.BooleanVar(value=False)
        self.auto_var = tk.BooleanVar(value=False)
        self.show_var = tk.BooleanVar(value=False)
        self.pw1 = tk.StringVar()
        self.pw2 = tk.StringVar()

        self.render()
        self.root.after(2000, self._theme_tick)

    def t(self, key, **kw):
        text = STRINGS[self.lang][key]
        return text.format(**kw) if kw else text

    def run(self):
        self.root.mainloop()

    def on_close(self):
        if self.busy:
            messagebox.showinfo(APP_NAME, self.t("wait_close"))
            return
        self.root.destroy()

    def label(self, parent, text, size=11, bold=False, color="fg", **kw):
        return tk.Label(
            parent, text=text, bg=parent.cget("bg"), fg=self.p[color],
            font=(self.font, size, "bold" if bold else "normal"), **kw
        )

    def button(self, parent, text, command, kind="secondary"):
        p = self.p
        if kind == "primary":
            normal, over, fg = p["green"], p["green_hover"], p["on_green"]
        else:
            normal, over, fg = p["button"], p["button_hover"], p["fg"]
        btn = tk.Button(
            parent, text=text, command=command, bg=normal, fg=fg,
            activebackground=over, activeforeground=fg, relief="flat", bd=0,
            cursor="hand2", padx=22, pady=9,
            font=(self.font, 11, "bold" if kind == "primary" else "normal"),
        )
        self._hover([btn], normal, over)
        return btn

    def entry(self, parent, variable):
        p = self.p
        return tk.Entry(
            parent, textvariable=variable, show="\u2022", bg=p["entry"], fg=p["bright"],
            insertbackground=p["bright"], relief="flat",
            disabledbackground=p["panel"], disabledforeground=p["muted"],
            highlightthickness=1, highlightbackground=p["border"],
            highlightcolor=p["accent"], font=(self.font, 12),
        )

    def check(self, parent, text, variable, command=None):
        p = self.p
        bg = parent.cget("bg")
        return tk.Checkbutton(
            parent, text=text, variable=variable, command=command, bg=bg, fg=p["fg"],
            selectcolor=p["entry"], activebackground=bg, activeforeground=p["bright"],
            highlightthickness=0, bd=0, font=(self.font, 10), cursor="hand2",
        )

    def _hover(self, widgets, normal, over):
        def on_enter(event):
            for w in widgets:
                w.config(bg=over)

        def on_leave(event):
            for w in widgets:
                w.config(bg=normal)

        for w in widgets:
            w.bind("<Enter>", on_enter)
            w.bind("<Leave>", on_leave)

    def error_text(self):
        if not self.error:
            return ""
        key, kw = self.error
        return self.t(key, **kw)

    def set_error(self, key=None, **kw):
        self.error = (key, kw) if key else None
        if self.error_label is not None:
            self.error_label.config(text=self.error_text())

    def apply_style(self):
        p = self.p
        self.font = FONTS.get(self.lang, DEFAULT_FONT)
        self.root.configure(bg=p["bg"])
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Steam.Horizontal.TProgressbar", background=p["accent"],
            troughcolor=p["panel"], bordercolor=p["border"],
            lightcolor=p["accent"], darkcolor=p["accent"],
        )

    def render(self):
        self.error_label = None
        self.entry1 = self.entry2 = None
        self.bar = self.pct = None
        self.root.unbind("<Return>")
        self.apply_style()
        self.build_shell()
        getattr(self, "view_" + self.view)()

    def _theme_tick(self):
        try:
            name = detect_theme()
            if name != self.theme and not self.busy and not self.dialog_open:
                self.theme = name
                self.p = PALETTES[name]
                self.render()
        finally:
            self.root.after(2000, self._theme_tick)

    def build_shell(self):
        p = self.p
        for child in self.root.winfo_children():
            child.destroy()

        topbar = tk.Frame(self.root, bg=p["topbar"], height=48)
        topbar.pack(side="top", fill="x")
        topbar.pack_propagate(False)
        self.label(topbar, APP_NAME.upper(), 11, True, "bright").pack(side="left", padx=22)

        language = tk.Menubutton(
            topbar, text=f"{LANGUAGES[self.lang]}  \u25be", bg=p["topbar"], fg=p["fg"],
            activebackground=p["panel_hover"], activeforeground=p["bright"],
            relief="flat", bd=0, padx=14, pady=6, cursor="hand2", font=(self.font, 10),
        )
        menu = tk.Menu(
            language, tearoff=0, bg=p["panel"], fg=p["fg"], activebackground=p["accent"],
            activeforeground="#ffffff", bd=0, font=(self.font, 10),
        )
        for code, name in LANGUAGES.items():
            menu.add_command(label=name, command=lambda c=code: self.set_language(c))
        language.config(menu=menu)
        language.pack(side="right", padx=14)
        self._hover([language], p["topbar"], p["panel_hover"])

        statusbar = tk.Frame(self.root, bg=p["topbar"], height=30)
        statusbar.pack(side="bottom", fill="x")
        statusbar.pack_propagate(False)
        self.label(
            statusbar, "AES-256-GCM  \u2022  Argon2id", 9, color="muted"
        ).pack(side="left", padx=22)

        body = tk.Frame(self.root, bg=p["bg"])
        body.pack(fill="both", expand=True)

        sidebar = tk.Frame(body, bg=p["sidebar"], width=210)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Frame(sidebar, bg=p["sidebar"], height=14).pack()
        active = "home" if self.view == "home" else self.mode
        self.nav_item(sidebar, self.t("nav_home"), self.go_home, active == "home")
        self.nav_item(
            sidebar, self.t("nav_encrypt"), lambda: self.go_pick("encrypt"), active == "encrypt"
        )
        self.nav_item(
            sidebar, self.t("nav_decrypt"), lambda: self.go_pick("decrypt"), active == "decrypt"
        )

        self.container = tk.Frame(body, bg=p["bg"])
        self.container.pack(side="left", fill="both", expand=True, padx=34, pady=26)

    def nav_item(self, parent, text, command, active):
        p = self.p
        base = p["nav_active"] if active else p["sidebar"]
        row = tk.Frame(parent, bg=base, cursor="hand2")
        row.pack(fill="x")
        bar = tk.Frame(row, bg=p["accent"] if active else base, width=4)
        bar.pack(side="left", fill="y")
        lbl = tk.Label(
            row, text=text, bg=base, fg=p["bright"] if active else p["fg"], anchor="w",
            padx=18, pady=12, cursor="hand2",
            font=(self.font, 11, "bold" if active else "normal"),
        )
        lbl.pack(side="left", fill="x", expand=True)
        for widget in (row, bar, lbl):
            widget.bind("<Button-1>", lambda e: command())
        if not active:
            self._hover([row, lbl, bar], base, p["panel_hover"])

    def page_header(self, title):
        p = self.p
        self.label(self.container, title, 20, True, "bright", anchor="w").pack(fill="x")
        tk.Frame(self.container, bg=p["accent"], height=2, width=60).pack(
            anchor="w", pady=(6, 20)
        )

    def go_home(self):
        if self.busy:
            return
        self.view = "home"
        self.error = None
        self.render()

    def go_pick(self, mode):
        if self.busy:
            return
        self.mode = mode
        self.view = "pick"
        self.error = None
        self.render()

    def set_language(self, code):
        if self.busy:
            return
        self.lang = code
        self.render()

    def view_home(self):
        p = self.p
        c = self.container
        self.label(c, APP_NAME, 28, True, "bright", anchor="w").pack(fill="x")
        tk.Frame(c, bg=p["accent"], height=2, width=60).pack(anchor="w", pady=(8, 30))

        tiles = tk.Frame(c, bg=p["bg"])
        tiles.pack(fill="x")
        specs = (
            ("title_encrypt", "home_encrypt_sub", "btn_encrypt", "green", "primary", "encrypt"),
            ("title_decrypt", "home_decrypt_sub", "btn_decrypt", "accent", "secondary", "decrypt"),
        )
        for column, (title, sub, label, strip, kind, mode) in enumerate(specs):
            tile = tk.Frame(
                tiles, bg=p["panel"], highlightbackground=p["border"], highlightthickness=1
            )
            tile.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 16, 0))
            tiles.grid_columnconfigure(column, weight=1, uniform="tile")
            tk.Frame(tile, bg=p[strip], height=4).pack(fill="x")
            inner = tk.Frame(tile, bg=p["panel"])
            inner.pack(fill="both", expand=True, padx=22, pady=22)
            self.label(
                inner, self.t(title), 14, True, "bright", anchor="w",
                wraplength=230, justify="left",
            ).pack(fill="x")
            self.label(
                inner, self.t(sub), 10, color="muted", anchor="w",
                wraplength=230, justify="left",
            ).pack(fill="x", pady=(8, 22))
            self.button(
                inner, self.t(label), lambda m=mode: self.go_pick(m), kind
            ).pack(anchor="w")

    def view_pick(self):
        p = self.p
        c = self.container
        mode = self.mode
        self.page_header(self.t("title_encrypt" if mode == "encrypt" else "title_decrypt"))

        zone = tk.Frame(
            c, bg=p["panel"], cursor="hand2", highlightbackground=p["accent"],
            highlightthickness=2,
        )
        zone.pack(fill="x")
        zone.pack_propagate(False)
        zone.configure(height=190)
        if DND_AVAILABLE:
            zone_text = self.t("drop_encrypt" if mode == "encrypt" else "drop_decrypt")
        else:
            zone_text = self.t("drop_click")
        lbl = tk.Label(
            zone, text=zone_text, bg=p["panel"], fg=p["fg"], font=(self.font, 13),
            cursor="hand2", wraplength=440, justify="center",
        )
        lbl.place(relx=0.5, rely=0.5, anchor="center")
        for widget in (zone, lbl):
            widget.bind("<Button-1>", lambda e: self.browse_file())
            if DND_AVAILABLE:
                widget.drop_target_register(DND_FILES)
                widget.dnd_bind("<<Drop>>", self.on_drop)

        row = tk.Frame(c, bg=p["bg"])
        row.pack(fill="x", pady=(16, 0))
        self.button(row, self.t("select_file"), self.browse_file, "primary").pack(side="left")
        if mode == "encrypt":
            self.button(row, self.t("select_folder"), self.browse_folder).pack(
                side="left", padx=(10, 0)
            )
            self.check(c, self.t("delete_original"), self.delete_var).pack(
                anchor="w", pady=(18, 0)
            )

        self.error_label = self.label(
            c, self.error_text(), 10, color="error", wraplength=540, justify="left"
        )
        self.error_label.pack(anchor="w", pady=(12, 0))

    def browse_file(self):
        if self.mode == "encrypt":
            path = filedialog.askopenfilename(title=self.t("pick_file"))
        else:
            path = filedialog.askopenfilename(
                title=self.t("pick_decrypt"),
                filetypes=[
                    (self.t("filetype_enc"), f"*{ENC_EXT}"),
                    (self.t("filetype_all"), "*.*"),
                ],
            )
        if path:
            self.item_selected(path)

    def browse_folder(self):
        path = filedialog.askdirectory(title=self.t("pick_folder"))
        if path:
            self.item_selected(path)

    def on_drop(self, event):
        items = self.root.tk.splitlist(event.data)
        if items:
            self.item_selected(items[0])

    def item_selected(self, path):
        path = os.path.normpath(path)
        if not os.path.exists(path):
            self.set_error("err_not_found")
            return
        if self.mode == "decrypt":
            if os.path.isdir(path):
                self.set_error("err_folder_decrypt")
                return
            if not is_encrypted_file(path):
                self.set_error("err_not_ours")
                return
        elif os.path.isdir(path) and not folder_is_allowed(path, get_desktop_dir()):
            self.set_error("err_folder_not_allowed")
            return
        self.path = path
        self.error = None
        self.pw1.set("")
        self.pw2.set("")
        self.auto_var.set(False)
        self.show_var.set(False)
        self.view = "password"
        self.render()

    def view_password(self):
        p = self.p
        c = self.container
        encrypting = self.mode == "encrypt"
        self.page_header(self.t("set_password" if encrypting else "enter_password"))

        bottom = tk.Frame(c, bg=p["bg"])
        bottom.pack(side="bottom", fill="x")
        self.button(bottom, self.t("back"), lambda: self.go_pick(self.mode)).pack(side="left")
        submit = self.submit_encrypt if encrypting else self.submit_decrypt
        self.button(
            bottom, self.t("action_encrypt" if encrypting else "action_decrypt"),
            submit, "primary",
        ).pack(side="right")

        card = tk.Frame(c, bg=p["panel"], highlightbackground=p["border"], highlightthickness=1)
        card.pack(fill="x")
        inner = tk.Frame(card, bg=p["panel"])
        inner.pack(fill="x", padx=24, pady=20)

        name = os.path.basename(self.path)
        if len(name) > 54:
            name = name[:51] + "..."
        label_key = "folder_label" if os.path.isdir(self.path) else "file_label"
        self.label(inner, self.t(label_key, name=name), 10, color="muted").pack(
            anchor="w", pady=(0, 14)
        )

        if encrypting:
            self.check(
                inner, self.t("auto_password"), self.auto_var, self._toggle_auto
            ).pack(anchor="w", pady=(0, 12))

        self.label(inner, self.t("password"), 10, color="muted").pack(anchor="w")
        self.entry1 = self.entry(inner, self.pw1)
        self.entry1.pack(fill="x", ipady=7, pady=(3, 12))

        if encrypting:
            self.label(inner, self.t("confirm_password"), 10, color="muted").pack(anchor="w")
            self.entry2 = self.entry(inner, self.pw2)
            self.entry2.pack(fill="x", ipady=7, pady=(3, 12))

        self.check(
            inner, self.t("show_password"), self.show_var, self._apply_entry_state
        ).pack(anchor="w")

        self.error_label = self.label(
            inner, self.error_text(), 10, color="error", wraplength=500, justify="left"
        )
        self.error_label.pack(anchor="w", pady=(10, 0))

        self._apply_entry_state()
        self.root.bind("<Return>", lambda e: submit())
        self.entry1.focus_set()

    def _apply_entry_state(self):
        char = "" if self.show_var.get() else "\u2022"
        state = "disabled" if self.auto_var.get() else "normal"
        for entry in (self.entry1, self.entry2):
            if entry is not None:
                entry.config(show=char, state=state)

    def _toggle_auto(self):
        if self.auto_var.get():
            self.pw1.set("")
            self.pw2.set("")
        self.set_error()
        self._apply_entry_state()
        if not self.auto_var.get():
            self.entry1.focus_set()

    def ask_confirm(self, message, secret=None):
        self.dialog_open = True
        try:
            return ConfirmDialog(self, message, secret).result
        finally:
            self.dialog_open = False

    def submit_encrypt(self):
        if self.auto_var.get():
            password = generate_password()
            if not self.ask_confirm(self.t("warn_generated"), password):
                return
        else:
            password, confirm = self.pw1.get(), self.pw2.get()
            if not password:
                self.set_error("err_empty_password")
                return
            if password != confirm:
                self.set_error("err_mismatch")
                return
            if not self.ask_confirm(self.t("warn_typed")):
                return
        self.start_work(password)

    def submit_decrypt(self):
        password = self.pw1.get()
        if not password:
            self.set_error("err_enter_password")
            return
        self.start_work(password)

    def start_work(self, password):
        self.busy = True
        self.progress_value = 0.0
        self.work_result = None
        self.error = None
        self.view = "working"
        self.render()

        mode, path, desktop = self.mode, self.path, get_desktop_dir()
        delete_original = mode == "encrypt" and self.delete_var.get()

        def report(fraction):
            self.progress_value = fraction

        def worker():
            try:
                status, detail = "", ""
                if mode == "encrypt":
                    scale = 0.5 if delete_original else 1.0
                    out = encrypt_path(path, desktop, password, lambda f: report(f * scale))
                    if delete_original:
                        try:
                            delete_original_if_verified(
                                path, out, password, lambda f: report(0.5 + f * 0.5)
                            )
                            status = "deleted"
                        except VerificationError:
                            os.remove(out)
                            self.work_result = ("verify_failed", None)
                            return
                        except OSError as exc:
                            status, detail = "not_deleted", str(exc)
                else:
                    out = decrypt_path(path, desktop, password, report)
                self.work_result = ("ok", (out, status, detail))
            except WrongPasswordError:
                self.work_result = ("wrong", None)
            except CorruptFileError:
                self.work_result = ("corrupt", None)
            except FolderNotAllowedError:
                self.work_result = ("folder_not_allowed", None)
            except Exception as exc:
                self.work_result = ("error", str(exc))

        threading.Thread(target=worker, daemon=True).start()
        self._poll()

    def view_working(self):
        p = self.p
        encrypting = self.mode == "encrypt"
        self.page_header(self.t("working_encrypt" if encrypting else "working_decrypt"))
        self.bar = ttk.Progressbar(
            self.container, style="Steam.Horizontal.TProgressbar",
            orient="horizontal", mode="determinate", maximum=100,
        )
        self.bar.pack(fill="x", ipady=6)
        self.pct = self.label(self.container, "0%", 11, color="muted")
        self.pct.pack(anchor="w", pady=(10, 0))

    def _poll(self):
        if self.bar is not None:
            percent = int(self.progress_value * 100)
            self.bar["value"] = percent
            self.pct.config(text=f"{percent}%")
        if self.work_result is None:
            self.root.after(80, self._poll)
            return
        self.busy = False
        kind, data = self.work_result
        if kind == "ok":
            out_path, status, detail = data
            text = self.t("done", name=os.path.basename(out_path))
            if status == "deleted":
                text += self.t("original_deleted")
            elif status == "not_deleted":
                text += self.t("original_not_deleted", error=detail)
            messagebox.showinfo(APP_NAME, text)
            self.root.destroy()
        elif kind == "wrong":
            self.pw1.set("")
            self.set_error("wrong_password")
            self.view = "password"
            self.render()
        else:
            message = {
                "verify_failed": self.t("verify_failed"),
                "corrupt": self.t("corrupt"),
                "folder_not_allowed": self.t("err_folder_not_allowed"),
            }.get(kind) or self.t("error", error=data)
            messagebox.showerror(APP_NAME, message)
            self.go_home()


if __name__ == "__main__":
    App().run()
