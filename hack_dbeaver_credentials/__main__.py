from hack_dbeaver_credentials.config import settings

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from rich import print as rprint
import typer

import json
from os import getenv
from binascii import hexlify, unhexlify


OS_USER = getenv("USER")
HOME_DIR = getenv("HOME")
DATA_SOURCE_FILE_PATH = f"/Users/{OS_USER}/Library/DBeaverData/workspace6/General/.dbeaver/data-sources.json"
CREDENTIALS_FILE_PATH = f"{HOME_DIR}/Library/DBeaverData/workspace6/General/.dbeaver/credentials-config.json"
DBEAVER_CREDENTIALS_KEY = settings.DBEAVER_CREDENTIALS_KEY


def _get_dbeaver_conn_name(connection_name: str) -> str:
    with open(DATA_SOURCE_FILE_PATH) as data_source_file:
        data_source_data = data_source_file.read()
        data_source_dict = json.loads(data_source_data)
        dbeaver_conn_name = next(connection for connection in data_source_dict["connections"] if data_source_dict["connections"][connection]["name"] == connection_name)

    return dbeaver_conn_name


def _decipher_data(ciphered_data: bytes, key: bytes, iv: bytes) -> bytes:
    decipherer = AES.new(unhexlify(key), AES.MODE_CBC, iv)
    plaintext = decipherer.decrypt(ciphered_data)

    return unpad(plaintext, AES.block_size)


def _cipher_data(plaintext: bytes, key: bytes) -> tuple[bytes]:
    cipherer = AES.new(unhexlify(key), AES.MODE_CBC)
    ciphered_data = cipherer.encrypt(pad(plaintext, AES.block_size))

    return cipherer.iv, ciphered_data


def edit_dbeaver_connection(dbeaver_conn_name: str, username: str, password: str):
    with open(CREDENTIALS_FILE_PATH, "rb+") as credentials_file:
        credentials_iv = credentials_file.read(16)
        credentials_data = credentials_file.read()
        deciphered_credentials = _decipher_data(credentials_data, DBEAVER_CREDENTIALS_KEY, credentials_iv)

        conn_dict = json.loads(deciphered_credentials.decode("utf-8"))
        conn_dict[dbeaver_conn_name]["#connection"]["user"] = username
        conn_dict[dbeaver_conn_name]["#connection"]["password"] = password

        new_conn_json = json.dumps(conn_dict)
        new_credentials_iv, new_credentials_data = _cipher_data(str.encode(new_conn_json), DBEAVER_CREDENTIALS_KEY)
        credentials_file.seek(0)
        credentials_file.write(new_credentials_iv)
        credentials_file.write(new_credentials_data)


def main(connection_name: str, username: str, password: str):
    dbeaver_conn_name = _get_dbeaver_conn_name(connection_name)
    edit_dbeaver_connection(dbeaver_conn_name, username, password)
    rprint(f"[bold green]DBEaver credentials for {connection_name} successfully edited![/bold green]")


if __name__ == "__main__":
    typer.run(main)
