from eth_account import Account
import cipher_utils
import traceback
import secrets
import getpass
import qrcode
import json
import ast
import os


def generator(number: int = 1):
    wallet_dict = dict()

    for i in range(number):
        private_key = "0x" + secrets.token_hex(32)
        address = Account.from_key(private_key)
        wallet_dict = {
            "private_key": str(private_key),
            "address": address.address
        }

    return wallet_dict


def encrypt_private_key(private_key: str):
    return Account.from_key(f"0x{private_key}").address


class GetEthereumWallet:
    def __init__(self):
        self.qr = qrcode.QRCode()

    def generate_new_wallet_file(self, wallet_name: str, output_path: str, password: str = None, qr: bool = True,
                                 display: bool = True):
        if password is None:
            password = getpass.getpass()
        encrypt_address_path = os.path.join(output_path, f"{wallet_name}.wallet")
        init_wallet = generator()
        address = init_wallet["address"]
        self.display_qr(data=address, qr=qr, display=display)
        init_wallet = {
            init_wallet["address"]: init_wallet["private_key"]
        }
        cipher_utils.password_encrypt_data(raw_password=password, input_data=str(init_wallet),
                                           output_path=encrypt_address_path)
        return address

    def get_private_key(self, address: str, input_path: str, password: str = None, qr: bool = True,
                        display: bool = True):
        raw_data = ""
        if password is None:
            password = getpass.getpass()

        try:
            raw_data = cipher_utils.password_decrypt_data(raw_password=password, input_path=input_path)
        except Exception as e:
            if str(e) == "Padding is incorrect.":
                raise Exception("Password is incorrect.")
            else:
                print(traceback.format_exc())
            exit(1)

        raw_wallet = ast.literal_eval(raw_data)
        if address in raw_wallet:
            self.display_qr(data=raw_wallet[address].replace("0x", ""), qr=qr, display=display)
        else:
            raise Exception("The address inputted does not exist in the wallet file.")
        return raw_wallet[address].replace("0x", "")

    def add_private_key(self, raw_key: str, input_path: str, password: str = None, qr: bool = True,
                        display: bool = True):
        raw_data = ""
        if password is None:
            password = getpass.getpass()

        try:
            raw_data = cipher_utils.password_decrypt_data(raw_password=password, input_path=input_path)
        except Exception as e:
            if str(e) == "Padding is incorrect.":
                raise Exception("Password is incorrect.")
            else:
                print(traceback.format_exc())
            exit(1)

        raw_wallet = ast.literal_eval(raw_data)
        new_address = encrypt_private_key(raw_key)
        self.display_qr(data=new_address, qr=qr, display=display)

        raw_wallet[new_address] = raw_key
        cipher_utils.password_encrypt_data(raw_password=password, input_data=str(raw_wallet), output_path=input_path)
        return new_address

    def add_new_address(self, input_path: str, batch: int = 1, password: str = None, qr: bool = True,
                        display: bool = True):
        raw_data = ""
        if password is None:
            password = getpass.getpass()
        address = None

        try:
            raw_data = cipher_utils.password_decrypt_data(raw_password=password, input_path=input_path)
        except Exception as e:
            if str(e) == "Padding is incorrect.":
                raise Exception("Password is incorrect.")
            else:
                print(traceback.format_exc())
            exit(1)

        raw_wallet = ast.literal_eval(raw_data)

        for i in range(batch):
            new_wallet = generator()
            if batch == 1:
                address = new_wallet["address"]
                self.display_qr(data=address, qr=qr, display=display)
            else:
                self.display_qr(data=new_wallet["address"], qr=False, display=display)
            raw_wallet[new_wallet["address"]] = new_wallet["private_key"]

        cipher_utils.password_encrypt_data(raw_password=password, input_data=str(raw_wallet), output_path=input_path)
        return address

    def extract_all_address(self, input_path: str, output_path: str = None, password: str = None):
        raw_data = ""
        if password is None:
            password = getpass.getpass()

        if output_path is None:
            address_book_path = input_path.replace(".wallet", "_addressbook.txt")
        else:
            address_book_path = os.path.join(
                output_path,
                input_path.split("/")[-1].replace(".wallet", "_addressbook.txt")
            )
        try:
            raw_data = cipher_utils.password_decrypt_data(raw_password=password, input_path=input_path)
        except Exception as e:
            if str(e) == "Padding is incorrect.":
                raise Exception("Password is incorrect.")
            else:
                print(traceback.format_exc())
            exit(1)

        raw_wallet = ast.literal_eval(raw_data)

        address_book = ""
        for address in raw_wallet:
            address_book += f"{address}\n"

        address_book_f = open(address_book_path, "w")
        address_book_f.write(address_book)
        address_book_f.close()

    def display_qr(self, data: str, qr: bool = True, display: bool = True):
        if display:
            print(data)
        if qr:
            self.qr.add_data(data)
            self.qr.print_ascii(tty=True)
