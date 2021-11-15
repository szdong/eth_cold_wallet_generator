from tkinter import filedialog
from tkinter import StringVar
import tkinter.ttk as ttk
import tkinter as tk
from wallet import *
import pyperclip
import PIL.ImageTk
import PIL.Image
import qrcode


def qr_generator(data: str):
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=8,
    )
    qr.add_data(data)
    qr.make(fit=True)
    return qr.make_image()


def select_dir(entry: StringVar):
    iDir = os.path.abspath(os.path.dirname(__file__))
    iDirPath = filedialog.askdirectory(initialdir=iDir)
    entry.set(iDirPath)


def select_file(entry: StringVar, file_type: list = None):
    if file_type is None:
        file_type = [("Wallet File", "*.wallet")]
    iFile = os.path.abspath(os.path.dirname(__file__))
    iFilePath = filedialog.askopenfilename(filetypes=file_type, initialdir=iFile)
    entry.set(iFilePath)


def copy_data(data: str):
    pyperclip.copy(data)


class EthereumWalletApp(tk.Frame, GetEthereumWallet):
    def __init__(self, master=None):
        super().__init__(master)

        self.master.title("ETH Wallet Generator")
        self.master.geometry("700x350")

        self.nb = ttk.Notebook(width=200, height=200)

        self.tab1 = tk.Frame(self.nb)
        self.tab2 = tk.Frame(self.nb)
        self.tab3 = tk.Frame(self.nb)
        self.tab4 = tk.Frame(self.nb)
        self.tab5 = tk.Frame(self.nb)
        self.nb.add(self.tab1, text='New Wallet', padding=3)
        self.nb.add(self.tab2, text='Add Address', padding=3)
        self.nb.add(self.tab3, text='Add Private Key', padding=3)
        self.nb.add(self.tab4, text='Get Private Key', padding=3)
        self.nb.add(self.tab5, text='Extract Address', padding=3)

        self.nb.pack(expand=1, fill='both')

        self.tab_1()
        self.tab_2()
        self.tab_3()
        self.tab_4()
        self.tab_5()

    def tab_1(self):
        label_width = 15
        entry_width = 20
        button_width = 8

        label_0 = tk.Label(self.tab1, text="Generate a new wallet", font=("", 16), height=2)
        label_0.pack(fill="x")

        frame_1 = tk.Frame(self.tab1, pady=10)
        frame_2 = tk.Frame(self.tab1, pady=10)
        frame_3 = tk.Frame(self.tab1, pady=10)
        frame_4 = tk.Frame(self.tab1, pady=10)

        label_1 = tk.Label(frame_1, font=("", 14), text="Name", width=label_width, anchor=tk.E)
        label_2 = tk.Label(frame_2, font=("", 14), text="Password", width=label_width, anchor=tk.E)
        label_3 = tk.Label(frame_3, font=("", 14), text="Password (Confirm)", width=label_width, anchor=tk.E)
        label_4 = tk.Label(frame_4, font=("", 14), text="Save wallet to..", width=label_width, anchor=tk.E)

        wallet_output_path_entry = StringVar()
        wallet_name = tk.Entry(frame_1, font=("", 14), justify="left", width=entry_width)
        wallet_password = tk.Entry(frame_2, font=("", 14), show='*', justify="left", width=entry_width)
        wallet_password_check = tk.Entry(frame_3, font=("", 14), show='*', justify="left", width=entry_width)
        wallet_output_path = tk.Entry(frame_4, textvariable=wallet_output_path_entry, font=("", 14), justify="left",
                                      width=entry_width)

        fake_button_1 = tk.Label(frame_1, font=("", 14), text="", width=button_width, anchor=tk.E)
        fake_button_2 = tk.Label(frame_2, font=("", 14), text="", width=button_width, anchor=tk.E)
        fake_button_3 = tk.Label(frame_3, font=("", 14), text="", width=button_width, anchor=tk.E)

        IDirButton = ttk.Button(frame_4, text="Select", command=lambda: select_dir(entry=wallet_output_path_entry),
                                width=button_width)

        frame_1.pack()
        frame_2.pack()
        frame_3.pack()
        frame_4.pack()

        label_1.pack(side="left")
        label_2.pack(side="left")
        label_3.pack(side="left")
        label_4.pack(side="left")

        wallet_name.pack(side="left")
        wallet_password.pack(side="left")
        wallet_password_check.pack(side="left")
        wallet_output_path.pack(side="left")

        fake_button_1.pack(side="left")
        fake_button_2.pack(side="left")
        fake_button_3.pack(side="left")
        IDirButton.pack(side="right")

        confirm_button = tk.Button(self.tab1, text="Generate", font=("", 14), bg="gray",
                                   command=lambda: self.new_wallet(wallet_name, wallet_output_path, wallet_password,
                                                                   wallet_password_check))
        confirm_button.pack()

    def tab_2(self):
        label_width = 20
        entry_width = 20
        button_width = 8

        label_0 = tk.Label(self.tab2, text="Add new address(es) to wallet", font=("", 16), height=2)
        label_0.pack(fill="x")

        frame_1 = tk.Frame(self.tab2, pady=10)
        frame_2 = tk.Frame(self.tab2, pady=10)
        frame_3 = tk.Frame(self.tab2, pady=10)

        label_1 = tk.Label(frame_1, font=("", 14), text="Wallet file", width=label_width, anchor=tk.E)
        label_2 = tk.Label(frame_2, font=("", 14), text="Password", width=label_width, anchor=tk.E)
        label_3 = tk.Label(frame_3, font=("", 14), text="Numbers to create (Option)", width=label_width, anchor=tk.E)

        wallet_file_path_entry = StringVar()
        wallet_input_path = tk.Entry(frame_1, textvariable=wallet_file_path_entry, font=("", 14), justify="left",
                                     width=entry_width)
        wallet_password = tk.Entry(frame_2, show='*', font=("", 14), justify="left", width=entry_width)
        batch = tk.Entry(frame_3, font=("", 14), justify="left", width=entry_width)

        IFileButton = ttk.Button(frame_1, text="Select", command=lambda: select_file(entry=wallet_file_path_entry),
                                 width=button_width)
        fake_button_2 = tk.Label(frame_2, font=("", 14), text="", width=button_width, anchor=tk.E)
        fake_button_3 = tk.Label(frame_3, font=("", 14), text="", width=button_width, anchor=tk.E)

        frame_1.pack()
        frame_2.pack()
        frame_3.pack()

        label_1.pack(side="left")
        label_2.pack(side="left")
        label_3.pack(side="left")

        wallet_input_path.pack(side="left")
        wallet_password.pack(side="left")
        batch.pack(side="left")

        IFileButton.pack(side="right")
        fake_button_2.pack(side="left")
        fake_button_3.pack(side="left")

        confirm_button = tk.Button(self.tab2, text="Add Address(es)", font=("", 14), bg="gray",
                                   command=lambda: self.add_address(batch, wallet_input_path, wallet_password))
        confirm_button.pack()

    def tab_3(self):
        label_width = 15
        entry_width = 20
        button_width = 8

        label_0 = tk.Label(self.tab3, text="Add private key", font=("", 16), height=2)
        label_0.pack(fill="x")

        frame_1 = tk.Frame(self.tab3, pady=10)
        frame_2 = tk.Frame(self.tab3, pady=10)
        frame_3 = tk.Frame(self.tab3, pady=10)

        label_1 = tk.Label(frame_1, font=("", 14), text="Wallet file", width=label_width, anchor=tk.E)
        label_2 = tk.Label(frame_2, font=("", 14), text="Password", width=label_width, anchor=tk.E)
        label_3 = tk.Label(frame_3, font=("", 14), text="Private Key", width=label_width, anchor=tk.E)

        wallet_file_path_entry = StringVar()
        wallet_input_path = tk.Entry(frame_1, textvariable=wallet_file_path_entry, font=("", 14), justify="left",
                                     width=entry_width)
        wallet_password = tk.Entry(frame_2, show='*', font=("", 14), justify="left", width=entry_width)
        private_key = tk.Entry(frame_3, font=("", 14), justify="left", width=entry_width)

        IFileButton = ttk.Button(frame_1, text="Select", command=lambda: select_file(entry=wallet_file_path_entry))
        fake_button_2 = tk.Label(frame_2, font=("", 14), text="", width=button_width, anchor=tk.E)
        fake_button_3 = tk.Label(frame_3, font=("", 14), text="", width=button_width, anchor=tk.E)

        frame_1.pack()
        frame_2.pack()
        frame_3.pack()

        label_1.pack(side="left")
        label_2.pack(side="left")
        label_3.pack(side="left")

        wallet_input_path.pack(side="left")
        wallet_password.pack(side="left")
        private_key.pack(side="left")

        IFileButton.pack(side="right")
        fake_button_2.pack(side="left")
        fake_button_3.pack(side="left")

        button_1 = tk.Button(self.tab3, text="Add Private Key", font=("", 14), bg="gray",
                             command=lambda: self.add_raw_private_key(private_key=private_key,
                                                                      wallet_input_path=wallet_input_path,
                                                                      wallet_password=wallet_password))
        button_1.pack()

    def tab_4(self):
        label_width = 15
        entry_width = 20
        button_width = 8

        label_0 = tk.Label(self.tab4, text="Get private key", font=("", 16), height=2)
        label_0.pack(fill="x")

        frame_1 = tk.Frame(self.tab4, pady=10)
        frame_2 = tk.Frame(self.tab4, pady=10)
        frame_3 = tk.Frame(self.tab4, pady=10)

        label_1 = tk.Label(frame_1, font=("", 14), text="Wallet file", width=label_width, anchor=tk.E)
        label_2 = tk.Label(frame_2, font=("", 14), text="Password", width=label_width, anchor=tk.E)
        label_3 = tk.Label(frame_3, font=("", 14), text="Address", width=label_width, anchor=tk.E)

        wallet_file_path_entry = StringVar()
        wallet_input_path = tk.Entry(frame_1, textvariable=wallet_file_path_entry, font=("", 14), justify="left",
                                     width=entry_width)
        wallet_password = tk.Entry(frame_2, show='*', font=("", 14), justify="left", width=entry_width)
        address = tk.Entry(frame_3, font=("", 14), justify="left", width=entry_width)

        IFileButton = ttk.Button(frame_1, text="Select", command=lambda: select_file(entry=wallet_file_path_entry))
        fake_button_2 = tk.Label(frame_2, font=("", 14), text="", width=button_width, anchor=tk.E)
        fake_button_3 = tk.Label(frame_3, font=("", 14), text="", width=button_width, anchor=tk.E)

        frame_1.pack()
        frame_2.pack()
        frame_3.pack()

        label_1.pack(side="left")
        label_2.pack(side="left")
        label_3.pack(side="left")

        wallet_input_path.pack(side="left")
        wallet_password.pack(side="left")
        address.pack(side="left")

        IFileButton.pack(side="right")
        fake_button_2.pack(side="left")
        fake_button_3.pack(side="left")

        button_1 = tk.Button(self.tab4, text="Get Private Key", font=("", 14), bg="gray",
                             command=lambda: self.private_key(wallet_input_path, wallet_password, address))
        button_1.pack()

    def tab_5(self):
        label_width = 15
        entry_width = 20
        button_width = 8

        label_0 = tk.Label(self.tab5, text="Extract Address List", font=("", 16), height=2)
        label_0.pack(fill="x")

        frame_1 = tk.Frame(self.tab5, pady=10)
        frame_2 = tk.Frame(self.tab5, pady=10)
        frame_3 = tk.Frame(self.tab5, pady=10)

        label_1 = tk.Label(frame_1, font=("", 14), text="Wallet file", width=label_width, anchor=tk.E)
        label_2 = tk.Label(frame_2, font=("", 14), text="Password", width=label_width, anchor=tk.E)
        label_3 = tk.Label(frame_3, font=("", 14), text="Save list to...", width=label_width, anchor=tk.E)

        wallet_file_path_entry = StringVar()
        wallet_output_path_entry = StringVar()
        wallet_input_path = tk.Entry(frame_1, textvariable=wallet_file_path_entry, font=("", 14), justify="left",
                                     width=entry_width)
        wallet_password = tk.Entry(frame_2, show='*', font=("", 14), justify="left", width=entry_width)
        wallet_output_path = tk.Entry(frame_3, textvariable=wallet_output_path_entry, font=("", 14), justify="left",
                                      width=entry_width)

        IFileButton = ttk.Button(frame_1, text="Select", command=lambda: select_file(entry=wallet_file_path_entry))
        fake_button_2 = tk.Label(frame_2, font=("", 14), text="", width=button_width, anchor=tk.E)
        IDirButton = ttk.Button(frame_3, text="Select", command=lambda: select_dir(entry=wallet_output_path_entry))

        frame_1.pack()
        frame_2.pack()
        frame_3.pack()

        label_1.pack(side="left")
        label_2.pack(side="left")
        label_3.pack(side="left")

        wallet_input_path.pack(side="left")
        wallet_password.pack(side="left")
        wallet_output_path.pack(side="left")

        IFileButton.pack(side="left")
        fake_button_2.pack(side="left")
        IDirButton.pack(side="left")

        button_1 = tk.Button(self.tab5, text="Extract List", font=("", 14), bg="gray",
                             command=lambda: self.extract_list(wallet_input_path, wallet_output_path, wallet_password))
        button_1.pack()

    def new_wallet(self, wallet_name: tk.Entry, wallet_output_path: tk.Entry, wallet_password: tk.Entry,
                   wallet_password_check: tk.Entry):
        if wallet_name.get() == "":
            raise Exception("Must specify the name for wallet file.")

        if wallet_output_path.get() == "":
            raise Exception("Must specify the output path for wallet file.")

        if wallet_password.get() == "":
            raise Exception("Must specify the password for wallet file.")

        if wallet_password.get() != wallet_password_check.get():
            raise Exception("The password entered is different.")

        address = self.generate_new_wallet_file(
            wallet_name=wallet_name.get().replace(" ", ""),
            output_path=wallet_output_path.get().replace(" ", ""),
            password=wallet_password.get().replace(" ", ""),
            qr=False,
            display=False
        )
        self.gen_qr(title="Address", data=address)

    def add_address(self, batch: tk.Entry, wallet_input_path: tk.Entry, wallet_password: tk.Entry):
        try:
            batch = int(batch.get().replace(" ", ""))
        except Exception as e:
            print(e)
            batch = 1

        if wallet_input_path.get() == "":
            raise Exception("Must specify the input path for wallet file.")

        if wallet_password.get() == "":
            raise Exception("Must specify the password for wallet file.")

        address = self.add_new_address(
            input_path=wallet_input_path.get().replace(" ", ""),
            batch=batch,
            password=wallet_password.get().replace(" ", ""),
            qr=False,
            display=False
        )

        if batch == 1:
            self.gen_qr(title="Address", data=address)

    def add_raw_private_key(self, private_key: tk.Entry, wallet_input_path: tk.Entry, wallet_password: tk.Entry):
        if private_key.get() == "":
            raise Exception("Must specify the raw private key.")

        if wallet_input_path.get() == "":
            raise Exception("Must specify the input path for wallet file.")

        if wallet_password.get() == "":
            raise Exception("Must specify the password for wallet file.")

        address = self.add_private_key(
            raw_key=private_key.get().replace(" ", ""),
            input_path=wallet_input_path.get().replace(" ", ""),
            password=wallet_password.get().replace(" ", ""),
            qr=False,
            display=False
        )

        self.gen_qr(title="Address", data=address)

    def private_key(self, wallet_input_path: tk.Entry, wallet_password: tk.Entry, address: tk.Entry):
        if wallet_input_path.get() == "":
            raise Exception("Must specify the input path for wallet file.")

        if wallet_password.get() == "":
            raise Exception("Must specify the password for wallet file.")

        if address.get() == "":
            raise Exception("Need to specify an address to derive the private key.")

        private_key = self.get_private_key(
            address=address.get().replace(" ", ""),
            input_path=wallet_input_path.get().replace(" ", ""),
            password=wallet_password.get().replace(" ", ""),
            qr=False,
            display=False
        )
        self.gen_qr(title="Private Key", data=private_key)

    def extract_list(self, wallet_input_path: tk.Entry, wallet_output_path: tk.Entry, wallet_password: tk.Entry):
        if wallet_output_path.get().replace(" ", "") == "":
            wallet_output_path = None
        else:
            wallet_output_path = wallet_output_path.get().replace(" ", "")

        if wallet_input_path.get() == "":
            raise Exception("Must specify the input path for wallet file.")

        if wallet_password.get() == "":
            raise Exception("Must specify the password for wallet file.")

        self.extract_all_address(
            input_path=wallet_input_path.get(),
            output_path=wallet_output_path,
            password=wallet_password.get().replace(" ", "")
        )

    def gen_qr(self, title: str, data: str, size: str = "550x575"):
        dlg_modeless = tk.Toplevel(self)
        dlg_modeless.title(title)
        dlg_modeless.geometry(size)

        img = PIL.ImageTk.PhotoImage(image=qr_generator(data))
        canvas = tk.Canvas(dlg_modeless, bg="black", width=500, height=500)
        canvas.place(x=25, y=50)
        canvas.create_image(50, 50, image=img, anchor=tk.NW)

        data_info = tk.Label(dlg_modeless, text=data, wraplength=500)
        data_info.place(x=25, y=5)

        IDirButton = ttk.Button(dlg_modeless, text=f"Copy {title}", command=lambda: copy_data(data=data))
        IDirButton.place(x=25, y=25)

        dlg_modeless.mainloop()


if __name__ == "__main__":
    root = tk.Tk()
    app = EthereumWalletApp(master=root)
    app.mainloop()
