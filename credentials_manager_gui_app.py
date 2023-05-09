import os
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
from PIL import Image, ImageTk
import py7zr
import clipboard



class CredentialsManagerApp(tk.Tk):
    # Initialize the CredentialsManagerApp class with default values
    def __init__(self, credentials_manager):
        super().__init__()
        self.credentials_manager = credentials_manager
        self.key = None
        self.enable_2fa = tk.BooleanVar()
        self.title('Credentials Manager')
        self.create_user_prompt()
        self.protocol('WM_DELETE_WINDOW', self.on_exit)

    # Function to create a prompt for the user to login, create, or remove an archive
    def create_user_prompt(self):
        self.user_prompt_frame = ttk.Frame(self)
        self.user_prompt_frame.pack(padx=20, pady=20)
        self.username_label = ttk.Label(self.user_prompt_frame, text=
            'Username:')
        self.username_label.grid(row=0, column=0, sticky='w')
        self.username_entry = ttk.Entry(self.user_prompt_frame)
        self.username_entry.grid(row=0, column=1)
        self.password_label = ttk.Label(self.user_prompt_frame, text=
            'Password:')
        self.password_label.grid(row=1, column=0, sticky='w')
        self.password_entry = ttk.Entry(self.user_prompt_frame, show='*')
        self.password_entry.grid(row=1, column=1)
        self.submit_button = ttk.Button(self.user_prompt_frame, text=
            'Submit', command=self.verify_and_load_archive)
        self.submit_button.grid(row=2, column=0, pady=10)
        self.create_button = ttk.Button(self.user_prompt_frame, text=
            'Create', command=self.create_archive)
        self.create_button.grid(row=2, column=1, pady=10)
        self.remove_archive_button = ttk.Button(self.user_prompt_frame,
            text='Remove', command=self.remove_archive)
        self.remove_archive_button.grid(row=3, column=0, columnspan=2)

    # Function to verify the entered username and password and load the archive
    def verify_and_load_archive(self, archive_name=None, archive_password=None
        ):
        if archive_name is not None and archive_password is not None:
            username = archive_name
            password = archive_password
        else:
            username = self.username_entry.get()
            password = self.password_entry.get()
        self.credentials_manager.user_name = username
        archive_name = f'{username}.7z'
        archive_path = os.path.join(self.credentials_manager.db_folder,
            archive_name)
        if os.path.exists(archive_path):
            self.credentials_manager.archive_path = archive_path
            self.credentials_manager.user_password = password
            try:
                if archive_name is not None and archive_password is not None:
                    with py7zr.SevenZipFile(self.credentials_manager.
                        archive_path, 'r', password=password) as archive:
                        try:
                            archive.read()
                            return True
                        except:
                            return False
                else:
                    with py7zr.SevenZipFile(self.credentials_manager.
                        archive_path, 'r', password=password) as archive:
                        try:
                            archive.read()
                        except:
                            messagebox.showerror('Wrong Password',
                                'The password you entered is incorrect.')
                            return False
                    self.credentials_manager.list_databases()
                    self.user_prompt_frame.pack_forget()
                    self.create_widgets()
            except ValueError as e:
                messagebox.showerror('Error', str(e))
                return False
        else:
            messagebox.showerror('Error',
                'No archive found with the given username.')

    # Function to create a new archive
    def create_archive(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        self.credentials_manager.user_name = username
        archive_name = f'{username}.7z'
        archive_path = os.path.join(self.credentials_manager.db_folder,
            archive_name)
        if not os.path.exists(archive_path):
            with tempfile.NamedTemporaryFile(delete=False) as temp_db_file:
                temp_db_path = temp_db_file.name
            with py7zr.SevenZipFile(archive_path, 'w', password=password
                ) as archive:
                archive.write(temp_db_path, 'blank.db')
            os.remove(temp_db_path)
            messagebox.showinfo('Success', 'New archive created successfully.')
            self.credentials_manager.archive_path = archive_path
            self.credentials_manager.user_password = password
            self.user_prompt_frame.pack_forget()
            self.create_widgets()
        else:
            messagebox.showerror('Error',
                'An archive with the given username already exists.')

    # Function to remove an archive
    def remove_archive(self):

        def remove_confirm():
            archive_name = archive_name_entry.get()
            archive_password = archive_password_entry.get()
            if self.verify_and_load_archive(archive_name, archive_password):
                os.remove(self.credentials_manager.archive_path)
                remove_popup.destroy()
            else:
                messagebox.showerror('Error',
                    'Incorrect  user name or password.')
        remove_popup = tk.Toplevel(self)
        remove_popup.title('Remove Archive')
        archive_name_label = ttk.Label(remove_popup, text='User Name:')
        archive_name_label.grid(row=0, column=0)
        archive_name_entry = ttk.Entry(remove_popup)
        archive_name_entry.grid(row=0, column=1)
        archive_password_label = ttk.Label(remove_popup, text=
            'User Password:')
        archive_password_label.grid(row=1, column=0)
        archive_password_entry = ttk.Entry(remove_popup, show='*')
        archive_password_entry.grid(row=1, column=1)
        confirm_button = ttk.Button(remove_popup, text='Confirm', command=
            remove_confirm)
        confirm_button.grid(row=2, column=0, columnspan=2, pady=10)

    # Function to create the main widgets to select, create, and delete databases
    def create_widgets(self):
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(padx=20, pady=20)
        self.choose_db_label = ttk.Label(self.main_frame, text=
            'Select an existing database or create a new one:')
        self.choose_db_label.grid(row=0, column=0, sticky='w')
        self.db_combobox = ttk.Combobox(self.main_frame, values=self.
            credentials_manager.get_existing_databases(self.
            credentials_manager.db_folder), width=40)
        self.db_combobox.grid(row=1, column=0, sticky='w')
        self.browse_button = ttk.Button(self.main_frame, text='Browse',
            command=self.browse_db)
        self.browse_button.grid(row=1, column=1)
        self.create_db_button = ttk.Button(self.main_frame, text=
            'Create New', command=self.create_new_db)
        self.create_db_button.grid(row=1, column=2)
        self.two_factor_checkbutton = ttk.Checkbutton(self.main_frame, text
            ='Enable 2-factor authentication', variable=self.enable_2fa)
        self.two_factor_checkbutton.grid(row=2, column=0, sticky='w')
        self.submit_button = ttk.Button(self.main_frame, text='Submit',
            command=self.submit_db)
        self.submit_button.grid(row=3, column=0, columnspan=3, pady=10)
        self.delete_db_button = ttk.Button(self.main_frame, text=
            'Delete Database', command=self.delete_database)
        self.delete_db_button.grid(row=1, column=3)

    # Function to browse for an existing database which is kind of useless but is still here
    def browse_db(self):
        file_path = filedialog.askopenfilename(defaultextension='.db',
            filetypes=[('Database Files', '*.db;*.enc'), ('All Files', '*.*')])
        if file_path:
            self.db_combobox.set(file_path)

    # Function to create a new database, the user may choose to enable 2FA
    def create_new_db(self):
        new_db_name = filedialog.asksaveasfilename(defaultextension='.db',
            filetypes=[('Database Files', '*.db'), ('All Files', '*.*')])
        if new_db_name:
            self.credentials_manager.db_file_name = new_db_name
            self.credentials_manager.create_and_populate_in_memory_database(
                new_db_name)
            if self.enable_2fa.get():
                self.credentials_manager.db_path = new_db_name
                self.credentials_manager.enable_two_factor()
                provisioning_uri = (self.credentials_manager.totp.
                    provisioning_uri(
                    f'Credentials Manager({os.path.basename(new_db_name)})'))
                img_data = self.credentials_manager.generate_qr_code(
                    provisioning_uri)
                self.display_qr_code(img_data)
                if self.credentials_manager.two_factor_enabled:
                    while True:
                        otp = simpledialog.askstring(
                            'Two-Factor Authentication',
                            'Enter the code from your authenticator app:',
                            show='*')
                        if otp is None:
                            return
                        if self.credentials_manager.verify_totp(otp):
                            break
                        else:
                            messagebox.showerror('Error',
                                'Invalid code. Please try again.')
                    new_db_name_enc = os.path.splitext(new_db_name)[0] + '.db'
                    self.credentials_manager.encrypt_database_file()
                    self.credentials_manager.close_connection()
                    os.remove(new_db_name)
                    self.db_combobox.set(new_db_name_enc)
                    self.credentials_manager.set_db_path(new_db_name_enc)
            else:
                self.db_combobox.set(new_db_name)
                self.credentials_manager.set_db_path(new_db_name)
                self.credentials_manager.update_unencrypted_database_file()
            self.credentials_manager.compress_database()
            self.credentials_manager.create_table()
            self.verify_key_and_manage_credentials(new_db=True)

    # Function to load a database from the archive for editing
    def submit_db(self):
        db_name = self.db_combobox.get()
        if not db_name:
            messagebox.showerror('Error',
                'Please select an existing database or create a new one.')
            return
        self.credentials_manager.db_path = db_name
        self.credentials_manager.db_file_name = db_name
        self.credentials_manager.check_two_factor_enabled()
        if self.credentials_manager.two_factor_enabled:
            while True:
                otp = simpledialog.askstring('Two-Factor Authentication',
                    'Enter the code from your authenticator app:', show='*')
                if otp is None:
                    return
                if self.credentials_manager.verify_totp(otp):
                    break
                else:
                    messagebox.showerror('Error',
                        'Invalid authenticator code. Please try again.')
        self.credentials_manager.extract_database()
        self.verify_key_and_manage_credentials()
        self.credentials_manager.load_database_from_memory()

    # Function to delete a database from the archive
    def delete_database(self):
        def delete_confirm():
            db_name = db_name_entry.get()
            archive_password = archive_password_entry.get()
            if self.verify_and_load_archive(self.credentials_manager.
                user_name, archive_password):
                try:
                    self.credentials_manager.delete_database(db_name)
                    delete_popup.destroy()
                    self.db_combobox['values'
                        ] = self.credentials_manager.get_existing_databases(
                        self.credentials_manager.db_folder)
                except Exception as e:
                    messagebox.showerror('Error', str(e))
            else:
                messagebox.showerror('Error', 'Incorrect user password.')
        delete_popup = tk.Toplevel(self)
        delete_popup.title('Delete Database')
        db_name_label = ttk.Label(delete_popup, text='Database Name:')
        db_name_label.grid(row=0, column=0)
        db_name_entry = ttk.Entry(delete_popup)
        db_name_entry.grid(row=0, column=1)
        db_name_entry.insert(0, self.db_combobox.get())
        archive_password_label = ttk.Label(delete_popup, text='User Password:')
        archive_password_label.grid(row=1, column=0)
        archive_password_entry = ttk.Entry(delete_popup, show='*')
        archive_password_entry.grid(row=1, column=1)
        confirm_button = ttk.Button(delete_popup, text='Confirm', command=
            delete_confirm)
        confirm_button.grid(row=2, column=0, columnspan=2, pady=10)

    # Function to add a database password and salt, I have it required but you may choose to create this as an optional step
    def verify_key_and_manage_credentials(self, new_db=False):
        dialog = tk.Toplevel()
        dialog.title('Enter Database Password and Salt')
        password_label = tk.Label(dialog, text='Enter database password:')
        password_label.pack()
        password_entry = tk.Entry(dialog, show='*')
        password_entry.pack()
        confirm_password_label = tk.Label(dialog, text=
            'Confirm database password:')
        confirm_password_label.pack()
        confirm_password_entry = tk.Entry(dialog, show='*')
        confirm_password_entry.pack()
        salt_label = tk.Label(dialog, text='Enter salt:')
        salt_label.pack()
        salt_entry = tk.Entry(dialog, show='*')
        salt_entry.pack()
        confirm_salt_label = tk.Label(dialog, text='Confirm salt:')
        confirm_salt_label.pack()
        confirm_salt_entry = tk.Entry(dialog, show='*')
        confirm_salt_entry.pack()
        ok_button = tk.Button(dialog, text='OK', command=lambda : self.
            submit_credentials(dialog, password_entry.get(),
            confirm_password_entry.get(), salt_entry.get(),
            confirm_salt_entry.get(), new_db))
        ok_button.pack()
        dialog.grab_set()
        dialog.focus_set()
        dialog.wait_window()

    # Function to submit the database password and salt
    def submit_credentials(self, dialog, program_password, confirm_password,
        salt, confirm_salt, new_db=False):
        if program_password != confirm_password:
            messagebox.showerror('Error',
                'Passwords do not match. Please try again.')
            return
        if salt != confirm_salt:
            messagebox.showerror('Error',
                'Salts do not match. Please try again.')
            return
        self.key = self.credentials_manager.generate_key(program_password,
            salt.encode('utf-8'))
        if new_db or self.credentials_manager.verify_existing_credentials(self
            .key):
            self.credentials_manager.create_table()
            if not new_db:
                decrypted_credentials = (self.credentials_manager.
                    read_and_decrypt_credentials(self.key))
            dialog.destroy()
            self.manage_credentials_window()
        else:
            messagebox.showerror('Error',
                'Incorrect program password or salt. Please try again.')

    # Function that displays a window for adding and managing credentials
    def manage_credentials_window(self):
        self.withdraw()
        manage_window = tk.Toplevel(self)
        manage_window.title('Manage Credentials')
        manage_window.protocol('WM_DELETE_WINDOW', self.on_exit)
        ttk.Label(manage_window, text='Website:').grid(row=0, column=0,
            sticky='w')
        website_entry = ttk.Entry(manage_window)
        website_entry.grid(row=0, column=1)
        ttk.Label(manage_window, text='Email:').grid(row=1, column=0,
            sticky='w')
        email_entry = ttk.Entry(manage_window)
        email_entry.grid(row=1, column=1)
        ttk.Label(manage_window, text='Username:').grid(row=2, column=0,
            sticky='w')
        username_entry = ttk.Entry(manage_window)
        username_entry.grid(row=2, column=1)
        ttk.Label(manage_window, text='Password:').grid(row=3, column=0,
            sticky='w')
        password_entry = ttk.Entry(manage_window, show='*')
        password_entry.grid(row=3, column=1)
        ttk.Button(manage_window, text='Generate', command=lambda : self.
            generate_password(password_entry)).grid(row=3, column=2)
        show_button = ttk.Button(manage_window, text='Show')
        show_button.grid(row=3, column=3)
        show_button.configure(command=lambda : self.show_password(
            password_entry, show_button))
        ttk.Label(manage_window, text='Notes:').grid(row=4, column=0,
            sticky='w')
        notes_entry = ttk.Entry(manage_window)
        notes_entry.grid(row=4, column=1)
        ttk.Button(manage_window, text='Search', command=lambda : self.
            search_credentials(website_entry, email_entry, username_entry,
            password_entry, notes_entry)).grid(row=5, column=0)
        ttk.Button(manage_window, text='Create', command=lambda : self.
            create_credentials(website_entry, email_entry, username_entry,
            password_entry, notes_entry)).grid(row=5, column=1)
        ttk.Button(manage_window, text='Main Menu', command=lambda : self.
            go_to_main_menu(manage_window)).grid(row=5, column=2)
        ttk.Button(manage_window, text='Back', command=lambda : self.
            go_back(manage_window)).grid(row=5, column=3)

    # Function to add a new credential
    def create_credentials(self, website_entry, email_entry, username_entry,
        password_entry, notes_entry):
        website = website_entry.get()
        email = email_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        notes = notes_entry.get()
        if not website or not email or not username or not password:
            messagebox.showerror('Error',
                'Please provide all fields to create new credentials.')
            return
        credentials = [website, email, username, password, notes]
        self.credentials_manager.add_new_credentials(self.key, credentials)
        messagebox.showinfo('Success', 'New credentials have been created.')

    # Function to search for credentials based on website, email, and/or username
    def search_credentials(self, website_entry, email_entry, username_entry,
        password_entry, notes_entry):
        website = website_entry.get().strip().lower()
        email = email_entry.get().strip().lower()
        username = username_entry.get().strip().lower()
        search_terms = [website, email, username]
        decrypted_credentials = self.credentials_manager.search_credentials(
            self.key, search_terms)
        matching_credentials = []
        for cred in decrypted_credentials:
            if (not website or website in cred[1].lower()) and (not email or
                email in cred[2].lower()) and (not username or username in
                cred[3].lower()):
                matching_credentials.append(cred)
        if not matching_credentials:
            messagebox.showinfo('Search Result',
                'No credentials found for the given search criteria.')
            return
        self.show_all_credentials(decrypted_credentials, matching_credentials)

    # Function to go back to the login screen
    def go_to_main_menu(self, manage_window):
        manage_window.destroy()
        self.reset_credentials_manager()
        self.deiconify()
        for child in self.winfo_children():
            child.destroy()
        self.create_user_prompt()

    # Function to go back one screen
    def go_back(self, manage_window):
        manage_window.destroy()
        self.deiconify()
        self.db_combobox['values'
            ] = self.credentials_manager.get_existing_databases(self.
            credentials_manager.db_folder)

    # Function to reset the credentials manager variables
    def reset_credentials_manager(self):
        self.credentials_manager.db_path = None
        self.credentials_manager.db_file_name = None
        self.credentials_manager.temp_db_path = None
        self.credentials_manager.archive_path = None
        self.credentials_manager.conn = None
        self.credentials_manager.cursor = None
        self.credentials_manager.key = None
        self.credentials_manager.salt = None
        self.credentials_manager.totp = None
        self.credentials_manager.two_factor_enabled = False
        self.credentials_manager.key_2fa = None
        self.credentials_manager.user_password = None
        self.credentials_manager.user_name = None
        self.credentials_manager.archive_name = (
            f'{self.credentials_manager.user_name}.7z')

    # Function to show search results if none are entered the entire database shows
    def show_all_credentials(self, decrypted_credentials, matching_credentials
        ):
        credentials_window = tk.Toplevel(self)
        credentials_window.title('All Credentials')
        credentials_frame = ttk.Frame(credentials_window)
        credentials_frame.pack()
        scrollbary = ttk.Scrollbar(credentials_frame)
        scrollbary.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbarx = ttk.Scrollbar(credentials_frame, orient=tk.HORIZONTAL)
        scrollbarx.pack(side=tk.BOTTOM, fill=tk.X)
        columns = ('ID', 'Website', 'Email', 'Username', 'Password',
            'Show Button', 'Notes', 'Delete Button', 'Date')
        credentials_tree = ttk.Treeview(credentials_frame, columns=columns,
            show='headings', yscrollcommand=scrollbary.set, xscrollcommand=
            scrollbarx.set)
        credentials_tree.pack(side=tk.LEFT, fill=tk.BOTH)
        scrollbary.config(command=credentials_tree.yview)
        scrollbarx.config(command=credentials_tree.xview)
        for col in columns:
            credentials_tree.heading(col, text=col)
        matching_credentials.sort(key=lambda x: x[5], reverse=True)
        decrypted_credentials = [credentials for credentials in
            matching_credentials]
        for credential in decrypted_credentials:
            show_button = 'Show'
            hidden_password = '*' * 20
            row_id = credentials_tree.insert('', tk.END, values=(credential
                [0], credential[1], credential[2], credential[3],
                hidden_password, show_button, credential[5], 'Delete',
                credential[6]))

        def on_treeview_click(event, decrypted_credentials):
            clicked_item = credentials_tree.identify('item', event.x, event.y)
            clicked_column = credentials_tree.identify('column', event.x,
                event.y)
            current_values = credentials_tree.item(clicked_item, 'values')
            credential_id = current_values[0]
            website, email, username, password, show, date = current_values[1:7
                ]
            matching_credentials = [cred for cred in decrypted_credentials if
                cred[1] == website and cred[2] == email and cred[3] ==
                username and cred[5] == date]
            if clicked_column == '#6':
                decrypted_password = matching_credentials[0][4
                    ] if matching_credentials else ''
                hidden_password = '*' * 20
                if current_values[5] == 'Show':
                    credentials_tree.item(clicked_item, values=(
                        current_values[0], current_values[1],
                        current_values[2], current_values[3],
                        decrypted_password, 'Hide', current_values[6],
                        'Delete'))
                else:
                    credentials_tree.item(clicked_item, values=(
                        current_values[0], current_values[1],
                        current_values[2], current_values[3],
                        hidden_password, 'Show', current_values[6], 'Delete'))
            elif clicked_column == '#8':
                delete_credential(clicked_item, credential_id,
                    matching_credentials)
            else:
                clicked_value = current_values[int(clicked_column[1]) - 1]
                clipboard.copy(clicked_value)
            show_copy_message()

        def show_copy_message():
            copy_label.config(text='Copied to clipboard!')
            credentials_window.after(2000, lambda : copy_label.config(text=''))

        def delete_credential(clicked_item, credential_id, matching_credentials
            ):

            def confirm_deletion():
                entered_password = password_entry.get()
                if self.credentials_manager.verify_password(entered_password):
                    self.credentials_manager.delete_credential_from_database(
                        credential_id)
                    credentials_tree.delete(clicked_item)
                    confirmation_window.destroy()
                    if self.credentials_manager.two_factor_enabled:
                        self.credentials_manager.update_encrypted_database_file(
                            )
                    else:
                        self.credentials_manager.update_unencrypted_database_file(
                            )
                else:
                    messagebox.showwarning(title='Warning', message=
                        'Incorrect password. Please try again.')
            confirmation_window = tk.Toplevel(credentials_window)
            confirmation_window.title('Delete Confirmation')
            confirmation_label = ttk.Label(confirmation_window, text=
                'Are you sure you want to delete this credential?')
            confirmation_label.pack()
            password_label = ttk.Label(confirmation_window, text=
                'Enter the program password:')
            password_label.pack()
            password_entry = ttk.Entry(confirmation_window, show='*')
            password_entry.pack()
            yes_button = ttk.Button(confirmation_window, text='Yes',
                command=confirm_deletion)
            yes_button.pack()
            no_button = ttk.Button(confirmation_window, text='No', command=
                confirmation_window.destroy)
            no_button.pack()
        credentials_tree.bind('<Button-1>', lambda event: on_treeview_click
            (event, decrypted_credentials))
        copy_label = ttk.Label(credentials_window, text='', foreground='green')
        copy_label.pack(pady=(5, 0))

    # Function to generate a random password
    def generate_password(self, password_entry):
        password_length = 12
        random_password = self.credentials_manager.generate_random_password(
            password_length)
        password_entry.delete(0, tk.END)
        password_entry.insert(0, random_password)

    # Function to show or hide a password
    def show_password(self, password_entry, show_button):
        if password_entry.cget('show') == '':
            password_entry.configure(show='*')
            show_button.configure(text='Show')
        else:
            password_entry.configure(show='')
            show_button.configure(text='Hide')

    # Function to exit the program
    def on_exit(self):
        if self.credentials_manager.conn:
            self.credentials_manager.conn.close()
        self.destroy()

    # Function to display the QR code for 2FA
    def display_qr_code(self, img_data):
        top_level = tk.Toplevel(self)
        top_level.title('Authenticator QR Code')
        img = Image.open(img_data)
        photo = ImageTk.PhotoImage(img)
        label = tk.Label(top_level, image=photo)
        label.image = photo
        label.pack()
        top_level.grab_set()
        top_level.focus_set()
        top_level.wait_window()