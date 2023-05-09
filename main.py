from credentials_manager import CredentialsManager
from credentials_manager_gui_app import CredentialsManagerApp

# Main function to run the program
if __name__ == '__main__':
    credentials_manager = CredentialsManager()
    app = CredentialsManagerApp(credentials_manager)
    app.mainloop()