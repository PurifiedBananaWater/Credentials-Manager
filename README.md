# Credentials-Manager
Disclaimer
This program was created with the assistance of GPT-4 and GitHub Co-pilot. While these tools were undoubtedly helpful in the development process, it's important to note that they alone could not build a program of this scale. I consider this code to be mostly my own creation, as I was responsible for its overall structure, flow, and some comments. The imported libraries were mainly suggested by GPT-4, but I opted for tkinter due to my familiarity with it.

Please be aware that I am not a security expert. I have done my best to make this program as secure as possible with my current knowledge, but I cannot guarantee its complete security. Use this code as a credentials manager at your own discretion.

Program Flow
1. A tkinter window prompts the user for a username and password, with three buttons: submit, create, and remove.
2. Assuming no user exists yet, the user enters their desired username and password and clicks "create" to generate a .7z archive named after the username and encrypted with the password.
3. A new window appears with a drop-down menu to display all files in the archive, along with "browse" and "create new" buttons.
4. The "create new" button prompts the user to specify a database name and password, as well as a salt for encryption. The database is then encrypted using these values (excluding the date) and saved to the archive.
5. If 2FA is enabled, the entire database file is encrypted using the 2FA secret key.
6. The credentials manager window allows the user to input website, email, username, password, and notes information, along with a "generate" and "show" button for the password field.
7. The window also includes "search", "create", "main menu", and "back" buttons for navigation and database interaction.

End Notes
I enjoyed creating this program with the help of AI, and it undoubtedly saved me a lot of time. However, I have worked on other AI-assisted projects in the past that I did not feel were truly my own creations, so I did not share them. This project, on the other hand, required a significant amount of my input, and I had to manually edit some sections of the code. I have reviewed the code to ensure there are no missed variables or functions, but if any issues arise, please accept my apologies. I hope you enjoy using this program as much as I enjoyed creating it.
