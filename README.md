# **Secure Messaging Application**

This **Secure Messaging Application** provides secure and encrypted messaging between users. It uses **AES (Advanced Encryption Standard)** for encrypting messages and **RSA (Rivest-Shamir-Adleman)** for securely exchanging the encryption key. The application ensures the privacy and security of messages using **end-to-end encryption**.

## **Features**

- **User Authentication**: 
  - Secure login with **username**, **password**, and **OTP** (One-Time Password) for added security.
  - **Password hashing** using **bcrypt** for secure password storage.

- **Message Encryption**:
  - Messages are encrypted using **AES** before transmission.
  - **RSA encryption** is used to securely exchange the AES key between the sender and receiver.
  
- **Message Decryption**:
  - Messages are decrypted on the recipient's side using the AES key decrypted with their **private RSA key**.
  
- **User Interface**:
  - Simple and intuitive **GUI** built using **Tkinter**.
  - Users can send and receive encrypted messages.
  
- **Simulated Communication**:
  - The application simulates a conversation with a delay to represent real-time communication.

## **Technologies Used**

- **Python**: Core programming language used to build the application.
- **Tkinter**: Used for creating the Graphical User Interface (GUI).
- **PyCryptodome**: Used for **AES** and **RSA encryption**.
- **bcrypt**: Used for securely hashing passwords.
- **SQLite**: Used for storing user credentials and encrypted data.

## **How to Run the Application**

### **Prerequisites**

Make sure you have **Python 3.x** installed. You will also need the following libraries:

- PyCryptodome
- bcrypt
- Tkinter (usually pre-installed with Python)
- SQLite3 (pre-installed with Python)

### **Installation Instructions**

1. Install the necessary Python libraries using `pip`:
    ```bash
    pip install pycryptodome bcrypt
    ```

2. Clone or download the project files from the repository.

3. Open the terminal or command prompt and navigate to the directory containing the `secure.py` file.

4. Run the application using:
    ```bash
    python secure.py
    ```

### **Usage**

- Upon running the application, the login screen will appear.
- You can either **log in** using an existing username/password or **register** a new account.
- Once logged in, you can start sending and receiving encrypted messages.
- The **OTP** for login will be sent to your email for verification.

## **Features to be Added (Future Improvements)**

1. **Multi-Factor Authentication** (MFA) for enhanced security.
2. **File Attachments**: Securely send and receive files by encrypting them using AES.
3. **Group Chat Support**: Enable encrypted communication for multiple participants.
4. **Performance Optimization**: Optimize encryption algorithms for better performance with large datasets.

## **Known Issues**

- **Email configuration for OTP**: Currently, the OTP functionality may require proper email configuration to work with your email service provider.
  
## **License**

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
