# Password-Cracker

Password-Cracker is a desktop application designed to unlock password-protected MS Office and PDF files. It utilizes a password list to attempt to open these files.

## Features

- Download a password list from the internet
- Attempt to unlock MS Office (docx, pptx, xlsx) and PDF files using the password list
- Ability to cancel the download and password cracking process
- Display logs of activities

## Prerequisites

- Python 3.x
- Required packages:
  - pikepdf
  - msoffcrypto-tool
  - PySide6
  - requests

## Installation and Usage

  1. Clone the repository:
   ```bash
   git clone https://github.com/090ebier/Password-Cracker.git
   cd Password-Cracker
   ```
  2. Install the required packages:
  ```bash
  pip install -r requirements.txt
```
  3. Run the application:

 ```bash
  python Password-Cracker.py
 ```

## Preview


![Alt text](https://github.com/090ebier/Password-Cracker/blob/main/Password-Cracker.png)
