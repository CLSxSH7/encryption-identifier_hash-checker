## Usage

1. **Run the script:**

    Execute the `text_identifier_and_decryptor.py` script and follow the prompts to input the text you want to identify the encryption or hash for.

    ```bash
    python text_identifier_and_decryptor.py
    ```

    Follow the on-screen prompts to enter the text. The script will then identify the type of encryption or hash used in the text.

2. **View the results:**

    The script will output the type of encryption or hash detected and, if applicable, additional information such as the decrypted message or the hashing algorithm used.

## Requirements

- Python 3.x
- pycryptodome (for AES encryption and RSA decryption)
- chardet (for encoding detection)
- hashlib (for hashing algorithms)

To install the required dependencies, you can use pip:

```bash
pip install pycryptodome
pip install chardet
pip install hashlib
