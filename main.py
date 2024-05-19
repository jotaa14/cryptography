import os
import base64
from cryptography.fernet import Fernet
import json
from datetime import datetime, timedelta

KEY_ROTATION_INTERVAL = timedelta(days=7)  # Intervalo de rotação de chaves

def generate_unique_key():
    # Gera uma chave única compatível com Fernet
    return Fernet.generate_key()

def encrypt_message(message):
    key = generate_unique_key()
    fernet = Fernet(key)
    salt = os.urandom(16)
    encrypted_message = fernet.encrypt(salt + message.encode('utf-8'))
    return base64.urlsafe_b64encode(salt + encrypted_message).decode('utf-8'), key.decode('utf-8')

def decrypt_message(encrypted_message, key):
    encrypted_message = base64.urlsafe_b64decode(encrypted_message.encode('utf-8'))
    salt = encrypted_message[:16]
    encrypted_message = encrypted_message[16:]
    fernet = Fernet(key.encode('utf-8'))
    decrypted_message = fernet.decrypt(encrypted_message)
    return decrypted_message[16:].decode('utf-8')

def load_keys():
    # Carrega chaves de um arquivo, ou gera uma nova se o arquivo não existir
    if os.path.exists("keys.json"):
        with open("keys.json", "r") as file:
            keys_data = json.load(file)
        keys_data['last_rotation'] = datetime.strptime(keys_data['last_rotation'], '%Y-%m-%d %H:%M:%S')
    else:
        keys_data = {
            'current_key': generate_unique_key(),
            'previous_key': None,
            'last_rotation': datetime.now()
        }
        save_keys(keys_data)
    return keys_data

def save_keys(keys_data):
    # Salva chaves em um arquivo
    keys_data['last_rotation'] = keys_data['last_rotation'].strftime('%Y-%m-%d %H:%M:%S')
    with open("keys.json", "w") as file:
        json.dump(keys_data, file)

def rotate_keys(keys_data):
    # Rotaciona as chaves se o intervalo de rotação foi atingido
    if datetime.now() - keys_data['last_rotation'] >= KEY_ROTATION_INTERVAL:
        keys_data['previous_key'] = keys_data['current_key']
        keys_data['current_key'] = generate_unique_key()
        keys_data['last_rotation'] = datetime.now()
        save_keys(keys_data)
    return keys_data

def menu():
    keys_data = load_keys()
    keys_data = rotate_keys(keys_data)

    while True:
        print("\nMenu:")
        print("1. Encriptar uma palavra chave")
        print("2. Decriptar uma palavra chave")
        print("0. Sair")
        choice = input("Escolha uma opção: ")

        if choice == '1':
            message = input("Digite a palavra chave para encriptar: ")
            encrypted_message, key = encrypt_message(message)
            print(f"Palavra chave encriptada: {encrypted_message}")
            print(f"Guarde esta chave para decriptação: {key}")
        elif choice == '2':
            encrypted_message = input("Digite a palavra chave encriptada: ")
            key = input("Digite a chave para decriptação: ")
            try:
                decrypted_message = decrypt_message(encrypted_message, key)
                print(f"Palavra chave decriptada: {decrypted_message}")
            except Exception as e:
                print(f"Erro ao decriptar a palavra chave. {e}")
        elif choice == '0':
            break
        else:
            print("Opção inválida. Por favor, escolha novamente.")

def main():
    menu()

if __name__ == "__main__":
    main()
