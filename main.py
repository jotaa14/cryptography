from cryptography.fernet import Fernet

def generate_key():
    # Gera uma chave e a salva em um arquivo
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    # Carrega a chave de um arquivo
    return open("secret.key", "rb").read()

def encrypt_message(message):
    key = load_key()
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message):
    key = load_key()
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message

def menu():
    while True:
        print("\n---------------------MENU---------------------")
        print("1. Encriptar uma palavra chave")
        print("2. Decriptar uma palavra chave")
        print("0. Sair")
        choice = input("Escolha uma opção: ")

        if choice == '1':
            message = input("Digite a palavra chave para encriptar: ")
            encrypted_message = encrypt_message(message)
            print(f"Palavra chave encriptada: {encrypted_message.decode()}")
        elif choice == '2':
            encrypted_message = input("Digite a palavra chave encriptada: ")
            try:
                decrypted_message = decrypt_message(encrypted_message.encode())
                print(f"Palavra chave decriptada: {decrypted_message}")
            except Exception as e:
                print(f"Erro ao decriptar a palavra chave: {e}")
        elif choice == '0':
            break
        else:
            print("Opção inválida. Por favor, escolha novamente.")

def main():
    generate_key()  # Gera e salva uma chave (apenas na primeira execução)
    menu()

if __name__ == "__main__":
    main()
