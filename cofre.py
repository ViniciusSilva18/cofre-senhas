"""
Cofre de Senhas — Gerenciador de senhas criptografado com AES-256 (Fernet).
Uso: python cofre.py
"""
import os, json, base64, getpass, secrets, string
from pathlib import Path
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VAULT_FILE = Path('.vault.enc')
SALT_FILE = Path('.vault.salt')

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def get_fernet(password: str) -> Fernet:
    if not SALT_FILE.exists():
        salt = os.urandom(32)
        SALT_FILE.write_bytes(salt)
    else:
        salt = SALT_FILE.read_bytes()
    return Fernet(derive_key(password, salt))

def load_vault(f: Fernet) -> dict:
    if not VAULT_FILE.exists(): return {}
    try:
        data = f.decrypt(VAULT_FILE.read_bytes())
        return json.loads(data)
    except InvalidToken:
        print('❌ Password mestre incorreta.')
        return None

def save_vault(vault: dict, f: Fernet):
    VAULT_FILE.write_bytes(f.encrypt(json.dumps(vault, ensure_ascii=False).encode()))

def generate_password(length: int = 20) -> str:
    chars = string.ascii_letters + string.digits + '!@#$%^&*()_+-=[]{}|;:,.<>?'
    return ''.join(secrets.choice(chars) for _ in range(length))

def menu():
    print('\n🔐 COFRE DE SENHAS — VibeCoder')
    print('='*40)
    master = getpass.getpass('Password mestre: ')
    fernet = get_fernet(master)
    vault = load_vault(fernet)
    if vault is None: return
    
    while True:
        print('\n📋 MENU:')
        print('1. Listar senhas')
        print('2. Adicionar senha')
        print('3. Ver senha')
        print('4. Gerar senha segura')
        print('5. Apagar senha')
        print('0. Sair')
        choice = input('\n> ').strip()
        
        if choice == '1':
            if not vault: print('📭 Cofre vazio.')
            else:
                print(f'\n🔑 {len(vault)} senha(s) guardadas:')
                for name, data in vault.items():
                    print(f"  • {name} ({data.get('username', '—')}) — {data.get('updated', '?')}")
        
        elif choice == '2':
            name = input('Nome/serviço: ').strip()
            if not name: continue
            username = input('Utilizador/email: ').strip()
            use_gen = input('Gerar senha segura? [s/n]: ').lower() == 's'
            password = generate_password() if use_gen else getpass.getpass('Password: ')
            if use_gen: print(f'✨ Senha gerada: {password}')
            vault[name] = {'username': username, 'password': password, 'updated': datetime.now().strftime('%Y-%m-%d')}
            save_vault(vault, fernet)
            print(f'✅ "{name}" guardado!')
        
        elif choice == '3':
            name = input('Nome do serviço: ').strip()
            if name in vault:
                entry = vault[name]
                print(f'\n🔑 {name}:')
                print(f'  Utilizador: {entry.get("username", "—")}')
                print(f'  Password: {entry["password"]}')
                print(f'  Atualizado: {entry.get("updated", "—")}')
            else:
                print('❌ Serviço não encontrado.')
        
        elif choice == '4':
            length = int(input('Comprimento [20]: ').strip() or '20')
            pwd = generate_password(length)
            print(f'✨ Senha gerada: {pwd}')
        
        elif choice == '5':
            name = input('Nome a apagar: ').strip()
            if name in vault:
                del vault[name]; save_vault(vault, fernet)
                print(f'🗑️  "{name}" apagado.')
            else: print('❌ Não encontrado.')
        
        elif choice == '0':
            print('👋 Até logo!'); break

if __name__ == '__main__':
    menu()
