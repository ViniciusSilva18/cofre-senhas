<div align="center">

# 🔒 Cofre de Senhas — AES-256

**Gerenciador de senhas local com encriptação AES-256 (Fernet) e master password derivada via PBKDF2.**

[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)]()
[![Cryptography](https://img.shields.io/badge/Cryptography-AES--256-f43f5e?style=for-the-badge)]()

</div>

## 🔒 Segurança
- AES-256 via Fernet (cryptography library)
- PBKDF2-SHA256 com 480.000 iterações para a master key
- Salt aleatório de 32 bytes
- Gerador de senhas criptograficamente seguro
- Zero dados em plaintext no disco

## 🚀 Setup
```bash
pip install -r requirements.txt
python cofre.py
```

---
<sub>Criado por <a href="https://github.com/ViniciusSilva18">ViniciusSilva18</a> — VibeCoder 🇵🇹</sub>
