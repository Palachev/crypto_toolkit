# Crypto Toolkit

**Crypto Toolkit** — это мощный инструмент для работы с криптографией, разработанный на Python. Он поддерживает множество алгоритмов и функций, которые помогут вам решать задачи, связанные с криптографией, тестированием уязвимостей и анализом данных.

---

## Возможности

- **Caesar Cipher**: Расшифровка текста с заданным сдвигом.
- **XOR Cipher**:
  - Расшифровка текста с ключом.
  - Брутфорс ключа для XOR-шифра.
- **RSA**:
  - Расшифровка сообщений.
  - Факторизация модуля `n`.
  - Генерация ключей.
- **AES**: Шифрование и расшифровка сообщений (CBC-режим).
- **Vigenere Cipher**: Расшифровка текста с использованием ключа.
- **Base64**: Кодирование и декодирование.
- **Hexadecimal**: Перевод из шестнадцатеричного формата.
- **Хэширование**:
  - MD5
  - SHA-1
  - SHA-256
- **Частотный анализ**: Анализ текста для расшифровки.
- **Решение модульных уравнений**: Решение \( ax \\equiv b \\pmod{n} \).
- **Интеграция с онлайн-API**: Проверка паролей на скомпрометированность через [PwnedPasswords API](https://haveibeenpwned.com/Passwords).

---

## Установка

1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/ВАШ_ЛОГИН/crypto-toolkit.git
   cd crypto-toolkit
   ```

2. Убедитесь, что установлен Python 3.6+.

3. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```

---

## Использование

### Основные команды

Пример использования в командной строке:

1. **Caesar Cipher**:
   ```bash
   python crypto_toolkit.py --mode caesar --input "Uifsf jt b tfdsfu!" --shift 1
   ```

2. **XOR с ключом**:
   ```bash
   python crypto_toolkit.py --mode xor --input "4d4c4b" --key 42
   ```

3. **Проверка пароля через PwnedPasswords**:
   ```bash
   python crypto_toolkit.py --mode pwned-passwords --input "password123"
   ```

### Список доступных режимов
- `caesar`: Шифр Цезаря.
- `xor`: XOR-шифрование.
- `xor-brute`: Брутфорс XOR.
- `rsa`: RSA-шифрование.
- `aes`: AES-шифрование.
- `vigenere`: Шифр Виженера.
- `base64`: Base64-кодирование.
- `hex`: Работа с шестнадцатеричным форматом.
- `hash-md5`, `hash-sha1`, `hash-sha256`: Генерация хэшей.
- `freq-analysis`: Частотный анализ текста.
- `modular`: Решение модульных уравнений.
- `pwned-passwords`: Проверка паролей.

---

## Примеры использования

1. Расшифровка RSA:
   ```bash
   python crypto_toolkit.py --mode rsa --input "ciphertext_in_hex" --n 123456789 --e 65537 --d 987654321
   ```

2. Решение модульного уравнения:
   ```bash
   python crypto_toolkit.py --mode modular --a 3 --b 2 --mod 7
   ```

---

## Требования

- Python 3.6+
- Модули:
  - `sympy`
  - `pycryptodome`
  - `requests`

---

## Лицензия

Этот проект распространяется под лицензией MIT. Подробнее в [LICENSE](LICENSE).
