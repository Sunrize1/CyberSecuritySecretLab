def caesar_encrypt(text, shift):
    """Шифрование текста шифром Цезаря"""
    result = ""
    for char in text:
        if char.isalpha():
            # Определяем базу (A или a)
            base = ord('A') if char.isupper() else ord('a')
            # Применяем сдвиг
            shifted = (ord(char) - base + shift) % 26
            result += chr(shifted + base)
        else:
            result += char
    return result

# Исходные тексты
text1 = """SECRET LABORATORY RESEARCH PROJECT ALPHA

CLASSIFICATION: TOP SECRET
EXPERIMENT ID: LAB-2025-001
RESEARCHER: DR. SMITH

OBJECTIVE: DEVELOP ADVANCED ENCRYPTION METHODS FOR SECURE DATA TRANSMISSION

FINDINGS:
- CURRENT CAESAR CIPHER IMPLEMENTATION IS VULNERABLE
- FREQUENCY ANALYSIS REVEALS PATTERNS
- RECOMMEND UPGRADING TO AES-256 ENCRYPTION
- KEY MANAGEMENT SYSTEM NEEDS IMPROVEMENT

SECURITY NOTES:
- THIS DOCUMENT CONTAINS CLASSIFIED INFORMATION
- UNAUTHORIZED ACCESS IS PROHIBITED
- REPORT ANY SECURITY BREACHES IMMEDIATELY

END OF DOCUMENT"""


# Шифруем тексты
encrypted1 = caesar_encrypt(text1, 7)  # Сдвиг 7


print("=== ЗАШИФРОВАННЫЙ ТЕКСТ 1 (сдвиг 7) ===")
print(encrypted1)


# Проверяем расшифровку
def caesar_decrypt(text, shift):
    """Расшифровка шифра Цезаря"""
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base - shift) % 26
            result += chr(shifted + base)
        else:
            result += char
    return result

print("\n=== ПРОВЕРКА РАСШИФРОВКИ ===")
print("Текст 1 расшифрован правильно:", caesar_decrypt(encrypted1, 7) == text1)
