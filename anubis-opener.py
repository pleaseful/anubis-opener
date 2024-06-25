import os
import re
import ast
import base64
import hashlib
from Crypto.Cipher import AES
import tokenize
import random
import io
from functools import reduce

class Decryption:
    def __init__(self, key):
        self.key = hashlib.sha256(key).digest()

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]

def decrypt_code(code):
    wall = "__ANUBIS_ENCRYPTED__" * 25
    if wall in code:
        segments = code.split(wall)
        key = segments[1].encode()
        encrypted_lines = segments[2:-1]
        
        decryption = Decryption(key)
        decrypted_code = ""
        for line in encrypted_lines:
            decrypted_code += decryption.decrypt(line) + "\n"
        
        return decrypted_code
    return code

def remove_docs_and_comments(code):
    io_obj = io.StringIO(code)
    out = ""
    prev_toktype = tokenize.INDENT
    last_lineno = -1
    last_col = 0
    for tok in tokenize.generate_tokens(io_obj.readline):
        token_type = tok[0]
        token_string = tok[1]
        start_line, start_col = tok[2]
        end_line, end_col = tok[3]
        if start_line > last_lineno:
            last_col = 0
        if start_col > last_col:
            out += (" " * (start_col - last_col))
        if token_type == tokenize.COMMENT:
            pass
        elif token_type == tokenize.STRING:
            if prev_toktype != tokenize.INDENT:
                if prev_toktype != tokenize.NEWLINE:
                    if start_col > 0:
                        out += token_string
        else:
            out += token_string
        prev_toktype = token_type
        last_col = end_col
        last_lineno = end_line
    out = '\n'.join(l for l in out.splitlines() if l.strip())
    return out

def remove_anti_debugging(code):
    anti_debug_pattern = re.compile(r"import ctypes.*?sys.exit\(0\)", re.DOTALL)
    return re.sub(anti_debug_pattern, "", code)

def remove_junk_code(code):
    junk_code_pattern = re.compile(r"class [A-Za-z0-9_]+:\n    def __init__.*?return self\.[A-Za-z0-9_]+\(\)\n", re.DOTALL)
    return re.sub(junk_code_pattern, "", code)

def extract_rename_map(code):
    rename_map = {}
    used_names = set()

    def random_name():
        name = ''.join([random.choice("Il") for _ in range(8, 21)])
        while name in used_names:
            name = ''.join([random.choice("Il") for _ in range(8, 21)])
        used_names.add(name)
        return name

    parsed = ast.parse(code)
    for node in ast.walk(parsed):
        if isinstance(node, ast.ClassDef) or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name not in rename_map:
                rename_map[node.name] = random_name()

        if isinstance(node, ast.arg) and node.arg not in rename_map:
            rename_map[node.arg] = random_name()

        if isinstance(node, ast.Attribute) and node.attr not in rename_map:
            rename_map[node.attr] = random_name()

        if isinstance(node, ast.Name) and node.id not in rename_map:
            rename_map[node.id] = random_name()

    return rename_map

def restore_original_names(code, rename_map):
    def replacer(match):
        token = match.group(0)
        return rename_map.get(token, token)

    pattern = re.compile(r'\b(' + '|'.join(re.escape(key) for key in rename_map.keys()) + r')\b')
    return pattern.sub(replacer, code)

def deobfuscate_code(code):
    code = decrypt_code(code)
    code = remove_anti_debugging(code)
    rename_map = extract_rename_map(code)
    code = restore_original_names(code, rename_map)
    code = remove_junk_code(code)
    return code

if __name__ == "__main__":
    obfuscated_file = input("Enter the path to the obfuscated file: ")
    if not os.path.exists(obfuscated_file):
        print("Error: File does not exist")
    else:
        with open(obfuscated_file, 'r', encoding='utf-8') as f:
            obfuscated_code = f.read()
        
        deobfuscated_code = deobfuscate_code(obfuscated_code)
        
        output_file = f"{os.path.splitext(obfuscated_file)[0]}_deobfuscated.py"
        with open(output_file, "w", encoding='utf-8') as f:
            f.write(deobfuscated_code)
        print(f"Deobfuscated code has been saved to {output_file}")
