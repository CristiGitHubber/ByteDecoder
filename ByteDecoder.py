import tkinter as tk
import customtkinter as ctk
import base64
import urllib.parse
import binascii
import morse_code
import base32_crockford
import struct
from pyfiglet import figlet_format
import codecs

def encode_base64(text):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def decode_base64(encoded_text):
    return base64.b64decode(encoded_text).decode('utf-8')

def encode_binary(text):
    return ' '.join(format(ord(char), '08b') for char in text)

def decode_binary(binary_text):
    binary_values = binary_text.split(' ')
    ascii_characters = [chr(int(bv, 2)) for bv in binary_values]
    return ''.join(ascii_characters)

def encode_morse(text):
    return morse_code.encode(text)

def decode_morse(morse_text):
    return morse_code.decode(morse_text)

def encode_hex(text):
    return text.encode('utf-8').hex()

def decode_hex(hex_str):
    return bytes.fromhex(hex_str).decode('utf-8')

def encode_url(text):
    return urllib.parse.quote(text)

def decode_url(encoded_text):
    return urllib.parse.unquote(encoded_text)

def encode_base32(text):
    return base32_crockford.encode(text.encode('utf-8'))

def decode_base32(encoded_text):
    return base32_crockford.decode(encoded_text).decode('utf-8')

def encode_ascii85(data):
    """Encode data using ASCII85 encoding."""
    def encode_85block(block):
        """Encode a 4-byte block to ASCII85."""
        return ''.join(
            chr(33 + (b % 85)) for b in struct.unpack('>BBBB', block)
        )

    padding = b'\x00' * (4 - len(data) % 4) if len(data) % 4 != 0 else b''
    data += padding
    encoded = b''.join(
        encode_85block(data[i:i + 4]) for i in range(0, len(data), 4)
    )
    return encoded.decode('ascii').rstrip('u')

def decode_ascii85(data):
    """Decode ASCII85 encoded data."""
    def decode_85block(encoded):
        """Decode a 5-character ASCII85 block."""
        return struct.pack(
            '>BBBB',
            *[((ord(c) - 33) % 85) for c in encoded]
        )

    data = data.encode('ascii') + b'u' * ((4 - len(data) % 5) % 4)
    decoded = b''.join(
        decode_85block(data[i:i + 5]) for i in range(0, len(data), 5)
    )
    return decoded.rstrip(b'\x00')

def encode_rot13(text):
    return codecs.encode(text, 'rot_13')

def decode_rot13(encoded_text):
    return codecs.encode(encoded_text, 'rot_13')

def process_text():
    text = text_entry.get()
    format_type = format_var.get()
    if format_type == 'Base64 Encode':
        result.set(encode_base64(text))
    elif format_type == 'Base64 Decode':
        result.set(decode_base64(text))
    elif format_type == 'Binary Encode':
        result.set(encode_binary(text))
    elif format_type == 'Binary Decode':
        result.set(decode_binary(text))
    elif format_type == 'Morse Code Encode':
        result.set(encode_morse(text))
    elif format_type == 'Morse Code Decode':
        result.set(decode_morse(text))
    elif format_type == 'Hexadecimal Encode':
        result.set(encode_hex(text))
    elif format_type == 'Hexadecimal Decode':
        result.set(decode_hex(text))
    elif format_type == 'URL Encode':
        result.set(encode_url(text))
    elif format_type == 'URL Decode':
        result.set(decode_url(text))
    elif format_type == 'Base32 Encode':
        result.set(encode_base32(text))
    elif format_type == 'Base32 Decode':
        result.set(decode_base32(text))
    elif format_type == 'ASCII85 Encode':
        result.set(encode_ascii85(text))
    elif format_type == 'ASCII85 Decode':
        result.set(decode_ascii85(text))
    elif format_type == 'Rot13 Encode/Decode':
        result.set(encode_rot13(text))
    elif format_type == 'Rot13 Decode/Encode':
        result.set(decode_rot13(text))

app = ctk.CTk()
app.title("ByteDecoder")
app.geometry("350x350")

ascii_art = figlet_format("ByteDecoder", font='small')
ascii_label = ctk.CTkLabel(app, text=ascii_art, font=("Courier", 12), justify=tk.LEFT, anchor="w")
ascii_label.pack(pady=10)

frame = ctk.CTkFrame(app)
frame.pack(padx=20, pady=20, fill="both", expand=True)

ctk.CTkLabel(frame, text="Text:").grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
text_entry = ctk.CTkEntry(frame, placeholder_text="Enter text here")
text_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

ctk.CTkLabel(frame, text="Format:").grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
format_var = tk.StringVar()
format_menu = ctk.CTkOptionMenu(frame, variable=format_var, values=[
    'Base64 Encode', 'Base64 Decode', 'Binary Encode', 'Binary Decode', 
    'Morse Code Encode', 'Morse Code Decode', 'Hexadecimal Encode', 
    'Hexadecimal Decode', 'URL Encode', 'URL Decode', 'Base32 Encode', 
    'Base32 Decode', 'ASCII85 Encode', 'ASCII85 Decode', 
    'Rot13 Encode/Decode', 'Rot13 Decode/Encode'])
format_menu.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

process_button = ctk.CTkButton(frame, text="Process", command=process_text)
process_button.grid(row=2, column=0, columnspan=2, padx=10, pady=20, sticky="ew")

ctk.CTkLabel(frame, text="Result:").grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
result = tk.StringVar()
result_display = ctk.CTkEntry(frame, textvariable=result, state='readonly')
result_display.grid(row=3, column=1, padx=10, pady=5, sticky="ew")

app.mainloop()
