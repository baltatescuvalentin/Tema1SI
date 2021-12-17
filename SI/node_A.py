from Crypto.Cipher import AES
import socket


iv = bytes.fromhex('400fc6d076f7961428d5c21f611d8e8b')
K_prim = bytes.fromhex('7998a8636aef9decdd5e75eb2f97c953')


def pad(text):
    empty_byte = 0b00000000
    pad_length = 16 - (len(text) % 16)
    for i in range(pad_length):
        text.append(empty_byte)



def xor_(curr_block, next_block): 
    xor_block = bytearray()
    if len(curr_block) > len(next_block):
        curr_block, next_block = next_block, curr_block
    xor_block = [ a^b for a, b in zip(curr_block, next_block) ]
    for i in range(len(curr_block), len(next_block)):
        xor_block.append(next_block[i])
    return bytes(xor_block)


def ECB_enc(text, key):
    enc_text = bytearray()
    text_bytes = bytearray(text, 'utf-8')
    cipher_enc = AES.new(key, AES.MODE_ECB)
    pad(text_bytes) 
    for i in range(0, len(text_bytes), 16):
        block = bytes(text_bytes[i: i + 16])
        enc_block = cipher_enc.encrypt(block)
        enc_text += enc_block
    return enc_text


def OFB_enc(text, key):
    enc_text = bytearray()
    text_bytes = bytearray(text, 'utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    prev_block = cipher.encrypt(iv)  
    for i in range(0, len(text_bytes), 16):
        block = bytes(text_bytes[i: i + 16])  
        enc_block = xor_(prev_block, block)
        enc_text += enc_block
        prev_block = cipher.encrypt(enc_block)
    return enc_text


def decrypt_key(enc_key):
    cipher = AES.new(K_prim, AES.MODE_ECB)
    dec_key = cipher.decrypt(enc_key)
    return dec_key
    


if __name__ == '__main__':
    mode = input("Mod(ECB/OFB): ")

    HOST = '127.0.0.1'
    PORT = 12340

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(bytes(mode, 'utf-8'))
        enc_key = s.recv(1024)
        print(f"Cheia criptata este: {enc_key.hex()} \n")

    HOST = '127.0.0.1'
    PORT = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(bytes(mode, 'utf-8'))
        data = s.recv(1024)
        if data == b"ok":
            s.sendall(enc_key)
            print("Trimitem cheia la nodul B \n")
            key = decrypt_key(enc_key)
            print("Cheia decriptata:", key.hex())
            response = s.recv(1024)
            print(f"Raspuns de la nodul B: \"{response.decode('utf-8')}\" \n")
            filename = input("Fisier: \n")
            f = open(filename, "r")
            text = f.read()
            if mode == "ECB":
                enc_text = ECB_enc(text, key)
            else:
                enc_text = OFB_enc(text, key)
            s.sendall(bytes(enc_text))
            print("Trimitem textul la nodul B.")
            f.close()
