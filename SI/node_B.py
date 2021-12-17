from Crypto.Cipher import AES
import socket


iv = bytes.fromhex('400fc6d076f7961428d5c21f611d8e8b')
K_prim = bytes.fromhex('7998a8636aef9decdd5e75eb2f97c953')


def unpad(text):
    empty_byte = 0b00000000
    for byte in reversed(text):
        if byte == empty_byte:
            text.remove(byte)
        else:
            return


def xor_(curr_block, next_block): 
    xor_block = bytearray()
    if len(curr_block) > len(next_block):
        curr_block, next_block = next_block, curr_block
    xor_block = [ a^b for a, b in zip(curr_block, next_block) ]
    for i in range(len(curr_block), len(next_block)):
        xor_block.append(next_block[i])
    return bytes(xor_block)


def ECB_dec(enc_text, key):
    dec_text = bytearray()
    cipher_dec = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(enc_text), 16):
        block = bytes(enc_text[i: i + 16])  
        dec_block = cipher_dec.decrypt(block)
        dec_text += dec_block
    unpad(dec_text)
    return dec_text.decode('utf-8')


def OFB_dec(enc_text, key):
    dec_text = bytearray()
    cipher = AES.new(key, AES.MODE_ECB)
    prev_block = cipher.encrypt(iv)  
    for i in range(0, len(enc_text), 16):
        block = bytes(enc_text[i: i + 16])  
        dec_block = xor_(prev_block, block)
        dec_text += dec_block
        prev_block = cipher.encrypt(block)
    unpad(dec_text)
    return dec_text.decode('utf-8')



def decrypt_key(enc_key):
    cipher = AES.new(K_prim, AES.MODE_ECB)
    dec_key = cipher.decrypt(enc_key)
    return dec_key
    

if __name__ == '__main__':
    HOST = '127.0.0.1'
    PORT = 12345
    print(f"Asteptam la port {PORT} o conexiune...\n")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            mode = conn.recv(1024)
            mode = mode.decode('utf-8')
            print("Modul de criptare este: {mode}\n")
            conn.sendall(b'ok')
            enc_key = conn.recv(1024)
            print(f"Cheia criptata primita este: {enc_key.hex()} \n")
            key = decrypt_key(enc_key)
            print(f"Cheie decriptata: {key.hex()}")
            conn.sendall(b'Trimite un text!')
            enc_text = conn.recv(10240)
            print("Text criptat: \n")
            print(enc_text.hex())
            if mode == "ECB":
                dec_text = ECB_dec(enc_text, key)
            else:
                dec_text = OFB_dec(enc_text, key)
            f = open("receive.txt", "w")
            f.write(dec_text)
            f.close()

