from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import socket

K = get_random_bytes(16)
K_prim = bytes.fromhex('7998a8636aef9decdd5e75eb2f97c953')

HOST = '127.0.0.1'
PORT = 12340


def encrypt_key(K):
    cipher = AES.new(K_prim, AES.MODE_ECB)
    K_enc = cipher.encrypt(K)
    return K_enc


if __name__ == '__main__':
    print("K: ", K.hex())
    print(f"\nAsteptam la port {PORT} o conexiune... \n")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024)
            key_enc = encrypt_key(K)
            print(f"K criptat: {key_enc.hex()} \n")
            conn.sendall(key_enc)
            print("Trimitem cheia la nodul A")
