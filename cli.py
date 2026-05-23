# Nathally Oliveira, [Colega]
import socket
import struct
import sys
import time

MESSAGE_TYPE = {'HEL': 1, 'TRY': 2, 'RES': 3, 'BYE': 4, 'ERR': 5}

def xor_checksum(data):
    result = 0
    for byte in data:
        result ^= byte
    return result

def pack_message(msg_type, seqnum, payload=None):
    msg_type_byte = MESSAGE_TYPE[msg_type]

    if msg_type in ['HEL', 'BYE', 'ERR']:
        msg = struct.pack('!BxH', msg_type_byte, seqnum)
    else:  # TRY, RES
        if payload is None:
            payload = b''
        payload = payload.ljust(8, b' ')
        msg = struct.pack('!BxH', msg_type_byte, seqnum) + payload

    to_checksum = bytes([msg[0]]) + msg[2:]
    checksum = xor_checksum(to_checksum)
    msg = msg[0:1] + struct.pack('!B', checksum) + msg[2:]
    return msg

def unpack_message(data):
    if len(data) < 4:
        return None
    msg_type = data[0]
    checksum = data[1]
    seqnum = struct.unpack('!H', data[2:4])[0]
    to_check = bytes([data[0]]) + data[2:]
    expected_checksum = xor_checksum(to_check)
    if checksum != expected_checksum:
        return None
    payload = None
    if len(data) > 4:
        payload = data[4:]
    return {'type': msg_type, 'seqnum': seqnum, 'payload': payload}

def main():
    if len(sys.argv) != 3:
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    server_addr = (host, port)

    # ========== MUDANÇA 1: controle separado de sequência e tentativas ==========
    # next_seqnum: número da próxima mensagem TRY a ser enviada (inicia em 1)
    # attempts_used: quantidade de tentativas válidas já consumidas
    next_seqnum = 1
    attempts_used = 0
    password_length = None
    max_attempts = None

    # Envia HEL
    hel_msg = pack_message('HEL', 0)
    max_retries = 2
    retry_count = 0

    while retry_count <= max_retries:
        try:
            sock.sendto(hel_msg, server_addr)
            response, _ = sock.recvfrom(1024)
            msg = unpack_message(response)

            if msg and msg['type'] == MESSAGE_TYPE['RES']:
                max_attempts = msg['seqnum']
                if msg['payload']:
                    pattern = msg['payload'].decode('ascii', errors='ignore').rstrip()
                    password_length = pattern.count('?')
                    print(f"NA={password_length}, NT={max_attempts}")
                break
            else:
                retry_count += 1
                if retry_count > max_retries:
                    print("NO RES")
                    sys.exit(1)
        except socket.timeout:
            retry_count += 1
            if retry_count > max_retries:
                print("NO RES")
                sys.exit(1)

    # ========== MUDANÇA 2: leitura e envio de palpites ==========
    # O loop agora usa next_seqnum e attempts_used separadamente.
    while attempts_used < max_attempts:
        try:
            line = input().strip()
            if not line:
                break

            # ========== MUDANÇA 3: remoção do ljust com zeros ==========
            # Antes: guess = line.encode('ascii')[:password_length]; guess = guess.ljust(password_length, b'0')
            # Agora: envia exatamente o que o usuário digitou (o pack_message já ajustará para 8 bytes com espaços)
            guess = line.encode('ascii')
            if len(guess) != password_length:
                # Opcional: valida comprimento, mas o servidor rejeitará com ERR
                pass

            try_msg = pack_message('TRY', next_seqnum, guess)
            retry_count = 0

            while retry_count <= max_retries:
                try:
                    sock.sendto(try_msg, server_addr)
                    response, _ = sock.recvfrom(1024)
                    msg = unpack_message(response)

                    if msg:
                        if msg['type'] == MESSAGE_TYPE['RES']:
                            remaining = msg['seqnum']
                            # RES válido → tentaiva consumida, avança próximo número de sequência
                            # ========== MUDANÇA 4: só incrementa após RES válido ==========
                            attempts_used += 1
                            next_seqnum += 1
                            if msg['payload']:
                                pattern = msg['payload'].decode('ascii', errors='ignore').rstrip()
                                print(f"{next_seqnum - 1}({remaining}) {pattern}")
                            break
                        elif msg['type'] == MESSAGE_TYPE['ERR']:
                            err_seqnum = msg['seqnum']
                            if err_seqnum > 0:
                                print(f"RETRY {err_seqnum}")
                                # ========== MUDANÇA 5: NÃO decrementa next_seqnum nem attempts_used ==========
                                # O jogador tenta novamente com o mesmo número de sequência
                                # Basta sair do loop de retransmissão e ler a próxima entrada
                                break
                            else:
                                print("ERRO")
                                sock.close()
                                sys.exit(1)
                    else:
                        retry_count += 1
                        if retry_count > max_retries:
                            print("NO RES")
                            sys.exit(1)
                except socket.timeout:
                    retry_count += 1
                    if retry_count > max_retries:
                        print("NO RES")
                        sys.exit(1)

        except EOFError:
            break

    # ========== MUDANÇA 6: BYE usa o último next_seqnum enviado (não decrementado) =========
    bye_msg = pack_message('BYE', next_seqnum - 1 if next_seqnum > 1 else 0)
    retry_count = 0

    while retry_count <= max_retries:
        try:
            sock.sendto(bye_msg, server_addr)
            response, _ = sock.recvfrom(1024)
            msg = unpack_message(response)

            if msg and msg['type'] == MESSAGE_TYPE['RES']:
                if msg['payload']:
                    password = msg['payload'].decode('ascii', errors='ignore').rstrip()
                    print(f"Senha={password}")
                break
            else:
                retry_count += 1
                if retry_count > max_retries:
                    print("NO RES")
                    sys.exit(1)
        except socket.timeout:
            retry_count += 1
            if retry_count > max_retries:
                print("NO RES")
                sys.exit(1)

    sock.close()

if __name__ == '__main__':
    main()
