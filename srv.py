# Nathally Oliveira, [Colega]
import socket
import struct
import sys
import random

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
    else:
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

def validate_password(password):
    if not (4 <= len(password) <= 8):
        return False
    if not password.isdigit():
        return False
    if len(set(password)) != len(password):
        return False
    return True

def generate_password(length):
    digits = list(range(10))
    random.shuffle(digits)
    return ''.join(str(d) for d in digits[:length])

def evaluate_guess(secret, guess):
    result = [None] * len(guess)
    secret_chars = list(secret)
    guess_chars = list(guess)
    for i in range(len(guess)):
        if i < len(secret) and guess_chars[i] == secret_chars[i]:
            result[i] = '*'
            secret_chars[i] = None
            guess_chars[i] = None
    for i in range(len(guess)):
        if result[i] is None:
            if guess_chars[i] is not None and guess_chars[i] in secret_chars:
                result[i] = '+'
                secret_chars[secret_chars.index(guess_chars[i])] = None
            else:
                result[i] = '-'
    return ''.join(result)

class GameState:
    def __init__(self):
        self.clients = {}
        self.last_messages = {}
        self.clients_finished = 0

class ClientState:
    def __init__(self, password, max_attempts):
        self.password = password
        self.max_attempts = max_attempts
        self.attempts_used = 0
        self.seq_num = 0
        self.finished = False

def main():
    if len(sys.argv) != 4:
        sys.exit(1)

    port = int(sys.argv[1])
    password = sys.argv[2]
    max_attempts = int(sys.argv[3])

    if password.count('0') == len(password):
        password = generate_password(len(password))

    if not validate_password(password):
        sys.exit(1)

    password_length = len(password)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', port))

    game_state = GameState()

    while game_state.clients_finished < 2:
        try:
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            continue

        msg = unpack_message(data)
        if msg is None:
            continue

        # ========== MUDANÇA 7: verificar se cliente já finalizou ==========
        if addr in game_state.clients and game_state.clients[addr].finished:
            # Cliente já enviou BYE, ignorar mensagens posteriores
            continue

        if addr not in game_state.clients:
            game_state.clients[addr] = ClientState(password, max_attempts)

        client = game_state.clients[addr]
        msg_type = msg['type']
        seqnum = msg['seqnum']
        payload = msg['payload']

        response = None

        if msg_type == MESSAGE_TYPE['HEL']:
            if seqnum == 0:
                pattern = '?' * password_length + ' ' * (8 - password_length)
                response = pack_message('RES', max_attempts, pattern.encode())
                game_state.last_messages[addr] = response

        elif msg_type == MESSAGE_TYPE['TRY']:
            # ========== MUDANÇA 8: verificar limite de tentativas ==========
            if client.attempts_used >= client.max_attempts:
                # Envia ERR com seqnum=0 (erro de protocolo)
                response = pack_message('ERR', 0)
            elif seqnum > 0 and seqnum == client.seq_num + 1:
                # ========== MUDANÇA 9: validar antes de atualizar estado ==========
                guess = payload[:password_length].decode('ascii')
                # Validação do palpite
                if len(guess) != password_length or not all(c.isdigit() for c in guess) or len(set(guess)) != len(guess):
                    # Palpite inválido → ERR, NÃO atualiza seq_num nem attempts_used
                    response = pack_message('ERR', seqnum)
                else:
                    # Palpite válido → atualiza estado e responde com RES
                    client.seq_num = seqnum
                    client.attempts_used += 1
                    result = evaluate_guess(password, guess)
                    remaining = max_attempts - client.attempts_used
                    response = pack_message('RES', remaining, result.encode())
                game_state.last_messages[addr] = response
            else:
                # Fora de ordem → ERR com seqnum=0
                response = pack_message('ERR', 0)
                game_state.last_messages[addr] = response

        elif msg_type == MESSAGE_TYPE['BYE']:
            if seqnum == client.seq_num:
                password_str = password + ' ' * (8 - len(password))
                response = pack_message('RES', 65535, password_str.encode())
                # ========== MUDANÇA 10: evitar múltiplos incrementos do contador de clientes finalizados ==========
                if not client.finished:
                    client.finished = True
                    game_state.clients_finished += 1
                game_state.last_messages[addr] = response

        # Reenvio de última mensagem para duplicatas
        elif msg_type in [MESSAGE_TYPE['HEL'], MESSAGE_TYPE['TRY'], MESSAGE_TYPE['BYE']]:
            if addr in game_state.last_messages:
                response = game_state.last_messages[addr]

        if response:
            sock.sendto(response, addr)

    sock.close()

if __name__ == '__main__':
    main()
