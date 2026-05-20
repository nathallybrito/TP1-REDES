# Nathally Oliveira, [Colega]
import socket
import struct
import sys
import random

MESSAGE_TYPE = {'HEL': 1, 'TRY': 2, 'RES': 3, 'BYE': 4, 'ERR': 5}

def xor_checksum(data):
    """Calculate XOR checksum of all bytes except the first byte (type)."""
    result = 0
    for byte in data:
        result ^= byte
    return result

def pack_message(msg_type, seqnum, payload=None):
    """Pack a message according to protocol specification."""
    msg_type_byte = MESSAGE_TYPE[msg_type]

    if msg_type in ['HEL', 'BYE', 'ERR']:
        msg = struct.pack('!BxH', msg_type_byte, seqnum)
    else:  # TRY, RES
        if payload is None:
            payload = b''
        payload = payload.ljust(8, b' ')
        msg = struct.pack('!BxH', msg_type_byte, seqnum) + payload

    # Calculate checksum on all bytes except checksum byte itself
    # msg = [type, padding, seqnum_high, seqnum_low, ...]
    # We need to XOR: type + seqnum_bytes + payload (skip the padding byte at position 1)
    to_checksum = bytes([msg[0]]) + msg[2:]
    checksum = xor_checksum(to_checksum)

    # Replace padding byte (position 1) with checksum
    msg = msg[0:1] + struct.pack('!B', checksum) + msg[2:]
    return msg

def unpack_message(data):
    """Unpack a message and verify checksum."""
    if len(data) < 4:
        return None

    msg_type = data[0]
    checksum = data[1]
    seqnum = struct.unpack('!H', data[2:4])[0]

    # Verify checksum (XOR of all bytes except checksum itself)
    to_check = bytes([data[0]]) + data[2:]
    expected_checksum = xor_checksum(to_check)
    if checksum != expected_checksum:
        return None

    payload = None
    if len(data) > 4:
        payload = data[4:]

    return {'type': msg_type, 'seqnum': seqnum, 'payload': payload}

def validate_password(password):
    """Check if password is valid: 4-8 digits, no repetitions."""
    if not (4 <= len(password) <= 8):
        return False
    if not password.isdigit():
        return False
    if len(set(password)) != len(password):  # Check for repetitions
        return False
    return True

def generate_password(length):
    """Generate a random password of given length."""
    digits = list(range(10))
    random.shuffle(digits)
    return ''.join(str(d) for d in digits[:length])

def evaluate_guess(secret, guess):
    """Evaluate a guess against the secret password."""
    result = [None] * len(guess)
    secret_chars = list(secret)
    guess_chars = list(guess)

    # First pass: mark correct positions
    for i in range(len(guess)):
        if i < len(secret) and guess_chars[i] == secret_chars[i]:
            result[i] = '*'
            secret_chars[i] = None
            guess_chars[i] = None

    # Second pass: mark wrong positions (but correct digits)
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
        self.clients = {}  # addr -> client_state
        self.last_messages = {}  # addr -> last message sent
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

    # Generate password if all zeros
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

        # Initialize client if first message
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
            if seqnum > 0 and seqnum == client.seq_num + 1:
                client.seq_num = seqnum
                client.attempts_used += 1

                guess = payload[:password_length].decode('ascii')

                # Validate guess
                if not all(c.isdigit() for c in guess) or len(set(guess)) != len(guess):
                    # Invalid guess - send ERR
                    response = pack_message('ERR', seqnum)
                else:
                    # Valid guess - send result
                    result = evaluate_guess(password, guess)
                    remaining = max_attempts - client.attempts_used
                    response = pack_message('RES', remaining, result.encode())

                game_state.last_messages[addr] = response

        elif msg_type == MESSAGE_TYPE['BYE']:
            if seqnum == client.seq_num:
                password_str = password + ' ' * (8 - len(password))
                response = pack_message('RES', 65535, password_str.encode())  # -1 as unsigned short
                client.finished = True
                game_state.clients_finished += 1
                game_state.last_messages[addr] = response

        # Resend last message if duplicate/out of order
        elif msg_type in [MESSAGE_TYPE['HEL'], MESSAGE_TYPE['TRY'], MESSAGE_TYPE['BYE']]:
            if addr in game_state.last_messages:
                response = game_state.last_messages[addr]

        if response:
            sock.sendto(response, addr)

    sock.close()

if __name__ == '__main__':
    main()
