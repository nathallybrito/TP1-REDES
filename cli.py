# Nathally Oliveira, [Colega]
import socket
import struct
import sys
import time

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

def main():
    if len(sys.argv) != 3:
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    server_addr = (host, port)

    seq_num = 0
    password_length = None
    max_attempts = None
    attempt_count = 0

    # Send HEL
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
                # Determine password length from pattern
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

    # Read guesses from stdin
    seq_num = 0
    while attempt_count < max_attempts:
        try:
            line = input().strip()
            if not line:
                break

            seq_num += 1
            attempt_count += 1
            guess = line.encode('ascii')[:password_length]
            guess = guess.ljust(password_length, b'0')

            try_msg = pack_message('TRY', seq_num, guess)
            retry_count = 0

            while retry_count <= max_retries:
                try:
                    sock.sendto(try_msg, server_addr)
                    response, _ = sock.recvfrom(1024)
                    msg = unpack_message(response)

                    if msg:
                        if msg['type'] == MESSAGE_TYPE['RES']:
                            remaining = msg['seqnum']
                            if msg['payload']:
                                pattern = msg['payload'].decode('ascii', errors='ignore').rstrip()
                                print(f"{seq_num}({remaining}) {pattern}")
                            break
                        elif msg['type'] == MESSAGE_TYPE['ERR']:
                            err_seqnum = msg['seqnum']
                            if err_seqnum > 0:
                                print(f"RETRY {err_seqnum}")
                                seq_num -= 1
                                attempt_count -= 1
                            else:
                                print("ERRO")
                                sock.close()
                                sys.exit(1)
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

        except EOFError:
            break

    # Send BYE
    bye_msg = pack_message('BYE', seq_num)
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
