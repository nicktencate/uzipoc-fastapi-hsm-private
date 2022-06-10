from copy import copy


def asint32(i):
    return i & 0xFFFFFFFF


def shift_rotate_left(number, shift, bits=32):
    return ((number << shift) | (number >> (bits - shift))) & (2 ** (bits) - 1)


def bytes_to_intarray(bytestring, byte_length, byte_order="little"):
    ret = []
    for i in range(0, len(bytestring), byte_length):
        c = bytestring[i : i + byte_length]
        ret.append(int.from_bytes(c, byte_order))

    return ret


def intarray_to_bytes(intarray, byte_length, byte_order="little"):
    ret = b""
    for theint in intarray:
        ret += theint.to_bytes(byte_length, byteorder=byte_order)

    return ret


def hsalsa_key_generation(iv, key):
    """
    |"expa"|Key   |Key   |Key   |
    |Key   |"nd 3"|Nonce |Nonce |
    |Nonce |Nonce |"2-by"|Key   |
    |Key   |Key   |Key   |"te k"|
    """

    # If a 128 bit key repeat the key
    if len(key) == 16:
        out_key = b"expa" + key + b"nd 1"
        out_key += iv
        out_key += b"6-by" + key + b"te k"
    else:
        out_key = b"expa" + key[:16] + b"nd 3"
        out_key += iv
        out_key += b"2-by" + key[16:] + b"te k"

    return out_key


def salsa_quarter_round(a, b, c, d):
    b = asint32(b ^ shift_rotate_left(asint32(a + d), 7))
    c = asint32(c ^ shift_rotate_left(asint32(b + a), 9))
    d = asint32(d ^ shift_rotate_left(asint32(c + b), 13))
    a = asint32(a ^ shift_rotate_left(asint32(d + c), 18))

    return [a, b, c, d]


def hsalsa_key_schedule(key_input, rounds=20):
    tro = copy(key_input)

    # Do 10 Rounds of both rows and diagonals
    for _ in range(rounds // 2):
        # Do Each Column Shifted down
        (tro[0], tro[4], tro[8], tro[12]) = salsa_quarter_round(
            tro[0], tro[4], tro[8], tro[12]
        )
        (tro[5], tro[9], tro[13], tro[1]) = salsa_quarter_round(
            tro[5], tro[9], tro[13], tro[1]
        )
        (tro[10], tro[14], tro[2], tro[6]) = salsa_quarter_round(
            tro[10], tro[14], tro[2], tro[6]
        )
        (tro[15], tro[3], tro[7], tro[11]) = salsa_quarter_round(
            tro[15], tro[3], tro[7], tro[11]
        )

        # Do Each Row
        (tro[0], tro[1], tro[2], tro[3]) = salsa_quarter_round(
            tro[0], tro[1], tro[2], tro[3]
        )
        (tro[5], tro[6], tro[7], tro[4]) = salsa_quarter_round(
            tro[5], tro[6], tro[7], tro[4]
        )
        (tro[10], tro[11], tro[8], tro[9]) = salsa_quarter_round(
            tro[10], tro[11], tro[8], tro[9]
        )
        (tro[15], tro[12], tro[13], tro[14]) = salsa_quarter_round(
            tro[15], tro[12], tro[13], tro[14]
        )

    # Take the Diagonal as the first 128 bits and 6-9 as the second 128 bits
    # The Diagonal is the "expand 16-byte k" part of the origional key_input.
    # The 6-9 is the Nonce part of the origional key_input.
    return intarray_to_bytes(
        [tro[0], tro[5], tro[10], tro[15]] + tro[6:10],
        4,
    )


def hsalsa20(key_input):
    nonce = b"\x00" * 16
    thekey = bytes_to_intarray(hsalsa_key_generation(nonce, key_input), 4)
    return hsalsa_key_schedule(thekey, 20)
