import string

en_char_freqs = {
    "A": 8.55,
    "K": 0.81,
    "U": 2.68,
    "B": 1.60,
    "L": 4.21,
    "V": 1.06,
    "C": 3.16,
    "M": 2.53,
    "W": 1.83,
    "D": 3.87,
    "N": 7.17,
    "X": 0.19,
    "E": 12.10,
    "O": 7.47,
    "Y": 1.72,
    "F": 2.18,
    "P": 2.07,
    "Z": 0.11,
    "G": 2.09,
    "Q": 0.10,
    "H": 4.96,
    "R": 6.33,
    "I": 7.33,
    "S": 6.73,
    "J": 0.22,
    "T": 8.94,
}


def fixed_xor(b1: bytes, b2: bytes) -> bytes:
    """
    >>> arg1 = bytes.fromhex('1c0111001f010100061a024b53535009181c')
    >>> arg2 = bytes.fromhex('686974207468652062756c6c277320657965')
    >>> fixed_xor(arg1, arg2)
    '746865206b696420646f6e277420706c6179'
    """
    # assert len(b1) == len(b2), "Should be the same length"

    res = []
    for a, b in zip(b1, b2):
        res.append(a ^ b)
    result = bytes(res).hex()
    return result


def single_byte_xor(plaintext: bytes, key: int):
    """
    >>> single_byte_xor(b"\\x00\\x00\\x00", 0x41)
    b'AAA'
    """

    assert 0 <= key < 256, "Key is out of range"
    return bytes(b ^ key for b in plaintext)


def break_single_xor_cipher_en(ciphertext: bytes) -> bytes:
    """
    use character frequency analyses to brute force single byte XOR ciphertext
    >>> break_single_xor_cipher_en(bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
    """
    candidates = []
    for i in range(256):
        candidates.append(single_byte_xor(ciphertext, i))

    scored_candidates = {}
    for candidate in candidates:
        scored_candidates[candidate] = score_english_text_by_freq(candidate)

    winner = sorted(scored_candidates.items(), key=lambda x: x[1])[-1]
    return winner


def score_english_text_by_freq(text: bytes) -> int:
    """
    Gives score how english text is. Text may contain punctuations and non-printables. Punctuations are not scored. Non printables are penalised.
    >>> score_english_text_by_freq(b"Hello worlds")
    0
    >>> score_english_text_by_freq(b"Hello worlds\\x00")
    -50
    """
    len_text = len(text)
    non_printable_char_penalty = 50
    printables = list(map(ord, string.printable))
    score = 0
    for b in text:
        if b not in printables:
            score -= non_printable_char_penalty

    for c, expected_freq in en_char_freqs.items():
        c_upper = ord(c.upper())
        c_lower = ord(c.lower())

        count_of_c_in_text = text.count(c_upper) + text.count((c_lower))
        freq_c_in_text = count_of_c_in_text / len_text

        score -= abs(expected_freq - freq_c_in_text)
    return score



