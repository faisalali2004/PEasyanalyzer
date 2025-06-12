import math

def calculate_entropy(data):
    if not data:
        return 0.0

    occurences = [0] * 256
    for b in data:
        occurences[b] += 1

    entropy = 0
    for count in occurences:
        if count:
            p = count / len(data)
            entropy -= p * math.log2(p)

    return round(entropy, 4)
