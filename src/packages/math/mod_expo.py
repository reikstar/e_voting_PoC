import gmpy2 as gmp


def bin_exp(n, exp, mod):
    result = gmp.mpz(1)
    n = gmp.f_mod(n, mod)
    exp_length = gmp.bit_length(exp)

    for i in range(exp_length - 1, -1, -1):
        result = gmp.f_mod(gmp.square(result), mod)

        if gmp.bit_test(exp, i):
            result = gmp.f_mod(result * n, mod)

    return result


def base_k_exp(n, exp, mod, k):
    if exp == 0:
        return 1

    n = gmp.f_mod(n, mod)
    mod = gmp.mpz(mod)
    base_k_exp = gmp.digits(exp, 2**k)

    pre_comps = [gmp.mpz(1)]
    for i in range(1, 2**k):
        pre_comps.append(gmp.f_mod(pre_comps[i - 1] * n, mod))

    result = pre_comps[int(base_k_exp[0])]

    for i in range(1, len(base_k_exp)):
        digit = int(base_k_exp[i])
        for j in range(k):
            result = gmp.f_mod(gmp.square(result), mod)
        if digit != 0:
            result = gmp.f_mod(pre_comps[digit] * result, mod)

    return result


def sliding_window_exp(n, exp, mod, k):
    n = gmp.f_mod(n, mod)
    mod = gmp.mpz(mod)

    result = gmp.mpz(1)

    pre_comps = [None for i in range(2**k + 1)]

    pre_comps[1] = gmp.mpz(n)
    pre_comps[2] = gmp.f_mod(gmp.square(n), mod)

    for i in range(3, 2**k, 2):
        pre_comps[i] = gmp.f_mod(pre_comps[i - 2] * pre_comps[2], mod)

    binary_rep = bin(exp)[2:]

    i = 0

    while i < len(binary_rep):
        if binary_rep[i] == "0":
            result = gmp.f_mod(gmp.square(result), mod)

            i += 1

        else:
            s = min(i + k - 1, len(binary_rep) - 1)

            while binary_rep[s] == "0":
                s -= 1

            for j in range(s - i + 1):
                result = gmp.f_mod(gmp.square(result), mod)

            index = int(binary_rep[i : s + 1], 2)

            result = gmp.f_mod(result * pre_comps[index], mod)

            i = s + 1

    return result
