import gmpy2 as gmp


class Modular_Polynomial:
    def __init__(self, coefficients_list, p):
        # First element in the list represents the highest order coefficient.

        self.coefficients = coefficients_list
        self.p = p

    def __call__(self, x):
        # Evaluate the polynomial using an iterative Horner Scheme.

        result = self.coefficients[0]
        for i in range(1, len(self.coefficients)):
            prod = gmp.f_mod(gmp.mul(result, x), self.p)
            result = gmp.f_mod(prod + self.coefficients[i], self.p)

        return int(result)

    def __str__(self):
        terms = []

        for i, coeff in enumerate(self.coefficients):
            if coeff == 0:
                continue  # Skip zero coefficients
            if i == 0:
                term = (
                    f"{coeff % self.p}"
                    if len(self.coefficients) == 1
                    else f"{coeff % self.p}x^{len(self.coefficients)-1-i}"
                )
            elif i == len(self.coefficients) - 1:
                term = f"{coeff % self.p}"
            else:
                term = f"{coeff % self.p}x^{len(self.coefficients)-1-i}"
            terms.append(term)

        if not terms:  # If the polynomial is all zeros
            return "0"
        return " + ".join(terms) + f" (mod {self.p})"
