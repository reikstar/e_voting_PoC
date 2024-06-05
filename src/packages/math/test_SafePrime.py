from time import time
from prime import getSafePrime


def measure_execution_time(func, *args, **kwargs):
    start_time = time()
    result = func(*args, **kwargs)
    end_time = time()
    execution_time = end_time - start_time
    return result, execution_time


iterations = 1
bits = 1000
total_getSafePrime = 0
for i in range(iterations):
    total_getSafePrime += measure_execution_time(getSafePrime, bits)[1]


print(total_getSafePrime / iterations)
