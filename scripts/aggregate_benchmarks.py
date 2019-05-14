#!/usr/bin/env python3
import math
import subprocess
import sys

# (labeled, inputs_bits, sender_size, receiver_size, poly_modulus_degree,
#  partition_count, window_size, iteration_count)
ITER_COUNT = 10
INPUT_BITS = 32
CASES = [
    (0, INPUT_BITS, 2**16, 5535, 8192, 8, 3, ITER_COUNT),
    (1, INPUT_BITS, 2**16, 5535, 8192, 8, 3, ITER_COUNT),

    (0, INPUT_BITS, 2**16, 11041, 16384, 8, 2, ITER_COUNT),
    (1, INPUT_BITS, 2**16, 11041, 16384, 8, 2, ITER_COUNT),

    (0, INPUT_BITS, 2**20, 5535, 8192, 64, 2, ITER_COUNT),
    (1, INPUT_BITS, 2**20, 5535, 8192, 64, 2, ITER_COUNT),

    (0, INPUT_BITS, 2**20, 11041, 16384, 32, 3, ITER_COUNT),
    (1, INPUT_BITS, 2**20, 11041, 16384, 32, 3, ITER_COUNT),

    (0, INPUT_BITS, 2**24, 5535, 8192, 256, 1, ITER_COUNT),
    (1, INPUT_BITS, 2**24, 5535, 8192, 256, 1, ITER_COUNT),

    (0, INPUT_BITS, 2**24, 11041, 16384, 128, 2, ITER_COUNT),
    (1, INPUT_BITS, 2**24, 11041, 16384, 128, 2, ITER_COUNT),
]

def run_case(case):
    result = subprocess.run(['./benchmark', *map(str, case)], capture_output=True, check=True)
    labeled, input_bits, sender_size, receiver_size, poly_modulus_degree, partition_count, window_size, iteration_count = case
    lines = [x for x in result.stdout.decode().split('\n') if (len(x) > 0)]
    # the last element of the tuple is (matches / receiver_size)
    runs = [(float(x[0]), float(x[1]), float(x[2]), int(x[3]) / case[3])
            for x in (y.split('\t') for y in lines)]

    print('{it} runs of {la} N_x={nx}, N_y={ny} with SEAL{pmd}, alpha={al}, l={l}:'.format(
        it=iteration_count,
        la='labeled' if (labeled == 1) else 'unlabeled',
        nx=sender_size,
        ny=receiver_size,
        pmd=poly_modulus_degree,
        al=window_size,
        l=partition_count,
    ))

    avg = lambda l: sum(l) / len(l)
    def stddev(l):
        l_avg = avg(l)
        return math.sqrt(sum((x - l_avg)**2 for x in l) / (len(l) - 1))

    for (index, name) in enumerate(['sender, s', 'receiver enc, s', 'receiver dec, s', 'matches, %']):
        values = [x[index] for x in runs]
        print('{name}: avg {avg:.2f}, stddev {stddev:.2f}, min {min:.2f}, max {max:.2f}'.format(
            name=name,
            avg=avg(values),
            stddev=stddev(values),
            min=min(values),
            max=max(values)
        ))

    print()

def main():
    skipped_cases = 0
    if len(sys.argv) == 2:
        skipped_cases = int(sys.argv[1])

    for case in CASES[skipped_cases:]:
        run_case(case)


if __name__ == '__main__':
    main()
