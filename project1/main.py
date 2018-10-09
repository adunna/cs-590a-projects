import argparse, hashlib, time
from multiprocessing import Pool
from itertools import product, count
from functools import partial

def pass_generator(maxlen, alphabet):
    return product(alphabet, repeat = maxlen)

def compute_hashes(clearcheck, algo, hashed, enc):
    if getattr(hashlib, algo)("".join(clearcheck).encode(enc)).hexdigest() == hashed:
        print("Cleartext found: " + "".join(clearcheck))
        print("Continuing search to find collisions...\n")
        return "".join(clearcheck)
    return None

def main(inp, method, cores, maxlen, strlen, strenc, rdict):
    if rdict is None:
        print("Starting brute force attack...\n")
    else:
        maxlen += 1
        if strlen != 0:
            strlen += 1
        print("Starting dictionary + brute force attack...\n")
    init_time = time.time()
    pool = Pool(processes=cores)
    inp = inp.lower()
    part = partial(compute_hashes, algo=method, hashed=inp, enc=strenc)
    alphabet = None
    dictuse = None
    results = []
    with open('alphabet.txt', 'r') as f:
        alphabet = f.read().rstrip('\n')
        alphabet = [x for x in alphabet]
    if rdict is not None:
        with open(rdict, 'r') as f:
            dictuse = f.read().splitlines()
        alphabet += dictuse
    if strlen == 0:
        for i in range(1, maxlen + 1):
            results.append(pool.map(part, pass_generator(i, alphabet)))
    else:
        results.append(pool.map(part, pass_generator(strlen, alphabet)))
    print("Total cleartext list:")
    for subarr in results:
        res = [x for x in subarr if x is not None]
        if len(res) != 0:
            print(res)
    print("\nTime to completion: " + str(time.time() - init_time) + "s")
    pool.close()
    pool.join()

if __name__ == '__main__':
    par = argparse.ArgumentParser(description = "Hash brute forcing.")
    par.add_argument('inputhash', metavar='hash', type=str, help="The input hash.")
    par.add_argument("hashmethod", metavar="method", type=str, help='The hash method. Use `--list` for a list of all available algorithms.')
    par.add_argument("--list", action="store_true", help="List available algorithms. Overrides other arguments.")
    par.add_argument("--dict", type=str, help="If assigned, reads the file and performs a dictionary attack with a brute force attack.", default=None)
    par.add_argument("--corecount", type=int, help="The number of threads to use (recommended to set to number of cores). Default is 1.", default=1)
    par.add_argument("--maxlen", type=int, default=3, help="Maximum length of string combination to brute force, if no string length is specified. Default is 3.")
    par.add_argument("--length", type=int, default=0, help="Designated length of string to brute force. Overrides the 'maxlen' option to set a specific length.")
    par.add_argument("--encoding", type=str, default="ascii", help="String encoding, 'utf-8' or 'ascii'; default is ASCII.")
    arg = par.parse_args()
    if arg.list:
        print(", ".join(hashlib.algorithms_guaranteed))
    else:
        main(arg.inputhash, arg.hashmethod, arg.corecount, arg.maxlen, arg.length, arg.encoding, arg.dict)
