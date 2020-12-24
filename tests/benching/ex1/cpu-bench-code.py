from multiprocessing import Pool, cpu_count


def f(x):
    while True:
        x * x


processes = cpu_count()
f"utilizing {processes} cores\n"
pool = Pool(processes)
pool.map(f, range(processes))
