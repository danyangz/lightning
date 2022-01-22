import atexit
import subprocess
import time
import numpy as np

from py_lightning_client import LightningStoreClient

proc = subprocess.Popen("../build/store")

def cleanup():
    global proc
    proc.terminate()

def test(client, object_size):
    s = int(object_size/8)
    buf = np.random.randint(2 ** 30, size=s, dtype='l')
    print(buf.nbytes, end = ','),

    num_tests = 100

    start = time.time()
    for i in range(num_tests):
        client.put_buffer(buf, i)
    duration = time.time() - start
    print(duration/num_tests, end = ','),

    start = time.time()
    for i in range(num_tests):
        client.get_buffer(i)
    duration = time.time() - start
    print(duration/num_tests, end = ','),

    start = time.time()
    for i in range(num_tests):
        client.delete(i)
    duration = time.time() - start
    print(duration/num_tests)

atexit.register(cleanup)
time.sleep(1)

client = LightningStoreClient("/tmp/lightning", "password")

for i in range(0,100):
    object_size = 1024 * 1024
    while (object_size >= 16):
        test(client, object_size)
        object_size /=2
