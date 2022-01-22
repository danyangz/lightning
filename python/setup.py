import os
from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize

ext_modules = [
    Extension(
        "py_lightning_client",
        sources=["_lightning_client.pyx", "../src/log_disk.cc", "../src/object_log.cc", "../src/malloc.cc", "../src/client.cc"],
        include_dirs=[os.path.abspath("../inc/")],
        extra_compile_args=["-std=c++11"],
        extra_link_args=["-std=c++11"],
    )
]

setup(name="py_lightning_client",
      ext_modules=cythonize(ext_modules))
