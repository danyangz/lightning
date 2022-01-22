# distutils: language = c++
# cython: embedsignature = True
# cython: language_level = 3

from libcpp cimport bool as c_bool
from libcpp.memory cimport shared_ptr, unique_ptr
from libcpp.string cimport string as c_string

from libc.stdint cimport uint8_t, int32_t, uint64_t, int64_t
from libc.string cimport memcpy
from libcpp.unordered_map cimport unordered_map
from libcpp.vector cimport vector as c_vector

from _lightning_client cimport CLightningClient
from cpython cimport Py_buffer, PyObject
from cpython.buffer cimport PyBUF_SIMPLE, PyObject_CheckBuffer, PyBuffer_Release, PyObject_GetBuffer, PyBuffer_FillInfo, PyBUF_READ, PyBUF_WRITE
from cpython.memoryview cimport PyMemoryView_FromMemory

cdef class LightningStoreClient:
    cdef:
        unique_ptr[CLightningClient] client

    def __cinit__(self):
        pass

    def __init__(self, socket_name, password):
        cdef CLightningClient *new_client
        new_client = new CLightningClient(socket_name.encode(), password.encode())
        self.client.reset(new_client)

    def put_buffer(self, obj, object_id):
        cdef:
            uint8_t *buf
            Py_buffer py_buf
        if not PyObject_CheckBuffer(obj):
            raise ValueError("Python object hasn't implemented the buffer interface")
        status = PyObject_GetBuffer(obj, &py_buf, PyBUF_SIMPLE)
        if status:
            raise ValueError("Failed to convert python object into buffer")
        status = self.client.get().Create(object_id, &buf, py_buf.len)
        if status == -1:
            # special case: the object exists
            return -1
        if status:
            raise Exception("Failed to create new object, error code = " + str(status))
        memcpy(buf, py_buf.buf, py_buf.len)
        status = self.client.get().Seal(object_id)
        if status:
            raise Exception("Failed to seal new object, error code = " + str(status))

    def get_buffer(self, object_id):
        cdef:
            uint8_t *ptr
            size_t size
        status = self.client.get().Get(object_id, &ptr, &size)
        if status:
            return None
        return PyMemoryView_FromMemory(<char *> ptr, size, PyBUF_WRITE)

    def release(self, object_id):
        status = self.client.get().Release(object_id)
        if status:
            raise Exception("Failed to release object {}, error code = {}".format(object_id, status))

    def delete(self, object_id):
        status = self.client.get().Delete(object_id)
        if status:
            raise Exception("Failed to delete object {}, error code = {}".format(object_id, status))
