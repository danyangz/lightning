# cython: language_level = 3

from libcpp cimport bool as c_bool
from libcpp.memory cimport shared_ptr, unique_ptr
from libcpp.string cimport string as c_string

from libc.stdint cimport uint8_t, int32_t, uint64_t, int64_t, uint32_t
from libcpp.unordered_map cimport unordered_map
from libcpp.vector cimport vector as c_vector

cdef extern from "../inc/client.h" namespace "" nogil:
    cdef cppclass CLightningClient "LightningClient":
        CLightningClient(const c_string &store_socket, const c_string &password)

        int Create(uint64_t object_id, uint8_t **ptr, size_t size)

        int Seal(uint64_t object_id)

        int Get(uint64_t object_id, uint8_t **ptr, size_t *size)

        int Release(uint64_t object_id)

        int Delete(uint64_t object_id)
