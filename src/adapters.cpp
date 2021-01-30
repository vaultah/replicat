#include <cstddef>
#include <cstdint>
#include <string_view>
#include <immintrin.h>
#include <cstring>
#include <pybind11/pybind11.h>

namespace py = pybind11;
using namespace std;

union M128 {
    uint8_t i8[16];
    uint64_t i64[2];
    __m128i i128;
};


/* We abuse the idea from https://crypto.stackexchange.com/a/87426
   (specifically the gclmulchunker::key function)
   TODO: endianness?
*/
class gclmulchunker {
public:
    gclmulchunker(size_t _min_length, size_t _max_length, string_view key)
            : min_length((_min_length + 3) & -4), max_length(_max_length) {
        if (key.size() != 16)
            throw std::invalid_argument("key must contain exactly 16 characters");
        if (min_length > max_length)
            throw std::invalid_argument("Minimum length is greater than the maximum one");

        memcpy(reinterpret_cast<char *>(params.i8), key.data(), 16);
        if (params.i64[0] == 0)
            throw std::invalid_argument("Bad key contents");

        k0 = params.i64[1];
        params.i64[1] = 27;
    };
    uint64_t key(const char*, size_t);
    size_t next_cut(string_view, bool);

    size_t min_length, max_length;
    uint64_t k0;
    M128 params;
};

size_t gclmulchunker::next_cut(string_view buffer, bool final = false) {
    size_t i = min_length, max_index = min_length, size = buffer.size();
    uint64_t max_value = 0;
    const char* buffer_data = buffer.data();

    if (final && size < 2 * max_length) {
        // TODO: something better for weirder limits?
        if (size <= max_length)
            return size;
        else if (size < max_length + min_length)
            return size / 2;
        else
            return max_length;
    } else if (!final && size < max_length)
        return 0;

    for (; i < max_length; i += 4) {
        if (auto k = key(buffer_data, i); k > max_value) {
            max_index = i;
            max_value = k;
        }
    }
    return max_index;
}

uint64_t gclmulchunker::key(const char* buffer, size_t offset) {
    M128 u = params, v{};
    memcpy(reinterpret_cast<char *>(v.i8), &buffer[offset - 4], 8);
    v.i128 = _mm_clmulepi64_si128(u.i128, v.i128, 0);
    u.i128 = _mm_clmulepi64_si128(u.i128, v.i128, 0b00010001);
    return k0 ^ u.i64[0] ^ v.i64[0];
}

PYBIND11_MODULE(_replicat_adapters, m) {
    py::class_<gclmulchunker>(m, "_gclmulchunker")
        .def(py::init<size_t, size_t, string_view>())
        .def_readonly("min_length", &gclmulchunker::min_length)
        .def_readonly("max_length", &gclmulchunker::max_length)
        .def("next_cut", &gclmulchunker::next_cut);
}
