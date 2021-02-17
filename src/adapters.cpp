#include <cstddef>
#include <cstdint>
#include <emmintrin.h>
#include <immintrin.h>
#include <pybind11/pybind11.h>
#include <stdexcept>
#include <string_view>

namespace py = pybind11;
using namespace std;


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

        params = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data()));
        auto k0 = _mm_extract_epi64(params, 0);
        if (k0 == 0)
            throw std::invalid_argument("Bad key contents");

        // We only care about the lower 64 bits here
        k1 = _mm_bsrli_si128(params, 8);
        params = _mm_set_epi64x(27, k0);
    };
    uint64_t key(const char*, size_t);
    size_t next_cut(string_view, bool);

    size_t min_length, max_length;
    __m128i params, k1;
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
    __m128i u = params, v = _mm_loadu_si64(&buffer[offset - 4]);
    v = _mm_clmulepi64_si128(u, v, 0);
    u = _mm_clmulepi64_si128(u, v, 0b00010001);
    return _mm_extract_epi64(_mm_xor_si128(_mm_xor_si128(k1, u), v), 0);
}


PYBIND11_MODULE(_replicat_adapters, m) {
    py::class_<gclmulchunker>(m, "_gclmulchunker")
        .def(py::init<size_t, size_t, string_view>())
        .def_readonly("min_length", &gclmulchunker::min_length)
        .def_readonly("max_length", &gclmulchunker::max_length)
        .def("next_cut", &gclmulchunker::next_cut);
}
