/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2016-2017 XMRig       <support@xmrig.com>
 *
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


#include "crypto/CryptoNight.h"

#if defined(XMRIG_ARM)
#   include "crypto/CryptoNight_arm.h"
#else
#   include "crypto/CryptoNight_x86.h"
#endif

#include "crypto/CryptoNight_test.h"


static void cryptonight_av1_aesni(const void *input, size_t size, void *output, struct cryptonight_ctx *ctx) {
#   if !defined(XMRIG_ARMv7)
    cryptonight_hash<0x80000, MEMORY, 0x1FFFF0, false>(input, size, output, ctx);
#   endif
}


static void cryptonight_av2_aesni_double(const void *input, size_t size, void *output, cryptonight_ctx *ctx) {
#   if !defined(XMRIG_ARMv7)
    cryptonight_double_hash<0x80000, MEMORY, 0x1FFFF0, false>(input, size, output, ctx);
#   endif
}


static void cryptonight_av3_softaes(const void *input, size_t size, void *output, cryptonight_ctx *ctx) {
    cryptonight_hash<0x80000, MEMORY, 0x1FFFF0, true>(input, size, output, ctx);
}


static void cryptonight_av4_softaes_double(const void *input, size_t size, void *output, cryptonight_ctx *ctx) {
    cryptonight_double_hash<0x80000, MEMORY, 0x1FFFF0, true>(input, size, output, ctx);
}


void (*cryptonight_variations[4])(const void *input, size_t size, void *output, cryptonight_ctx *ctx) = {
            cryptonight_av1_aesni,
            cryptonight_av2_aesni_double,
            cryptonight_av3_softaes,
            cryptonight_av4_softaes_double
        };

void(*cryptonight_hash_ctx)(const void *input, size_t size, void *output, cryptonight_ctx *ctx) = cryptonight_variations[0];

bool CryptoNight::hash(const uint8_t *input, size_t size, uint8_t *output, cryptonight_ctx *ctx)
{
    cryptonight_hash_ctx(input, size, output, ctx);

	//return *reinterpret_cast<uint64_t*>(input + 24) < 0x99922206;
	return true;
}

bool CryptoNight::selfTest() {
    if (cryptonight_hash_ctx == nullptr) {
        return false;
    }

    char output[64];

    struct cryptonight_ctx *ctx = (struct cryptonight_ctx*) _mm_malloc(sizeof(struct cryptonight_ctx), 16);
    ctx->memory = (uint8_t *) _mm_malloc(MEMORY * 2, 16);

    cryptonight_hash_ctx(test_input, 76, output, ctx);

    _mm_free(ctx->memory);
    _mm_free(ctx);

    return memcmp(output, test_output0, 32) == 0;
}
