#include <iostream>
#include <random>
#include <cstring>
using namespace std;

uint32_t murmur3_32(const uint8_t *key, size_t len, uint32_t seed)
{
    uint32_t h = seed;
    if (len > 3)
    {
        const uint32_t *key_x4 = (const uint32_t *)key;
        size_t i = len >> 2;
        do
        {
            uint32_t k = *key_x4++;
            k *= 0xcc9e2d51;
            k = (k << 15) | (k >> 17);
            k *= 0x1b873593;
            h ^= k;
            h = (h << 13) | (h >> 19);
            h = (h * 5) + 0xe6546b64;
        } while (--i);
        key = (const uint8_t *)key_x4;
    }
    if (len & 3)
    {
        size_t i = len & 3;
        uint32_t k = 0;
        key = &key[i - 1];
        do
        {
            k <<= 8;
            k |= *key--;
        } while (--i);
        k *= 0xcc9e2d51;
        k = (k << 15) | (k >> 17);
        k *= 0x1b873593;
        h ^= k;
    }
    h ^= len;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

const uint32_t b = 4;                // b for fingerprint per bucket
const uint32_t f = 8;                // f for fingerprint length
const uint32_t m = (1 << 20);        // m for number of buckets
const uint32_t n = 100000;           // n for number of elements
const uint32_t hash_seed = 93565883; //seed for hash
const uint32_t fp_seed = 10764371;   //seed for hash

uint8_t cuckoo_buckets[(f * m * b + 7) / 8];
default_random_engine generator;
uniform_int_distribution<int> kick_distribution(0, b);
uniform_int_distribution<int> data_distribution(0, UINT32_MAX);

bool write_fp_to_table(uint8_t *buckets, const uint32_t fp_index, uint32_t fp)
{
    uint32_t bit_offset = fp_index * f;
    uint8_t *ptr = buckets + bit_offset / 8;
    uint32_t bit_got = 0;
    uint8_t tmp = 0;
    bit_offset = bit_offset % 8;

    // first byte (may be part)
    tmp = (uint8_t)(fp << bit_offset);
    *ptr = (((*ptr) << (8 - bit_offset)) >> (8 - bit_offset) | tmp);
    bit_got += 8 - bit_offset;
    fp = fp >> (8 - bit_offset);
    ptr++;

    //middle
    while (bit_got + 8 < f)
    {
        *ptr = (uint8_t)fp;
        fp = fp >> 8;
        bit_got += 8;
        ptr++;
    }

    // last byte (may be part)
    uint32_t bit_left = f - bit_got;
    *ptr = (((*ptr) >> bit_left) << bit_left) | fp;

    return true;
}
const uint32_t get_fp_in_table(const uint8_t *buckets, const uint32_t fp_index)
{
    uint32_t bit_offset = fp_index * f;
    const uint8_t *ptr = buckets + (bit_offset / 8);
    uint32_t bit_got = 0;
    uint32_t ret = 0;
    bit_offset = bit_offset % 8;

    // first byte (may be part)
    ret = (*ptr) >> bit_offset;
    bit_got += 8 - bit_offset;
    ptr++;

    // middle bytes
    while (bit_got + 8 < f)
    {
        ret = ret | ((uint32_t)(*ptr) << bit_got);
        bit_got += 8;
        ptr++;
    }

    // last byte (may be part)
    uint32_t bit_left = f - bit_got;
    ret = ret | ((((*ptr) << (8 - bit_left)) >> (8 - bit_left)) << bit_got);
    return ret;
}

int32_t bucket_has_empty(const uint8_t *buckets, const uint32_t bucket_index)
{
    for (int i = 0; i < b; i++)
    {
        if (get_fp_in_table(buckets, bucket_index * b + i) == 0)
            return i;
    }
    return -1;
}

bool insert_fingerprint(uint8_t *buckets, const uint32_t buckets_number, const uint32_t fp, const uint32_t hash, const int32_t kick_round)
{
    if (kick_round >= 80)
        return false;
    uint32_t alter_pos = (murmur3_32((const uint8_t *)&fp, sizeof(fp), hash_seed) ^ hash) & (buckets_number - 1);
    // cout << hex << hash << ' ' << alter_pos << endl;
    int32_t pos_in_bucket = bucket_has_empty(buckets, alter_pos);
    if (pos_in_bucket >= 0)
    {
        // cout << pos_in_bucket << endl;
        return write_fp_to_table(buckets, pos_in_bucket + alter_pos * b, fp);
    }
    else
    {
        int kicked_index = kick_distribution(generator);
        uint32_t kicked_fp = get_fp_in_table(buckets, kicked_index + alter_pos * b);
        write_fp_to_table(buckets, pos_in_bucket + alter_pos * b, fp);
        return insert_fingerprint(buckets, buckets_number, kicked_fp, alter_pos, kick_round + 1);
    }
}
bool insert_element(uint8_t *buckets, const uint32_t buckets_number, const uint32_t element)
{
    uint32_t hash = murmur3_32((const uint8_t *)&element, sizeof(element), hash_seed);
    uint32_t fp = murmur3_32((const uint8_t *)&element, sizeof(element), fp_seed);
    hash = hash % buckets_number;
    fp = (fp << (32 - f)) >> (32 - f);
    // cout << hex << hash << endl;
    int32_t pos_in_bucket = bucket_has_empty(buckets, hash);
    // cout << pos_in_bucket << endl;
    if (pos_in_bucket >= 0)
    {
        return write_fp_to_table(buckets, pos_in_bucket + hash * b, fp);
    }
    else
    {
        int kicked_index = kick_distribution(generator);
        uint32_t kicked_fp = get_fp_in_table(buckets, kicked_index + hash * b);
        write_fp_to_table(buckets, pos_in_bucket + hash * b, fp);
        return insert_fingerprint(buckets, buckets_number, kicked_fp, hash, 1);
    }
}

int main()
{
    uint32_t key1 = 622923, key2 = 74745009;
    memset(cuckoo_buckets, 0, sizeof(cuckoo_buckets));
    for (int i = 0;; i++)
    {
        if (!insert_element(cuckoo_buckets, m, data_distribution(generator)))
        {
            cout << dec << "Fail, i = " << i << endl;
            break;
        }
    }
    return 0;
}