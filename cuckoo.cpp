#include <iostream>
#include <random>
#include <unordered_set>
#include <chrono>
#include <cstring>
#include <cassert>
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
uint32_t get_highest_1(uint32_t x) // WARNING: may overflow
{
    x = x | (x >> 1);
    x = x | (x >> 2);
    x = x | (x >> 4);
    x = x | (x >> 8);
    x = x | (x >> 16);
    return (x + 1) >> 1;
}

const uint32_t b = 4;
// const uint32_t m = (0xaaaaaa);       // m for number of buckets
// const uint32_t n = 100000;           // n for number of elements
const uint32_t hash_seed = 93565883; //seed for hash
const uint32_t fp_seed = 10764371;   //seed for fingerprint

default_random_engine generator;
uniform_int_distribution<int> kick_distribution(0, 3);
uniform_int_distribution<int> data_distribution(0, UINT32_MAX);

bool write_fp_to_table(uint8_t *buckets, const uint32_t fp_index, uint32_t fp)
{
    uint8_t *ptr = buckets + fp_index;
    *ptr = (uint8_t)fp;
    return true;
}
const uint32_t get_fp_in_table(const uint8_t *buckets, const uint32_t fp_index)
{
    return *(buckets + fp_index);
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

bool kick_fingerprint(uint8_t *buckets, const uint32_t buckets_number, const uint32_t fp, const uint32_t hash, const int32_t kick_round)
{
    // cout << "hash = " << hash << ", fp = " << fp << endl;

    if (kick_round >= 100)
        return false;
    uint32_t alter_pos = (murmur3_32((const uint8_t *)&fp, sizeof(fp), hash_seed) ^ hash) & (buckets_number - 1);
    // cout << "alter_pos = " << alter_pos << ", fp = " << fp << endl;
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
        write_fp_to_table(buckets, kicked_index + alter_pos * b, fp);
        // cout << "kicked_index = " << kicked_index << ", kicked fp = " << kicked_fp << endl;
        return kick_fingerprint(buckets, buckets_number, kicked_fp, alter_pos, kick_round + 1);
    }
}
bool insert_element(uint8_t *buckets, const uint32_t buckets_number, const uint32_t element, const uint32_t hash, const uint32_t fp)
{
    assert(hash < buckets_number);
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
        write_fp_to_table(buckets, kicked_index + hash * b, fp);
        return kick_fingerprint(buckets, buckets_number, kicked_fp, hash, 1);
    }
}

bool query_element(const uint8_t *buckets, const uint32_t buckets_number, const uint32_t hash, const uint32_t fp)
{
    assert(hash < buckets_number);

    for (int i = 0; i < b; i++)
    {
        if (get_fp_in_table(buckets, hash * b + i) == fp)
            return true;
    }
    uint32_t alter_pos = (murmur3_32((const uint8_t *)&fp, sizeof(fp), hash_seed) ^ hash) & (buckets_number - 1);

    for (int i = 0; i < b; i++)
    {
        if (get_fp_in_table(buckets, alter_pos * b + i) == fp)
            return true;
    }
    return false;
}

struct dcuckoo_division
{
    uint8_t *buckets = nullptr;
    uint32_t end = 0;
    uint32_t bucket_number = 0;
};

void dcuckoo(uint32_t table_size, const unordered_set<uint32_t> &elements, const unordered_set<uint32_t> &negative_elements)
{
    cout << "Divided cuckoo: size = " << table_size << endl;
    dcuckoo_division dcuckoo_buckets[32];
    uint32_t dcuckoo_used = 0;
    uint32_t m_left = table_size, m_acc = 0;
    while (m_left != 0)
    {
        uint32_t curr = get_highest_1(m_left);
        m_acc += curr;
        m_left -= curr;
        dcuckoo_buckets[dcuckoo_used].buckets = new uint8_t[curr * b];
        memset(dcuckoo_buckets[dcuckoo_used].buckets, 0, curr * b);
        dcuckoo_buckets[dcuckoo_used].end = m_acc;
        dcuckoo_buckets[dcuckoo_used].bucket_number = curr;
        dcuckoo_used++;
    }
    auto start = chrono::system_clock::now();
    for (uint32_t element : elements)
    {
        uint32_t hash = murmur3_32((const uint8_t *)&element, sizeof(element), hash_seed);
        hash = hash % table_size;
        uint32_t fp = murmur3_32((const uint8_t *)&element, sizeof(element), fp_seed);
        fp = fp & 0xff;
        uint32_t bucket_to_use_index = 0;
        for (uint32_t j = 0; j < dcuckoo_used; j++)
        {
            if (hash > dcuckoo_buckets[j].end)
            {
                continue;
            }
            else
            {
                hash = hash & (dcuckoo_buckets[j].bucket_number - 1);
                bucket_to_use_index = j;
                break;
            }
        }
        if (!insert_element(dcuckoo_buckets[bucket_to_use_index].buckets, dcuckoo_buckets[bucket_to_use_index].bucket_number, element, hash, fp))
        {
            // do nothing, just disgard
            // cout << dec << "Fail, i = " << i << endl;
            // goto end;
        }
    }
    auto end = chrono::system_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    cout << "Insert time: " << duration.count() << "us, " << (double)duration.count() / elements.size() << "us per op" << endl;

    // query
    uint32_t true_positive = 0, true_negative = 0, false_positive = 0, false_negative = 0;
    start = chrono::system_clock::now();
    for (const uint32_t element : elements)
    {
        uint32_t hash = murmur3_32((const uint8_t *)&element, sizeof(element), hash_seed);
        hash = hash % table_size;
        uint32_t fp = murmur3_32((const uint8_t *)&element, sizeof(element), fp_seed);
        fp = fp & 0xff;
        uint32_t bucket_to_use_index = 0;

        for (uint32_t j = 0; j < dcuckoo_used; j++)
        {
            if (hash > dcuckoo_buckets[j].end)
            {
                continue;
            }
            else
            {
                hash = hash & (dcuckoo_buckets[j].bucket_number - 1);
                bucket_to_use_index = j;
                break;
            }
        }

        if (query_element(dcuckoo_buckets[bucket_to_use_index].buckets, dcuckoo_buckets[bucket_to_use_index].bucket_number, hash, fp))
        {
            true_positive++;
        }
        else
        {
            false_negative++;
        }
    }
    for (const uint32_t element : negative_elements)
    {
        uint32_t hash = murmur3_32((const uint8_t *)&element, sizeof(element), hash_seed);
        hash = hash % table_size;
        uint32_t fp = murmur3_32((const uint8_t *)&element, sizeof(element), fp_seed);
        fp = fp & 0xff;
        uint32_t bucket_to_use_index = 0;
        for (uint32_t j = 0; j < dcuckoo_used; j++)
        {
            if (hash > dcuckoo_buckets[j].end)
            {
                continue;
            }
            else
            {
                hash = hash & (dcuckoo_buckets[j].bucket_number - 1);
                bucket_to_use_index = j;
                break;
            }
        }
        if (query_element(dcuckoo_buckets[bucket_to_use_index].buckets, dcuckoo_buckets[bucket_to_use_index].bucket_number, hash, fp))
        {
            false_positive++;
        }
        else
        {
            true_negative++;
        }
    }
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    cout << "Query time: " << duration.count() << "us, " << (double)duration.count() / (elements.size() + negative_elements.size()) << "us per op" << endl;
    cout << "true positive:" << true_positive << ';' << "false positive:" << false_positive << "; false positive rate = " << (double)false_positive / (false_positive + true_positive) << endl;
    cout << "false negative:" << false_negative << ';' << "true negative:" << true_negative << "; false negative rate = " << (double)false_negative / (false_negative + true_negative) << endl;
    cout << endl;

end:
    for (int i = 0; i < dcuckoo_used; i++)
    {
        delete[] dcuckoo_buckets[i].buckets;
    }
    return;
}

void cuckoo(uint32_t table_size, const unordered_set<uint32_t> &elements, const unordered_set<uint32_t> &negative_elements)
{
    assert(table_size - get_highest_1(table_size) == 0);
    uint8_t *cuckoo_buckets = new uint8_t[table_size * b];
    memset(cuckoo_buckets, 0, table_size * b);
    cout << "Standard cuckoo: size = " << table_size << endl;
    // insert
    auto start = chrono::system_clock::now();
    for (const uint32_t element : elements)
    {
        uint32_t hash = murmur3_32((const uint8_t *)&element, sizeof(element), hash_seed);
        hash = hash % table_size;
        uint32_t fp = murmur3_32((const uint8_t *)&element, sizeof(element), fp_seed);
        fp = fp & 0xff;
        // cout << hash << ' ' << fp << endl;
        if (!insert_element(cuckoo_buckets, table_size, element, hash, fp))
        {
            // do nothing, just disgard
            // cout << dec << "Fail, i = " << i << endl;
            // break;
            // cout << "insert fail" << endl;
        }
    }
    auto end = chrono::system_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    cout << "Insert time: " << duration.count() << "us, " << (double)duration.count() / elements.size() << "us per op" << endl;

    // query
    uint32_t true_positive = 0, true_negative = 0, false_positive = 0, false_negative = 0;
    start = chrono::system_clock::now();
    for (const uint32_t element : elements)
    {
        uint32_t hash = murmur3_32((const uint8_t *)&element, sizeof(element), hash_seed);
        hash = hash % table_size;
        uint32_t fp = murmur3_32((const uint8_t *)&element, sizeof(element), fp_seed);
        fp = fp & 0xff;
        if (query_element(cuckoo_buckets, table_size, hash, fp))
        {
            true_positive++;
        }
        else
        {
            false_negative++;
        }
    }
    for (const uint32_t element : negative_elements)
    {
        uint32_t hash = murmur3_32((const uint8_t *)&element, sizeof(element), hash_seed);
        hash = hash % table_size;
        uint32_t fp = murmur3_32((const uint8_t *)&element, sizeof(element), fp_seed);
        fp = fp & 0xff;
        if (query_element(cuckoo_buckets, table_size, hash, fp))
        {
            false_positive++;
        }
        else
        {
            true_negative++;
        }
    }
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    cout << "Query time: " << duration.count() << "us, " << (double)duration.count() / (elements.size() + negative_elements.size()) << "us per op" << endl;
    cout << "true positive:" << true_positive << ';' << "false positive:" << false_positive << "; false positive rate = " << (double)false_positive / (false_positive + true_positive) << endl;
    cout << "false negative:" << false_negative << ';' << "true negative:" << true_negative << "; false negative rate = " << (double)false_negative / (false_negative + true_negative) << endl;
    cout << endl;

    delete[] cuckoo_buckets;
}

int main()
{
    // const uint32_t dcuckoo_size = 0x3fffff;
    uint32_t dcuckoo_size = 0x200000;
    uint32_t num_1 = 1;
    const double loading_factor = 0.95;

    while (dcuckoo_size <= 0x3fffff)
    {
        cout << "Dcuckoo size = " << dcuckoo_size << ", num of 1 = " << num_1 << endl;
        uint32_t cuckoo_size = get_highest_1(dcuckoo_size - 1) << 1;
        const uint32_t delement_number = dcuckoo_size * loading_factor * b;
        const uint32_t element_number = cuckoo_size * loading_factor * b;
        unordered_set<uint32_t> elements;
        unordered_set<uint32_t> negative_elements;

        while (elements.size() < delement_number)
        {
            uint32_t element = data_distribution(generator);
            uint32_t fp = murmur3_32((const uint8_t *)&element, sizeof(element), fp_seed);
            fp = fp & 0xff;
            if (fp != 0)
            {
                elements.insert(element);
            }
        }
        while (negative_elements.size() < delement_number)
        {
            uint32_t element = data_distribution(generator);
            uint32_t fp = murmur3_32((const uint8_t *)&element, sizeof(element), fp_seed);
            fp = fp & 0xff;
            if (fp != 0 && elements.find(element) == elements.end())
            {
                negative_elements.insert(element);
            }
        }
        dcuckoo(dcuckoo_size, elements, negative_elements);

        while (elements.size() < element_number)
        {
            uint32_t element = data_distribution(generator);
            uint32_t fp = murmur3_32((const uint8_t *)&element, sizeof(element), fp_seed);
            fp = fp & 0xff;
            if (fp != 0)
            {
                elements.insert(element);
            }
        }
        while (negative_elements.size() < element_number)
        {
            uint32_t element = data_distribution(generator);
            uint32_t fp = murmur3_32((const uint8_t *)&element, sizeof(element), fp_seed);
            fp = fp & 0xff;
            if (fp != 0 && elements.find(element) == elements.end())
            {
                negative_elements.insert(element);
            }
        }
        cuckoo(cuckoo_size, elements, negative_elements);

        dcuckoo_size += (1 << (num_1 - 1));
        num_1++;
    }
    return 0;
}