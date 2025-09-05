#include "../include/random.h"
int write1024 = 0;
int write256 = 0;
int write64 = 0;

int Bufferpool::get_queue1024_len()
{
    return this->queue_1024.size();
}
int Bufferpool::get_queue256_len()
{
    return this->queue_256.size();
}

int Bufferpool::get_queue64_len()
{
    return this->queue_64.size();
}

int Bufferpool::init(int len)
{
    // clock_t time = clock();
    // gmp_randstate_t grt;
    mpz_t r;
    mpz_init(r);
    // gmp_randinit_default(grt);
    // gmp_randseed_ui(grt, time);
    if (len == 1024 && queue_1024.empty())
    {
        for (int i = 0; i < 2; i++)
        {
            mutex_1024.lock();
            mpz_urandomb(r, this->grt, len);
            char *str = mpz_get_str(NULL, 16, r);
            queue_1024.push(str);
            mutex_1024.unlock();
        }
    }
    else if (len == 256 && queue_256.empty())
    {
        for (int i = 0; i < 2; i++)
        {
            mutex_256.lock();
            mpz_urandomb(r, this->grt, len);
            char *str = mpz_get_str(NULL, 16, r);
            queue_256.push(str);
            mutex_256.unlock();
        }
    }
    else if (len == 64 && queue_64.empty())
    {
        for (int i = 0; i < 2; i++)
        {
            mutex_64.lock();
            mpz_urandomb(r, this->grt, len);
            char *str = mpz_get_str(NULL, 16, r);
            queue_64.push(str);
            mutex_64.unlock();
        }
    }
    return 0;
}
int Bufferpool::gen_random(int len)
{
    // clock_t time = clock();
    // gmp_randstate_t grt;
    mpz_t r;
    mpz_init(r);
    // gmp_randinit_default(grt);
    // gmp_randseed_ui(grt, time);
    if (len == 1024)
    {
        for (int i = 0; i < length; i++)
        {
            mpz_urandomb(r, this->grt, len);
            char *str = mpz_get_str(NULL, 16, r);
            mutex_1024.lock();
            queue_1024.push(str);
            mutex_1024.unlock();
        }
        write1024 = 0;
    }
    else if (len == 256)
    {
        for (int i = 0; i < length; i++)
        {
            mpz_urandomb(r, this->grt, len);
            char *str = mpz_get_str(NULL, 16, r);
            mutex_256.lock();
            queue_256.push(str);
            mutex_256.unlock();
        }
        write256 = 0;
    }
    else if (len == 64)
    {
        for (int i = 0; i < length; i++)
        {
            mpz_urandomb(r, this->grt, len);
            char *str = mpz_get_str(NULL, 16, r);
            mutex_64.lock();
            queue_64.push(str);
            mutex_64.unlock();
        }
        write64 = 0;
    }
    return 0;
}
int Bufferpool::get_random(mpz_t r, int len)
{
    mpz_init(r);
    if (len == 1024)
    {
        if (queue_1024.empty())
        {
            // Bufferpool* bp;
            // clock_t time = clock();
            // gmp_randstate_t grt;
            mpz_init(r);
            // gmp_randinit_default(grt);
            // gmp_randseed_ui(grt, time);
            mpz_urandomb(r, this->grt, len);
            if (!write1024)
            {
                write1024 = 1;
                thread t(&Bufferpool::gen_random, this, len);
                t.detach();
            }
        }
        else
        {
            mutex_1024.lock();
            char *str = queue_1024.front();
            queue_1024.pop();
            mutex_1024.unlock();
            mpz_set_str(r, str, 16);
        }
    }
    else if (len == 256)
    {
        if (queue_256.empty())
        {
            // Bufferpool* bp;
            // clock_t time = clock();
            // gmp_randstate_t grt;
            mpz_init(r);
            // gmp_randinit_default(grt);
            // gmp_randseed_ui(grt, time);
            mpz_urandomb(r, this->grt, len);
            if (!write256)
            {
                write256 = 1;
                thread t(&Bufferpool::gen_random, this, len);
                t.detach();
            }
        }
        else
        {
            mutex_256.lock();
            char *str = queue_256.front();
            queue_256.pop();
            mutex_256.unlock();
            mpz_set_str(r, str, 16);
        }
    }
    else if (len == 64)
    {
        if (queue_64.empty())
        {
            // Bufferpool* bp;
            // clock_t time = clock();
            // gmp_randstate_t grt;
            mpz_init(r);
            // gmp_randinit_default(grt);
            // gmp_randseed_ui(grt, time);
            mpz_urandomb(r, this->grt, len);
            if (!write64)
            {
                write64 = 1;
                thread t(&Bufferpool::gen_random, this, len);
                t.detach();
            }
        }
        else
        {
            mutex_64.lock();
            char *str = queue_64.front();
            queue_64.pop();
            mutex_64.unlock();
            mpz_set_str(r, str, 16);
        }
    }
    else
    {
        mpz_init(r);
        mpz_urandomb(r, this->grt, len);
    }
    return 0;
}
Bufferpool::Bufferpool()
{
    if (!this->flag)
    {
        clock_t time = clock();
        gmp_randinit_default(this->grt);
        gmp_randseed_ui(this->grt, time);
        this->flag = 1;
        mpz_t r;
        for (int i = 0; i < 10; i++)
        {
            mpz_init(r);
            mpz_urandomb(r, this->grt, 1024);
            mpz_set_ui(r, time);
        }
    }
}
int Bufferpool::set_length(int l)
{
    this->length = l;
    return 0;
}
int Bufferpool::get_length()
{
    return this->length;
}
// Bufferpool::~Bufferpool()
// {
// }

queue<char *> Bufferpool::queue_1024;
queue<char *> Bufferpool::queue_256;
queue<char *> Bufferpool::queue_64;
int Bufferpool::length = 1000;
int Bufferpool::flag = 0;
gmp_randstate_t Bufferpool::grt;
int Random::get_rand(mpz_t r, int len)
{
    mpz_init(r);
    bp.get_random(r, len);
    return 0;
}
int Random::set_pool_len(int l)
{
    bp.set_length(l);
    return 0;
}
Random::Random()
{
    // thread t1(&Bufferpool::init, &bp, 1024);
    // thread t2(&Bufferpool::init, &bp, 256);
    // thread t3(&Bufferpool::init, &bp, 64);
    // t1.join();
    // t2.join();
    // t3.join();
}

