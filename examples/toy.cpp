#include "../include/pside.h"
#include <cstdio>
#include <thread>

static constexpr unsigned long long ADDS = 40'000'000ULL;

void a() {
  volatile unsigned long long x;
  for (x = 0; x < ADDS; ++x)
    ;
}

void b() {
  volatile unsigned long long y;
  for (y = 0; y < ADDS / 2; ++y)
    ;
}

int main() {
  std::printf("Starting — two threads.\n");

  for (int i = 0; i < 100; ++i) {
    std::thread a_thread(a);
    std::thread b_thread(b);

    a_thread.join();
    b_thread.join();

    PSIDE_THROUGHPUT_POINT("loop_iter");

    std::printf(".");
    std::fflush(stdout);
  }

  std::printf("\n");
}
