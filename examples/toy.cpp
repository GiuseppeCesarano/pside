#include "../include/pside.h"
#include <cstdio>
#include <thread>

static constexpr unsigned long long HOT_ADDS = 4'000'000ULL;
static constexpr unsigned long long CAP_ADDS = HOT_ADDS / 2;

static constexpr int ITERATIONS = 1000;

void hot() {
  volatile unsigned long long x;
  for (x = 0; x < HOT_ADDS; ++x)
    ;
}

void cap() {
  volatile unsigned long long y;
  for (y = 0; y < CAP_ADDS; ++y)
    ;
}

int main() {
  std::printf("Starting: two threads.\n");

  for (int i = 0; i < ITERATIONS; ++i) {
    std::thread hot_thread(hot);
    std::thread cap_thread(cap);

    hot_thread.join();
    cap_thread.join();

    PSIDE_THROUGHPUT_POINT("loop_iter");

    if (i % 100 == 0) {
      std::printf(".");
      std::fflush(stdout);
    }
  }

  std::printf("\n");
}
