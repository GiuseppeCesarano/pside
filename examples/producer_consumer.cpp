#include <cassert>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include "../include/pside.h"

static constexpr int ITEMS = 1'000'000;
static constexpr int QUEUE_CAPACITY = 10;
static constexpr int PRODUCER_COUNT = 5;
static constexpr int CONSUMER_COUNT = 3;

static_assert(ITEMS % PRODUCER_COUNT == 0,
              "ITEMS must be evenly divisible by PRODUCER_COUNT");

struct SharedQueue {
  std::queue<int> q;
  std::mutex mtx;
  std::condition_variable cv_not_full;
  std::condition_variable cv_not_empty;

  int produced = 0;
  int consumed = 0;

  bool all_produced = false;
};

void producer(SharedQueue &sq) {
  constexpr int items_per_producer = ITEMS / PRODUCER_COUNT;

  for (int i = 0; i < items_per_producer; ++i) {
    std::unique_lock lock(sq.mtx);

    sq.cv_not_full.wait(
        lock, [&] { return static_cast<int>(sq.q.size()) < QUEUE_CAPACITY; });

    sq.q.push(123);
    ++sq.produced;
    sq.cv_not_empty.notify_one();
  }

  {
    std::unique_lock lock(sq.mtx);
    if (sq.produced == ITEMS) {
      sq.all_produced = true;
      sq.cv_not_empty.notify_all();
    }
  }
}

void consumer(SharedQueue &sq) {
  while (true) {
    std::unique_lock lock(sq.mtx);

    sq.cv_not_empty.wait(lock,
                         [&] { return !sq.q.empty() || sq.all_produced; });

    if (sq.q.empty())
      return;

    const int val = sq.q.front();
    sq.q.pop();
    assert(val == 123);
    ++sq.consumed;

    lock.unlock();
    sq.cv_not_full.notify_one();

    PSIDE_THROUGHPUT_POINT("tp");
  }
}

int main() {
  SharedQueue sq;

  std::vector<std::thread> producers, consumers;
  producers.reserve(PRODUCER_COUNT);
  consumers.reserve(CONSUMER_COUNT);

  for (int i = 0; i < PRODUCER_COUNT; ++i)
    producers.emplace_back(producer, std::ref(sq));

  for (int i = 0; i < CONSUMER_COUNT; ++i)
    consumers.emplace_back(consumer, std::ref(sq));

  for (auto &t : producers)
    t.join();
  for (auto &t : consumers)
    t.join();

  assert(sq.produced == ITEMS);
  assert(sq.consumed == ITEMS);
}
