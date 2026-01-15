#define PSIDE_THROUGHPUT_POINT(name)                                           \
  static_assert(sizeof(name) != 0, "PSIDE point needs a neme");                \
  __asm__ __volatile__(                                                        \
      ".p2align 4\n\t"                                                         \
      "1:\n\t"                                                                 \
      ".byte 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00\n\t"               \
      ".byte 0x0f, 0x1f, 0x40, 0x00\n\t"                                       \
                                                                               \
      ".pushsection .pside_throughput, \"R\", @progbits\n\t"                   \
      ".quad 1b\n\t"                                                           \
      ".asciz \"" name "\"\n\t"                                                \
      ".popsection\n\t" ::                                                     \
          : "rax")
