__attribute__((noreturn)) void _start() {
  asm volatile("mov $42, %rax\n"
               "hlt\n");

  while (1) {
  }
}