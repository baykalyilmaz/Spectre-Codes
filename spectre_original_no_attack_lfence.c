#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

unsigned int array1_size = 16;
uint8_t array1[160] = {
  1,2,3,4,5,6,7,8,9,10,
  11,12,13,14,15,16
};
uint8_t array2[256 * 512];
uint8_t temp = 0xff;

void victim_function(size_t x) {
  if (x < array1_size) {
    __asm__ __volatile__("lfence" ::: "memory");  // Intel x86
    temp &= array2[array1[x] * 512];
  }
}

int main(int argc, const char **argv) {
  size_t safe_x = 5;  // A safe index inside array1
  int i;
  char dummy[40];

  for (i = 0; i < sizeof(array2); i++)
    array2[i] = 1;

  printf("Safe run of victim_function\n");

  // Optional: Add timing around this call if you want to compare durations
  victim_function(safe_x);

  printf("Finished safe access. temp=0x%02x\n", temp);
  return 0;
}

