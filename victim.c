#include <emmintrin.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <unistd.h>

#include <x86intrin.h> /* for rdtscp and clflush */

#include "victim.h"

int shmid_array1;
int shmid_array1_size;
int shmid_array2;

uint8_t *array1;
uint8_t *array2;
size_t *array1_size;

uint8_t unused[64];
char *secret = "FLAG{spooky_scary_spectres_sends_shivers_down_your_spine}";
uint8_t unused2[64];
uint8_t unused3[64];

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

void victim_function(size_t x) {
  if (x < *array1_size) {
    temp &= array2[array1[x] * 512];
  }
}

void *init_shm(int projid, size_t size, int *shmid) {
  key_t key = ftok(SHM_PATHNAME, projid);
  *shmid = shmget(key, size, 0666 | IPC_CREAT);
  if (*shmid == -1) {
    perror("shmget failed");
    exit(1);
  }
  void *res = shmat(*shmid, NULL, 0);
  if (res == (uint8_t *)-1) {
    perror("shmat failed");
    exit(1);
  }
  return res;
}

void destroy(int projid) {
  key_t key = ftok(SHM_PATHNAME, projid);
  int shmid = shmget(key, 1024, 0666 | IPC_CREAT);
  shmctl(shmid, IPC_RMID, NULL);
}

void handler(int sig) {
  printf("Caught signal %d\n", sig);

  shmdt(array1);
  shmdt(array1_size);
  shmdt(array2);

  // delete shared memory
  shmctl(shmid_array1, IPC_RMID, NULL);
  shmctl(shmid_array1_size, IPC_RMID, NULL);
  shmctl(shmid_array2, IPC_RMID, NULL);

  exit(0);
}

void flush_array2() {
  // printf("Flushing array2\n");
  for (int i = 0; i < 256; i++)
    _mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */
}

int main() {
  signal(SIGINT, handler);

  array1_size =
      init_shm(ARRAY1_SIZE_PROJID, sizeof(size_t), &shmid_array1_size);
  *array1_size = 256;
  array1 = init_shm(ARRAY1_PROJID, *array1_size, &shmid_array1);
  array2 = init_shm(ARRAY2_PROJID, ARRAY2_SIZE, &shmid_array2);

  int msgid = msgget(MSG_KEY, 0666 | IPC_CREAT);
  if (msgid == -1) {
    perror("msgget failed");
    exit(1);
  }

  // put values in array1
  for (int i = 0; i < 16; i++)
    array1[i] = i + 1 + '0';

  printf("array1: %p\n", array1);
  printf("secret_ptr: %p\n", secret);
  printf("diff: %p\n", (size_t)(secret - (char *)array1));
  printf("initialized. waiting for messages...\n");
  while (1) {
    msg_buffer msg;
    if (msgrcv(msgid, &msg, sizeof(msg), 0, 0) == -1) {
      perror("msgrcv failed");
      exit(1);
    }
    if (msg.value == 0) {
      // do other memory-intensive stuff such that array2 is flushed
      flush_array2();
    } else {
      // printf("received message: %ld\n", msg.value);
      _mm_clflush(array1_size);
      _mm_mfence();
      victim_function(msg.value);
    }
    msgsnd(msgid, &(msg_buffer){2, 0}, sizeof(size_t), 0);
  }
}
