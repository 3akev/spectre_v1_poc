#ifndef VICTIM_H
#define VICTIM_H

#include <stddef.h>
#define SHM_PATHNAME "victim"

#define ARRAY1_PROJID 41
#define ARRAY2_PROJID 42
#define ARRAY1_SIZE_PROJID 43

#define ARRAY2_SIZE 512 * 512

// msg queue for calling victim function
#define MSG_KEY 1234

typedef struct {
  long msg_type;
  size_t value;
} msg_buffer;

#endif
