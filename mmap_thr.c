/* 
    Copyright (c) 2011 Anil Madhavapeddy <anil@recoil.org>

    Permission is hereby granted, free of charge, to any person
    obtaining a copy of this software and associated documentation
    files (the "Software"), to deal in the Software without
    restriction, including without limitation the rights to use,
    copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following
    conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
    OTHER DEALINGS IN THE SOFTWARE.
*/

#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/time.h>
#include <err.h>
#include <inttypes.h>
#include <netdb.h>
#include <pthread.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include "test.h"
#include "xutil.h"
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/sem.h>
#include <semaphore.h>
#include <sys/resource.h>

#define SEMNAME "mmap_test_lat"
                                     
sem_t *mutex;
int request;

typedef struct {
  struct iovec rbuf;
  struct iovec wbuf;
} mem_state;

mem_state mems;

int sfd;

static void
init_test(test_data *td)
{
 
  int *addr;                  /* Pointer to shared memory region */
  if ((mutex = sem_open(SEMNAME, O_CREAT|O_RDWR, 0644, 1))
      == SEM_FAILED) {                                                          
    err(1, "sem_open");                                                       
    sem_unlink(SEMNAME);                                                        
    exit(1);                                                                    
  }                  
  sfd = open("/smem", O_RDWR, S_IRWXU | S_IRWXG);

  addr = mmap(NULL, td->size, PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_ANONYMOUS, sfd, 0);
 
 if (addr == MAP_FAILED){
    err(1, "MAP FAILED");
  }

  td->data = (void *)addr;
  mems.rbuf.iov_base = xmalloc(td->size); 
  mems.wbuf.iov_base = xmalloc(td->size); 
  mems.rbuf.iov_len = td->size;
  mems.wbuf.iov_len = td->size;
  printf("Read buf is at %p\n", mems.rbuf.iov_base);
  printf("Write buf is at %p\n", mems.wbuf.iov_base);
}

static void
init_local(test_data *td)
{
}

static struct iovec*
get_read_buf(test_data *td, int len, int* n_vecs)
{
  sem_wait(mutex);                                                       
  printf("Child: Reading to %p\n", mems.rbuf.iov_base);
  memcpy(mems.rbuf.iov_base, td->data, td->size);
  sem_post(mutex);
  *n_vecs = 1;
  return &mems.rbuf;
}

static void
release_read_buf(test_data *td, struct iovec* vecs, int n_vecs) {
  assert(n_vecs == 1);
  assert(vecs == &mems.buffer);
}

static struct iovec* get_write_buf(test_data *td, int len, int* n_vecs) {
  assert(len == td->size);
  *n_vecs = 1;
  return &mems.wbuf;
}

static void
release_write_buf(test_data *td, struct iovec* vecs, int n_vecs)
{
  assert(vecs == &mems.buffer && n_vecs == 1);
  assert(vecs[0].iov_base == &mems.buffer.iov_base && n_vecs == 1);
  printf("Parent: Writing to %p\n", mems.wbuf.iov_base);
  memcpy(td->data, vecs[0].iov_base, vecs[0].iov_len);
  sem_post(mutex);
  sem_wait(mutex);                                                       
}

int
main(int argc, char *argv[])
{
  test_t t = { 
    .name = "mmap_thr",
    .is_latency_test = 0,
    .init_test = init_test,
    .init_parent = init_local,
    .init_child = init_local,
    .get_write_buffer = get_write_buf,
    .release_write_buffer = release_write_buf,
    .get_read_buffer = get_read_buf,
    .release_read_buffer = release_read_buf
  };
  run_test(argc, argv, &t);
  close(sfd);
  sem_close(mutex);
  sem_unlink(SEMNAME);
  return 0;
}

//int
//main(int argc, char *argv[])
//{
//    int *addr;                  /* Pointer to shared memory region */
//
//#ifdef USE_MAP_ANON             /* Use MAP_ANONYMOUS */
//    addr = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
//                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
//    if (addr == MAP_FAILED)
//        errExit("mmap");
//
//#else                           /* Map /dev/zero */
//    int fd;
//
//    fd = open("/dev/zero", O_RDWR);
//    if (fd == -1)
//        errExit("open");
//
//    addr = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
//    if (addr == MAP_FAILED)
//        errExit("mmap");
//
//    if (close(fd) == -1)        /* No longer needed */
//        errExit("close");
//#endif
//
//    *addr = 1;                  /* Initialize integer in mapped region */
//
//    switch (fork()) {           /* Parent and child share mapping */
//    case -1:
//        errExit("fork");
//
//    case 0:                     /* Child: increment shared integer and exit */
//        printf("Child started, value = %d\n", *addr);
//        (*addr)++;
//        if (munmap(addr, sizeof(int)) == -1)
//            errExit("munmap");
//        exit(EXIT_SUCCESS);
//
//    default:                    /* Parent: wait for child to terminate */
//        if (wait(NULL) == -1)
//            errExit("wait");
//        printf("In parent, value = %d\n", *addr);
//        if (munmap(addr, sizeof(int)) == -1)
//            errExit("munmap");
//        exit(EXIT_SUCCESS);
//    }
//}
