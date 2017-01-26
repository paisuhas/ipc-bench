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

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include "test.h"
#include "xutil.h"
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>

void Mutex_init(pthread_mutex_t *m, pthread_mutexattr_t *ma) {                                              
  if (pthread_mutex_init(m, ma) < 0)                                             
    err(1, "Mutex init failed");                                               
}                                                                                  
                                                                                   
void Mutex_lock(pthread_mutex_t *m) {                                              
  int rc = pthread_mutex_lock(m);                                                  
  if (rc < 0)                                                                      
    err(1, "Mutex lock failed");                                               
}                                                                                  
                                                                                   
void Mutex_unlock(pthread_mutex_t *m) {                                            
  int rc = pthread_mutex_unlock(m);                                                
  if (rc < 0)                                                                      
    err(1, "Mutex unlock failed");                                             
}                                                                                  
                                                                                   
void Cond_init(pthread_cond_t *c, pthread_condattr_t *ca) {                                                
  if(pthread_cond_init(c, ca) < 0)                                               
    err(1, "CV init failed");                                                  
}                                                                                  
                                                                                   
void Cond_wait(pthread_cond_t *c, pthread_mutex_t *m) {                            
  int rc = pthread_cond_wait(c, m);                                                
  if (rc < 0)                                                                      
    err(1, "CV wait failed");                                                  
}                                                                                  
                                                                                   
void Cond_signal(pthread_cond_t *c) {                                              
  int rc = pthread_cond_signal(c);                                                 
  if (rc < 0)                                                                      
    err(1, "CV wait failed");                                                  
}                                      

pthread_cond_t* empty, full;
pthread_mutex_t* m;
int request;

typedef struct {
  void* cbuf;
  void* pbuf;
} mem_state;

mem_state mems;

int sfd;

  int des_cond, des_msg, des_mutex;

static void
init_test(test_data *td)
{
 
  int mode = S_IRWXU | S_IRWXG;
  int *addr;                  /* Pointer to shared memory region */
  des_mutex = shm_open("/tmp/mutex", O_CREAT | O_RDWR | O_TRUNC, mode);

  if (des_mutex < 0)
  {
    perror("failure on shm_open on des_mutex");
    exit(1);
  }
  
  des_cond = shm_open("/tmp/cond", O_CREAT | O_RDWR | O_TRUNC, mode);
  if (des_cond < 0)
  {
    perror("failure on shm_open on des_cond");
    exit(1);
  }
  des_msg = shm_open("/tmp/cond1", O_CREAT | O_RDWR | O_TRUNC, mode);
  if (des_cond < 0)
  {
    perror("failure on shm_open on des_cond");
    exit(1);
  } empty  = (pthread_cond_t*) mmap(NULL, sizeof(pthread_cond_t), PROT_READ | PROT_WRITE, MAP_SHARED, des_cond, 0);
  full   = (pthread_cond_t*) mmap(NULL, sizeof(pthread_cond_t), PROT_READ | PROT_WRITE, MAP_SHARED, des_msg, 0);                              
  m      = (pthread_mutex_t*) mmap(NULL, sizeof(pthread_mutex_t), PROT_READ | PROT_WRITE, MAP_SHARED, des_mutex, 0);
  pthread_mutexattr_t* ma;
  pthread_mutexattr_setpshared(ma, PTHREAD_PROCESS_SHARED);
  pthread_condattr_t* ca;
  pthread_condattr_setpshared(ca, PTHREAD_PROCESS_SHARED);
  Mutex_init(m,ma);
  Cond_init(empty,ca);
  Cond_init(full,ca);
  
  sfd = open("/smem", O_RDWR,  mode);

  addr = mmap(NULL, td->size, PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_ANONYMOUS, sfd, 0);
  if (addr == MAP_FAILED){
    err(1, "MAP FAILED");
  }
  td->data = (void *)addr;
  mems.cbuf = xmalloc(td->size); 
  mems.pbuf = xmalloc(td->size); 
  request = 0;
}

static void
local_init(test_data *td)
{
}

static void
child_ping(test_data *td)
{
  Mutex_lock(m);
  Cond_wait(full, m);
  memcpy(mems.cbuf, td->data, td->size);
  memset(td->data, 1, td->size);
  Cond_signal(&empty);
}

static void
parent_ping(test_data *td, pid_t child_pid)
{
  Mutex_lock(m);                                                                
  memset(td->data, 1, td->size);
  Cond_signal(full);
  Cond_wait(empty, m);                                                       
  memcpy(mems.pbuf, td->data, td->size);
}

int
main(int argc, char *argv[])
{
  test_t t = { .name = "mmap_lat", 
	       .is_latency_test = 1,
	       .init_test = init_test,
	       .init_parent = local_init,
	       .init_child = local_init,
	       .parent_ping = parent_ping,
	       .child_ping = child_ping
  };
  run_test(argc, argv, &t);
  shm_unlink("/tmp/mutex");
  shm_unlink("/tmp/cond");
   shm_unlink("/tmp/cond1");
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
