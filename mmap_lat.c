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

void Mutex_init(pthread_mutex_t *m) {                                              
  if (pthread_mutex_init(m, NULL) < 0)                                             
    unix_error("Mutex init failed");                                               
}                                                                                  
                                                                                   
void Mutex_lock(pthread_mutex_t *m) {                                              
  int rc = pthread_mutex_lock(m);                                                  
  if (rc < 0)                                                                      
    unix_error("Mutex lock failed");                                               
}                                                                                  
                                                                                   
void Mutex_unlock(pthread_mutex_t *m) {                                            
  int rc = pthread_mutex_unlock(m);                                                
  if (rc < 0)                                                                      
    unix_error("Mutex unlock failed");                                             
}                                                                                  
                                                                                   
void Cond_init(pthread_cond_t *c) {                                                
  if(pthread_cond_init(c, NULL) < 0)                                               
    unix_error("CV init failed");                                                  
}                                                                                  
                                                                                   
void Cond_wait(pthread_cond_t *c, pthread_mutex_t *m) {                            
  int rc = pthread_cond_wait(c, m);                                                
  if (rc < 0)                                                                      
    unix_error("CV wait failed");                                                  
}                                                                                  
                                                                                   
void Cond_signal(pthread_cond_t *c) {                                              
  int rc = pthread_cond_signal(c);                                                 
  if (rc < 0)                                                                      
    unix_error("CV wait failed");                                                  
}                                      

pthread_cond_t empty, fill;
pthread_mutex_t m;

typedef struct {
  int ifds[2];
  int ofds[2];
  void* buf;
} pipe_state;

static void
sigHandler(int sig)
{
}

static void
init_test(test_data *td)
{
  int *addr;                  /* Pointer to shared memory region */
  empty  = (pthread_cond_t)PTHREAD_COND_INITIALIZER;                               
  fill   = (pthread_cond_t)PTHREAD_COND_INITIALIZER;                               
  m      = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
  addr = mmap(NULL, td->size, PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (addr == MAP_FAILED){
    err(1, "MAP FAILED");
  }
  td->data = (void *)addr;
}

static void
local_init(test_data *td)
{
}

static void
child_ping(test_data *td)
{
//  int fd;
//  fd = open("/dev/zero", O_RDWR);
//  if (fd < 0)
//    err(1, "open");
  pid_t parent_pid = getppid();
  void *buf = xmalloc(td->size);
  if(kill(parent_pid, SIGHUP) == -1)
    err(1, "signal from child to parent");
  memcpy(buf, td->data, td->size);
  //xread(fd, td->data, td->size);
  if(kill(parent_pid, SIGHUP) == -1)
    err(1, "signal from child to parent");
  memset(td->data, -1, td->size);
  //xwrite(fd, td->data, td->size); 
//  if (close(fd) < 0)
//    err(1, "close");
}

static void
parent_ping(test_data *td, pid_t child_pid)
{
  /*
  pipe_state *ps = (pipe_state *)td->data;
  xwrite(ps->ifds[1], ps->buf, td->size); 
  xread(ps->ofds[0], ps->buf, td->size);
  */
//  int fd;
//  fd = open("/dev/zero", O_RDWR);
//  if (fd < 0)
//    err(1, "open");
  void *buf = xmalloc(td->size);
  pause();
  memset(td->data, -1, td->size);
  //xwrite(fd, td->data, td->size); 
  if(kill(child_pid, SIGHUP) == -1)
    err(1, "signal from parent to child");
  pause();
  memcpy(buf, td->data, td->size);
  //xread(fd, td->data, td->size);
//  if (close(fd) < 0)
//    err(1, "close");
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
  if (signal(SIGHUP, sigHandler) == SIG_ERR)
    err(1, "sigHandler");
  run_test(argc, argv, &t);
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
