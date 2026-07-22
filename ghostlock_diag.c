/* ghostlock_diag2.c — EDEADLK 级联版: owner 在 requeue 之后才碰 f_chain */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int f_chain = 0, f_wait = 0, f_target = 0;
static atomic_int stage = 0;

static int futex(int *uaddr, int op, int val, const void *a4, int *uaddr2, int val3) {
    return syscall(SYS_futex, uaddr, op, val, a4, uaddr2, val3);
}

static void *t_waiter(void *a) {
    (void)a;
    int r = futex(&f_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[waiter ] LOCK_PI f_chain = %d (errno=%d)\n", r, errno);
    atomic_store(&stage, 1);
    while (atomic_load(&stage) < 3) sched_yield();
    r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, NULL, &f_target, 0);
    printf("[waiter ] WAIT_REQUEUE_PI 返回 %d (errno=%d %s)\n", r, errno, strerror(errno));
    printf("[waiter ] >>> 已带悬空 pi_blocked_on 返回用户态 <<<\n");
    futex(&f_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

static void *t_owner(void *a) {
    (void)a;
    while (atomic_load(&stage) < 1) sched_yield();
    int r = futex(&f_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[owner  ] LOCK_PI f_target = %d (errno=%d)\n", r, errno);
    atomic_store(&stage, 2);
    while (atomic_load(&stage) < 4) sched_yield();   /* 等 requeue 完成 */
    r = futex(&f_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[owner  ] LOCK_PI f_chain = %d (errno=%d %s)  <- 期望 EDEADLK(级联铁证)\n",
           r, errno, strerror(errno));
    r = futex(&f_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    printf("[owner  ] UNLOCK_PI f_target = %d (errno=%d)\n", r, errno);
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    pthread_t tw, to;
    pthread_create(&tw, NULL, t_waiter, NULL);
    while (atomic_load(&stage) < 1) sched_yield();
    pthread_create(&to, NULL, t_owner, NULL);
    while (atomic_load(&stage) < 2) sched_yield();
    atomic_store(&stage, 3);                    /* 放 waiter 进入等待 */
    usleep(200000);                             /* 等它真正睡进 f_wait */
    int r = futex(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_target, 0);
    printf("[requeuer] CMP_REQUEUE_PI = %d (errno=%d %s)\n", r, errno, strerror(errno));
    atomic_store(&stage, 4);                    /* 放 owner 去碰 f_chain → 级联 */
    sleep(3);
    printf("[*] 诊断结束\n");
    return 0;
}
