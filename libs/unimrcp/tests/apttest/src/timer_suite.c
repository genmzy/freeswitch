#include "apr.h"
#include "apr_general.h"
#include "apt.h"
#include "apt_log.h"
#include "apt_pool.h"
#include "apt_test_suite.h"
#include "apt_timer_queue.h"
#include <apr_time.h>
#include <assert.h>
#include <stdio.h>
#include <time.h>

/* typedef void (*apt_timer_proc_f)(apt_timer_t *timer, void *obj); */
static void timeout_proc(apt_timer_t *timer, void *obj)
{
	int idx = (uint64_t)obj;
	apt_log(APT_LOG_MARK, APT_PRIO_NOTICE, "Timer %c tick !!!", 'a'+idx);
}

static apr_uint32_t current_milli_timestamp()
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec * 1000L + (ts.tv_nsec / 1000000L);
}

static apt_bool_t timer_test(apt_test_suite_t *suite, int argc, const char * const *argv)
{
	apt_timer_queue_t *queue;
	queue = apt_timer_queue_create(suite->pool);
	if (!queue) {
		apt_log(APT_LOG_MARK, APT_PRIO_ERROR, "Create queue failed");
		return FALSE;
	}

	for (uint64_t i = 0; i < 30; i++) {
		apt_timer_t *timer = apt_timer_create(queue, timeout_proc, (void *)i, suite->pool);
		apt_timer_set(timer, 60000L*(i+1));
	}

	apr_uint32_t queue_timeout;
	apr_time_t time_last;
	apr_time_t time_now;

	int i = 0;
	for ( ; i < 5; ) {
		if (apt_timer_queue_timeout_get(queue, &queue_timeout) == TRUE) { // receive timeout
			/* time_last = current_milli_timestamp(); */
			time_last = apr_time_now() / 1000L;
			apt_log(APT_LOG_MARK, APT_PRIO_NOTICE, "Queue got timer time_last: %ld timeout: %u", time_last, queue_timeout);
		} else { // not timeout
			queue_timeout = -1;
			++i;
			apt_log(APT_LOG_MARK, APT_PRIO_NOTICE, "Timer queue empty !!!");
		}

		apr_sleep(1000000L); /* sleep 1 second */

		if (queue_timeout != -1) { // timeout
			/* time_now = current_milli_timestamp(); */
			time_now = apr_time_now() / 1000L;
			apr_size_t diff = time_now - time_last;
			apt_log(APT_LOG_MARK, APT_PRIO_NOTICE, "time now: %ld, advance %ld", time_now, diff);
			apt_timer_queue_advance(queue, diff);
		}
	}
	apt_timer_queue_destroy(queue);

	return TRUE;
}

apt_test_suite_t* timer_test_suite_create(apr_pool_t *pool)
{
	apt_test_suite_t *suite = apt_test_suite_create(pool, "timer", NULL, timer_test);
	return suite;
}
