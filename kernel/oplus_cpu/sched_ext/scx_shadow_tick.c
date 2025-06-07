#include <linux/tick.h>
#include <kernel/time/tick-sched.h>
#include <trace/hooks/sched.h>

#ifdef CONFIG_HMBIRD_SCHED
#include "./hmbird/hmbird_sched.h"
#else
#include "./hmbird_gki/scx_main.h"
#endif

#define HIGHRES_WATCH_CPU       0
#ifdef CONFIG_HMBIRD_SCHED
extern unsigned int highres_tick_ctrl;
extern unsigned int highres_tick_ctrl_dbg;
static bool shadow_tick_enable(void) {return highres_tick_ctrl;}
static bool shadow_tick_dbg_enable(void) {return highres_tick_ctrl_dbg;}
#else
static bool shadow_tick_enable(void) {return true;}
static bool shadow_tick_dbg_enable(void) {return false;}
#endif

noinline int tracing_mark_write(const char *buf)
{
        trace_printk(buf);
        return 0;
}


#define shadow_tick_printk(fmt, args...)	\
do {							\
	int cpu = smp_processor_id();			\
	if (shadow_tick_dbg_enable() && cpu == HIGHRES_WATCH_CPU)	\
		trace_printk("hmbird shadow tick :"fmt, args);	\
} while (0)

#define shadow_tick_systrace(fmt, ...)	\
do {							\
	if (unlikely(shadow_tick_dbg_enable())) {	\
		char buf[256];					\
		snprintf(buf, sizeof(buf), fmt, ##__VA_ARGS__);	\
		tracing_mark_write(buf);	\
	}					\
} while (0)

#define REGISTER_TRACE_VH(vender_hook, handler) \
{ \
	ret = register_trace_##vender_hook(handler, NULL); \
	if (ret) { \
		pr_err("failed to register_trace_"#vender_hook", ret=%d\n", ret); \
	} \
}

DEFINE_PER_CPU(struct hrtimer, stt);
#define shadow_tick_timer(cpu) (&per_cpu(stt, (cpu)))

#define STOP_IDLE_TRIGGER     (1)
#define PERIODIC_TICK_TRIGGER (2)

#define TICK_INTVAL	(1000000ULL)
/*
 * restart hrtimer while resume from idle. scheduler tick may resume after 4ms,
 * so we can't restart hrtimer in scheduler tick.
 */
static DEFINE_PER_CPU(u8, trigger_event);

/*
 * Implement 1ms tick by inserting 3 hrtimer ticks to schduler tick.
 * stop hrtimer when tick reachs 4, then restart it at scheduler timer handler.
 */
static DEFINE_PER_CPU(u8, tick_phase);


static inline void highres_timer_ctrl(bool enable, int cpu)
{
	if (enable && scx_enabled()) {
		if (!hrtimer_active(shadow_tick_timer(cpu)))
			hrtimer_start(shadow_tick_timer(cpu),
				ns_to_ktime(TICK_INTVAL), HRTIMER_MODE_REL);
		shadow_tick_systrace("C|9999|highres_tick_%d|%d\n", cpu, 1);
	} else {
		if (!enable) {
			hrtimer_cancel(shadow_tick_timer(cpu));
			shadow_tick_systrace("C|9999|highres_tick_%d|%d\n", cpu, 0);
		}
	}
	WARN_ON(cpu != smp_processor_id());
}

static inline void high_res_clear_phase(int cpu)
{
	per_cpu(tick_phase, cpu) = 0;
	shadow_tick_systrace("C|9999|tick_phase_%d|%d\n", cpu, per_cpu(tick_phase, cpu));
}

static enum hrtimer_restart highres_next_phase(int cpu, struct hrtimer *timer)
{
	per_cpu(tick_phase, cpu) = ++per_cpu(tick_phase, cpu) % 3;
	shadow_tick_systrace("C|9999|tick_phase_%d|%d\n", cpu, per_cpu(tick_phase, cpu));
	if (per_cpu(tick_phase, cpu)) {
		hrtimer_forward_now(timer, ns_to_ktime(TICK_INTVAL));
		return HRTIMER_RESTART;
	}
	shadow_tick_systrace("C|9999|highres_tick_%d|%d\n", cpu, 0);
	return HRTIMER_NORESTART;
}

static void sched_switch_handler(void *data, bool preempt, struct task_struct *prev,
		struct task_struct *next, unsigned int prev_state)
{
	int cpu = smp_processor_id();

	if (shadow_tick_enable() && (cpu_rq(cpu)->idle == prev)) {
		per_cpu(trigger_event, cpu) = STOP_IDLE_TRIGGER;
		high_res_clear_phase(cpu);
		highres_timer_ctrl(true, cpu);
	}
}

static enum hrtimer_restart scheduler_tick_no_balance(struct hrtimer *timer)
{
	int cpu = smp_processor_id();
	struct rq *rq = cpu_rq(cpu);
	struct task_struct *curr = rq->curr;
	struct rq_flags rf;

	rq_lock(rq, &rf);
	update_rq_clock(rq);
#ifdef CONFIG_HMBIRD_SCHED_GKI
	scx_tick_entry(rq);
#endif
	curr->sched_class->task_tick(rq, curr, 0);
	rq_unlock(rq, &rf);
#ifdef CONFIG_HMBIRD_SCHED_GKI
	scx_scheduler_tick();
#endif
	return highres_next_phase(cpu, timer);
}

void shadow_tick_timer_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		hrtimer_init(shadow_tick_timer(cpu), CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED);
		shadow_tick_timer(cpu)->function = &scheduler_tick_no_balance;
	}
}

void start_shadow_tick_timer(void)
{
	int cpu = smp_processor_id();

	if (shadow_tick_enable()) {
		if (per_cpu(trigger_event, cpu) == STOP_IDLE_TRIGGER)
			highres_timer_ctrl(false, cpu);
		per_cpu(trigger_event, cpu) = PERIODIC_TICK_TRIGGER;
		high_res_clear_phase(cpu);
		highres_timer_ctrl(true, cpu);
	}
}

static void stop_shadow_tick_timer(void)
{
	int cpu = smp_processor_id();

	per_cpu(trigger_event, cpu) = 0;
	high_res_clear_phase(cpu);
	highres_timer_ctrl(false, cpu);
}

void android_vh_tick_nohz_idle_stop_tick_handler(void *unused, void *data)
{
	stop_shadow_tick_timer();
}

#ifdef CONFIG_HMBIRD_SCHED
static void scheduler_tick_handler(void *unused, struct rq *rq)
{
	start_shadow_tick_timer();
}
#endif


int scx_shadow_tick_init(void)
{
	int ret = 0;
	shadow_tick_timer_init();

	REGISTER_TRACE_VH(android_vh_tick_nohz_idle_stop_tick,
				android_vh_tick_nohz_idle_stop_tick_handler);
#ifdef CONFIG_HMBIRD_SCHED
	REGISTER_TRACE_VH(android_vh_scheduler_tick,
				scheduler_tick_handler);
#endif
	REGISTER_TRACE_VH(sched_switch, sched_switch_handler);
	return ret;
}
