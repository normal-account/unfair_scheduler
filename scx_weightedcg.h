#ifndef __SCX_WEIGHTEDCG_H
#define __SCX_WEIGHTEDCG_H

#ifndef DEBUG
#define DEBUG 0
#endif

/*
 * Per-map operation timing (lookup/update/delete/atomic/...). Callback
 * timing is independent. Leave undefined or 0 to compile it out.
 */
#ifndef MAP_OP_STATS
#define MAP_OP_STATS 1
#endif

/*
 * Per-callback timing (select_cpu/enqueue/dispatch/...). Map operation
 * timing is independent. Leave undefined or 0 to compile it out.
 */
#ifndef CALLBACK_STATS
#define CALLBACK_STATS 0
#endif

enum {
	HWEIGHT_ONE		= 1LLU << 16,
};

enum stat_idx {
	STAT_ACT,
	STAT_DEACT,
	STAT_LOCAL,
	STAT_GLOBAL,

	STAT_HWT_UPDATES,
	STAT_HWT_CACHE,
	STAT_HWT_SKIP,
	STAT_HWT_RACE,

	STAT_ENQ_SKIP,
	STAT_ENQ_RACE,
	STAT_ENQ_IRQ,
	STAT_ENQ_KSOFTIRQD,
	STAT_ENQ_NAPI,
	STAT_ENQ_WQ_WORKER,
	STAT_ENQ_KTHREAD,

	STAT_CNS_KEEP,
	STAT_CNS_EXPIRE,
	STAT_CNS_EMPTY,
	STAT_CNS_GONE,

	STAT_PNC_NO_CGRP,
	STAT_PNC_NEXT,
	STAT_PNC_EMPTY,
	STAT_PNC_GONE,
	STAT_PNC_RACE,
	STAT_PNC_FAIL,
	STAT_PNC_AFFINITY,

	STAT_BAD_REMOVAL,

	STAT_NR,
};

enum callback_idx {
	CALLBACK_SELECT_CPU,
	CALLBACK_ENQUEUE,
	CALLBACK_DISPATCH,
	CALLBACK_RUNNABLE,
	CALLBACK_RUNNING,
	CALLBACK_STOPPING,
	CALLBACK_QUIESCENT,
	CALLBACK_DEQUEUE,
	CALLBACK_INIT_TASK,
	CALLBACK_EXIT_TASK,
	CALLBACK_CGROUP_SET_WEIGHT,
	CALLBACK_CGROUP_INIT,
	CALLBACK_CGROUP_EXIT,
	CALLBACK_CGROUP_MOVE,
	CALLBACK_INIT,
	CALLBACK_EXIT,

	CALLBACK_NR,
};

#define TIMING_HIST_BUCKETS 64

struct callback_timing {
	__u64 total_ns;
	__u64 count;
	__u64 latency_hist[TIMING_HIST_BUCKETS];
};

enum map_idx {
	MAP_STATS,
	MAP_CPU_CTX,
	MAP_CGRP_CTX,
	MAP_CGV_NODE_STASH,
	MAP_CLS_CNTS,
	MAP_CPUSET,
	MAP_RT_TASK_ASSIGNMENTS,
	MAP_TASK_VTIME,
	MAP_CGRP_STATS,
	MAP_TASK_CTX,

	MAP_NR,
};

/*
 * How a map value is shared across CPUs, not whether the map object is shared.
 *
 * per_cpu_value:  physically separate value for each CPU
 * cpu_indexed:    shared map, keyed by CPU; each CPU normally uses its own slot
 * task_local:     storage associated with one task
 * cgroup_shared:  tasks in the same cgroup access the same value
 * global_shared:  all CPUs may access the same entry
 */
enum map_value_scope {
	MAP_SCOPE_PER_CPU_VALUE,
	MAP_SCOPE_CPU_INDEXED,
	MAP_SCOPE_TASK_LOCAL,
	MAP_SCOPE_CGROUP_SHARED,
	MAP_SCOPE_GLOBAL_SHARED,
};

enum map_op_idx {
	MAP_OP_LOOKUP,
	MAP_OP_UPDATE,
	MAP_OP_DELETE,
	MAP_OP_STORAGE_GET,
	MAP_OP_ATOMIC,
	MAP_OP_FOREACH,

	MAP_OP_NR,
};

struct map_timing {
	__u64 total_ns;
	__u64 count;
	__u64 max_ns;
	__u64 slow_count;
	__u64 latency_hist[TIMING_HIST_BUCKETS];
};

#define MAP_SLOW_OP_NS 1000

#define CPU_MASK_BITS 96
#define MASK_WORDS    (CPU_MASK_BITS / 64)

struct cgrp_ctx {
	u32			nr_active;
	u32			nr_runnable;
	u32			queued;
	u32			weight;
	u32			hweight;
	u64			child_weight_sum;
	u64			hweight_gen;
	s64			cvtime_delta;
	u64			tvtime_now;

	u8  rt_class;    		// 1=RT, 0=BK
	u64 enq_count;        	// monotonic, bumps on every enqueue intent

	struct bpf_spin_lock cpuset_lock;
    __u64 cpuset_mask[MASK_WORDS];
    __u32 cpuset_init;
};

struct cgrp_stats {
	char  name[8];

	__u64 first_enq_ts;   	// 0 ==> not armed

	__u64 lat_sum_ns;     	// accumulated activation latency
    __u64 lat_cnt;        	// number of dispatches
	__u64 lat_max;			// max latency encountered

	__u64 enq_idle_sum_ns;
    __u64 enq_idle_cnt;
	__u64 enq_idle_max;

	__u64 enq_bk_sum_ns;
    __u64 enq_bk_cnt;
	__u64 enq_bk_max;

	__u64 enq_rt_sum_ns;
    __u64 enq_rt_cnt;
	__u64 enq_rt_max;

	__u64 enq_cnt;

	__u64 move_lat_sum_ns;
	__u64 move_lat_cnt;

	u8  rt_class;    		// 1=RT, 0=BK
	u32			weight;
};

#ifndef DIR_ENQ
#define DIR_ENQ 1
#endif

#ifndef RT_VTIME
#define RT_VTIME 0
#endif

#ifndef RT_ACTIVE_CHECK
#define RT_ACTIVE_CHECK 1
#endif

#ifndef WEIGHTED_FALLBACK_DSQ
#define WEIGHTED_FALLBACK_DSQ 1
#endif

#ifndef PIN_TASKS
#define PIN_TASKS 1
#endif

#ifndef RT_CGROUP_NAME
#define RT_CGROUP_NAME "hw"
#endif

#ifndef CGROUP_NAME_LEN
#define CGROUP_NAME_LEN 64
#endif

#ifndef DUMP_TRACES
#define DUMP_TRACES 1
#endif

#if DEBUG
#define log(fmt, rt_class, ...) if ( rt_class == 1 ) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define log(fmt, rt_class, ...)
#endif

#endif
