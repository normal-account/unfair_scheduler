#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <inttypes.h>
#include <fcntl.h>
#include <time.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_weightedcg.h"
#include "scx_weightedcg.bpf.skel.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>


#ifndef FILEID_KERNFS
#define FILEID_KERNFS		0xfe
#endif

const char help_fmt[] =
"A flattened cgroup hierarchy sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-s SLICE_US] [-i INTERVAL] [-v]\n"
"\n"
"  -s SLICE_US   Override slice duration\n"
"  -i INTERVAL   Report interval\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int dummy)
{
	exit_req = 1;
}

static inline double ns_to_s(uint64_t ns) { return (double)ns / 1e9; }

static inline double avg_ms(uint64_t sum, uint64_t cnt) { return cnt ? ( (double)sum / cnt / 1e6 ) : 0; }

static inline double ns_to_ms(uint64_t ns) { return ns ? ( (double)ns / 1e6 ) : 0; }

#if CALLBACK_STATS
static const char * const callback_names[CALLBACK_NR] = {
	[CALLBACK_SELECT_CPU] = "select_cpu",
	[CALLBACK_ENQUEUE] = "enqueue",
	[CALLBACK_DISPATCH] = "dispatch",
	[CALLBACK_RUNNABLE] = "runnable",
	[CALLBACK_RUNNING] = "running",
	[CALLBACK_STOPPING] = "stopping",
	[CALLBACK_QUIESCENT] = "quiescent",
	[CALLBACK_DEQUEUE] = "dequeue",
	[CALLBACK_INIT_TASK] = "init_task",
	[CALLBACK_EXIT_TASK] = "exit_task",
	[CALLBACK_CGROUP_SET_WEIGHT] = "cgroup_set_weight",
	[CALLBACK_CGROUP_INIT] = "cgroup_init",
	[CALLBACK_CGROUP_EXIT] = "cgroup_exit",
	[CALLBACK_CGROUP_MOVE] = "cgroup_move",
	[CALLBACK_INIT] = "init",
	[CALLBACK_EXIT] = "exit",
};
#endif

#if MAP_OP_STATS
static const char * const map_names[MAP_NR] = {
	[MAP_STATS] = "stats",
	[MAP_CPU_CTX] = "cpu_ctx",
	[MAP_CGRP_CTX] = "cgrp_ctx",
	[MAP_CGV_NODE_STASH] = "cgv_node_stash",
	[MAP_CLS_CNTS] = "cls_cnts",
	[MAP_CPUSET] = "cpuset_map",
	[MAP_RT_TASK_ASSIGNMENTS] = "rt_assignments",
	[MAP_TASK_VTIME] = "task_vtime",
	[MAP_CGRP_STATS] = "cgrp_stats",
	[MAP_TASK_CTX] = "task_ctx",
};

static const char * const map_op_names[MAP_OP_NR] = {
	[MAP_OP_LOOKUP] = "lookup",
	[MAP_OP_UPDATE] = "update",
	[MAP_OP_DELETE] = "delete",
	[MAP_OP_STORAGE_GET] = "storage_get",
	[MAP_OP_ATOMIC] = "atomic",
	[MAP_OP_FOREACH] = "foreach",
};

static const char * const map_scope_names[] = {
	[MAP_SCOPE_PER_CPU_VALUE] = "per_cpu_value",
	[MAP_SCOPE_CPU_INDEXED] = "cpu_indexed",
	[MAP_SCOPE_TASK_LOCAL] = "task_local",
	[MAP_SCOPE_CGROUP_SHARED] = "cgroup_shared",
	[MAP_SCOPE_GLOBAL_SHARED] = "global_shared",
};

static const enum map_value_scope map_scopes[MAP_NR] = {
	[MAP_STATS] = MAP_SCOPE_PER_CPU_VALUE,		/* PERCPU_ARRAY */
	[MAP_CPU_CTX] = MAP_SCOPE_CPU_INDEXED,		/* ARRAY keyed by CPU */
	[MAP_CGRP_CTX] = MAP_SCOPE_CGROUP_SHARED,	/* CGRP_STORAGE */
	[MAP_CGV_NODE_STASH] = MAP_SCOPE_CGROUP_SHARED,	/* HASH keyed by cgid */
	[MAP_CLS_CNTS] = MAP_SCOPE_GLOBAL_SHARED,	/* one-element ARRAY */
	[MAP_CPUSET] = MAP_SCOPE_CGROUP_SHARED,		/* HASH keyed by cgid */
	[MAP_RT_TASK_ASSIGNMENTS] = MAP_SCOPE_TASK_LOCAL, /* HASH keyed by pid */
	[MAP_TASK_VTIME] = MAP_SCOPE_TASK_LOCAL,		/* HASH keyed by pid */
	[MAP_CGRP_STATS] = MAP_SCOPE_CGROUP_SHARED,	/* HASH keyed by cgid */
	[MAP_TASK_CTX] = MAP_SCOPE_TASK_LOCAL,		/* TASK_STORAGE */
};
#endif

#if CALLBACK_STATS || MAP_OP_STATS
static __u64 histogram_percentile(const __u64 *hist, __u64 count,
				  unsigned int percentile)
{
	__u64 seen = 0;
	__u64 rank;
	int bucket;

	if (!count)
		return 0;

	rank = (uint64_t)(((__uint128_t)count * percentile + 99) / 100);
	for (bucket = 0; bucket < TIMING_HIST_BUCKETS; bucket++) {
		seen += hist[bucket];
		if (seen >= rank)
			return bucket == 63 ? UINT64_MAX : (1ULL << (bucket + 1)) - 1;
	}

	return UINT64_MAX;
}
#endif

#if CALLBACK_STATS || MAP_OP_STATS
static double timing_lifetime_s(struct scx_weightedcg_bpf *skel)
{
	struct timespec now;
	__u64 started_ns = skel->bss->timing_started_ns;
	__u64 ended_ns = skel->bss->timing_ended_ns;
	__u64 now_ns;

	if (!started_ns)
		return 0;

	if (ended_ns > started_ns)
		return (ended_ns - started_ns) / 1e9;

	clock_gettime(CLOCK_MONOTONIC, &now);
	now_ns = (__u64)now.tv_sec * 1000000000ull + now.tv_nsec;
	return now_ns > started_ns ? (now_ns - started_ns) / 1e9 : 0;
}
#endif

#if CALLBACK_STATS
static void print_callback_timings(struct scx_weightedcg_bpf *skel,
				   double lifetime_s)
{
	int idx;

	for (idx = 0; idx < CALLBACK_NR; idx++) {
		const struct callback_timing *timing =
			&skel->bss->callback_timing_stats[idx];

		if (!timing->count)
			continue;

		printf("CALLBACK   %-17s calls:%12llu rate:%10.1f/s "
		       "mean:%9.1f ns p50<=%9llu p95<=%9llu p99<=%9llu ns "
		       "total:%14llu ns\n",
		       callback_names[idx],
		       (unsigned long long)timing->count,
		       lifetime_s > 0 ? timing->count / lifetime_s : 0.0,
		       (double)timing->total_ns / timing->count,
		       (unsigned long long)histogram_percentile(
			       timing->latency_hist, timing->count, 50),
		       (unsigned long long)histogram_percentile(
			       timing->latency_hist, timing->count, 95),
		       (unsigned long long)histogram_percentile(
			       timing->latency_hist, timing->count, 99),
		       (unsigned long long)timing->total_ns);
	}
}
#endif

#if MAP_OP_STATS
static void print_map_timings(struct scx_weightedcg_bpf *skel,
			      double lifetime_s)
{
	int map, op;

	for (map = 0; map < MAP_NR; map++) {
		for (op = 0; op < MAP_OP_NR; op++) {
			const struct map_timing *timing =
				&skel->bss->map_timing_stats[map][op];

			if (!timing->count)
				continue;

			printf("MAP        %-18s %-11s %-15s ops:%12llu "
			       "rate:%10.1f/s mean:%9.1f ns "
			       "p50<=%9llu p95<=%9llu p99<=%9llu max:%9llu ns "
			       "slow(>=%u ns):%10llu (%5.2f%%, %8.1f/s) "
			       "total:%14llu ns\n",
			       map_names[map], map_op_names[op],
			       map_scope_names[map_scopes[map]],
			       (unsigned long long)timing->count,
			       lifetime_s > 0 ? timing->count / lifetime_s : 0.0,
			       (double)timing->total_ns / timing->count,
			       (unsigned long long)histogram_percentile(
				       timing->latency_hist, timing->count, 50),
			       (unsigned long long)histogram_percentile(
				       timing->latency_hist, timing->count, 95),
			       (unsigned long long)histogram_percentile(
				       timing->latency_hist, timing->count, 99),
			       (unsigned long long)timing->max_ns,
			       MAP_SLOW_OP_NS,
			       (unsigned long long)timing->slow_count,
			       100.0 * timing->slow_count / timing->count,
			       lifetime_s > 0 ?
				       timing->slow_count / lifetime_s : 0.0,
			       (unsigned long long)timing->total_ns);
		}
	}
}
#endif

static void read_cgrp_stats(struct scx_weightedcg_bpf *skel) 
{
	int fd = bpf_map__fd(skel->maps.cgrp_stats);
	struct cgrp_stats val;
	__u64 key = 0, next;

	for (;;) {
		if (bpf_map_get_next_key(fd, &key, &next) != 0) break;
		if (bpf_map_lookup_elem(fd, &next, &val) == 0) 
		{
			if ( strcmp(val.name, "session") != 0 )
			{
				if ( val.rt_class )
				{
					printf("CGRP LAT   name:%6s     RT:%6u weight:%6lu idle cnt:%4luk idle avg:%6.4f idle max:%6.2f bk cnt:%4luk bk avg:%6.4f bk max:%6.2f rt cnt:%4luk rt avg:%6.2f rt max:%6.2f\n",
						val.name,
						val.rt_class,
						val.weight,
						val.enq_idle_cnt / 1000,
						avg_ms(val.enq_idle_sum_ns, val.enq_idle_cnt),
						ns_to_ms(val.enq_idle_max),
						val.enq_bk_cnt / 1000,
						avg_ms(val.enq_bk_sum_ns, val.enq_bk_cnt),
						ns_to_ms(val.enq_bk_max),
						val.enq_rt_cnt / 1000,
						avg_ms(val.enq_rt_sum_ns, val.enq_rt_cnt),
						ns_to_ms(val.enq_rt_max)
					);
				}
				else 
				{
					printf("CGRP LAT   name:%6s     RT:%6u weight:%6lu  enq: %6llu  dp:%6llu dp avg:%6.4f  dp max:%6.2f move cnt:%6llu\n",
						val.name,
						val.rt_class,
						val.weight,
						(unsigned long long)val.enq_cnt,
						(unsigned long long)val.lat_cnt,
						avg_ms(val.lat_sum_ns, val.lat_cnt),
						ns_to_ms(val.lat_max),
						val.move_lat_cnt
					);
				}
			}
		}
		key = next;
	}
}


static float read_cpu_util(__u64 *last_sum, __u64 *last_idle)
{
	FILE *fp;
	char buf[4096];
	char *line, *cur = NULL, *tok;
	__u64 sum = 0, idle = 0;
	__u64 delta_sum, delta_idle;
	int idx;

	fp = fopen("/proc/stat", "r");
	if (!fp) {
		perror("fopen(\"/proc/stat\")");
		return 0.0;
	}

	if (!fgets(buf, sizeof(buf), fp)) {
		perror("fgets(\"/proc/stat\")");
		fclose(fp);
		return 0.0;
	}
	fclose(fp);

	line = buf;
	for (idx = 0; (tok = strtok_r(line, " \n", &cur)); idx++) {
		char *endp = NULL;
		__u64 v;

		if (idx == 0) {
			line = NULL;
			continue;
		}
		v = strtoull(tok, &endp, 0);
		if (!endp || *endp != '\0') {
			fprintf(stderr, "failed to parse %dth field of /proc/stat (\"%s\")\n",
				idx, tok);
			continue;
		}
		sum += v;
		if (idx == 4)
			idle = v;
	}

	delta_sum = sum - *last_sum;
	delta_idle = idle - *last_idle;
	*last_sum = sum;
	*last_idle = idle;

	return delta_sum ? (float)(delta_sum - delta_idle) / delta_sum : 0.0;
}

static void read_stats(struct scx_weightedcg_bpf *skel, __u64 *stats)
{
	__u64 cnts[STAT_NR][skel->rodata->nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * STAT_NR);

	for (idx = 0; idx < STAT_NR; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < skel->rodata->nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

int main(int argc, char **argv)
{
	struct scx_weightedcg_bpf *skel;
	struct bpf_link *link;
	struct timespec intv_ts = { .tv_sec = 2, .tv_nsec = 0 };
	bool dump_cgrps = false;
	__u64 last_cpu_sum = 0, last_cpu_idle = 0;
	__u64 last_stats[STAT_NR] = {};
	unsigned long seq = 0;
	__s32 opt;
	__u64 ecode;

	assert( 0 == system("./clear_traces.sh") );

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(weightedcg_ops, scx_weightedcg_bpf);

	skel->rodata->nr_cpus = libbpf_num_possible_cpus();
	assert(skel->rodata->nr_cpus > 0);

	skel->rodata->cgrp_slice_ns = __COMPAT_ENUM_OR_ZERO("scx_public_consts", "SCX_SLICE_DFL");
	skel->rodata->task_slice_ns = __COMPAT_ENUM_OR_ZERO("scx_public_consts", "SCX_SLICE_DFL");

	printf("slice=%.1lfms intv=%.1lfs dump_cgrps=%d",
	       (double)skel->rodata->cgrp_slice_ns / 1000000.0,
	       (double)intv_ts.tv_sec + (double)intv_ts.tv_nsec / 1000000000.0,
	       dump_cgrps);

	SCX_OPS_LOAD(skel, weightedcg_ops, scx_weightedcg_bpf, uei);
	link = SCX_OPS_ATTACH(skel, weightedcg_ops, scx_weightedcg_bpf);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 acc_stats[STAT_NR];
		__u64 stats[STAT_NR];
		float cpu_util;
		int i;

		cpu_util = read_cpu_util(&last_cpu_sum, &last_cpu_idle);

		read_stats(skel, acc_stats);
		for (i = 0; i < STAT_NR; i++)
			stats[i] = acc_stats[i] - last_stats[i];

		memcpy(last_stats, acc_stats, sizeof(acc_stats));

		printf("\n[SEQ %6lu cpu=%5.1lf hweight_gen=%" PRIu64 "]\n",
		       seq++, cpu_util * 100.0, skel->data->hweight_gen);
		printf("RUNNING     act:%6llu  deact:%6llu global:%6llu local:%6llu\n",
		       stats[STAT_ACT],
		       stats[STAT_DEACT],
		       stats[STAT_GLOBAL],
		       stats[STAT_LOCAL]);
		printf("CGRP ENQ  cache:%6llu update:%6llu   skip:%6llu  race:%6llu\n",
		       stats[STAT_HWT_CACHE],
		       stats[STAT_HWT_UPDATES],
		       stats[STAT_HWT_SKIP],
		       stats[STAT_HWT_RACE]);
		printf("ENQUEUE    skip:%6llu   race:%6llu kworkr:%6llu  napi:%6llu  softirq:%6llu  wq worker:%6llu  kthread:%6llu\n",
		       stats[STAT_ENQ_SKIP],
		       stats[STAT_ENQ_RACE],
			   stats[STAT_ENQ_IRQ],
			   stats[STAT_ENQ_NAPI],
			   stats[STAT_ENQ_KSOFTIRQD],
			   stats[STAT_ENQ_WQ_WORKER],
			   stats[STAT_ENQ_KTHREAD]);
		printf("DISPATCH   keep:%6llu expire:%6llu  empty:%6llu  gone:%6llu\n",
		       stats[STAT_CNS_KEEP],
		       stats[STAT_CNS_EXPIRE],
		       stats[STAT_CNS_EMPTY],
		       stats[STAT_CNS_GONE]);
		printf("PICK NEXT  next:%6llu  empty:%6llu nocgrp:%6llu  gone:%6llu     race:%6llu       fail:%6llu aff-fail:%6llu\n",
		       stats[STAT_PNC_NEXT],
		       stats[STAT_PNC_EMPTY],
		       stats[STAT_PNC_NO_CGRP],
		       stats[STAT_PNC_GONE],
		       stats[STAT_PNC_RACE],
		       stats[STAT_PNC_FAIL],
			   stats[STAT_PNC_AFFINITY]);
		printf("BAD      remove:%6llu\n",
		       acc_stats[STAT_BAD_REMOVAL]);

#if CALLBACK_STATS || MAP_OP_STATS
		double lifetime_s = timing_lifetime_s(skel);
#if CALLBACK_STATS
		print_callback_timings(skel, lifetime_s);
#endif
#if MAP_OP_STATS
		print_map_timings(skel, lifetime_s);
#endif
#endif
		read_cgrp_stats( skel );
		
		fflush(stdout);

		nanosleep(&intv_ts, NULL);
	}

	bpf_link__destroy(link);
#if CALLBACK_STATS || MAP_OP_STATS
	double final_lifetime = timing_lifetime_s(skel);
#if CALLBACK_STATS
	printf("\n[FINAL CALLBACK TIMINGS]\n");
	print_callback_timings(skel, final_lifetime);
#endif
#if MAP_OP_STATS
	printf("\n[FINAL MAP OPERATION TIMINGS]\n");
	print_map_timings(skel, final_lifetime);
#endif
#endif
	ecode = UEI_REPORT(skel, uei);
	scx_weightedcg_bpf__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;

#if DUMP_TRACES
	assert( 0 == system("./dump_traces.sh") );
#endif

	return 0;
}