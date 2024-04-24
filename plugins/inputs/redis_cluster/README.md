# Redis Cluster Input Plugin

### Configuration:

```toml
[[inputs.redis_cluster]]
  ## specify servers via a url matching:
  ##  [protocol://]address[:port]
  ##  e.g.
  ##    tcp://localhost:6379
  ##
  ## If no servers are specified, then localhost is used as the host.
  ## If no port is specified, 6379 is used
  servers = ["tcp://127.0.0.1:7001", "tcp://127.0.0.1:7002"]

  ## specify server password
  # password = "s#cr@t%"

  ## specify cluster name
  cluster_name = "redis_cluster_test"

  ## specify cluster mode, default is 1
  ## 1: original cluster
  ## 2: tencent cloud
  ## note: aliyun cloud only support direct connect, the same mode 1.
  # mode = 1

  ## Optional TLS Config
  # tls_ca = "/etc/telegraf/ca.pem"
  # tls_cert = "/etc/telegraf/cert.pem"
  # tls_key = "/etc/telegraf/key.pem"
  ## Use TLS but skip chain & host verification
  # insecure_skip_verify = true
```

### Measurements & Fields:

The plugin gathers the results of the [INFO](https://redis.io/commands/info) redis command.
There are two separate measurements: _redis_ and _redis\_keyspace_, the latter is used for gathering database related statistics.

Additionally the plugin also calculates the hit/miss ratio (keyspace\_hitrate) and the elapsed time since the last rdb save (rdb\_last\_save\_time\_elapsed).

- redis_cluster
    - keyspace_hitrate(float, number)
    - rdb_last_save_time_elapsed(int, seconds)

    **Server**
    - uptime(int, seconds)
    - lru_clock(int, number)
    - redis_version(string)

    **Clients**
    - clients(int, number)
    - client_longest_output_list(int, number)
    - client_biggest_input_buf(int, number)
    - blocked_clients(int, number)

    **Memory**
    - used_memory(int, bytes)
    - used_memory_rss(int, bytes)
    - used_memory_peak(int, bytes)
    - total_system_memory(int, bytes)
    - used_memory_lua(int, bytes)
    - maxmemory(int, bytes)
    - maxmemory_policy(string)
    - mem_fragmentation_ratio(float, number)

    **Persistence**
    - loading(int,flag)
    - rdb_changes_since_last_save(int, number)
    - rdb_bgsave_in_progress(int, flag)
    - rdb_last_save_time(int, seconds)
    - rdb_last_bgsave_status(string)
    - rdb_last_bgsave_time_sec(int, seconds)
    - rdb_current_bgsave_time_sec(int, seconds)
    - aof_enabled(int, flag)
    - aof_rewrite_in_progress(int, flag)
    - aof_rewrite_scheduled(int, flag)
    - aof_last_rewrite_time_sec(int, seconds)
    - aof_current_rewrite_time_sec(int, seconds)
    - aof_last_bgrewrite_status(string)
    - aof_last_write_status(string)

    **Stats**
    - total_connections_received(int, number)
    - total_commands_processed(int, number)
    - instantaneous_ops_per_sec(int, number)
    - total_net_input_bytes(int, bytes)
    - total_net_output_bytes(int, bytes)
    - instantaneous_input_kbps(float, KB/sec)
    - instantaneous_output_kbps(float, KB/sec)
    - rejected_connections(int, number)
    - sync_full(int, number)
    - sync_partial_ok(int, number)
    - sync_partial_err(int, number)
    - expired_keys(int, number)
    - evicted_keys(int, number)
    - keyspace_hits(int, number)
    - keyspace_misses(int, number)
    - pubsub_channels(int, number)
    - pubsub_patterns(int, number)
    - latest_fork_usec(int, microseconds)
    - migrate_cached_sockets(int, number)

    **Replication**
    - connected_slaves(int, number)
    - master_link_down_since_seconds(int, number)
    - master_link_status(string)
    - master_repl_offset(int, number)
    - second_repl_offset(int, number)
    - repl_backlog_active(int, number)
    - repl_backlog_size(int, bytes)
    - repl_backlog_first_byte_offset(int, number)
    - repl_backlog_histlen(int, bytes)

    **CPU**
    - used_cpu_sys(float, number)
    - used_cpu_user(float, number)
    - used_cpu_sys_children(float, number)
    - used_cpu_user_children(float, number)

    **Cluster**
    - cluster_enabled(int, flag)

- redis_cluster_keyspace
    - keys(int, number)
    - expires(int, number)
    - avg_ttl(int, number)

- redis_cluster_cmdstat
    Every Redis used command will have 3 new fields:
    - calls(int, number)
    - usec(int, mircoseconds)
    - usec_per_call(float, microseconds)

- redis_cluster_replication
  - tags:
    - myid
    - server
    - replication_role
    - replica_ip
    - replica_port
    - state (either "online", "wait_bgsave", or "send_bulk")

  - fields:
    - lag(int, number)
    - offset(int, number)

- redis_cluster_info
  - tags:
    - cluster_name

  - fields:
    - cluster_state(int, number)
    - cluster_slots_assigned(int, number)
    - cluster_slots_ok(int, number)
    - cluster_slots_pfail(int, number)
    - cluster_slots_fail(int, number)
    - cluster_known_nodes(int, number)
    - cluster_size(int, number)

> redis_cluster_info ignore myid and server tag.

### Tags:

- All measurements have the following tags:
    - myid(cluster myid)
    - server(ip:port)
    - replication_role

- The redis_keyspace measurement has an additional database tag:
    - database

- The redis_cmdstat measurement has an additional tag:
    - command

### Example Output:

Using this configuration:
```toml
[[inputs.redis_cluster]]
  ## specify servers via a url matching:
  ##  [protocol://]address[:port]
  ##  e.g.
  ##    tcp://localhost:6379
  ##
  ## If no servers are specified, then localhost is used as the host.
  ## If no port is specified, 6379 is used
  ## you can set one or all cluster nodes
  servers = ["tcp://10.1.1.53:7001", "tcp://10.1.1.53:7002"]

  ## specify server password
  # password = "s#cr@t%"

  ## specify cluster name
  cluster_name = "redis_cluster_test"

  ## specify cluster mode, default is 1
  ## 1: original cluster
  ## 2: tencent cloud
  # mode = 1

  ## Optional TLS Config
  # tls_ca = "/etc/telegraf/ca.pem"
  # tls_cert = "/etc/telegraf/cert.pem"
  # tls_key = "/etc/telegraf/key.pem"
  ## Use TLS but skip chain & host verification
  # insecure_skip_verify = true
```

When run with:
```
./telegraf --config telegraf.conf --input-filter redis_cluster --test
```

It produces(too many if many nodes):
```
* Plugin: redisi_cluster, Collection 1
redis_cluster,cluster_name=redis_cluster_test,host=manager,maxmemory_policy=noeviction,myid=a4eb340d755a8cd56a94c5be8939647d42fee755,replication_role=master,server=10.1.1.53:7001,version=6.0.9 active_defrag_hits=0i,active_defrag_key_hits=0i,active_defrag_key_misses=0i,active_defrag_misses=0i,active_defrag_running=0i,allocator_active=3726336i,allocator_allocated=2572008i,allocator_frag_bytes=1154328,allocator_frag_ratio=1.45,allocator_resident=3726336i,allocator_rss_bytes=0i,allocator_rss_ratio=1,aof_base_size=0i,aof_buffer_length=0i,aof_current_rewrite_time_sec=-1i,aof_current_size=0i,aof_delayed_fsync=0i,aof_enabled=1i,aof_last_bgrewrite_status=1i,aof_last_cow_size=0i,aof_last_rewrite_time_sec=-1i,aof_last_write_status=1i,aof_pending_bio_fsync=0i,aof_pending_rewrite=0i,aof_rewrite_buffer_length=0i,aof_rewrite_in_progress=0i,aof_rewrite_scheduled=0i,blocked_clients=0i,client_recent_max_input_buffer=40i,client_recent_max_output_buffer=0i,clients=3i,clients_in_timeout_table=0i,cluster_enabled=1i,connected_slaves=1i,evicted_keys=0i,expire_cycle_cpu_milliseconds=7194i,expired_keys=0i,expired_stale_perc=0,expired_time_cap_reached_count=0i,instantaneous_input_kbps=0.15,instantaneous_ops_per_sec=5i,instantaneous_output_kbps=11.64,io_threaded_reads_processed=0i,io_threaded_writes_processed=0i,keyspace_hitrate=0,keyspace_hits=0i,keyspace_misses=2i,latest_fork_usec=234i,lazyfree_pending_objects=0i,loading=0i,lru_clock=2822033i,master_repl_offset=807464i,maxmemory=100000000i,mem_aof_buffer=24i,mem_clients_normal=34096i,mem_clients_slaves=17048i,mem_fragmentation_bytes=1192216i,mem_fragmentation_ratio=1.46,mem_not_counted_for_evict=0i,mem_replication_backlog=1052656i,migrate_cached_sockets=0i,module_fork_in_progress=0i,module_fork_last_cow_size=0i,number_of_cached_scripts=0i,pubsub_channels=0i,pubsub_patterns=0i,rdb_bgsave_in_progress=0i,rdb_changes_since_last_save=0i,rdb_current_bgsave_time_sec=-1i,rdb_last_bgsave_status=1i,rdb_last_bgsave_time_sec=0i,rdb_last_cow_size=212992i,rdb_last_save_time=1713520417i,rdb_last_save_time_elapsed=577649i,rejected_connections=0i,repl_backlog_active=1i,repl_backlog_first_byte_offset=1i,repl_backlog_histlen=807464i,repl_backlog_size=1048576i,rss_overhead_bytes=37888i,rss_overhead_ratio=1.01,second_repl_offset=-1i,slave_expires_tracked_keys=0i,sync_full=1i,sync_partial_err=1i,sync_partial_ok=0i,total_commands_processed=959807i,total_connections_received=164i,total_net_input_bytes=31280864i,total_net_output_bytes=1753241099i,total_reads_processed=959897i,total_system_memory=16656293888i,total_writes_processed=440714i,tracking_clients=0i,tracking_total_items=0i,tracking_total_keys=0i,tracking_total_prefixes=0i,unexpected_error_replies=0i,uptime=577723i,used_cpu_sys=251.26323,used_cpu_sys_children=0.00114,used_cpu_user=337.06798,used_cpu_user_children=0,used_memory=2623856i,used_memory_dataset=112640i,used_memory_dataset_perc=9.26,used_memory_lua=37888i,used_memory_overhead=2511216i,used_memory_peak=2706928i,used_memory_peak_perc=96.93,used_memory_rss=3764224i,used_memory_scripts=0i,used_memory_startup=1407392i 1714098066000000000
...
...
```

redis_cluster_keyspace:

> redis cluster only db 0

```
> redis_cluster_keyspace,cluster_name=redis_cluster_test,database=db0,host=manager,maxmemory_policy=noeviction,myid=a4eb340d755a8cd56a94c5be8939647d42fee755,replication_role=master,server=10.1.1.53:7001,version=6.0.9 avg_ttl=0i,expires=0i,keys=1i 1714120374000000000
...
```

redis_cluster_command:
```
> redis_cluster_cmdstat,cluster_name=redis_cluster_test,command=info,host=manager,maxmemory_policy=noeviction,myid=0bf05a9352f8dd91580c38a4feb225bfa3eb9c0e,replication_role=slave,server=10.1.1.53:7004,version=6.0.9 calls=382654i,usec=42930787i,usec_per_call=112.19 1714098066000000000
```
