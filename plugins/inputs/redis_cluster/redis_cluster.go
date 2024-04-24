package redis_cluster

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"errors"

	"github.com/go-redis/redis"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/common/tls"
	"github.com/influxdata/telegraf/plugins/inputs"
)

type RedisClusterCommand struct {
	Command []interface{}
	Field   string
	Type    string
}

type RedisCluster struct {
	Servers  []string
	Password string
	ClusterName string `toml:"cluster_name"`
	Mode int
	tls.ClientConfig

	Log telegraf.Logger

	clusterclient ClusterClient
	initialized bool
}

type ClusterClient interface {
	Do(args ...interface{}) *redis.Cmd
	ClusterInfo() *redis.StringCmd
	ClusterNodes() *redis.StringCmd
	Options() *redis.ClusterOptions
	ForEachNode(fn func(client *redis.Client) error) error
	BaseTags() map[string]string
	AddTags(meta map[string]string) error
}

type RedisClusterClient struct {
	client *redis.ClusterClient
	tags   map[string]string
}

type RedisClusterInfoTypes struct {
	ClusterState                int64   `json:"cluster_state"`
	ClusterSlotsAssigned        int64   `json:"cluster_slots_assigned"`
	ClusterSlotsOk              int64   `json:"cluster_slots_ok"`
	ClusterSlotsPfail           int64   `json:"cluster_slots_pfail"`
	ClusterSlotsFail            int64   `json:"cluster_slots_fail"`
	ClusterKnownNodes           int64   `json:"cluster_known_nodes"`
	ClusterSize                 int64   `json:"cluster_size"`
}

// RedisFieldTypes defines the types expected for each of the fields redis reports on
type RedisClusterFieldTypes struct {
	ActiveDefragHits            int64   `json:"active_defrag_hits"`
	ActiveDefragKeyHits         int64   `json:"active_defrag_key_hits"`
	ActiveDefragKeyMisses       int64   `json:"active_defrag_key_misses"`
	ActiveDefragMisses          int64   `json:"active_defrag_misses"`
	ActiveDefragRunning         int64   `json:"active_defrag_running"`
	AllocatorActive             int64   `json:"allocator_active"`
	AllocatorAllocated          int64   `json:"allocator_allocated"`
	AllocatorFragBytes          float64 `json:"allocator_frag_bytes"` // for historical reasons this was left as float although redis reports it as an int
	AllocatorFragRatio          float64 `json:"allocator_frag_ratio"`
	AllocatorResident           int64   `json:"allocator_resident"`
	AllocatorRssBytes           int64   `json:"allocator_rss_bytes"`
	AllocatorRssRatio           float64 `json:"allocator_rss_ratio"`
	AofCurrentRewriteTimeSec    int64   `json:"aof_current_rewrite_time_sec"`
	AofEnabled                  int64   `json:"aof_enabled"`
	AofLastBgrewriteStatus      int64   `json:"aof_last_bgrewrite_status"`
	AofLastCowSize              int64   `json:"aof_last_cow_size"`
	AofLastRewriteTimeSec       int64   `json:"aof_last_rewrite_time_sec"`
	AofLastWriteStatus          int64   `json:"aof_last_write_status"`
	AofRewriteInProgress        int64   `json:"aof_rewrite_in_progress"`
	AofRewriteScheduled         int64   `json:"aof_rewrite_scheduled"`
	BlockedClients              int64   `json:"blocked_clients"`
	ClientRecentMaxInputBuffer  int64   `json:"client_recent_max_input_buffer"`
	ClientRecentMaxOutputBuffer int64   `json:"client_recent_max_output_buffer"`
	Clients                     int64   `json:"clients"`
	ClientsInTimeoutTable       int64   `json:"clients_in_timeout_table"`
	ClusterEnabled              int64   `json:"cluster_enabled"`
	ConnectedSlaves             int64   `json:"connected_slaves"`
	EvictedKeys                 int64   `json:"evicted_keys"`
	ExpireCycleCPUMilliseconds  int64   `json:"expire_cycle_cpu_milliseconds"`
	ExpiredKeys                 int64   `json:"expired_keys"`
	ExpiredStalePerc            float64 `json:"expired_stale_perc"`
	ExpiredTimeCapReachedCount  int64   `json:"expired_time_cap_reached_count"`
	InstantaneousInputKbps      float64 `json:"instantaneous_input_kbps"`
	InstantaneousOpsPerSec      int64   `json:"instantaneous_ops_per_sec"`
	InstantaneousOutputKbps     float64 `json:"instantaneous_output_kbps"`
	IoThreadedReadsProcessed    int64   `json:"io_threaded_reads_processed"`
	IoThreadedWritesProcessed   int64   `json:"io_threaded_writes_processed"`
	KeyspaceHits                int64   `json:"keyspace_hits"`
	KeyspaceMisses              int64   `json:"keyspace_misses"`
	LatestForkUsec              int64   `json:"latest_fork_usec"`
	LazyfreePendingObjects      int64   `json:"lazyfree_pending_objects"`
	Loading                     int64   `json:"loading"`
	LruClock                    int64   `json:"lru_clock"`
	MasterReplOffset            int64   `json:"master_repl_offset"`
	MaxMemory                   int64   `json:"maxmemory"`
	MaxMemoryPolicy             string  `json:"maxmemory_policy"`
	MemAofBuffer                int64   `json:"mem_aof_buffer"`
	MemClientsNormal            int64   `json:"mem_clients_normal"`
	MemClientsSlaves            int64   `json:"mem_clients_slaves"`
	MemFragmentationBytes       int64   `json:"mem_fragmentation_bytes"`
	MemFragmentationRatio       float64 `json:"mem_fragmentation_ratio"`
	MemNotCountedForEvict       int64   `json:"mem_not_counted_for_evict"`
	MemReplicationBacklog       int64   `json:"mem_replication_backlog"`
	MigrateCachedSockets        int64   `json:"migrate_cached_sockets"`
	ModuleForkInProgress        int64   `json:"module_fork_in_progress"`
	ModuleForkLastCowSize       int64   `json:"module_fork_last_cow_size"`
	NumberOfCachedScripts       int64   `json:"number_of_cached_scripts"`
	PubsubChannels              int64   `json:"pubsub_channels"`
	PubsubPatterns              int64   `json:"pubsub_patterns"`
	RdbBgsaveInProgress         int64   `json:"rdb_bgsave_in_progress"`
	RdbChangesSinceLastSave     int64   `json:"rdb_changes_since_last_save"`
	RdbCurrentBgsaveTimeSec     int64   `json:"rdb_current_bgsave_time_sec"`
	RdbLastBgsaveStatus         int64   `json:"rdb_last_bgsave_status"`
	RdbLastBgsaveTimeSec        int64   `json:"rdb_last_bgsave_time_sec"`
	RdbLastCowSize              int64   `json:"rdb_last_cow_size"`
	RdbLastSaveTime             int64   `json:"rdb_last_save_time"`
	RdbLastSaveTimeElapsed      int64   `json:"rdb_last_save_time_elapsed"`
	RedisVersion                string  `json:"redis_version"`
	RejectedConnections         int64   `json:"rejected_connections"`
	ReplBacklogActive           int64   `json:"repl_backlog_active"`
	ReplBacklogFirstByteOffset  int64   `json:"repl_backlog_first_byte_offset"`
	ReplBacklogHistlen          int64   `json:"repl_backlog_histlen"`
	ReplBacklogSize             int64   `json:"repl_backlog_size"`
	MasterLinkStatus            int64   `json:"master_link_status"`
	RssOverheadBytes            int64   `json:"rss_overhead_bytes"`
	RssOverheadRatio            float64 `json:"rss_overhead_ratio"`
	SecondReplOffset            int64   `json:"second_repl_offset"`
	SlaveExpiresTrackedKeys     int64   `json:"slave_expires_tracked_keys"`
	SyncFull                    int64   `json:"sync_full"`
	SyncPartialErr              int64   `json:"sync_partial_err"`
	SyncPartialOk               int64   `json:"sync_partial_ok"`
	TotalCommandsProcessed      int64   `json:"total_commands_processed"`
	TotalConnectionsReceived    int64   `json:"total_connections_received"`
	TotalNetInputBytes          int64   `json:"total_net_input_bytes"`
	TotalNetOutputBytes         int64   `json:"total_net_output_bytes"`
	TotalReadsProcessed         int64   `json:"total_reads_processed"`
	TotalSystemMemory           int64   `json:"total_system_memory"`
	TotalWritesProcessed        int64   `json:"total_writes_processed"`
	TrackingClients             int64   `json:"tracking_clients"`
	TrackingTotalItems          int64   `json:"tracking_total_items"`
	TrackingTotalKeys           int64   `json:"tracking_total_keys"`
	TrackingTotalPrefixes       int64   `json:"tracking_total_prefixes"`
	UnexpectedErrorReplies      int64   `json:"unexpected_error_replies"`
	Uptime                      int64   `json:"uptime"`
	UsedCPUSys                  float64 `json:"used_cpu_sys"`
	UsedCPUSysChildren          float64 `json:"used_cpu_sys_children"`
	UsedCPUUser                 float64 `json:"used_cpu_user"`
	UsedCPUUserChildren         float64 `json:"used_cpu_user_children"`
	UsedMemory                  int64   `json:"used_memory"`
	UsedMemoryDataset           int64   `json:"used_memory_dataset"`
	UsedMemoryDatasetPerc       float64 `json:"used_memory_dataset_perc"`
	UsedMemoryLua               int64   `json:"used_memory_lua"`
	UsedMemoryOverhead          int64   `json:"used_memory_overhead"`
	UsedMemoryPeak              int64   `json:"used_memory_peak"`
	UsedMemoryPeakPerc          float64 `json:"used_memory_peak_perc"`
	UsedMemoryRss               int64   `json:"used_memory_rss"`
	UsedMemoryScripts           int64   `json:"used_memory_scripts"`
	UsedMemoryStartup           int64   `json:"used_memory_startup"`
}

func (r *RedisClusterClient) Do(args ...interface{}) *redis.Cmd {
	return r.client.Do(args...)
}

func (r *RedisClusterClient) ClusterInfo() *redis.StringCmd {
	return r.client.ClusterInfo()
}

func (r *RedisClusterClient) ClusterNodes() *redis.StringCmd {
	return r.client.ClusterNodes()
}

func (r *RedisClusterClient) Options() *redis.ClusterOptions {
	return r.client.Options()
}

func (r *RedisClusterClient) ForEachNode(fn func(client *redis.Client) error) error {
	return r.client.ForEachNode(fn)
}

func (r *RedisClusterClient) BaseTags() map[string]string {
	tags := make(map[string]string)
	for k, v := range r.tags {
		tags[k] = v
	}
	return tags
}

func (r *RedisClusterClient) AddTags(meta map[string]string) error {
	for k, v := range meta {
		r.tags[k] = v
	}

	return nil
}

var replicationSlaveMetricPrefix = regexp.MustCompile(`^slave\d+`)

var sampleConfig = `
  ## specify servers via a url matching:
  ##  [protocol://]address[:port]
  ##  e.g.
  ##    tcp://localhost:6379
  ##
  ## If no servers are specified, then localhost is used as the host.
  ## If no port is specified, 6379 is used
  servers = ["tcp://localhost:6379"]

  ## specify server password
  # password = "s#cr@t%"

  ## specify cluster name
  cluster_name = "redis_cluster"

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
`

func (r *RedisCluster) SampleConfig() string {
	return sampleConfig
}

func (r *RedisCluster) Description() string {
	return "Read metrics from one or many redis cluster servers"
}

var Tracking = map[string]string{
	"uptime_in_seconds": "uptime",
	"connected_clients": "clients",
	"role":              "replication_role",
}

func (r *RedisCluster) init() error {
	if r.initialized {
		return nil
	}

	if len(r.Servers) == 0 {
		r.Servers = []string{"tcp://localhost:6379"}
	}

	if r.Mode == 0 {
		r.Mode = 1
	}

	password := ""
	if len(r.Password) > 0 {
		password = r.Password
	}

	addrs := []string{}
	tlsConfig, err := r.ClientConfig.TLSConfig()
	if err != nil {
		return err
	}

	for _, serv := range r.Servers {
		if !strings.HasPrefix(serv, "tcp://") {
			r.Log.Warn("Server URL found without scheme; please update your configuration file")
			serv = "tcp://" + serv
		}

		u, err := url.Parse(serv)
		if err != nil {
			return fmt.Errorf("unable to parse to address %q: %s", serv, err.Error())
		}

		if u.User != nil {
			_, ok := u.User.Password()
			if ok {
				r.Log.Warn("We'll ignore password in url, as redis cluster must use the same password")
			}
		}

		var address string = u.Host
		addrs = append(addrs, address)
	}

	rdb := redis.NewClusterClient(
		&redis.ClusterOptions{
			Addrs:     addrs,
			Password:  password,
			PoolSize:  1,
			TLSConfig: tlsConfig,
		},
	)

	tags := map[string]string{}
	tags["cluster_name"] = r.ClusterName

	r.clusterclient = &RedisClusterClient{
		client: rdb,
		tags: tags,
	}

	r.initialized = true
	return nil
}

func getSubstr(regEx, line string) (map[string]string, error) {
	var compRegEx = regexp.MustCompile(regEx)
	match := compRegEx.FindStringSubmatch(line)

	subs := make(map[string]string)
	for i, name := range compRegEx.SubexpNames() {
		if i > 0 && i <= len(match) {
			subs[name] = match[i]
		}
	}

	if len(subs) == 0 {
		return nil, errors.New("match none")
	}

	return subs, nil
}

func (r *RedisCluster) matchClusterNodes() (map[string]string, error) {
	info, err := r.clusterclient.ClusterNodes().Result()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(info)), "\n")

	metas := make(map[string]string)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		meta, err := getSubstr(`(?P<myid>\w+)\s+(?P<server>\d+\.\d+\.\d+\.\d+:\d+)@`, string(line))
		if err != nil {
			continue
		}
		myid := meta["myid"]
		server := meta["server"]

		metas[myid] = server
	}

	if len(metas) > 0 {
		return metas, nil
	}

	return nil, errors.New("can not parse cluster nodes")


	return metas, err
}

// Reads stats from all configured servers accumulates stats.
// Returns one of the errors encountered while gather stats (if any).
func (r *RedisCluster) Gather(acc telegraf.Accumulator) error {
	if !r.initialized {
		err := r.init()
		if err != nil {
			return err
		}
	}

	// choose one client
	acc.AddError(r.gatherState(r.clusterclient, acc))

	var wg sync.WaitGroup

	if r.Mode == 1 {
		err := r.clusterclient.ForEachNode(func(c *redis.Client) error {
			wg.Add(1)
			go func(c *redis.Client) {
				defer wg.Done()
				acc.AddError(r.gatherServer(c, acc))
			}(c)

			return nil
		})

		if err != nil {
			return err
		}
	}

	if r.Mode == 2 {
		nodes, err := r.matchClusterNodes()
		if err != nil {
			return err
		}

		for myid, server := range nodes {
			wg.Add(1)
			go func(c ClusterClient, myid string, server string) {
				defer wg.Done()
				acc.AddError(r.gatherClusterServer(c, acc, myid, server))
			}(r.clusterclient, myid, server)
		}
	}

	wg.Wait()
	return nil
}

func (r *RedisCluster) gatherState(client ClusterClient, acc telegraf.Accumulator) error {
	info, err := client.ClusterInfo().Result()
	if err != nil {
		return fmt.Errorf("redis cluster error, %s", err)
	}

	rdr := strings.NewReader(info)
	return gatherStateOutput(rdr, acc, client.BaseTags())
}

func gatherStateOutput(
	rdr io.Reader,
	acc telegraf.Accumulator,
	tags map[string]string,
) error {
	scanner := bufio.NewScanner(rdr)
	fields := make(map[string]interface{})

	// tags only use cluster_name
	ntags := make(map[string]string)
	ntags["cluster_name"] = tags["cluster_name"]

	for scanner.Scan() {
		line := scanner.Text()

		if len(line) == 0 {
			continue
		}

		if line[0] == '#' {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		name := parts[0]
		val  := strings.TrimSpace(parts[1])
		val  =  strings.TrimSuffix(val, "%")

		// Treat it as string
		if name == "cluster_state" {
			// https://redis.io/docs/latest/commands/cluster-info/
			switch val {
			case "ok":
				val = "1"
			case "fail":
				val = "2"
			case "error":
				val = "3"
			default:
				val = "4" // unkown error
			}
		}

		// Try parsing as int
		if ival, err := strconv.ParseInt(val, 10, 64); err == nil {
			fields[name] = ival
			continue
		}

		// Try parsing as a float
		if fval, err := strconv.ParseFloat(val, 64); err == nil {
			fields[name] = fval
			continue
		}
	}

	o := RedisClusterInfoTypes{}
	setStructFieldsFromObject(fields, nil, &o)
	setExistingFieldsFromStruct(fields, nil, &o)

	acc.AddFields("redis_cluster_info", fields, ntags)
	return nil
}

func (r *RedisCluster) gatherServer(client *redis.Client, acc telegraf.Accumulator) error {
	addr := client.Options().Addr
	myid, err := client.Do("cluster", "myid").String()
	if err != nil {
		return fmt.Errorf("redis(%s) - err", addr)
	}

	info, err := client.Do("info", "ALL").String()
	if err != nil {
		return fmt.Errorf("redis(%v) - %s", addr, err)
	}

	err = r.clusterclient.AddTags(map[string]string{"myid": myid, "server": addr})
	if err != nil {
		return fmt.Errorf("redis(%v) - %s", addr, err)
	}

	rdr := strings.NewReader(info)
	return gatherInfoOutput(rdr, acc, r.clusterclient.BaseTags())
}

func (r *RedisCluster) gatherClusterServer(client ClusterClient, acc telegraf.Accumulator, myid string, server string) error {
	info, err := client.Do("info", "ALL", myid).String()
	if err != nil {
		return err
	}

	err = client.AddTags(map[string]string{"myid": myid, "server": server})
	if err != nil {
		return fmt.Errorf("redis(%v) - %s", server, err)
	}

	rdr := strings.NewReader(info)
	return gatherInfoOutput(rdr, acc, client.BaseTags())
}

// gatherInfoOutput gathers
func gatherInfoOutput(
	rdr io.Reader,
	acc telegraf.Accumulator,
	tags map[string]string,
) error {
	var section string
	var keyspaceHits, keyspaceMisses int64

	scanner := bufio.NewScanner(rdr)
	fields := make(map[string]interface{})

	for scanner.Scan() {
		line := scanner.Text()

		if len(line) == 0 {
			continue
		}

		if line[0] == '#' {
			if len(line) > 2 {
				section = line[2:]
			}
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		name := parts[0]

		if section == "Server" {
			if name != "lru_clock" && name != "uptime_in_seconds" && name != "redis_version" {
				continue
			}
		}

		if strings.HasPrefix(name, "master_replid") {
			continue
		}

		if name == "mem_allocator" {
			continue
		}

		if strings.HasSuffix(name, "_human") {
			continue
		}

		metric, ok := Tracking[name]
		if !ok {
			if section == "Keyspace" {
				kline := strings.TrimSpace(parts[1])
				gatherKeyspaceLine(name, kline, acc, tags)
				continue
			}
			if section == "Commandstats" {
				kline := strings.TrimSpace(parts[1])
				gatherCommandstateLine(name, kline, acc, tags)
				continue
			}
			if section == "Replication" && replicationSlaveMetricPrefix.MatchString(name) {
				kline := strings.TrimSpace(parts[1])
				gatherReplicationLine(name, kline, acc, tags)
				continue
			}

			metric = name
		}

		val := strings.TrimSpace(parts[1])

		// Some percentage values have a "%" suffix that we need to get rid of before int/float conversion
		val = strings.TrimSuffix(val, "%")

		// Try parsing as int
		if ival, err := strconv.ParseInt(val, 10, 64); err == nil {
			switch name {
			case "keyspace_hits":
				keyspaceHits = ival
			case "keyspace_misses":
				keyspaceMisses = ival
			case "rdb_last_save_time":
				// influxdb can't calculate this, so we have to do it
				fields["rdb_last_save_time_elapsed"] = time.Now().Unix() - ival
			}
			fields[metric] = ival
			continue
		}

		// Try parsing as a float
		if fval, err := strconv.ParseFloat(val, 64); err == nil {
			fields[metric] = fval
			continue
		}

		// Treat it as a string

		if name == "role" {
			tags["replication_role"] = val
			continue
		}

		if name == "redis_version" {
			tags["version"] = val
			continue
		}

		if name == "maxmemory_policy" {
			tags["maxmemory_policy"] = val
			continue
		}

		if strings.EqualFold(name, "rdb_last_bgsave_status") || strings.EqualFold(name, "aof_last_bgrewrite_status") || strings.EqualFold(name, "aof_last_write_status") || strings.EqualFold(name, "master_link_status") {
			if strings.EqualFold(val, "up") || strings.EqualFold(val, "ok") {
				val = "1" // up or ok
			} else {
				val = "0"
			}
		}

		fields[metric] = val
	}
	var keyspaceHitrate float64
	if keyspaceHits != 0 || keyspaceMisses != 0 {
		keyspaceHitrate = float64(keyspaceHits) / float64(keyspaceHits+keyspaceMisses)
	}
	fields["keyspace_hitrate"] = keyspaceHitrate

	o := RedisClusterFieldTypes{}

	setStructFieldsFromObject(fields, &o, nil)
	setExistingFieldsFromStruct(fields, &o, nil)

	acc.AddFields("redis_cluster", fields, tags)
	return nil
}

// Parse the special Keyspace line at end of redis stats
// This is a special line that looks something like:
//     db0:keys=2,expires=0,avg_ttl=0
// And there is one for each db on the redis instance
func gatherKeyspaceLine(
	name string,
	line string,
	acc telegraf.Accumulator,
	globalTags map[string]string,
) {
	if strings.Contains(line, "keys=") {
		fields := make(map[string]interface{})
		tags := make(map[string]string)
		for k, v := range globalTags {
			tags[k] = v
		}
		tags["database"] = name
		dbparts := strings.Split(line, ",")
		for _, dbp := range dbparts {
			kv := strings.Split(dbp, "=")
			ival, err := strconv.ParseInt(kv[1], 10, 64)
			if err == nil {
				fields[kv[0]] = ival
			}
		}
		acc.AddFields("redis_cluster_keyspace", fields, tags)
	}
}

// Parse the special cmdstat lines.
// Example:
//     cmdstat_publish:calls=33791,usec=208789,usec_per_call=6.18
// Tag: cmdstat=publish; Fields: calls=33791i,usec=208789i,usec_per_call=6.18
func gatherCommandstateLine(
	name string,
	line string,
	acc telegraf.Accumulator,
	globalTags map[string]string,
) {
	if !strings.HasPrefix(name, "cmdstat") {
		return
	}

	fields := make(map[string]interface{})
	tags := make(map[string]string)
	for k, v := range globalTags {
		tags[k] = v
	}
	tags["command"] = strings.TrimPrefix(name, "cmdstat_")
	parts := strings.Split(line, ",")
	for _, part := range parts {
		kv := strings.Split(part, "=")
		if len(kv) != 2 {
			continue
		}

		switch kv[0] {
		case "calls":
			fallthrough
		case "usec":
			ival, err := strconv.ParseInt(kv[1], 10, 64)
			if err == nil {
				fields[kv[0]] = ival
			}
		case "usec_per_call":
			fval, err := strconv.ParseFloat(kv[1], 64)
			if err == nil {
				fields[kv[0]] = fval
			}
		}
	}
	acc.AddFields("redis_cluster_cmdstat", fields, tags)
}

// Parse the special Replication line
// Example:
//     slave0:ip=127.0.0.1,port=7379,state=online,offset=4556468,lag=0
// This line will only be visible when a node has a replica attached.
func gatherReplicationLine(
	name string,
	line string,
	acc telegraf.Accumulator,
	globalTags map[string]string,
) {
	fields := make(map[string]interface{})
	tags := make(map[string]string)
	for k, v := range globalTags {
		tags[k] = v
	}

	tags["replica_id"] = strings.TrimLeft(name, "slave")
	tags["replication_role"] = "slave"

	parts := strings.Split(line, ",")
	for _, part := range parts {
		kv := strings.Split(part, "=")
		if len(kv) != 2 {
			continue
		}

		switch kv[0] {
		case "ip":
			tags["replica_ip"] = kv[1]
		case "port":
			tags["replica_port"] = kv[1]
		case "state":
			tags[kv[0]] = kv[1]
		default:
			ival, err := strconv.ParseInt(kv[1], 10, 64)
			if err == nil {
				fields[kv[0]] = ival
			}
		}
	}

	acc.AddFields("redis_cluster_replication", fields, tags)
}

func init() {
	inputs.Add("redis_cluster", func() telegraf.Input {
		return &RedisCluster{}
	})
}

func setExistingFieldsFromStruct(fields map[string]interface{}, o1 *RedisClusterFieldTypes, o2 *RedisClusterInfoTypes) {
	var o interface{}
	if o1 == nil {
		o = o2
	} else {
		o = o1
	}
	val := reflect.ValueOf(o).Elem()
	typ := val.Type()

	for key := range fields {
		if _, exists := fields[key]; exists {
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				jsonFieldName := f.Tag.Get("json")
				if jsonFieldName == key {
					fields[key] = val.Field(i).Interface()
					break
				}
			}
		}
	}
}

func setStructFieldsFromObject(fields map[string]interface{}, o1 *RedisClusterFieldTypes, o2 *RedisClusterInfoTypes) {
	var o interface{}
	if o1 == nil {
		o = o2
	} else {
		o = o1
	}

	val := reflect.ValueOf(o).Elem()
	typ := val.Type()

	for key, value := range fields {
		if _, exists := fields[key]; exists {
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				jsonFieldName := f.Tag.Get("json")
				if jsonFieldName == key {
					structFieldValue := val.Field(i)
					structFieldValue.Set(coerceType(value, structFieldValue.Type()))
					break
				}
			}
		}
	}
}

func coerceType(value interface{}, typ reflect.Type) reflect.Value {
	switch sourceType := value.(type) {
	case bool:
		switch typ.Kind() {
		case reflect.String:
			if sourceType {
				value = "true"
			} else {
				value = "false"
			}
		case reflect.Int64:
			if sourceType {
				value = int64(1)
			} else {
				value = int64(0)
			}
		case reflect.Float64:
			if sourceType {
				value = float64(1)
			} else {
				value = float64(0)
			}
		default:
			panic(fmt.Sprintf("unhandled destination type %s", typ.Kind().String()))
		}
	case int, int8, int16, int32, int64:
		switch typ.Kind() {
		case reflect.String:
			value = fmt.Sprintf("%d", value)
		case reflect.Int64:
			// types match
		case reflect.Float64:
			value = float64(reflect.ValueOf(sourceType).Int())
		default:
			panic(fmt.Sprintf("unhandled destination type %s", typ.Kind().String()))
		}
	case uint, uint8, uint16, uint32, uint64:
		switch typ.Kind() {
		case reflect.String:
			value = fmt.Sprintf("%d", value)
		case reflect.Int64:
			// types match
		case reflect.Float64:
			value = float64(reflect.ValueOf(sourceType).Uint())
		default:
			panic(fmt.Sprintf("unhandled destination type %s", typ.Kind().String()))
		}
	case float32, float64:
		switch typ.Kind() {
		case reflect.String:
			value = fmt.Sprintf("%f", value)
		case reflect.Int64:
			value = int64(reflect.ValueOf(sourceType).Float())
		case reflect.Float64:
			// types match
		default:
			panic(fmt.Sprintf("unhandled destination type %s", typ.Kind().String()))
		}
	case string:
		switch typ.Kind() {
		case reflect.String:
			// types match
		case reflect.Int64:
			value, _ = strconv.ParseInt(value.(string), 10, 64)
		case reflect.Float64:
			value, _ = strconv.ParseFloat(value.(string), 64)
		default:
			panic(fmt.Sprintf("unhandled destination type %s", typ.Kind().String()))
		}
	default:
		panic(fmt.Sprintf("unhandled source type %T", sourceType))
	}
	return reflect.ValueOf(value)
}
