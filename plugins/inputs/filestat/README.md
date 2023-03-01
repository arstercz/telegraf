# filestat Input Plugin

The filestat plugin gathers metrics about file existence, size, content match, and other stats.

### Configuration:

```
[[inputs.filestat]]
  ## Files to gather stats about.
  ## These accept standard unix glob matching rules, but with the addition of
  ## ** as a "super asterisk". ie:
  ##   "/var/log/**.log"  -> recursively find all .log files in /var/log
  ##   "/var/log/*/*.log" -> find all .log files with a parent dir in /var/log
  ##   "/var/log/apache.log" -> just tail the apache log file
  ##
  ## See https://github.com/gobwas/glob for more examples
  ##
  files = ["/var/log/**.log"]

  ## If true, read the entire file and calculate an md5 checksum.
  md5 = false

  ## If true, will calculate the md5's crc checksum, to adapt prometheus value
  ## both md5 and md5_crc will calculate md5.
  md5_crc = false

  use_match = true
  match_cmd = "wm-logfilter --last-minutes 1 --maxline 1 --match 'kernel|timeout|error'"
  timeout = "5s"
```

examples:
```toml
# Read stats about given file(s)
[[inputs.filestat]]
  files = ["/var/log/messages", "/var/log/cron"]
  md5 = false

  use_match = true
  match_cmd = "wt-logfilter --last-minutes 2 --maxline 1 --match 'error|telegraf'"
  timeout = "5s"


[[inputs.filestat]]
  files = ["/var/log/juicefs.log"]
  md5 = false

  use_match = true
  match_cmd = "wt-logfilter --last-minutes 2 --format '%Y/%m/%d %M:%H:%S' --maxline 1 --match 'error|warn'"
  timeout = "5s"

[[inputs.filestat]]
  files = ["/etc/telegraf/telegraf.conf"]
  md5 = false

  use_match = true
  match_cmd = "grep -P 'server|http'"
  timeout = "5s"

[[inputs.filestat]]
  files = ["/etc/motd"]
  md5 = true
  md5_crc = false

  use_match = false
```

### Measurements & Fields:

- filestat
    - exists (int, 0 | 1)
    - size_bytes (int, bytes)
    - modification_time (int, unix time nanoseconds)
    - md5 (optional, string)
    - is_match (int, 0: no match, 1: match, 2: error)

### Tags:

- All measurements have the following tags:
    - file (the path the to file, as specified in the config)
    - use_match (0: not use, 1: use)

### Example Output:

```
$ telegraf --config /etc/telegraf/telegraf.conf --input-filter filestat --test
> filestat,file=/etc/motd,host=cz-centos7-2,use_match=0 exists=1i,md5_crc=991388534i,modification_time=1370615492000000000i,size_bytes=0i 1677895596000000000
> filestat,file=/var/log/juicefs.log-1,host=cz-centos7-2,use_match=1 exists=0i 1677895596000000000
> filestat,file=/etc/telegraf/telegraf.conf,host=cz-centos7-2,use_match=1 exists=1i,is_match=1i,modification_time=1668051433598754623i,size_bytes=3174i 1677895596000000000
> filestat,file=/var/log/messages,host=cz-centos7-2,use_match=1 exists=1i,is_match=0i,modification_time=1677895561044771988i,size_bytes=6727723i 1677895596000000000
> filestat,file=/var/log/cron,host=cz-centos7-2,use_match=1 exists=1i,is_match=1i,modification_time=1677895561051772627i,size_bytes=1884029i 1677895596000000000
```
