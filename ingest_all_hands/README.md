Add the following to `jvm.options`

```
-XX:MaxDirectMemorySize=64m
-XX:-MaxFDLimit
```

MaxDirectMemorySize : limits the direct memory used by JVM
-MaxFDLimit : on Mac avoid the JVM limiting the number of file descriptors


# Launching LS

```
ulimit -S -n 1048576 && bin/logstash -f /Users/andrea/workspace/logstash_andsel/ingest_all_hands/ssl_tcp_pipeline.conf
```

## Launching the TCP benchmark tool

```
ruby -J-Xmx16g -J-XX:-MaxFDLimit benchmark_client.rb
```

- `-MaxFDLimit` is used to avoid the FD limit imposed by the JVM

## Launching the Beats benchmark tool
Provide at least 128Mb for direct memory (MaxDirectMemorySize)

```
ruby -J-Xmx16g -J-XX:-MaxFDLimit benchmark_client.rb --test=beats -a yes -f 3
```
- `-a` is used to consumes the ACK messages
-  `-f 3` define the speed of ACKs reads per seconds.


Using bundler:
```
bundle exec ruby -J-Xmx16g -J-XX:-MaxFDLimit benchmark_client.rb --test=beats --msg_sizes=2000 -a yes
```

- `--msg_sizes` is a comma separated message sizes like 8Kb, 31Kb or just plain int number like 2000.
- `--batch_size` followed by a  number, is the batch size, by default if not specified is 2000.