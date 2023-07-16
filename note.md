### 查看pipe

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### format 位置

```bash
cat /sys/kernel/debug/tracing/events/syscalls/xxx/format
```

### minikube

```shell
minikube start --driver=virtualbox --nodes=3
```

#### stop
```shell
minikube stop && minikube delete
```
