proxy:
	go build -o proxy.out ./proxy1/proxy.go ./proxy1/proxy_client.go

proxy_reverse:
	go build -o proxy_reverse.out ./proxy2/proxy_reverse.go

pprof:
	go tool pprof pprof http://127.0.0.1:9999/debug/pprof/profile -seconds 30

flame_graph:
	go tool pprof -http=:8081 ~/pprof/pprof.samples.cpu.001.pb.gz

.PHONY: clean
clean:
	rm *out