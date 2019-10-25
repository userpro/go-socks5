proxy_naive:
	go build -o proxy_naive.out ./proxy1/proxy.go ./proxy1/proxy_client.go

proxy:
	go build -o proxy.out ./proxy2/proxy.go

pprof:
	go tool pprof pprof http://127.0.0.1:9999/debug/pprof/profile -seconds 30

flame_graph:
	go tool pprof -http=:8081 ~/pprof/pprof.samples.cpu.001.pb.gz

clean_flame_graph:
	rm ~/pprof/pprof.samples.cpu.001.pb.gz

.PHONY: clean
clean:
	rm *out