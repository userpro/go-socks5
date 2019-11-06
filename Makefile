build:
	go build -o proxy.out ./proxy/proxy.go

pprof:
	go tool pprof pprof http://127.0.0.1:9999/debug/pprof/profile -seconds 30

flame_graph:
	go tool pprof -http=:8081 ~/pprof/pprof.samples.cpu.001.pb.gz

clean_flame_graph:
	rm ~/pprof/pprof.samples.cpu.001.pb.gz

.PHONY: clean
clean:
	rm *out