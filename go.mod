module test/testsocks5

go 1.13

replace socks5 => ./socks5

require (
	github.com/sirupsen/logrus v1.4.2
	github.com/xtaci/lossyconn v0.0.0-20190602105132-8df528c0c9ae // indirect
	socks5 v0.0.0-00010101000000-000000000000
)
