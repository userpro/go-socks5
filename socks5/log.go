package socks5

import (
	"github.com/sirupsen/logrus"
)

type _log struct{}

var log _log

func (l *_log) Info(args ...interface{}) {
	logrus.Info(args)
}

func (l *_log) Infof(f string, args ...interface{}) {
	logrus.Infof(f, args)
}

func (l *_log) Error(args ...interface{}) {
	logrus.Error(args)
}

func (l *_log) Errorf(f string, args ...interface{}) {
	logrus.Errorf(f, args)
}

func (l *_log) Fatal(args ...interface{}) {
	logrus.Fatal(args)
}

func (l *_log) Warn(args ...interface{}) {
	logrus.Warn(args)
}
