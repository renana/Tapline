package main

// Inspector is the peek hook for later PII / DLP scanners.
type Inspector interface {
	OnBytes(dir Dir, p []byte)
}

type Dir int

const (
	DirUpstream Dir = iota
	DirDownstream
)

type NoopInspector struct{}

func (NoopInspector) OnBytes(Dir, []byte) {}
