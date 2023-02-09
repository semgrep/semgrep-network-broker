package pkg

import (
	"sync"

	log "github.com/sirupsen/logrus"
)

type TeardownFunc func() error

type TeardownFuncs struct {
	mu    sync.Mutex
	funcs []TeardownFunc
}

func (tfs *TeardownFuncs) Push(tf TeardownFunc) {
	tfs.mu.Lock()
	defer tfs.mu.Unlock()

	tfs.funcs = append([]TeardownFunc{tf}, tfs.funcs...)
}

func (tfs *TeardownFuncs) Teardown() {
	tfs.mu.Lock()
	defer tfs.mu.Unlock()

	for _, tf := range tfs.funcs {
		if tf != nil {
			err := tf()
			if err != nil {
				log.Warnf("error during teardown: %v", err)
			}
		}
	}
}
