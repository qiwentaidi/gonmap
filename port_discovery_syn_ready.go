package gonmap

import (
	"context"
	"net"
	"sync"
	"time"
)

const synPrepareWorkers = 16

// Only senders with a preparation phase reorder work. Raw IP senders retain
// their existing path. prepare must not invoke user callbacks or touch scanner
// maps: the scan caller owns progress, source cache, pending probes and events.
type synPacketPreparer interface {
	prepare(context.Context, net.IP) (net.IP, error)
}
type synPreparedHost struct {
	tasks   []synScanTask
	src     net.IP
	err     error
	elapsed time.Duration
}
type synReadyTasks struct {
	current []synScanTask
	results <-chan synPreparedHost
	cancel  context.CancelFunc
	done    <-chan struct{}
}

func newSYNReadyTasks(ctx context.Context, tasks []synScanTask, sender synPacketSender) *synReadyTasks {
	preparer, ok := sender.(synPacketPreparer)
	if !ok {
		return &synReadyTasks{current: tasks}
	}
	groups := make([][]synScanTask, 0)
	index := make(map[string]int)
	for _, task := range tasks {
		if ctx.Err() != nil {
			return &synReadyTasks{}
		}
		key := task.ip.String()
		n, exists := index[key]
		if !exists {
			n = len(groups)
			index[key] = n
			groups = append(groups, nil)
		}
		groups[n] = append(groups[n], task)
	}
	workers := synPrepareWorkers
	if len(groups) < workers {
		workers = len(groups)
	}
	child, cancel := context.WithCancel(ctx)
	jobs := make(chan []synScanTask)
	results := make(chan synPreparedHost, workers)
	done := make(chan struct{})
	var wg sync.WaitGroup
	// Include the producer in the acknowledgement barrier. Every blocked send
	// selects cancellation, so early returns cannot leave queue workers behind.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(jobs)
		for _, group := range groups {
			select {
			case <-child.Done():
				return
			case jobs <- group:
			}
		}
	}()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-child.Done():
					return
				case group, ok := <-jobs:
					if !ok {
						return
					}
					if child.Err() != nil {
						return
					}
					started := time.Now()
					src, err := preparer.prepare(child, group[0].ip)
					result := synPreparedHost{tasks: group, src: src, err: err, elapsed: time.Since(started)}
					select {
					case <-child.Done():
						return
					case results <- result:
					}
				}
			}
		}()
	}
	go func() { wg.Wait(); close(results); close(done) }()
	return &synReadyTasks{results: results, cancel: cancel, done: done}
}

func (q *synReadyTasks) next(ctx context.Context) (synScanTask, *synPreparedHost, bool) {
	var preparation *synPreparedHost
	if ctx.Err() != nil {
		return synScanTask{}, nil, false
	}
	if len(q.current) == 0 {
		if q.results == nil {
			return synScanTask{}, nil, false
		}
		select {
		case <-ctx.Done():
			return synScanTask{}, nil, false
		case result, ok := <-q.results:
			if !ok {
				return synScanTask{}, nil, false
			}
			q.current = result.tasks
			preparation = &result
		}
	}
	task := q.current[0]
	q.current = q.current[1:]
	return task, preparation, true
}
func (q *synReadyTasks) stop() {
	if q.cancel != nil {
		q.cancel()
		<-q.done
	}
}
