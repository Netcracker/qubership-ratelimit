package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/go-logr/logr"
)

// DefaultResync is how often the watcher re-reads the manifest on its own,
// events or not. The kubelet's swap is one rename the watch sees at once;
// the timer covers a watch that missed it, and a directory that did not
// exist when the watch was set up.
const DefaultResync = 10 * time.Second

// DefaultSettle is how long the watcher waits after an event before reading.
// The kubelet writes a directory, a temporary link, and one rename; reading
// on the first of those would find the old files, and the rename is the
// last.
const DefaultSettle = 100 * time.Millisecond

// Watcher reads the mounted directory when it changes and hands each reading
// to the applier.
//
// The kubelet projects a ConfigMap update by writing a new timestamped
// directory and swapping the ..data symlink to it with one rename, so a
// change is one event on the mount directory; the watch is on that
// directory, never on the files, which are the symlink's targets and change
// underneath it. What the watcher compares is the manifest's bytes: a reading
// whose manifest equals the last one's is the same configuration, whatever
// the events said, so the kubelet's periodic refresh of an unchanged volume
// applies nothing.
type Watcher struct {
	Dir     string
	Applier *Applier
	Log     logr.Logger

	Resync time.Duration
	Settle time.Duration

	// applied and refused are the manifests of the last apply and of the
	// last refusal, so that each is reported once per manifest rather than
	// once per read; absent says the last read found no manifest.
	applied []byte
	refused []byte
	absent  bool
}

// Run reads once, then on every change until ctx ends.
func (w *Watcher) Run(ctx context.Context) error {
	resync, settle := w.Resync, w.Settle
	if resync <= 0 {
		resync = DefaultResync
	}
	if settle <= 0 {
		settle = DefaultSettle
	}

	notify, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create the file watcher: %w", err)
	}
	defer func() { _ = notify.Close() }()

	// The directory may not exist yet: outside a pod, or before the volume
	// is mounted. The resync retries the watch; the reads in between report
	// the absence and keep the replica NotReady.
	watching := w.watch(notify)
	w.read()

	ticker := time.NewTicker(resync)
	defer ticker.Stop()
	timer := time.NewTimer(settle)
	if !timer.Stop() {
		<-timer.C
	}
	var pending <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-notify.Events:
			// One read per burst: the timer is armed by the first event and
			// not re-armed by the rest.
			if pending == nil {
				timer.Reset(settle)
				pending = timer.C
			}
		case err := <-notify.Errors:
			w.Log.Error(err, "file watcher error; the resync timer covers it")
		case <-pending:
			pending = nil
			w.read()
		case <-ticker.C:
			if !watching {
				watching = w.watch(notify)
			}
			w.read()
		}
	}
}

// watch puts the mount directory under the file watcher. It reports whether
// it could; a directory that does not exist yet cannot be watched.
func (w *Watcher) watch(notify *fsnotify.Watcher) bool {
	if err := notify.Add(w.Dir); err != nil {
		w.Log.Info("the configuration directory cannot be watched yet, reading it on the resync timer",
			"dir", w.Dir, "error", err.Error())
		return false
	}
	return true
}

// read applies or refuses the directory's current contents, once per change
// of the manifest.
func (w *Watcher) read() {
	cfg, err := Read(w.Dir)
	switch {
	case errors.Is(err, ErrAbsent):
		if w.absent {
			return
		}
		w.absent = true
		if w.Applier.Ready() {
			w.Log.Info("the configuration is gone from the mounted directory, keeping the applied snapshot", "dir", w.Dir)
		} else {
			w.Log.Info("no configuration in the mounted directory yet, the replica stays NotReady", "dir", w.Dir)
		}
		return
	case err != nil:
		w.absent = false
		var refusal *Refusal
		if !errors.As(err, &refusal) {
			w.Log.Error(err, "failed to read the configuration, keeping the applied snapshot", "dir", w.Dir)
			return
		}
		if bytes.Equal(refusal.raw, w.refused) {
			return
		}
		w.refused = refusal.raw
		w.Applier.Refuse(refusal)
		return
	}
	w.absent = false
	// The manifest already applied is applied again only to clear a refusal
	// that came between: the engines are reused by hash, and the report
	// loses the refusal.
	if bytes.Equal(cfg.Raw, w.applied) && w.refused == nil {
		return
	}
	w.applied, w.refused = cfg.Raw, nil
	w.Applier.Apply(cfg)
}
