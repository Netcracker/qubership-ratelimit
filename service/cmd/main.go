// The service: the data-plane half of the split. It answers ShouldRateLimit
// from the configuration the operator wrote and the kubelet mounted, serves
// the management API over the same counters, and holds no Kubernetes client:
// its pod carries no Role and no token, and what it knows of the cluster is
// a directory and the Downward API.
package main

import (
	"flag"
	"os"
	"strconv"

	_ "github.com/netcracker/qubership-core-lib-go/v3/memlimit"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"

	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/internal/process"
	"github.com/netcracker/qubership-ratelimit/service/internal/app"
	"github.com/netcracker/qubership-ratelimit/service/internal/config"
	"github.com/netcracker/qubership-ratelimit/service/internal/rls"
)

// loggerName prefixes every log line this process writes. Sub-loggers are
// derived from it, e.g. ratelimit/rls.
const loggerName = "ratelimit"

func main() {
	var options app.Options

	flag.StringVar(&options.ProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&options.MetricsAddr, "metrics-bind-address", ":8080",
		"The address the Prometheus metrics endpoint binds to. \"0\" disables it.")
	flag.StringVar(&options.RLSAddr, "rls-bind-address", ":"+strconv.Itoa(contract.GRPCPort),
		"The address the rate limit gRPC endpoint binds to.")
	flag.StringVar(&options.ManagementAddr, "management-bind-address", "0",
		"The address the management API binds to. \"0\" disables it. It must never be reachable "+
			"from the data path: these endpoints lift limits.")
	flag.StringVar(&options.ConfigDir, "config-dir", contract.MountPath,
		"The directory the configuration ConfigMap is mounted at.")
	flag.DurationVar(&options.Resync, "config-resync", config.DefaultResync,
		"How often the configuration directory is re-read without a file event.")
	flag.DurationVar(&options.DrainTimeout, "rls-drain-timeout", rls.DefaultDrainTimeout,
		"How long in-flight rate limit checks may delay shutdown.")
	flag.Parse()

	// Properties first, loggers second: LOG_LEVEL and the namespace both arrive
	// through configloader, and logging.GetLogger reads its level from it.
	configloader.InitWithSourcesArray(configloader.BasePropertySources())
	ctxmanager.Register([]ctxmanager.ContextProvider{xrequestid.XRequestIdProvider{}})

	setupLog := logging.GetLogger(loggerName)
	options.Log = process.NewLogrLogger(loggerName)
	options.Platform = setupLog
	options.Replica = process.PodName()

	namespace, err := process.Namespace()
	if err != nil {
		setupLog.Errorf("%v", err)
		os.Exit(1)
	}
	service, err := app.Build(namespace, options)
	if err != nil {
		setupLog.Errorf("service exited with an error: %v", err)
		os.Exit(1)
	}

	setupLog.Infof("starting service namespace=%v pod=%v config=%v", namespace, options.Replica, options.ConfigDir)
	if err := service.Run(process.SignalContext()); err != nil {
		setupLog.Errorf("service exited with an error: %v", err)
		os.Exit(1)
	}
}
