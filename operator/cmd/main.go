// The operator: the control-plane half of the split. It reconciles the
// RateLimitPolicy objects of its namespace into one ConfigMap the service
// mounts, writes the policy status, and reads the service replicas of the
// other Deployment to judge Ready. It serves no traffic and holds no counter
// store; it is the only process of the delivery with a Role.
package main

import (
	"flag"
	"fmt"
	"os"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	_ "github.com/netcracker/qubership-core-lib-go/v3/memlimit"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	ratelimitv1alpha1 "github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/internal/process"
	"github.com/netcracker/qubership-ratelimit/operator/internal/app"
)

// loggerName prefixes every log line this process writes.
const loggerName = "ratelimit-operator"

// version is stamped into the manifest as operatorVersion. The chart sets it
// through OPERATOR_VERSION, from the image tag it deploys; this value, set by
// the build through -ldflags, is the fallback, and "dev" is a local build.
// The pipeline passes no build arguments to the image, so without the
// variable every image would say "dev".
var version = "dev"

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ratelimitv1alpha1.AddToScheme(scheme))
}

func main() {
	options := app.Options{Version: operatorVersion(), LeaderElection: true}

	flag.StringVar(&options.ProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&options.MetricsAddr, "metrics-bind-address", ":8080",
		"The address the Prometheus metrics endpoint binds to. \"0\" disables it.")
	flag.StringVar(&options.Deployment, "deployment", "",
		"The operator's own Deployment, which owns the configuration ConfigMap so that it goes with the "+
			"operator. Defaults to microservice.name.")
	flag.Parse()

	configloader.InitWithSourcesArray(configloader.BasePropertySources())
	ctxmanager.Register([]ctxmanager.ContextProvider{xrequestid.XRequestIdProvider{}})

	setupLog := logging.GetLogger(loggerName)
	logrLogger := process.NewLogrLogger(loggerName)
	ctrl.SetLogger(logrLogger)
	klog.SetLogger(logrLogger)
	options.Log = logrLogger
	options.Warn = setupLog.Warnf

	if options.Deployment == "" {
		options.Deployment = configloader.GetOrDefaultString("microservice.name", app.ManagedBy)
	}

	namespace, err := process.Namespace()
	if err != nil {
		setupLog.Errorf("%v", err)
		os.Exit(1)
	}
	mgr, err := app.Build(ctrl.GetConfigOrDie(), scheme, namespace, options)
	if err != nil {
		setupLog.Errorf("operator exited with an error: %v", err)
		os.Exit(1)
	}

	setupLog.Infof("starting operator namespace=%v deployment=%v leaderIdentity=%v version=%v",
		namespace, options.Deployment, process.PodName(), options.Version)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Errorf("%v", fmt.Errorf("run manager: %w", err))
		os.Exit(1)
	}
}

// operatorVersion is OPERATOR_VERSION when set, else the build's own stamp.
func operatorVersion() string {
	if v := os.Getenv("OPERATOR_VERSION"); v != "" {
		return v
	}
	return version
}
