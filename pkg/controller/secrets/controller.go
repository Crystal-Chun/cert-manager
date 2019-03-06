package secrets

import (
	"context"
	"fmt"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/runtime"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	"k8s.io/client-go/tools/cache"
	"k8s.io/apimachinery/pkg/util/wait"

	corelisters "k8s.io/client-go/listers/core/v1"
	
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/scheduler"
	"github.com/jetstack/cert-manager/pkg/util"
)

type Controller struct {
	*controllerpkg.Context

	syncHandler func(ctx context.Context, key string) error

	secretLister 		corelisters.SecretLister
	certificateLister 	cmlisters.CertificateLister

	queue              workqueue.RateLimitingInterface
	scheduledWorkQueue scheduler.ScheduledWorkQueue
	workerWg           sync.WaitGroup
	syncedFuncs        []cache.InformerSynced
}

func New(ctx *controllerpkg.Context) *Controller {
	ctrl := &Controller{Context: ctx}
	ctrl.syncHandler = ctrl.processNextWorkItem
	ctrl.queue = workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), "certificates")

	// Create a scheduled work queue that calls the ctrl.queue.Add method for
	// each object in the queue. This is used to schedule re-checks of
	// Certificate resources when they get near to expiry
	ctrl.scheduledWorkQueue = scheduler.NewScheduledWorkQueue(ctrl.queue.AddRateLimited)

	certificateInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().Certificates()
	certificateInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
	ctrl.certificateLister = certificateInformer.Lister()
	ctrl.syncedFuncs = append(ctrl.syncedFuncs, certificateInformer.Informer().HasSynced)

	secretInformer := ctrl.KubeSharedInformerFactory.Core().V1().Secrets()
	secretInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
	ctrl.secretLister = secretInformer.Lister()
	ctrl.syncedFuncs = append(ctrl.syncedFuncs, secretInformer.Informer().HasSynced)

	return ctrl
}

func (c *Controller) Run(workers int, stopCh <-chan struct{}) error {
	klog.Info("Running secrets controller")
	if !cache.WaitForCacheSync(stopCh, c.syncedFuncs...) {
		return fmt.Errorf("error waiting for informer caches to sync")
	}

	for i:= 0; i < workers; i++ {
		c.workerWg.Add(1)
		go wait.Until(func() { c.worker(stopCh) }, time.Second, stopCh)
	}
	<-stopCh
	c.queue.ShutDown()
	c.workerWg.Wait()
	return nil
}

func (c *Controller) worker(stopCh <-chan struct{}) {
	defer c.workerWg.Done()
	for {
		obj, shutdown := c.queue.Get()
		if shutdown {
			break
		}
		var key string
		func() {
			defer c.queue.Done(obj)
			var ok bool
			if key, ok = obj.(string); !ok {
				return
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = util.ContextWithStopCh(ctx, stopCh)
			if err := c.syncHandler(ctx, key); err != nil {
				klog.Errorf("%s controller: Re-queuing item %q due to error processing: %s", ControllerName, key, err.Error())
				c.queue.AddRateLimited(obj)
				return
			}
			klog.Infof("%s controller: Finished processing work item %q", ControllerName, key)
			c.queue.Forget(obj)
		}()
	}
	klog.V(4).Infof("Exiting %q worker loop", ControllerName)
}

func (c *Controller) processNextWorkItem(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	klog.Info("Next work item: \nNamespace: %s, Name: %s", namespace, name)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}
	secret, err := c.secretLister.Secrets(namespace).Get(name)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			c.scheduledWorkQueue.Forget(key)
			runtime.HandleError(fmt.Errorf("secret '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	return c.Sync(ctx, secret)
}

var keyFunc = controllerpkg.KeyFunc

const (
	ControllerName = "secret"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) controllerpkg.Interface {
		return New(ctx).Run
	})
}