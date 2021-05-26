package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hermeznetwork/hermez-node/common"
	"github.com/hermeznetwork/hermez-node/log"
	"github.com/hermeznetwork/tracerr"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/p2p/discovery"
)

const (
	txTopicName     = "hez-tx"     // TODO: replace with <SC addr>-tx
	atomicTopicName = "hez-atomic" // TODO: replace with <SC addr>-atomic
	authTopicName   = "hez-auth"   // TODO: replace with <SC addr>-auth
	Libp2pAddr      = "/ip4/0.0.0.0/tcp/"
	// DiscoveryInterval is how often we re-publish our mDNS records.
	DiscoveryInterval = time.Hour // TODO: this should be configurable
	// DiscoveryServiceTag is used in our mDNS advertisements to discover other chat peers.
	DiscoveryServiceTag = "hermez-network-pubsub" // TODO: consider replacing for <SC addr> to avoid sharing connections with different nets
)

type HezPubSub struct {
	Ctx           context.Context
	pubSubService *pubsub.PubSub
	id            peer.ID
	txTopic       *pubsub.Topic
	atomicTopic   *pubsub.Topic
	authTopic     *pubsub.Topic
}

func StartPubSub(port string) (*HezPubSub, error) {
	// Start pubsub
	ctx := context.Background()
	// create a new libp2p Host that listens on a random TCP port
	h, err := libp2p.New(ctx, libp2p.ListenAddrStrings(Libp2pAddr+port))
	if err != nil {
		return nil, err
	}
	// create a new PubSub service using the GossipSub router
	pubSubService, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return nil, err
	}
	// setup discovery
	if err = setupDiscovery(ctx, h); err != nil {
		return nil, err
	}

	// id := host.Host.ID()
	hps := &HezPubSub{
		Ctx:           ctx,
		pubSubService: pubSubService,
		// id:            id,
	}

	/* TODO: consider making subscription optional, this could be used by 3rd parties interested only in publishing:
	- Separated subscribe functions (per topic) that allow custom handlers
	- Single function to cover our needs
	*/
	// Subscribe to tx topic
	txTopic, err := hps.subscribe(txTopicName, txHandler)
	if err != nil {
		return nil, err
	}
	hps.txTopic = txTopic
	// Subscribe to atomic txs topic
	atomicTopic, err := hps.subscribe(atomicTopicName, atomicHandler)
	if err != nil {
		// TODO: stop previous subscriptions
		return nil, err
	}
	hps.atomicTopic = atomicTopic
	// Subscribe to auths topic
	authTopic, err := hps.subscribe(authTopicName, authHandler)
	if err != nil {
		// TODO: stop previous subscriptions
		return nil, err
	}
	hps.authTopic = authTopic

	return hps, nil
}

func (hps *HezPubSub) subscribe(topicName string, handler func(msg *pubsub.Message)) (*pubsub.Topic, error) {
	// Joint the topic
	topic, err := hps.pubSubService.Join(topicName)
	if err != nil {
		return nil, err
	}
	// Subscribe to the topic
	subscription, err := topic.Subscribe()
	if err != nil {
		return nil, err
	}
	// Listen to messages
	go hps.subscriptionLoop(subscription, handler)
	return topic, nil
}

func txHandler(msg *pubsub.Message) {
	// TODO: forward Data to apropiate function
	log.Info("Tx received:", string(msg.Data))
}

func atomicHandler(msg *pubsub.Message) {
	// TODO: forward Data to apropiate function
	log.Info("Atomic txs received:", string(msg.Data))
}

func authHandler(msg *pubsub.Message) {
	// TODO: forward Data to apropiate function
	log.Info("Auth received:", string(msg.Data))
}

func (hps *HezPubSub) subscriptionLoop(subscription *pubsub.Subscription, handler func(msg *pubsub.Message)) {
	for {
		// TODO: break loop using context?

		// Wait for next message
		msg, err := subscription.Next(hps.Ctx)
		if err != nil {
			log.Error(tracerr.Wrap(err))
			// TODO: stop other subscription loops using context?
			return
		}

		// TODO: avoid handling messages send by self !!!

		// Handle the message
		go handler(msg)
	}
}

// discoveryNotifee gets notified when we find a new peer via mDNS discovery
// TODO: decide if we need to show logs when new peer is found
type discoveryNotifee struct {
	h host.Host
}

// HandlePeerFound connects to peers discovered via mDNS. Once they're connected,
// the PubSub system will automatically start interacting with them if they also
// support PubSub.
func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	fmt.Printf("discovered new peer %s\n", pi.ID.Pretty())
	err := n.h.Connect(context.Background(), pi)
	if err != nil {
		fmt.Printf("error connecting to peer %s: %s\n", pi.ID.Pretty(), err)
	}
}

func setupDiscovery(ctx context.Context, h host.Host) error {
	// TODO: use coordinators registered in SC instead of local peers

	// setup mDNS discovery to find local peers
	disc, err := discovery.NewMdnsService(ctx, h, DiscoveryInterval, DiscoveryServiceTag)
	if err != nil {
		return err
	}

	n := discoveryNotifee{h: h}
	disc.RegisterNotifee(&n)
	return nil
}

func (hps *HezPubSub) PublishTx(tx common.PoolL2Tx) error {
	msgBytes, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	return hps.txTopic.Publish(hps.Ctx, msgBytes)
}

func (hps *HezPubSub) PublishAtomicTxs(txs []common.PoolL2Tx) error {
	msgBytes, err := json.Marshal(txs)
	if err != nil {
		return err
	}
	return hps.atomicTopic.Publish(hps.Ctx, msgBytes)
}

func (hps *HezPubSub) PublishAccountCreationAuth(auth common.AccountCreationAuth) error {
	msgBytes, err := json.Marshal(auth)
	if err != nil {
		return err
	}
	return hps.authTopic.Publish(hps.Ctx, msgBytes)
}
