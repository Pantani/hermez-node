package api

import (
	"testing"

	"github.com/hermeznetwork/hermez-node/common"
	"github.com/stretchr/testify/assert"
)

func TestPubSub(t *testing.T) {
	ps1, err := StartPubSub("1111")
	assert.NoError(t, err)
	ps2, err := StartPubSub("2222")
	assert.NoError(t, err)
	assert.NoError(t, ps1.PublishTx(common.PoolL2Tx{}))
	assert.NoError(t, ps2.PublishAccountCreationAuth(common.AccountCreationAuth{}))
}
