/*
Package apitypes is used to map the common types used across the node with the format expected by the API.

This is done using different strategies:
- Marshallers: they get triggered when the API marshals the response structs into JSONs
- Scanners/Valuers: they get triggered when a struct is sent/received to/from the SQL database
- Adhoc functions: when the already mentioned strategies are not suitable, functions are added to the structs to facilitate the conversions
*/
package apitypes

import (
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/hermeznetwork/hermez-node/common"
	"github.com/hermeznetwork/tracerr"
	"github.com/iden3/go-iden3-crypto/babyjub"
)

// BigIntStr is used to scan/value *big.Int directly into strings from/to sql DBs.
// It assumes that *big.Int are inserted/fetched to/from the DB using the BigIntMeddler meddler
// defined at github.com/hermeznetwork/hermez-node/db.  Since *big.Int is
// stored as DECIMAL in SQL, there's no need to implement Scan()/Value()
// because DECIMALS are encoded/decoded as strings by the sql driver, and
// BigIntStr is already a string.
type BigIntStr string

// NewBigIntStr creates a *BigIntStr from a *big.Int.
// If the provided bigInt is nil the returned *BigIntStr will also be nil
func NewBigIntStr(bigInt *big.Int) *BigIntStr {
	if bigInt == nil {
		return nil
	}
	bigIntStr := BigIntStr(bigInt.String())
	return &bigIntStr
}

// StrBigInt is used to unmarshal BigIntStr directly into an alias of big.Int
type StrBigInt big.Int

// UnmarshalText unmarshals a StrBigInt
func (s *StrBigInt) UnmarshalText(text []byte) error {
	bi, ok := (*big.Int)(s).SetString(string(text), 10)
	if !ok {
		return tracerr.Wrap(fmt.Errorf("could not unmarshal %s into a StrBigInt", text))
	}
	*s = StrBigInt(*bi)
	return nil
}

// CollectedFeesAPI is send common.batch.CollectedFee through the API
type CollectedFeesAPI map[common.TokenID]BigIntStr

// NewCollectedFeesAPI creates a new CollectedFeesAPI from a *big.Int map
func NewCollectedFeesAPI(m map[common.TokenID]*big.Int) CollectedFeesAPI {
	c := CollectedFeesAPI(make(map[common.TokenID]BigIntStr))
	for k, v := range m {
		c[k] = *NewBigIntStr(v)
	}
	return c
}

// HezEthAddr is used to scan/value Ethereum Address directly into strings that follow the Ethereum address hez format (^hez:0x[a-fA-F0-9]{40}$) from/to sql DBs.
// It assumes that Ethereum Address are inserted/fetched to/from the DB using the default Scan/Value interface
type HezEthAddr string

// NewHezEthAddr creates a HezEthAddr from an Ethereum addr
func NewHezEthAddr(addr ethCommon.Address) HezEthAddr {
	return HezEthAddr("hez:" + addr.String())
}

// ToEthAddr returns an Ethereum Address created from HezEthAddr
func (a HezEthAddr) ToEthAddr() (ethCommon.Address, error) {
	addrStr := strings.TrimPrefix(string(a), "hez:")
	var addr ethCommon.Address
	return addr, addr.UnmarshalText([]byte(addrStr))
}

// Scan implements Scanner for database/sql
func (a *HezEthAddr) Scan(src interface{}) error {
	ethAddr := &ethCommon.Address{}
	if err := ethAddr.Scan(src); err != nil {
		return tracerr.Wrap(err)
	}
	if ethAddr == nil {
		return nil
	}
	*a = NewHezEthAddr(*ethAddr)
	return nil
}

// Value implements valuer for database/sql
func (a HezEthAddr) Value() (driver.Value, error) {
	ethAddr, err := a.ToEthAddr()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return ethAddr.Value()
}

// StrHezEthAddr is used to unmarshal HezEthAddr directly into an alias of ethCommon.Address
type StrHezEthAddr ethCommon.Address

// UnmarshalText unmarshals a StrHezEthAddr
func (s *StrHezEthAddr) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*s = StrHezEthAddr(common.EmptyAddr)
		return nil
	}
	withoutHez := strings.TrimPrefix(string(text), "hez:")
	var addr ethCommon.Address
	if err := addr.UnmarshalText([]byte(withoutHez)); err != nil {
		return tracerr.Wrap(err)
	}
	*s = StrHezEthAddr(addr)
	return nil
}

// HezBJJ is used to scan/value *babyjub.PublicKeyComp directly into strings that follow the BJJ public key hez format (^hez:[A-Za-z0-9_-]{44}$) from/to sql DBs.
// It assumes that *babyjub.PublicKeyComp are inserted/fetched to/from the DB using the default Scan/Value interface
type HezBJJ string

// NewHezBJJ creates a HezBJJ from a *babyjub.PublicKeyComp.
// Calling this method with a nil bjj causes panic
func NewHezBJJ(pkComp babyjub.PublicKeyComp) HezBJJ {
	sum := pkComp[0]
	for i := 1; i < len(pkComp); i++ {
		sum += pkComp[i]
	}
	bjjSum := append(pkComp[:], sum)
	return HezBJJ("hez:" + base64.RawURLEncoding.EncodeToString(bjjSum))
}

func hezStrToBJJ(s string) (babyjub.PublicKeyComp, error) {
	const decodedLen = 33
	const encodedLen = 44
	formatErr := errors.New("invalid BJJ format. Must follow this regex: ^hez:[A-Za-z0-9_-]{44}$")
	encoded := strings.TrimPrefix(s, "hez:")
	if len(encoded) != encodedLen {
		return common.EmptyBJJComp, formatErr
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return common.EmptyBJJComp, formatErr
	}
	if len(decoded) != decodedLen {
		return common.EmptyBJJComp, formatErr
	}
	bjjBytes := [decodedLen - 1]byte{}
	copy(bjjBytes[:decodedLen-1], decoded[:decodedLen-1])
	sum := bjjBytes[0]
	for i := 1; i < len(bjjBytes); i++ {
		sum += bjjBytes[i]
	}
	if decoded[decodedLen-1] != sum {
		return common.EmptyBJJComp, tracerr.Wrap(errors.New("checksum verification failed"))
	}
	bjjComp := babyjub.PublicKeyComp(bjjBytes)
	return bjjComp, nil
}

// ToBJJ returns a babyjub.PublicKeyComp created from HezBJJ
func (b HezBJJ) ToBJJ() (babyjub.PublicKeyComp, error) {
	return hezStrToBJJ(string(b))
}

// Scan implements Scanner for database/sql
func (b *HezBJJ) Scan(src interface{}) error {
	bjj := &babyjub.PublicKeyComp{}
	if err := bjj.Scan(src); err != nil {
		return tracerr.Wrap(err)
	}
	if bjj == nil {
		return nil
	}
	*b = NewHezBJJ(*bjj)
	return nil
}

// Value implements valuer for database/sql
func (b HezBJJ) Value() (driver.Value, error) {
	bjj, err := b.ToBJJ()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return bjj.Value()
}

// StrHezBJJ is used to unmarshal HezBJJ directly into an alias of babyjub.PublicKeyComp
type StrHezBJJ babyjub.PublicKeyComp

// UnmarshalText unmarshalls a StrHezBJJ
func (s *StrHezBJJ) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*s = StrHezBJJ(common.EmptyBJJComp)
		return nil
	}
	bjj, err := hezStrToBJJ(string(text))
	if err != nil {
		return tracerr.Wrap(err)
	}
	*s = StrHezBJJ(bjj)
	return nil
}

// HezIdx is used to value common.Idx directly into strings that follow the Idx key hez format (hez:tokenSymbol:idx) to sql DBs.
// Note that this can only be used to insert to DB since there is no way to automatically read from the DB since it needs the tokenSymbol
type HezIdx string

// StrHezIdx is used to unmarshal HezIdx directly into an alias of common.Idx
type StrHezIdx common.Idx

// UnmarshalText unmarshals a StrHezIdx
func (s *StrHezIdx) UnmarshalText(text []byte) error {
	withoutHez := strings.TrimPrefix(string(text), "hez:")
	splitted := strings.Split(withoutHez, ":")
	const expectedLen = 2
	if len(splitted) != expectedLen {
		return tracerr.Wrap(fmt.Errorf("can not unmarshal %s into StrHezIdx", text))
	}
	idxInt, err := strconv.Atoi(splitted[1])
	if err != nil {
		return tracerr.Wrap(err)
	}
	*s = StrHezIdx(common.Idx(idxInt))
	return nil
}

// EthSignature is used to scan/value []byte representing an Ethereum signature directly into strings from/to sql DBs.
type EthSignature string

// NewEthSignature creates a *EthSignature from []byte
// If the provided signature is nil the returned *EthSignature will also be nil
func NewEthSignature(signature []byte) *EthSignature {
	if signature == nil {
		return nil
	}
	ethSignature := EthSignature("0x" + hex.EncodeToString(signature))
	return &ethSignature
}

// Scan implements Scanner for database/sql
func (e *EthSignature) Scan(src interface{}) error {
	if srcStr, ok := src.(string); ok {
		// src is a string
		*e = *(NewEthSignature([]byte(srcStr)))
		return nil
	} else if srcBytes, ok := src.([]byte); ok {
		// src is []byte
		*e = *(NewEthSignature(srcBytes))
		return nil
	} else {
		// unexpected src
		return tracerr.Wrap(fmt.Errorf("can't scan %T into apitypes.EthSignature", src))
	}
}

// Value implements valuer for database/sql
func (e EthSignature) Value() (driver.Value, error) {
	without0x := strings.TrimPrefix(string(e), "0x")
	return hex.DecodeString(without0x)
}

// UnmarshalText unmarshals a StrEthSignature
func (e *EthSignature) UnmarshalText(text []byte) error {
	without0x := strings.TrimPrefix(string(text), "0x")
	signature, err := hex.DecodeString(without0x)
	if err != nil {
		return tracerr.Wrap(err)
	}
	*e = EthSignature([]byte(signature))
	return nil
}

// PoolL2Tx represents the transactions that the coordinator receive through API,
// and will get stored to the pool if validations are correct
type PoolL2Tx struct {
	// JSON fields
	TxID        common.TxID            `meddler:"tx_id"`
	FromIdx     common.Idx             `meddler:"from_idx"`
	ToIdx       *common.Idx            `meddler:"to_idx"`
	ToEthAddr   *ethCommon.Address     `meddler:"to_eth_addr"`
	ToBJJ       *babyjub.PublicKeyComp `meddler:"to_bjj"`
	TokenID     common.TokenID         `meddler:"token_id"`
	Amount      *big.Int               `meddler:"amount,bigint"`
	Fee         common.FeeSelector     `meddler:"fee"`
	Nonce       common.Nonce           `meddler:"nonce"`
	Signature   babyjub.SignatureComp  `meddler:"signature"`
	RqFromIdx   *common.Idx            `meddler:"rq_from_idx"`
	RqToIdx     *common.Idx            `meddler:"rq_to_idx"`
	RqToEthAddr *ethCommon.Address     `meddler:"rq_to_eth_addr"`
	RqToBJJ     *babyjub.PublicKeyComp `meddler:"rq_to_bjj"`
	RqTokenID   *common.TokenID        `meddler:"rq_token_id"`
	RqAmount    *big.Int               `meddler:"rq_amount,bigintnull"`
	RqFee       *common.FeeSelector    `meddler:"rq_fee"`
	RqNonce     *common.Nonce          `meddler:"rq_nonce"`
	Type        common.TxType          `meddler:"tx_type"`
	// Extra DB write fields (not included in JSON)
	AmountFloat float64              `meddler:"amount_f"`
	ClientIP    string               `meddler:"client_ip"`
	State       common.PoolL2TxState `meddler:"state"`
	// Used for JSON marshaling (not included in JSON, nor stored in DB), must be setted before marshaling
	// if sending txs to a coordinator, otherwise the format of idxs will be unexpected
	TokenSymbol   string `meddler:"-"`
	RqTokenSymbol string `meddler:"-"`
}

// NewPoolL2Tx creates a apitypes PoolL2Tx from a common PoolL2Tx.
// rqTokenSymbol is only used if commonTx.RqFromIdx != 0.
// It's safe to pass clientIP = "".
func NewPoolL2Tx(commonTx common.PoolL2Tx, tokenSymbol, rqTokenSymbol, clientIP string) (PoolL2Tx, error) {
	if tokenSymbol == "" {
		return PoolL2Tx{}, errors.New("Invalit tokenSymbol")
	}
	// Calculate AmountFloat
	f := new(big.Float).SetInt((*big.Int)(commonTx.Amount))
	amountF, _ := f.Float64()
	tx := PoolL2Tx{
		TxID:        commonTx.TxID,
		FromIdx:     commonTx.FromIdx,
		ToIdx:       &commonTx.ToIdx,
		TokenID:     commonTx.TokenID,
		Amount:      commonTx.Amount,
		Fee:         commonTx.Fee,
		Nonce:       commonTx.Nonce,
		Signature:   commonTx.Signature,
		Type:        commonTx.Type,
		AmountFloat: amountF,
		ClientIP:    clientIP,
		State:       commonTx.State,
		TokenSymbol: tokenSymbol,
	}
	// Set optional To fields
	if commonTx.ToEthAddr != common.EmptyAddr {
		tx.ToEthAddr = &commonTx.ToEthAddr
	}
	if commonTx.ToBJJ != common.EmptyBJJComp {
		tx.ToBJJ = &commonTx.ToBJJ
	}
	// Set Rq fields if RqFromIdx != 0, otherwise they're going to be nil
	if commonTx.RqFromIdx != 0 {
		if rqTokenSymbol == "" {
			return PoolL2Tx{}, errors.New("Invalit rqTokenSymbol")
		}
		tx.RqTokenSymbol = rqTokenSymbol
		// Mandatory Rq fields
		tx.RqFromIdx = &commonTx.RqFromIdx
		tx.RqAmount = commonTx.RqAmount
		tx.RqFee = &commonTx.RqFee
		tx.RqNonce = &commonTx.RqNonce
		// Set optional To fields
		tx.RqTokenID = &commonTx.RqTokenID
		if commonTx.RqToIdx != 0 {
			tx.RqToIdx = &commonTx.RqToIdx
		}
		if commonTx.RqToEthAddr != common.EmptyAddr {
			tx.RqToEthAddr = &commonTx.RqToEthAddr
		}
		if commonTx.RqToBJJ != common.EmptyBJJComp {
			tx.RqToBJJ = &commonTx.RqToBJJ
		}
	}
	return tx, nil
}

func (tx PoolL2Tx) MarshalJSON() ([]byte, error) {
	jsonFormat := struct {
		TxID        common.TxID           `json:"id" binding:"required"`
		Type        common.TxType         `json:"type" binding:"required"`
		TokenID     common.TokenID        `json:"tokenId"`
		FromIdx     string                `json:"fromAccountIndex" binding:"required"`
		ToIdx       *string               `json:"toAccountIndex"`
		ToEthAddr   *string               `json:"toHezEthereumAddress"`
		ToBJJ       *string               `json:"toBjj"`
		Amount      string                `json:"amount" binding:"required"`
		Fee         common.FeeSelector    `json:"fee"`
		Nonce       common.Nonce          `json:"nonce"`
		Signature   babyjub.SignatureComp `json:"signature" binding:"required"`
		RqFromIdx   *string               `json:"requestFromAccountIndex"`
		RqToIdx     *string               `json:"requestToAccountIndex"`
		RqToEthAddr *string               `json:"requestToHezEthereumAddress"`
		RqToBJJ     *string               `json:"requestToBjj"`
		RqTokenID   *common.TokenID       `json:"requestTokenId"`
		RqAmount    *string               `json:"requestAmount"`
		RqFee       *common.FeeSelector   `json:"requestFee"`
		RqNonce     *common.Nonce         `json:"requestNonce"`
	}{}
	// TODO: impl
	return json.Marshal(jsonFormat)
}

// UnmarshalJSON transforms marshaled json (in API expected format) into struct.
// ClientIP and State are not included as part of the json
func (tx *PoolL2Tx) UnmarshalJSON(data []byte) error {
	receivedJSON := struct {
		TxID        common.TxID           `json:"id" binding:"required"`
		Type        common.TxType         `json:"type" binding:"required"`
		TokenID     common.TokenID        `json:"tokenId"`
		FromIdx     StrHezIdx             `json:"fromAccountIndex" binding:"required"`
		ToIdx       *StrHezIdx            `json:"toAccountIndex"`
		ToEthAddr   *StrHezEthAddr        `json:"toHezEthereumAddress"`
		ToBJJ       *StrHezBJJ            `json:"toBjj"`
		Amount      StrBigInt             `json:"amount" binding:"required"`
		Fee         common.FeeSelector    `json:"fee"`
		Nonce       common.Nonce          `json:"nonce"`
		Signature   babyjub.SignatureComp `json:"signature" binding:"required"`
		RqFromIdx   *StrHezIdx            `json:"requestFromAccountIndex"`
		RqToIdx     *StrHezIdx            `json:"requestToAccountIndex"`
		RqToEthAddr *StrHezEthAddr        `json:"requestToHezEthereumAddress"`
		RqToBJJ     *StrHezBJJ            `json:"requestToBjj"`
		RqTokenID   *common.TokenID       `json:"requestTokenId"`
		RqAmount    *StrBigInt            `json:"requestAmount"`
		RqFee       *common.FeeSelector   `json:"requestFee"`
		RqNonce     *common.Nonce         `json:"requestNonce"`
	}{}
	if err := json.Unmarshal(data, &receivedJSON); err != nil {
		return err
	}
	// Calculate AmountFloat
	f := new(big.Float).SetInt((*big.Int)(&receivedJSON.Amount))
	amountF, _ := f.Float64()
	// Set values
	*tx = PoolL2Tx{
		TxID:        receivedJSON.TxID,
		FromIdx:     common.Idx(receivedJSON.FromIdx),
		ToIdx:       (*common.Idx)(receivedJSON.ToIdx),
		ToEthAddr:   (*ethCommon.Address)(receivedJSON.ToEthAddr),
		ToBJJ:       (*babyjub.PublicKeyComp)(receivedJSON.ToBJJ),
		TokenID:     receivedJSON.TokenID,
		Amount:      (*big.Int)(&receivedJSON.Amount),
		AmountFloat: amountF,
		Fee:         receivedJSON.Fee,
		Nonce:       receivedJSON.Nonce,
		Signature:   receivedJSON.Signature,
		RqFromIdx:   (*common.Idx)(receivedJSON.RqFromIdx),
		RqToIdx:     (*common.Idx)(receivedJSON.RqToIdx),
		RqToEthAddr: (*ethCommon.Address)(receivedJSON.RqToEthAddr),
		RqToBJJ:     (*babyjub.PublicKeyComp)(receivedJSON.RqToBJJ),
		RqTokenID:   receivedJSON.RqTokenID,
		RqAmount:    (*big.Int)(receivedJSON.RqAmount),
		RqFee:       receivedJSON.RqFee,
		RqNonce:     receivedJSON.RqNonce,
		Type:        receivedJSON.Type,
	}
	return nil
}
