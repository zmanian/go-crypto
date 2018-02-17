package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type keyData struct {
	priv       string
	pub        string
	addr       string
	bech32addr string
	bech32pub  string
}

var secpDataTable = []keyData{
	{
		priv:       "a96e62ed3955e65be32703f12d87b6b5cf26039ecfa948dc5107a495418e5330",
		pub:        "02950e1cdfcb133d6024109fd489f734eeb4502418e538c28481f22bce276f248c",
		addr:       "1CKZ9Nx4zgds8tU7nJHotKSDr4a9bYJCa3",
		bech32addr: "csmsaddr:cklnrf3g0s4mg25tu6termrk8egltfyme4q7sg3h9myxnv",
		bech32pub:  "csmspub:ucfk4sszj58peh7tzv7kqfqsnl2gnae5a669qfqcu5uv9pyp7g4uufm0yjxqpj95k8",
	},
}

func TestPubKeySecp256k1Address(t *testing.T) {
	for _, d := range secpDataTable {
		privB, _ := hex.DecodeString(d.priv)
		pubB, _ := hex.DecodeString(d.pub)
		addrBbz, _, _ := base58.CheckDecode(d.addr)
		addrB := Address{addrBbz, ""}
		addrDecoded := Address{}
		err := addrDecoded.FromString(d.bech32addr)
		if err != nil {
			t.Fatal(err)
		}
		var priv PrivKeySecp256k1
		copy(priv[:], privB)

		pubT := priv.PubKey().(PubKeySecp256k1)
		pubDeserialized := priv.PubKey().(PubKeySecp256k1)
		err = pubDeserialized.FromString(d.bech32pub)
		if err != nil {
			t.Fatal(err)
		}

		pub := pubT.Bytes()

		addr := priv.PubKey().Address()
		assert.Equal(t, pubT.String(), d.bech32pub)
		assert.Equal(t, pubT, pubDeserialized)
		assert.Equal(t, addr.String(), d.bech32addr)
		assert.Equal(t, addr, addrDecoded)
		assert.Equal(t, pub, pubB, "Expected pub keys to match")
		assert.Equal(t, addr, addrB, "Expected addresses to match")
	}
}

func TestPubKeyInvalidDataProperReturnsEmpty(t *testing.T) {
	pk, err := PubKeyFromBytes([]byte("foo"))
	require.NotNil(t, err, "expecting a non-nil error")
	require.Nil(t, pk, "expecting an empty public key on error")
}
