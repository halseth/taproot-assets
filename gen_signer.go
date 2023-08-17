package taprootassets

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/keychain"
)

// LndRpcGenSigner is an implementation of the asset.GenesisSigner interface
// backed by an active lnd node.
type LndRpcGenSigner struct {
	lnd *lndclient.LndServices
}

// NewLndRpcGenSigner returns a new gen signer instance backed by the passed
// connection to a remote lnd node.
func NewLndRpcGenSigner(lnd *lndclient.LndServices) *LndRpcGenSigner {
	return &LndRpcGenSigner{
		lnd: lnd,
	}
}

// SignGroupKey tweaks the public key identified by the passed key
// descriptor with the the first passed Genesis description, and signs
// the second passed Genesis description with the tweaked public key.
// For minting the first asset in a group, only one Genesis object is
// needed, since we tweak with and sign over the same Genesis object.
// The final tweaked public key and the signature are returned.
func (l *LndRpcGenSigner) SignGroupKey(sigHash []byte, keyDesc keychain.KeyDescriptor,
	assetID asset.ID, reveal asset.GroupKeyReveal,
) (*asset.GroupKey, error) {

	//	tweakedPubKey := txscript.ComputeTaprootOutputKey(
	//		keyDesc.PubKey, initialGen.GroupKeyTweak(),
	//	)

	// If the current genesis is not set, we are minting the first asset in
	// the group. This means that we use the same Genesis object for both
	// the key tweak and to create the asset ID we sign. If the current
	// genesis is set, the asset type of the new asset must match the type
	// of the first asset in the group.
	//id := assetID
	//	if currentGen != nil {
	//		if initialGen.Type != currentGen.Type {
	//			return nil, nil, fmt.Errorf("asset group type mismatch")
	//		}
	//
	//		id = currentGen.ID()
	//	}

	// TODO: must add extra tweak option
	sig, err := l.lnd.Signer.SignMessage(
		context.Background(), sigHash, keyDesc.KeyLocator,
		lndclient.SignSchnorr(assetID[:]),
	)
	if err != nil {
		return nil, err
	}

	schnorrSig, err := schnorr.ParseSignature(sig)
	if err != nil {
		return nil, fmt.Errorf("unable to parse schnorr sig: %w",
			err)
	}
	_ = schnorrSig

	return &asset.GroupKey{
		RawKey: keyDesc,
		//AssetID:     assetID,
		GroupPubKey: btcec.PublicKey{},
		Reveal:      reveal,
		//Sig:         *schnorrSig,
	}, nil
}

// A compile time assertion to ensure LndRpcGenSigner meets the
// asset.GenesisSigner interface.
var _ asset.GenesisSigner = (*LndRpcGenSigner)(nil)
