package tree_ecdh

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/Braun-Alex/elliptic-wrapper/pkg/ec"
	"math/big"
)

func GenerateKeypair() (privateKey *big.Int, publicKey ec.ElCPoint, err error) {
	curve := elliptic.P521()
	params := curve.Params()
	basePointOrder := params.N

	privateKey, err = rand.Int(rand.Reader, basePointOrder)
	if err != nil {
		return nil, ec.ElCPoint{}, err
	}

	if privateKey.Sign() == 0 {
		return nil, ec.ElCPoint{}, fmt.Errorf("private key is zero")
	}

	publicKey = ec.ScalarMult(*privateKey, ec.BasePointGGet())

	if !ec.IsOnCurveCheck(publicKey) {
		return nil, ec.ElCPoint{}, fmt.Errorf("public key is not on curve")
	}

	return privateKey, publicKey, nil
}

func GenerateSharedSecret(privateKey *big.Int, publicKey ec.ElCPoint) *big.Int {
	sharedPoint := ec.ScalarMult(*privateKey, publicKey)
	return sharedPoint.X
}

type TreeNode struct {
	PrivateKey *big.Int
	PublicKey  ec.ElCPoint
}

func GenerateTreeKeypair(nodes []*TreeNode) (*big.Int, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("empty node list")
	}

	if len(nodes) == 1 {
		return nodes[0].PrivateKey, nil
	}

	var nextLevel []*TreeNode
	i := 0

	for ; i < len(nodes)-1; i += 2 {
		left := nodes[i]
		right := nodes[i+1]

		sharedSecret := GenerateSharedSecret(left.PrivateKey, right.PublicKey)
		publicKey := ec.ScalarMult(*sharedSecret, ec.BasePointGGet())

		nextLevel = append(nextLevel, &TreeNode{
			PrivateKey: sharedSecret,
			PublicKey:  publicKey,
		})
	}

	if i < len(nodes) {
		nextLevel = append(nextLevel, nodes[i])
	}

	return GenerateTreeKeypair(nextLevel)
}
