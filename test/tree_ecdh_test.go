package tree_ecdh_test

import (
	"crypto/elliptic"
	"github.com/Braun-Alex/elliptic-wrapper/pkg/ec"
	"github.com/Braun-Alex/tree-ecdh/pkg/tree_ecdh"
	"math/big"
	"testing"
)

func TestKeypairGeneration(t *testing.T) {
	priv, pub, err := tree_ecdh.GenerateKeypair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	if priv.Cmp(big.NewInt(0)) == 0 {
		t.Error("Private key is zero")
	}

	curve := elliptic.P521()
	if priv.Cmp(curve.Params().N) >= 0 {
		t.Error("Private key exceeds curve order")
	}

	if !ec.IsOnCurveCheck(pub) {
		t.Error("Public key is not on curve")
	}
}

func TestKeyUniqueness(t *testing.T) {
	priv1, _, _ := tree_ecdh.GenerateKeypair()
	priv2, _, _ := tree_ecdh.GenerateKeypair()

	if priv1.Cmp(priv2) == 0 {
		t.Error("Private keys are not unique")
	}
}

func TestSharedSecret(t *testing.T) {
	alicePriv, alicePub, _ := tree_ecdh.GenerateKeypair()
	bobPriv, bobPub, _ := tree_ecdh.GenerateKeypair()

	secretAlice := tree_ecdh.GenerateSharedSecret(alicePriv, bobPub)
	secretBob := tree_ecdh.GenerateSharedSecret(bobPriv, alicePub)

	if secretAlice.Cmp(secretBob) != 0 {
		t.Error("Shared secrets mismatch")
	}
}

func TestTreeFourNodes(t *testing.T) {
	nodes := make([]*tree_ecdh.TreeNode, 4)
	for i := range nodes {
		priv, pub, _ := tree_ecdh.GenerateKeypair()
		nodes[i] = &tree_ecdh.TreeNode{PrivateKey: priv, PublicKey: pub}
	}

	secret, err := tree_ecdh.GenerateTreeKeypair(nodes)
	if err != nil {
		t.Fatal(err)
	}

	ab := tree_ecdh.GenerateSharedSecret(nodes[0].PrivateKey, nodes[1].PublicKey)
	cd := tree_ecdh.GenerateSharedSecret(nodes[2].PrivateKey, nodes[3].PublicKey)
	expected := tree_ecdh.GenerateSharedSecret(ab, ec.ScalarMult(*cd, ec.BasePointGGet()))

	if secret.Cmp(expected) != 0 {
		t.Error("Tree DH secret mismatch for 4 nodes")
	}
}

func TestTreeFiveNodes(t *testing.T) {
	nodes := make([]*tree_ecdh.TreeNode, 5)
	for i := range nodes {
		priv, pub, _ := tree_ecdh.GenerateKeypair()
		nodes[i] = &tree_ecdh.TreeNode{PrivateKey: priv, PublicKey: pub}
	}

	secret, err := tree_ecdh.GenerateTreeKeypair(nodes)
	if err != nil {
		t.Fatal(err)
	}

	ab := tree_ecdh.GenerateSharedSecret(nodes[0].PrivateKey, nodes[1].PublicKey)
	cd := tree_ecdh.GenerateSharedSecret(nodes[2].PrivateKey, nodes[3].PublicKey)
	abcd := tree_ecdh.GenerateSharedSecret(ab, ec.ScalarMult(*cd, ec.BasePointGGet()))
	expected := tree_ecdh.GenerateSharedSecret(abcd, nodes[4].PublicKey)

	if secret.Cmp(expected) != 0 {
		t.Error("Tree DH secret mismatch for 5 nodes")
	}
}

func TestTreeConsistency(t *testing.T) {
	nodes := make([]*tree_ecdh.TreeNode, 8)
	for i := range nodes {
		priv, pub, _ := tree_ecdh.GenerateKeypair()
		nodes[i] = &tree_ecdh.TreeNode{PrivateKey: priv, PublicKey: pub}
	}

	secret1, _ := tree_ecdh.GenerateTreeKeypair(nodes)
	secret2, _ := tree_ecdh.GenerateTreeKeypair(nodes)

	if secret1.Cmp(secret2) != 0 {
		t.Error("Tree DH produces different results for the same input")
	}
}

func TestSingleNodeTree(t *testing.T) {
	priv, pub, _ := tree_ecdh.GenerateKeypair()
	nodes := []*tree_ecdh.TreeNode{{PrivateKey: priv, PublicKey: pub}}

	secret, err := tree_ecdh.GenerateTreeKeypair(nodes)
	if err != nil {
		t.Fatal(err)
	}

	if priv.Cmp(secret) != 0 {
		t.Error("Single node secret mismatch")
	}
}

func TestEmptyNodeList(t *testing.T) {
	_, err := tree_ecdh.GenerateTreeKeypair([]*tree_ecdh.TreeNode{})
	if err == nil {
		t.Error("Empty node list not detected")
	}
}

func TestNodeOrderIndependence(t *testing.T) {
	nodes1 := make([]*tree_ecdh.TreeNode, 4)
	nodes2 := make([]*tree_ecdh.TreeNode, 4)
	for i := 0; i < 4; i++ {
		priv, pub, _ := tree_ecdh.GenerateKeypair()
		nodes1[i] = &tree_ecdh.TreeNode{PrivateKey: priv, PublicKey: pub}
		nodes2[3-i] = &tree_ecdh.TreeNode{PrivateKey: priv, PublicKey: pub}
	}

	secret1, _ := tree_ecdh.GenerateTreeKeypair(nodes1)
	secret2, _ := tree_ecdh.GenerateTreeKeypair(nodes2)

	if secret1.Cmp(secret2) != 0 {
		t.Error("Node order affects result unexpectedly")
	}
}
