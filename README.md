# 🌳 Tree ECDH 🔐

## 🚀 Introduction

Tree ECDH (Tree Diffie-Hellman on Elliptic Curves) is an efficient key exchange protocol designed for secure group communication. It extends the classical Diffie-Hellman algorithm by introducing a hierarchical key structure, significantly reducing computational complexity from **O(N²)** to **O(N log N)**. This implementation leverages elliptic curve cryptography (ECC) for enhanced security and efficiency.

## 🎯 Features

- ✅ **Efficient group key exchange**. Uses a tree-based structure to reduce computational complexity.
- 🔐 **Elliptic curve cryptography**. Implements ECDH on the **P-521** curve for enhanced security.
- 🌲 **Hierarchical key management**. Supports scalable and efficient key computation for large groups.
- 🛠️ **Unit-tested implementation**. Ensures correctness and reliability.

## 🌳 Tree Diffie-Hellman algorithm

1. 🌲 Arrange nodes in a **binary tree** structure.
2. 🔄 Recursively compute shared secrets between pairs of nodes.
3. 🔑 Generate an intermediate public key for each pair.
4. 🎯 Continue the process until a **single root key** is obtained.

## 📝 Usage

To generate a key pair:

```go
privateKey, publicKey, err := tree_ecdh.GenerateKeypair()
```

To compute a shared secret between two nodes:

```go
sharedSecret := tree_ecdh.GenerateSharedSecret(privateKeyA, publicKeyB)
```

To compute a group key for multiple nodes:

```go
groupSecret, err := tree_ecdh.GenerateTreeKeypair(nodes)
```

## 📜 License

This project is licensed under the MIT License. See LICENSE for details.
