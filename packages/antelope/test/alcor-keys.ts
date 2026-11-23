import {assert} from 'chai'
import {ed25519} from '@noble/curves/ed25519.js'

import {
    Authority,
    Base58,
    Bytes,
    Checksum256,
    KeyType,
    PrivateKey,
    PublicKey,
    Serializer,
    Signature,
    SignedTransaction,
    TRANSACTION_SIGNING_PREFIX,
    Transaction,
    transactionSigningText,
} from '$lib'


import keysCorpus from './data/keys-corpus.json'

// alcor-chain EM / ED keys. Known answers are computed independently with @noble/curves 1.9.7 (what MetaMask and
// Phantom are built on); ED keys are RFC 8032 test vector 1. test/data/keys-corpus.json is the differential corpus
// the node's tests run as well (alcor-chain tools/keys-oracle), so both sides are held to the same answers.


suite('alcor-chain keys', function () {
    this.slow(500)

    test('variant indices', function () {
        assert.equal(KeyType.indexFor(KeyType.EM), 3)
        assert.equal(KeyType.indexFor(KeyType.ED), 4)
        assert.equal(KeyType.from(3), KeyType.EM)
        assert.equal(KeyType.from(4), KeyType.ED)
        assert.equal(KeyType.from('EM'), KeyType.EM)
        assert.equal(KeyType.from('ED'), KeyType.ED)
        assert.throws(() => KeyType.from(5))
    })

    // Known answers computed with @noble/curves 1.9.7: digest = sha256("alcor-chain signing message KAT v1"),
    // EM key = sha256("alcor-chain EM KAT key"); EM = EIP-191 personal_sign over the signing text (what MetaMask
    // returns for it), ED = ed25519 over the same text with the RFC 8032 test vector 1 key.
    // Do not edit the expected values.
    const katDigest = '68d9a8e9aa5e50f9f07e839afb32618d7d38ff5c5d6c1ed9b179f614cced1db7'
    const katText = 'Alcor Chain transaction\nSign only in an app you trust\n' + katDigest
    const katPvt = 'PVT_EM_0x0a6acba5937f622b064ea9858d92fee9634e8570a7c7f0e5c10ee067229ff894'
    const katPub =
        'PUB_EM_043879a3eb16db3436e268317b2b91cae78676888bc6b4fbdf869cb5571b91e72f' +
        '12131816f069b89a8ad1ad321581fcbbbb0f19cc19bebdc728d8339a81e144d0'
    const katSig =
        'SIG_EM_0x3e737208180c45e0d4c32fb845507f9afec51e65b77ad079591e490ffe3bc2f4' +
        '3862c27ba06fdd0d3b41bc74c01ea75c03d22e780532d60c4a6cf6d2d9a27bf01b'
    // RFC 8032 test vector 1: seed ‖ public key
    const rfcPvt =
        'PVT_ED_49W385L4rePHy6PAaQUovbD2aacgN4HsKXSMeUzRg4fmwXszN91JuMFrQRj3vMDpZuRF3ZknQBuRBoWQJEfXstMw'
    const rfcPub = 'PUB_ED_FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z'

    test('transaction signing text', function () {
        const digest = Checksum256.from(katDigest)
        assert.isTrue(
            digest.equals(Checksum256.hash(Bytes.from('alcor-chain signing message KAT v1', 'utf8')))
        )
        assert.equal(transactionSigningText(digest.array), katText)
        assert.equal(TRANSACTION_SIGNING_PREFIX + katDigest, katText)
    })

    test('EM MetaMask known answer', function () {
        const key = PrivateKey.from(katPvt)
        const digest = Checksum256.from(katDigest)
        assert.equal(key.type, KeyType.EM)
        assert.equal(key.toString(), katPvt)
        assert.equal(key.toPublic().toString(), katPub)
        assert.equal(key.signDigest(digest).toString(), katSig)

        // MetaMask gives no public key: it is recovered from a signature.
        const sig = Signature.from(katSig)
        assert.equal(sig.recoverDigest(digest).toString(), katPub)
        assert.isTrue(sig.verifyDigest(digest, PublicKey.from(katPub)))

        // Recovery is digest-bound.
        const wrongDigest = katDigest.slice(0, -1) + (katDigest.endsWith('7') ? '8' : '7')
        assert.notEqual(sig.recoverDigest(wrongDigest).toString(), katPub)
        assert.isFalse(sig.verifyDigest(wrongDigest, PublicKey.from(katPub)))
    })

    // A plain personal_sign over the 32 digest bytes (what a site gets by asking to sign a "nonce") is not a
    // transaction signature. Made with @noble/curves by the KAT key over sha256("alcor-chain bare digest").
    test('EM bare-digest signature is not a transaction signature', function () {
        const digest = Checksum256.from(
            'abbf7539802afb581abc1090fcfce815eb3f32d5f8e9356bf45da33a73c50840'
        )
        const bareSig =
            'SIG_EM_0xb8142c94f8fba4ef54dc705975c19fb18da1dc483596f0e23bd659957397daf8' +
            '62c151b0a953bf43d8357d098fc80e017d8bcbc02bbffe89d57584f16c357f771c'
        assert.notEqual(Signature.from(bareSig).recoverDigest(digest).toString(), katPub)
        assert.isFalse(Signature.from(bareSig).verifyDigest(digest, PublicKey.from(katPub)))
    })

    test('ED Phantom known answer', function () {
        const key = PrivateKey.from(rfcPvt)
        const sig = key.signDigest(Checksum256.from(katDigest))
        assert.equal(
            sig.data.hexString,
            'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a' +
                'fde84de10bc47b14e5ed0d058a8b430a89fb61167734e21cc992acd01545d637' +
                '7d52d5ca4abb3211f8572197ca6adbf02ef84f2e61371f2b12ab2991fbc0ee0e'
        )
    })

    test('EM compressed and uncompressed key strings', function () {
        // 3G on secp256k1
        const compressed =
            'PUB_EM_02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'
        const uncompressed =
            'PUB_EM_04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672'
        assert.isTrue(PublicKey.from(compressed).equals(uncompressed))
        assert.equal(PublicKey.from(compressed).toString(), uncompressed)
    })

    test('EM string forms', function () {
        const key = PrivateKey.generate(KeyType.EM)
        const pub = key.toPublic()
        const pubStr = pub.toString()
        assert.match(pubStr, /^PUB_EM_04[0-9a-f]{128}$/)
        assert.match(key.toString(), /^PVT_EM_0x[0-9a-f]{64}$/)
        assert.equal(PrivateKey.from(key.toString()).toString(), key.toString())
        assert.isTrue(PublicKey.from(pubStr).equals(pub))
        assert.equal(JSON.stringify(pub), JSON.stringify(pubStr))
        assert.equal(pub.data.length, 33)

        // The raw secret MetaMask exports, without 0x
        assert.equal(PrivateKey.from('PVT_EM_' + key.data.hexString).toString(), key.toString())

        // Bare x ‖ y (128 hex), with and without 0x
        const xy = pubStr.slice('PUB_EM_04'.length)
        assert.isTrue(PublicKey.from('PUB_EM_' + xy).equals(pub))
        assert.isTrue(PublicKey.from('PUB_EM_0x04' + xy).equals(pub))
    })

    // 0x02 and 0x03 prefixes are both preserved.
    test('EM compressed prefix roundtrip', function () {
        const seen = new Set<number>()
        for (let i = 0; i < 80 && seen.size < 2; i++) {
            const pub = PrivateKey.generate(KeyType.EM).toPublic()
            const prefix = pub.data.array[0]
            assert.include([0x02, 0x03], prefix)
            const parsed = PublicKey.from('PUB_EM_0x' + pub.data.hexString)
            assert.equal(parsed.data.hexString, pub.data.hexString)
            seen.add(prefix)
        }
        assert.equal(seen.size, 2)
    })

    test('EM rejects bare x', function () {
        const pub = PrivateKey.generate(KeyType.EM).toPublic()
        assert.throws(() => PublicKey.from('PUB_EM_0x' + pub.data.hexString.slice(2)))
        assert.throws(() => PublicKey.from('PUB_EM_05' + 'ab'.repeat(64)))
        assert.throws(() => PublicKey.from('PUB_EM_0x02' + '00'.repeat(32))) // x = 0 is not on the curve
    })

    test('EM sign and recover', function () {
        const digest = Checksum256.hash(Bytes.from('Test Cases', 'utf8'))
        const key = PrivateKey.generate(KeyType.EM)
        const sig = key.signDigest(digest)
        const sigStr = sig.toString()
        assert.match(sigStr, /^SIG_EM_0x[0-9a-f]{130}$/)
        assert.include([27, 28], sig.data.array[64])
        // low-s, like libsecp256k1
        assert.isBelow(sig.data.array[32], 0x80)
        assert.equal(Signature.from(sigStr).toString(), sigStr)
        assert.isTrue(sig.recoverDigest(digest).equals(key.toPublic()))
        const message = Bytes.from('Test Cases', 'utf8')
        assert.isTrue(key.signMessage(message).recoverMessage(message).equals(key.toPublic()))
        assert.throws(() => Signature.from('SIG_EM_0x' + sig.data.hexString.slice(2)))
    })

    // Authority keys sort by type index, then unsigned bytes.
    test('authority key order', function () {
        const em = (second: number) => {
            const data = new Uint8Array(33)
            data[0] = 0x02
            data[1] = second
            return PublicKey.from({type: 'EM', compressed: data})
        }
        assert.isBelow(em(0x01).compare(em(0x80)), 0)
        assert.isAbove(em(0x80).compare(em(0x01)), 0)

        const k1 = PrivateKey.generate(KeyType.K1).toPublic()
        const emKey = PrivateKey.generate(KeyType.EM).toPublic()
        const edKey = PrivateKey.generate(KeyType.ED).toPublic()
        const auth = Authority.from({
            threshold: 2,
            keys: [
                {key: edKey, weight: 1},
                {key: emKey, weight: 1},
                {key: k1, weight: 1},
            ],
        })
        assert.deepEqual(
            auth.keys.map(({key}) => key.type),
            [KeyType.K1, KeyType.EM, KeyType.ED]
        )
        const decoded = Serializer.decode({
            data: Serializer.encode({object: auth}),
            type: Authority,
        })
        assert.isTrue(decoded.equals(auth))
    })

    // RFC 8032 test vector 1
    test('ED string vectors', function () {
        const pubStr = rfcPub
        const pub = PublicKey.from(pubStr)
        assert.equal(pub.type, KeyType.ED)
        assert.equal(pub.data.length, 32)
        assert.equal(pub.toString(), pubStr)
        assert.equal(JSON.stringify(pub), JSON.stringify(pubStr))

        const pvtStr = rfcPvt
        const pvt = PrivateKey.from(pvtStr)
        assert.equal(pvt.type, KeyType.ED)
        assert.equal(pvt.data.length, 64)
        assert.equal(pvt.toString(), pvtStr)
        // libsodium secret = seed ‖ public key
        assert.equal(pvt.toPublic().data.hexString, pvt.data.hexString.slice(64))

        assert.throws(() => PublicKey.from('PUB_ED_' + Base58.encode(new Uint8Array(31).fill(1))))
        assert.throws(() => PublicKey.from('PUB_ED_' + Base58.encode(new Uint8Array(33).fill(1))))
        assert.throws(() => PrivateKey.from('PVT_ED_' + Base58.encode(new Uint8Array(32).fill(1))))
    })

    test('ED sign and recover', function () {
        const key = PrivateKey.generate(KeyType.ED)
        const pub = key.toPublic()
        assert.match(pub.toString(), /^PUB_ED_[1-9A-HJ-NP-Za-km-z]{43,44}$/)
        assert.equal(PrivateKey.from(key.toString()).toString(), key.toString())

        const digest = Checksum256.hash(Bytes.from('ed recovery payload', 'utf8'))
        const sig = key.signDigest(digest)
        assert.equal(sig.data.length, 96)
        assert.equal(sig.data.hexString.slice(0, 64), pub.data.hexString) // embedded key
        assert.match(sig.toString(), /^SIG_ED_/)
        assert.equal(Signature.from(sig.toString()).toString(), sig.toString())
        assert.isTrue(sig.recoverDigest(digest).equals(pub))
        assert.isTrue(sig.verifyDigest(digest, pub))

        // The signed payload is the alcor-chain signing text, not the bare hex nor the raw bytes.
        const detached = sig.data.array.subarray(32)
        const text = Bytes.from(transactionSigningText(digest.array), 'utf8').array
        const hexMessage = Bytes.from(digest.hexString, 'utf8').array
        assert.isTrue(ed25519.verify(detached, text, pub.data.array))
        assert.isFalse(ed25519.verify(detached, hexMessage, pub.data.array))
        assert.isFalse(ed25519.verify(detached, digest.array, pub.data.array))

        // A different digest does not recover.
        const wrong = Checksum256.hash(Bytes.from('some other payload', 'utf8'))
        assert.throws(() => sig.recoverDigest(wrong))
        assert.isFalse(sig.verifyDigest(wrong, pub))
        assert.isFalse(sig.verifyDigest(digest, PrivateKey.generate(KeyType.ED).toPublic()))
    })

    test('ED private key with a foreign public half', function () {
        const a = PrivateKey.generate(KeyType.ED)
        const b = PrivateKey.generate(KeyType.ED)
        const mixed = Base58.encode(
            Bytes.from(a.data.array.slice(0, 32)).appending(b.toPublic().data)
        )
        assert.throws(() => PrivateKey.from('PVT_ED_' + mixed).toPublic())
    })

    // Variant index first, then 33 / 32 key bytes and 65 / 96 signature bytes.
    test('binary layout', function () {
        const digest = Checksum256.hash(Bytes.from('layout', 'utf8'))
        const em = PrivateKey.generate(KeyType.EM)
        const ed = PrivateKey.generate(KeyType.ED)

        const emPub = Serializer.encode({object: em.toPublic()}).array
        const edPub = Serializer.encode({object: ed.toPublic()}).array
        assert.equal(emPub.length, 1 + 33)
        assert.equal(edPub.length, 1 + 32)
        assert.equal(emPub[0], 3)
        assert.equal(edPub[0], 4)

        const emSig = Serializer.encode({object: em.signDigest(digest)}).array
        const edSig = Serializer.encode({object: ed.signDigest(digest)}).array
        assert.equal(emSig.length, 1 + 65)
        assert.equal(edSig.length, 1 + 96)
        assert.equal(emSig[0], 3)
        assert.equal(edSig[0], 4)
        assert.deepEqual(Array.from(edSig.subarray(1, 33)), Array.from(edPub.subarray(1)))

        assert.isTrue(Serializer.decode({data: emPub, type: PublicKey}).equals(em.toPublic()))
        assert.isTrue(Serializer.decode({data: edPub, type: PublicKey}).equals(ed.toPublic()))
        assert.isTrue(
            Serializer.decode({data: emSig, type: Signature}).equals(em.signDigest(digest))
        )
        assert.isTrue(
            Serializer.decode({data: edSig, type: Signature}).equals(ed.signDigest(digest))
        )
    })

    // What SHiP and get_block hand to the indexer: signature[] mixing every type. A wrong length for any
    // one type would shift every field after it.
    test('signed transaction with K1, EM and ED signatures', function () {
        const chainId = 'aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906'
        const transaction = Transaction.from({
            expiration: '2026-11-15T00:00:00',
            ref_block_num: 1,
            ref_block_prefix: 2,
            actions: [],
        })
        const digest = transaction.signingDigest(chainId)
        // digest = sha256(chain_id ‖ packed_trx ‖ 32 zero bytes) when there is no context-free data
        const expected = Checksum256.hash(
            Bytes.from(chainId, 'hex')
                .appending(Serializer.encode({object: transaction}))
                .appending(new Uint8Array(32))
        )
        assert.isTrue(digest.equals(expected))

        const keys = [KeyType.K1, KeyType.EM, KeyType.ED].map((type) => PrivateKey.generate(type))
        const signed = SignedTransaction.from({
            ...transaction,
            signatures: keys.map((key) => key.signDigest(digest)),
            context_free_data: ['beef'],
        })
        const decoded = Serializer.decode({
            data: Serializer.encode({object: signed}),
            type: SignedTransaction,
        })
        assert.equal(decoded.context_free_data[0].hexString, 'beef')
        assert.deepEqual(
            decoded.signatures.map((sig, i) =>
                sig.recoverDigest(digest).equals(keys[i].toPublic())
            ),
            [true, true, true]
        )
        const json = JSON.parse(JSON.stringify(decoded))
        assert.match(json.signatures[1], /^SIG_EM_0x/)
        assert.match(json.signatures[2], /^SIG_ED_/)
        assert.isTrue(Serializer.objectify(decoded).signatures[2].startsWith('SIG_ED_'))
    })

    // What a wallet hands back: MetaMask a 0x hex of r ‖ s ‖ v, Phantom 64 bytes over the signing text.
    test('wallet signature formats', function () {
        const digest = Checksum256.hash(Bytes.from('wallet', 'utf8'))

        const em = PrivateKey.from(katPvt)
        const metamaskHex = '0x' + em.signDigest(digest).data.hexString
        assert.equal(
            Signature.from('SIG_EM_' + metamaskHex).toString(),
            em.signDigest(digest).toString()
        )

        const ed = PrivateKey.generate(KeyType.ED)
        const phantom = ed25519.sign(
            Bytes.from(transactionSigningText(digest.array), 'utf8').array,
            ed.data.array.subarray(0, 32)
        )
        const sig = Signature.from('SIG_ED_' + Base58.encode(ed.toPublic().data.appending(phantom)))
        assert.isTrue(sig.equals(ed.signDigest(digest)))
        assert.isTrue(sig.recoverDigest(digest).equals(ed.toPublic()))
    })

    // The differential corpus: signed as MetaMask and Phantom sign, with the edge cases the node must refuse.
    // accept = recovers exactly pub, mismatch = recovers another key, reject = throws.
    test('differential corpus', function () {
        assert.equal(keysCorpus.prefix, TRANSACTION_SIGNING_PREFIX)
        const failures: string[] = []
        for (const c of keysCorpus.cases) {
            const digest = Checksum256.from(c.digest)
            let got: string | undefined
            try {
                got = Signature.from(c.sig).recoverDigest(digest).toString()
            } catch {
                got = undefined
            }
            const pub = PublicKey.from(c.pub).toString()
            const ok =
                c.expect === 'accept'
                    ? got === pub
                    : c.expect === 'mismatch'
                    ? got !== undefined && got !== pub
                    : got === undefined
            if (!ok) failures.push(`${c.kind} ${c.case}: ${got ?? 'threw'}`)
        }
        assert.deepEqual(failures, [])
        assert.isAtLeast(keysCorpus.cases.length, 300)
    })

    test('stock key types unchanged', function () {
        const k1 = PrivateKey.from('5KQvfsPJ9YvGuVbLRLXVWPNubed6FWvV8yax6cNSJEzB4co3zFu')
        const digest = Checksum256.hash(Bytes.from('stock', 'utf8'))
        const sig = k1.signDigest(digest)
        assert.match(sig.toString(), /^SIG_K1_/)
        assert.equal(Serializer.encode({object: sig}).array.length, 66)
        assert.isTrue(sig.recoverDigest(digest).equals(k1.toPublic()))
        assert.equal(
            k1.toPublic().toLegacyString(),
            'EOS6RrvujLQN1x5Tacbep1KAk8zzKpSThAQXBCKYFfGUYeABhJRin'
        )
    })
})
