import {ABIDecoder} from '../serializer/decoder'
import {ABIEncoder} from '../serializer/encoder'
import {ABISerializableObject} from '../serializer/serializable'

import {Base58} from '../base58'
import {arrayToHex, isInstanceOf} from '../utils'
import {emUncompress} from '../crypto/em'
import {decodeEdBase58, decodeEmPublicKey} from './em-ed-strings'

import {Bytes, KeyType} from '../'

export type PublicKeyType = PublicKey | string | {type: string; compressed: Uint8Array}

export class PublicKey implements ABISerializableObject {
    static abiName = 'public_key'

    /** Type, e.g. `K1` */
    type: KeyType
    /** Compressed public key point. */
    data: Bytes

    /** Create PublicKey object from representing types. */
    static from(value: PublicKeyType) {
        if (isInstanceOf(value, PublicKey)) {
            return value
        }
        if (typeof value === 'object' && value.type && value.compressed) {
            return new PublicKey(KeyType.from(value.type), new Bytes(value.compressed))
        }
        if (typeof value !== 'string') {
            throw new Error('Invalid public key')
        }
        if (value.startsWith('PUB_')) {
            const parts = value.split('_')
            if (parts.length !== 3) {
                throw new Error('Invalid public key string')
            }
            const type = KeyType.from(parts[1])
            if (type === KeyType.EM) {
                return new PublicKey(type, new Bytes(decodeEmPublicKey(parts[2])))
            }
            if (type === KeyType.ED) {
                return new PublicKey(type, new Bytes(decodeEdBase58(parts[2], 32)))
            }
            const size = type === KeyType.K1 || type === KeyType.R1 ? 33 : undefined
            const data = Base58.decodeRipemd160Check(parts[2], size, type)
            return new PublicKey(type, data)
        } else if (value.startsWith('EOS') || value.length >= 50) {
            // Legacy EOS key; leading zero bytes shorten the encoding, e.g. the null key
            const encoded = value.startsWith('EOS') ? value.slice(3) : value.slice(-50)
            const data = Base58.decodeRipemd160Check(encoded, 33)
            return new PublicKey(KeyType.K1, data)
        } else {
            throw new Error('Invalid public key string')
        }
    }

    /** @internal */
    static fromABI(decoder: ABIDecoder) {
        const type = KeyType.from(decoder.readByte())
        if (type == KeyType.WA) {
            const startPos = decoder.getPosition()
            decoder.advance(33) // key_data
            decoder.advance(1) // user presence
            decoder.advance(decoder.readVaruint32()) // rpid
            const len = decoder.getPosition() - startPos
            decoder.setPosition(startPos)
            const data = Bytes.from(decoder.readArray(len))
            return new PublicKey(KeyType.WA, data)
        }
        const size = type === KeyType.ED ? 32 : 33
        return new PublicKey(type, new Bytes(decoder.readArray(size)))
    }

    /** @internal */
    constructor(type: KeyType, data: Bytes) {
        this.type = type
        this.data = data
    }

    /**
     * Returns the core 33-byte compressed public key data as a Uint8Array.
     * This is suitable for cryptographic operations like verification.
     */
    getCompressedKeyBytes(): Uint8Array {
        return this.type === KeyType.WA ? this.data.array.slice(0, 33) : this.data.array
    }

    equals(other: PublicKeyType) {
        const otherKey = PublicKey.from(other)
        return this.type === otherKey.type && this.data.equals(otherKey.data)
    }

    /** Compare with another key using the ordering nodeos enforces on authority keys. */
    compare(other: PublicKeyType): number {
        const otherKey = PublicKey.from(other)
        const type = KeyType.indexFor(this.type)
        const otherType = KeyType.indexFor(otherKey.type)
        if (type !== otherType) {
            return type < otherType ? -1 : 1
        }
        if (this.type === KeyType.WA) {
            return compareWebAuthn(this.data.array, otherKey.data.array)
        }
        return compareBytes(this.data.array, otherKey.data.array)
    }

    /**
     * Return Antelope/EOSIO legacy (`EOS<base58data>`) formatted key.
     * @throws If the key type isn't `K1`
     */
    toLegacyString(prefix = 'EOS') {
        if (this.type !== KeyType.K1) {
            throw new Error('Unable to create legacy formatted string for non-K1 key')
        }
        return `${prefix}${Base58.encodeRipemd160Check(this.data)}`
    }

    /**
     * Return key in modern Antelope/EOSIO format (`PUB_<type>_<base58data>`).
     * alcor-chain keys print as the chain does: `PUB_EM_<hex of the uncompressed point>`,
     * `PUB_ED_<base58 of the key, no checksum>`.
     */
    toString() {
        if (this.type === KeyType.EM) {
            return `PUB_EM_${arrayToHex(emUncompress(this.data.array))}`
        }
        if (this.type === KeyType.ED) {
            return `PUB_ED_${Base58.encode(this.data)}`
        }
        return `PUB_${this.type}_${Base58.encodeRipemd160Check(this.data, this.type)}`
    }

    /** @internal */
    toABI(encoder: ABIEncoder) {
        encoder.writeByte(KeyType.indexFor(this.type))
        encoder.writeArray(this.data.array)
    }

    /** @internal */
    toJSON() {
        return this.toString()
    }
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
    const length = Math.min(a.length, b.length)
    for (let i = 0; i < length; i++) {
        if (a[i] !== b[i]) {
            return a[i] < b[i] ? -1 : 1
        }
    }
    if (a.length === b.length) {
        return 0
    }
    return a.length < b.length ? -1 : 1
}

function compareWebAuthn(a: Uint8Array, b: Uint8Array): number {
    // fc compares (key, user presence, rpid) as a tuple, the rpid as a string.
    const prefix = compareBytes(a.subarray(0, 34), b.subarray(0, 34))
    if (prefix !== 0) {
        return prefix
    }
    return compareBytes(readRpid(a), readRpid(b))
}

function readRpid(data: Uint8Array): Uint8Array {
    // Skip the varuint32 that length-prefixes the rpid on the wire.
    let offset = 34
    while (data[offset] & 0x80) {
        offset++
    }
    return data.subarray(offset + 1)
}
