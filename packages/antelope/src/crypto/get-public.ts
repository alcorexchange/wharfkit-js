import {getCurve} from './curves'
import {edGetPublic} from './ed'

/**
 * Get public key corresponding to given private key.
 * @internal
 */
export function getPublic(privkey: Uint8Array, type: string) {
    if (type === 'ED') {
        return edGetPublic(privkey)
    }
    const curve = getCurve(type)
    return curve.getPublicKey(privkey, true)
}
