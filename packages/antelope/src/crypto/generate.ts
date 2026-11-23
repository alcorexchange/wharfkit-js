import {getCurve} from './curves'
import {edGenerate} from './ed'

/**
 * Generate a new private key for given type.
 * @internal
 */
export function generate(type: string) {
    if (type === 'ED') {
        return edGenerate()
    }
    const curve = getCurve(type)
    return curve.utils.randomSecretKey()
}
