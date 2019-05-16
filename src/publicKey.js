const got = require('got')

/**
 * @function
 * @public
 *
 * Gets the public key for a given realm
 * * Only uses the first key provided from realm
 *
 * @param   {String} url Keycloak realm url
 * @returns {String} Public key
 * @throws  {Error}
 */
async function getRealmPublicKey (url) {
  try {
    let certs = await getRealmCerts(url)

    if (!certs.keys || certs.keys.length !== 1) {
      throw new Error('Public key failed')
    }

    const cert = certs.keys[0]
    const key = decodePublicKey(cert.n, cert.e)
    if (!key) {
      throw new Error('Public key failed')
    }

    return key
  } catch (error) {

  }
}

/**
 * @function
 * @private
 *
 * Get the realm certificates for the provided realm
 *
 * @param {String} url Keycloak realm URL
 * @returns {{
 *   keys: Array.<{
 *     alg: String
 *     e: String
 *     kid: String
 *     kty: String
 *     n: String
 *     use: String
 *   }>
 * }} Realm certificates
 */
async function getRealmCerts (url) {
  const certUrl = `${url}/protocol/openid-connect/certs`

  let body = {}
  try {
    ({ body } = await got.get(certUrl))
    body = JSON.parse(body)
  } catch (err) {
    throw Error(err)
  }

  return body
}

/**
 * @function
 * @private
 *
 * Decodes the certificate to retrieve the public key
 *
 * @param   {String} modulus
 * @param   {String} exponent
 * @returns {String} Decoded public key
 */
function decodePublicKey (modulus, exponent) {
  const BEGIN_KEY = '-----BEGIN RSA PUBLIC KEY-----\n'
  const END_KEY = '\n-----END RSA PUBLIC KEY-----\n'
  const toHex = number => {
    const str = number.toString(16)
    return str.length % 2 ? `0${str}` : str
  }
  const toLongHex = number => {
    const str = toHex(number)
    const lengthByteLength = 128 + str.length / 2
    return toHex(lengthByteLength) + str
  }
  const encodeLength = n => (n <= 127 ? toHex(n) : toLongHex(n))
  const convertToHex = str => {
    const hex = Buffer.from(str, 'base64').toString('hex')
    return hex[0] < '0' || hex[0] > '7' ? `00${hex}` : hex
  }

  const mod = convertToHex(modulus)
  const exp = convertToHex(exponent)
  const encModLen = encodeLength(mod.length / 2)
  const encExpLen = encodeLength(exp.length / 2)
  const part = [mod, exp, encModLen, encExpLen]
    .map(n => n.length / 2)
    .reduce((a, b) => a + b)
  const bufferSource = `30${encodeLength(
    part + 2
  )}02${encModLen}${mod}02${encExpLen}${exp}`
  const pubkey = Buffer.from(bufferSource, 'hex').toString('base64')
  return BEGIN_KEY + pubkey.match(/.{1,64}/g).join('\n') + END_KEY
}

module.exports = {
  getRealmPublicKey
}
