const got = require('got')
const GrantManager = require('keycloak-connect/middleware/auth-utils/grant-manager')
const KeycloakToken = require('keycloak-connect/middleware/auth-utils/token')
const apiKey = require('./apiKey')
const cache = require('./cache')
const token = require('./token')
const publicKey = require('./publicKey')
const { raiseUnauthorized, errorMessages, fakeReply, verify } = require('./utils')
const pkg = require('../package.json')

/**
 * @type {Object}
 * @private
 *
 * The plugin related options and instances.
 */
let options
let manager
let store

/**
 * @function
 * @private
 *
 * Verify the signed token offline with help of the related
 * public key or online with the Keycloak server and JWKS.
 * Both are non-live. Resolve if the verification succeeded.
 *
 * @param {string} tkn The token to be validated
 * @returns {Promise} The error-handled promise
 */
async function verifySignedJwt (tkn) {
  const kcTkn = new KeycloakToken(tkn, options.clientId)
  await manager.validateToken(kcTkn, 'Bearer')

  return tkn
}

/**
 * @function
 * @private
 *
 * Dyanmically switch between realm public keys to verify
 * the token.
 *
 * @param {string} tkn The token to be validated
 * @returns {Promise} The error-handled promise
 */
async function verifyMultiIssuerSignedJwt (tkn) {
  try {
    const kcTkn = new KeycloakToken(tkn, options.clientId)
    const realmUrl = getKeycloakIssuer(kcTkn)
    const publicKey = await getPublicKey(realmUrl)
    const manage = new GrantManager({ ...options, publicKey, realmUrl })
    await manage.validateToken(kcTkn, 'Bearer')

    return tkn
  } catch (err) {
    throw raiseUnauthorized(errorMessages.invalid, err.message)
  }
}

/**
 * @function
 * @private
 *
 * Validate the token live with help of the related
 * Keycloak server, the client identifier and its secret.
 * Resolve if the request succeeded and token is valid.
 *
 * @param {string} tkn The token to be validated
 * @returns {Promise} The error-handled promise
 *
 * @throws {Error} If token is invalid or request failed
 */
async function multiIssuerIntrospect (tkn) {
  try {
    const kcTkn = new KeycloakToken(tkn, options.clientId)
    const realmUrl = getKeycloakIssuer(kcTkn)
    const manage = new GrantManager({ ...options, realmUrl })

    const isValid = await manage.validateAccessToken(tkn)
    if (isValid === false) throw Error(errorMessages.invalid)

    return tkn
  } catch (err) {
    throw raiseUnauthorized(errorMessages.invalid, err.message)
  }
}

/**
 * @function
 * @private
 *
 * Retrieves the Keycloak issuer from token for multi issuers.
 *
 * @param {KeycloakToken} tkn
 *
 * @throws {Error} If issuer is not found in token
 */
function getKeycloakIssuer (tkn) {
  const { urls, multiRealm } = options
  const { iss } = tkn.content

  const baseUrl = multiRealm
    ? urls.find(url => iss.indexOf(url) === 0)
    : urls.find(url => iss === url)

  if (!baseUrl) {
    throw new Error('Invalid issuer')
  }

  const realm = iss.substring(iss.lastIndexOf('/') + 1, iss.length)

  return multiRealm ? `${baseUrl}/${realm}` : baseUrl
}

/**
 * @function
 * @private
 *
 * Retrieves public key and stores in cache.
 *
 * @param {String} url Keycloak realm URL
 *
 * @returns {Promise.<String>}
 */
async function getPublicKey (url) {
  let { cache: cacheOpts, retrievePublicKey, multiRealm } = options

  if (!retrievePublicKey && !multiRealm) {
    return options.publicKey
  }

  let pubKey = await cache.get(store, url)
  if (!pubKey) {
    pubKey = await publicKey.getRealmPublicKey(url)
    const expiresIn =
      cacheOpts && cacheOpts.expiresIn
        ? cacheOpts.expiresIn
        : 1 * 60 * 1000

    await cache.set(store, url, pubKey, expiresIn)
  }

  return pubKey
}

/**
 * @function
 * @private
 *
 * Validate the token live with help of the related
 * Keycloak server, the client identifier and its secret.
 * Resolve if the request succeeded and token is valid.
 *
 * @param {string} tkn The token to be validated
 * @returns {Promise} The error-handled promise
 *
 * @throws {Error} If token is invalid or request failed
 */
async function introspect (tkn) {
  try {
    const isValid = await manager.validateAccessToken(tkn)
    if (isValid === false) throw Error(errorMessages.invalid)
  } catch (err) {
    throw Error(errorMessages.invalid)
  }

  return tkn
}

/**
 * @function
 * @private
 *
 * Retrieve the Requesting Party Token from the Keycloak Server.
 *
 * @param {string} tkn The token to be used for authentication
 * @returns {Promise} The modified, non-error-handling promise
 *
 * @throws {Error} If token is invalid or request failed
 */
async function getRpt (tkn) {
  let body = {}

  try {
    ({ body } = await got.get(`${options.realmUrl}/authz/entitlement/${options.clientId}`, {
      headers: { authorization: `bearer ${tkn}` }
    }))
  } catch (err) {
    throw Error(errorMessages.rpt)
  }

  return body.rpt
}

/**
 * @function
 * @private
 *
 * Get validation strategy based on the options.
 * If `secret` is set the token gets introspected.
 * If `entitlement` is truthy it retrieves the RPT.
 * Else perform a non-live validation with public keys.
 *
 * @returns {Function} The related validation strategy
 */
function getValidateFn () {
  if (options.urls) {
    return options.secret
      ? multiIssuerIntrospect
      : verifyMultiIssuerSignedJwt
  }

  return options.secret ? introspect : options.entitlement ? getRpt : verifySignedJwt
}

/**
 * @function
 * @public
 *
 * Validate a token either with the help of Keycloak
 * or a related public key. Store the user data in
 * cache if enabled.
 *
 * @param {string} tkn The token to be validated
 * @param {Function} h The toolkit
 *
 * @throws {Boom.unauthorized} If previous validation fails
 */
async function handleKeycloakValidation (tkn, h) {
  try {
    const info = await getValidateFn()(tkn)
    let { expiresIn, credentials } = token.getData(info || tkn, options)
    const userData = { credentials }

    if (options.validate) {
      credentials = await options.validate(tkn, credentials)
    }

    await cache.set(store, tkn, userData, expiresIn)
    return h.continue(userData)
    // return h.authenticated(userData)
  } catch (err) {
    return h(raiseUnauthorized(errorMessages.invalid, err.message))
    // throw raiseUnauthorized(errorMessages.invalid, err.message)
  }
}

/**
 * @function
 * @public
 *
 * Check if token is already cached in memory.
 * If yes, return cached user data. Otherwise
 * handle validation with help of Keycloak.
 *
 * @param {string} field The authorization field, e.g. the value of `Authorization`
 * @param {Object} h The reply toolkit
 *
 * @throws {Boom.unauthorized} If header is missing or has an invalid format
 */
async function validate (field, h = (data) => data) {
  const tkn = token.create(field)
  const reply = fakeReply(h)

  if (!field) {
    return reply(raiseUnauthorized(errorMessages.missing))
    // throw raiseUnauthorized(errorMessages.missing)
  }

  if (!tkn) {
    return reply(raiseUnauthorized(errorMessages.invalid))
    // throw raiseUnauthorized(errorMessages.invalid)
  }

  const cached = await cache.get(store, tkn)
  // return cached ? reply.authenticated(cached) : handleKeycloakValidation(tkn, reply)
  return cached ? reply.continue(cached) : handleKeycloakValidation(tkn, reply)
}

/**
 * @function
 * @private
 *
 * The authentication strategy based on keycloak.
 * Expect `Authorization: bearer x.y.z` as header.
 * If the token was sent before and is still cached,
 * return the cached user data as credentials.
 *
 * @param {Hapi.Server} server The created server instance
 * @returns {Object} The authentication scheme
 */
function strategy (server) {
  return {
    authenticate (request, h) {
      return validate(request.raw.req.headers.authorization, h)
    }
  }
}

/**
 * @function
 * @public
 *
 * The authentication plugin handler.
 * Initialize memory cache, grant manager for
 * Keycloak and register Basic Auth.
 *
 * @param {Hapi.Server} server The created server instance
 * @param {Object} opts The plugin related options
 */
function register (server, opts, next) {
  options = verify(opts)
  manager = new GrantManager(options)
  store = cache.create(server, options.cache)

  apiKey.init(server, options)
  server.auth.scheme('keycloak-jwt', strategy)
  server.decorate('server', 'kjwt', { validate })

  return next()
}

module.exports = register
module.exports.attributes = {
  pkg
}

// module.exports = { register, pkg }
