/**
 * @function
 * @public
 *
 * Initiate a cache
 *
 * @param {Hapi.Server} server The created server instance
 * @param {Object|boolean} [opts=false] The instance its options
 * @returns {Object|false} The cache instance
 */
function create (server, opts = false) {
  return opts && server.cache(opts === true ? { segment: 'keycloakJwt' } : opts)
}

/**
 * @function
 * @public
 *
 * Get value out of cache by key.
 * Just if cache is initiated.
 *
 * @param {Object} The cache instance
 * @param {*} key The key to be searched
 * @param {Array} rest
 */
function get (cache, key, ...rest) {
  return cache ? cbToPromise(cache.get.bind(cache), ...[key].concat(rest)) : false
}

/**
 * @function
 * @public
 *
 * Set value specified by key in cache.
 * Just if cache is initiated.
 *
 * @param {Object} The cache instance
 * @param {Array} rest The arguments passed to hapi its `cache.set`
 */
async function set (cache, ...rest) {
  cache && await cbToPromise(cache.set.bind(cache), ...rest)
}

/**
 * Transforms a callback to a promise
 * @param {Function} method Callback function to transform to promise
 * @param {Array} args Arguments to pass to function
 */
async function cbToPromise(method, ...args) {
  return new Promise((resolve, reject) => {
    return method(...args, (error, result) => {
      return error ? reject(error) : resolve(result);
    });
  });
}

module.exports = {
  create,
  get,
  set
}
