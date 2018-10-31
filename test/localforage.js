class localforage {
  constructor (params = {}) {
    this.userDB = params.db || {}
  }
  async clear () {
    this.userDB = {}
    return Promise.resolve()
  }
  async keys () {
    return Promise.resolve(Object.keys(this.userDB))
  }
  async setItem (key, value) {
    this.userDB[key] = value
    return Promise.resolve(value)
  }
  async getItem (key) {
    if (this.userDB[key]) {
      return Promise.resolve(this.userDB[key])
    }
    return Promise.resolve(null)
  }
  async dump () {
    return Promise.resolve(this.userDB)
  }
}

module.exports = localforage
