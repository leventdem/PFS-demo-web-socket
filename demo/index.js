
let userDB = {}

function clear () {
  userDB = {}
  return Promise.resolve()
}
function storage () {
  return userDB
}
function config (conf) {
  return Promise.resolve(true)
}
function keys () {
  return Promise.resolve(Object.keys(userDB))
}
function setItem (key, value) {
  userDB[key] = value
  return Promise.resolve(value)
}
function removeItem (key) {
  delete userDB[key]
  return Promise.resolve()
}
function getItem (key) {
  if (userDB[key]) {
    return Promise.resolve(userDB[key])
  }
  return Promise.resolve(null)
}

const debug = false
var log = (...args) => {
  const reg = (all, cur) => {
    if (typeof (cur) === 'string') {
      return all + cur
    } else {
      return all + cur.toString()
    }
  }
  if (debug) {
    console.log('[Masq sync]', args.reduce(reg, ''))
  }
}

/**
 * Print error messages
 *
 * @param {Error} err Error message
 */
const logFail = (err) => {
  console.log(err)
}

/*
 * User interface :
 * Event and button : only for demo purpose
 */

document.addEventListener('DOMContentLoaded', function () {
  var el = document.getElementById('exchangeRSAKey')
  if (el) {
    el.addEventListener('click', function (e) {
      exchangeRSAKey()
    })
  }
  el = document.getElementById('init')
  if (el) {
    el.addEventListener('click', function (e) {
      init()
    })
  }

  el = document.getElementById('start_ecdh')
  if (el) {
    el.addEventListener('click', function (e) {
      startECDH()
    })
  }
})

const peer = {
  hostname: 'localhost',
  port: 9009
}

let c1 = null
let RSAExchangedDone = false

const generateRSAKeys = async () => {
  const cipherRSA = new MasqCrypto.RSA({})
  const c1RSAKeys = await cipherRSA.genRSAKeyPair(1024)
  const rawKey = await cipherRSA.exportRSAPubKey()
  await setItem('username', peer.id)
  await setItem(peer.id, {
    RSA: {
      publicKey: c1RSAKeys.publicKey,
      privateKey: c1RSAKeys.privateKey,
      publicKeyRaw: rawKey
    }
  })
}

const init = async () => {
  var value = document.querySelector('input[name="user"]:checked').value
  peer.id = value
  peer.id2 = peer.id === 'alice' ? 'bob' : 'alice'
  console.log('Generation of RSA keys,', peer.id)

  await generateRSAKeys()
  let res = await getItem(peer.id)
  const masqStore = {
  }
  masqStore.getCurrentDevice = () => {
    return res.RSA
  }
  masqStore.addPairedDevice = async (device) => {
    const peer2 = peer.id === 'alice' ? 'bob' : 'alice'
    await setItem(peer2, device)
  }
  masqStore.listDevices = async () => {
    const pairedDevice = await getItem(peer.id2)
    let ret = {}
    ret[peer.id2] = pairedDevice
    return ret
  }
  peer.masqStore = masqStore
  c1 = new MasqSync.Client(peer)
  await c1.init()
  c1.on('initECDH', (key) => {
    let el = document.getElementById('ECDHStep1')
    el.innerHTML = `Common secret key derived : messages are now en/decrypted with ${MasqCrypto.utils.bufferToHexString(key.key)}`

    if (peer.id === 'alice') {
      let params = {
        to: peer.id2,
        groupkey: '1314b211a1b211a1b211a1b211a1b2a2'
      }
      let el = document.getElementById('ECDHStep2')
      el.innerHTML = `${peer.id} sends : ${params.groupkey}`
      c1.sendChannelKey(params)
    }
  })
  c1.on('RSAPublicKey', async (key) => {
    let el = document.getElementById('RSAExchangeDone')
    el.innerHTML = `Received RSA public key of ${key.from}`
  })
  c1.on('channelKey', async (key) => {
    let el = document.getElementById('ECDHStep2')
    el.innerHTML = `Received group key from ${key.from} : ${key.key}`
  })
  if (peer.id === 'bob') {
    console.log('Bob saves the symmetric key')
    c1.saveRSAExchangeEncKey('11a1b211a1b211a1b211a1b211a1b2a2')
  }
  let el = document.getElementById('validation')
  el.innerHTML = `RSA keys generated for ${peer.id}`
}

/**
 * We exchange the RSA keys :
 * THe reveived key is stored as :
 * peerName : {
 * name : 'deviceName',
 * RSAPublicKey : {},
 * isSynched : boolean
 * }
 */
const exchangeRSAKey = async () => {
  if (peer.id === 'bob') {
    console.log('Error : please the initior of exchange key and ECDHE is Alice !')
    let el = document.getElementById('RSAExchangeDone')
    el.innerHTML = `Error : please the initior of exchange key and ECDHE is Alice, not Bob ! Retry with Alice`
    return
  }
  const peer2 = peer.id2
  await c1.subscribePeer(peer2)

  let p1 = await getItem(peer.id)
  let options = {
    to: peer2,
    symmetricKey: '11a1b211a1b211a1b211a1b211a1b2a2',
    publicKey: p1.RSA.publicKeyRaw,
    ack: false
  }
  c1.sendRSAPublicKey(options)
  RSAExchangedDone = true
}

const startECDH = async () => {
  if (peer.id === 'bob') {
    console.log('Error : please the initior of exchange key and ECDHE is Alice !')
    let el = document.getElementById('ECDHStep1')
    el.innerHTML = `Error : please the initior of exchange key and ECDHE is Alice, not Bob ! Retry with Alice`
    return
  }
  if (RSAExchangedDone === false) {
    console.log('error RSAExchangedDone')

    let el = document.getElementById('ECDHStep1')
    el.innerHTML = `Error : please exchange the public RSA keys before starting ECDHE! `
    return
  }
  let params = {
    from: peer.id,
    to: peer.id2,
    ack: false
  }
  c1.sendECPublicKey(params)
}
