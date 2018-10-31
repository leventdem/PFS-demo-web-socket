import socketClusterServer from 'socketcluster-server'
import MasqSync from '../src/index'
import common from 'masq-common'
import MasqStore from './masq-store'
jest.mock('masq-crypto')

const OPTIONS = {
  hostname: 'localhost',
  port: 9009
}

let server
const nrPeers = 3

// Those errors must be added into masq-common
let newErrors = {
  CHANNELNOTSUBSCRIBED: 'The channel is not subscribed',
  NOCOMMONKEY: 'The ECDH common key does not exist',
  NOECPRIVATEKEY: 'The EC private key does not exist',
  NORSAPUBLICKEYSTORED: 'The sender RSA public key does not exist',
  VERIFICATIONFAILED: 'The received EC public key verification failed, check the registered sender RSA public key',
  RSAEXCHANGEENCKEY: 'The ephemeral AES encryption key used to encrypt RSA public keys during pairing operation is not known'
}
let ERRORS = { ...common.ERRORS, ...newErrors }

// Start WebSocket server
beforeAll((done) => {
  server = socketClusterServer.listen(OPTIONS.port)
  server.on('closure', () => {})
  server.on('disconnection', () => {})
  server.once('ready', () => {
    done()
  })
})

// Close sockets & WebSocket server after all tests end
afterAll(() => {
  server.close()
})

describe('Bootstrapping tests', () => {
  it('should have connected the server', () => {
    expect(server.isReady).toBeTruthy()
  })
})

describe('Client should fail to init', async () => {
  it('when the provided server is not reachable', async () => {
    const opts = { hostname: 'localhost', port: 9999 }
    const client = new MasqSync.Client(opts)
    await expect(client.init()).rejects.toBeDefined()
  })
})

describe('Initial key exchange', () => {
  let c1 = null
  beforeAll(async (done) => {
    const peer1 = {
      hostname: 'localhost',
      port: 9009,
      id: 'peer01'
    }
    c1 = new MasqSync.Client(peer1)
    await c1.init()
    done()
  })
  it('should fail to send message : not subscription to the other peer', async () => {
    expect.assertions(1)
    const channel = 'peer2channel'
    try {
      c1.sendMessage(channel, {})
    } catch (error) {
      expect(error.name).toBe(ERRORS.CHANNELNOTSUBSCRIBED)
    }
  })

  it('Should fail during RSA public key sent : c1 generates RSAExchangeEncKey but does not call saveRSAExchangeEncKey', async () => {
    expect.assertions(1)
    /**
     * We suppose :
     * The pairing function is called in c2, a RSAExchangeEncKey is generated.
     * C1 receives the RSAExchangeEncKey
     * c1 calls sendRSAPublicKey
     * c2 does not receive the symmetric key (as expected)
     * c2 must have stored the symmetric key by calling saveRSAExchangeEncKey
     */

    try {
      let resp = {}
      await c1.sendRSAPublicKey(resp)
    } catch (error) {
      expect(error.name).toBe(ERRORS.RSAEXCHANGEENCKEY)
    }
  })

  it('2 clients should succesfully exchange their public keys : c1 initiates the exchange', async (done) => {
    expect.assertions(5)
    const peer1 = {
      hostname: 'localhost',
      port: 9009,
      id: 'peer001'
    }
    const device1 = {
      name: peer1.id,
      publicKey: 'publicKey',
      publicKeyRaw: 'RSAPublicKeyRaw',
      isCurrentDevice: true
    }
    const peer2 = {
      hostname: 'localhost',
      port: 9009,
      id: 'peer002'
    }
    const device2 = {
      name: peer2.id,
      publicKey: 'publicKey',
      publicKeyRaw: 'RSAPublicKeyRaw',
      isCurrentDevice: true
    }

    const masq1 = new MasqStore()
    await masq1.addDevice(device1)
    let params1 = { ...peer1, masqStore: masq1 }
    const cl1 = new MasqSync.Client(params1)
    const masq2 = new MasqStore()
    await masq2.addDevice(device2)
    let params2 = { ...peer2, masqStore: masq2 }
    const cl2 = new MasqSync.Client(params2)

    await Promise.all([
      cl1.init(),
      cl2.init()
    ])
    await cl1.subscribePeer(peer2.id)
    cl1.on('RSAPublicKey', key => {
      expect(key.from).toBe(peer2.id)
      expect(key.key).toBe('"RSAPublicKeyRaw"')
      done()
    })
    cl2.on('RSAPublicKey', key => {
      expect(key.from).toBe(peer1.id)
      expect(key.key).toBe('"RSAPublicKeyRaw"')
    })
    let options = {
      to: peer2.id,
      symmetricKey: '11a1b211a1b211a1b211a1b211a1b2a2',
      ack: false
    }
    cl2.saveRSAExchangeEncKey(options.symmetricKey)
    expect(cl2.RSAExchangeEncKey).toEqual(Uint8Array.from([17, 161, 178, 17, 161, 178, 17, 161, 178, 17, 161, 178, 17, 161, 178, 162]))
    cl1.sendRSAPublicKey(options)
  })
})

describe('ECDHE', () => {
  it('Should fail to send group key : no common derived secret key', async () => {
    expect.assertions(1)
    const c = new MasqSync.Client()
    try {
      await c.sendChannelKey({})
    } catch (error) {
      expect(error.name).toBe(ERRORS.NOCOMMONKEY)
    }
  })
  it('2 clients should derive a common secret : c1 initiates the exchange', async (done) => {
    const peer1 = {
      hostname: 'localhost',
      port: 9009,
      id: 'peer1'
    }
    const device1 = {
      name: peer1.id,
      publicKey: 'publicKey',
      publicKeyRaw: 'RSAPublicKeyRaw',
      isCurrentDevice: true
    }
    const peer2 = {
      hostname: 'localhost',
      port: 9009,
      id: 'peer02'
    }
    const device2 = {
      name: peer2.id,
      publicKey: 'publicKey',
      publicKeyRaw: 'RSAPublicKeyRaw',
      isCurrentDevice: true
    }

    const masq1 = new MasqStore()
    await masq1.addDevice(device1)
    let params1 = { ...peer1, masqStore: masq1 }
    const c01 = new MasqSync.Client(params1)
    const masq2 = new MasqStore()
    await masq2.addDevice(device2)
    let params2 = { ...peer2, masqStore: masq2 }
    const c02 = new MasqSync.Client(params2)

    await Promise.all([
      c01.init(),
      c02.init()
    ])
    await c01.subscribePeer(peer2.id)

    let options = {
      to: peer2.id,
      symmetricKey: '11a1b211a1b211a1b211a1b211a1b2a2',
      ack: false
    }
    c02.saveRSAExchangeEncKey(options.symmetricKey)
    expect(c02.RSAExchangeEncKey).toEqual(Uint8Array.from([17, 161, 178, 17, 161, 178, 17, 161, 178, 17, 161, 178, 17, 161, 178, 162]))
    c01.sendRSAPublicKey(options)

    await new Promise(resolve => setTimeout(resolve, 300))

    c01.on('initECDH', (key) => {
      expect(key.from).toBe(peer2.id)
      expect(key.key).toEqual(Uint8Array.from([17, 161, 178, 17, 161, 178, 17, 161, 178, 17, 161, 178, 17, 161, 178, 162]))

      // TODO : destroy
      let params = {
        to: peer2.id,
        groupkey: '1314b211a1b211a1b211a1b211a1b2a2'
      }
      c01.sendChannelKey(params)
    })
    c02.on('initECDH', (key) => {
      expect(key.from).toBe(peer1.id)
      expect(key.key).toEqual(Uint8Array.from([17, 161, 178, 17, 161, 178, 17, 161, 178, 17, 161, 178, 17, 161, 178, 162]))
    })
    c02.on('channelKey', (key) => {
      expect(key.from).toBe(peer1.id)
      expect(key.key).toBe('1314b211a1b211a1b211a1b211a1b2a2')
      expect.assertions(7)
      done()
    })
    let params = {
      from: peer1.id,
      to: peer2.id,
      ack: false
    }
    c01.sendECPublicKey(params)
  })
})

describe('Peers', () => {
  let clients = []
  let peers = {}

  beforeAll((done) => {
    for (let i = 0; i < nrPeers; i++) {
      clients.push(new MasqSync.Client(OPTIONS))
    }
    // each peer has a list of IDs of other peers
    let pending = []
    clients.forEach((client) => {
      peers[client.ID] = clients.map(peer => peer.ID).filter((peer) => peer !== client.ID)
      const prom = client.init()
      pending.push(prom)
    })
    Promise.all(pending).then(() => {
      done()
    })
  })

  // Close clients & server after all tests end
  // afterAll(() => {
  //   clients.forEeach((client) => client.destroy())
  // })

  it('should be able to elect a master peer', () => {
    const ids = clients.map(client => client.ID)

    let master = clients[1].electMaster(ids)
    expect(master).toEqual(ids.sort()[0])

    master = clients[1].electMaster()
    expect(master).toEqual(clients[1].ID)
  })

  it('should not subscribe to an invalid peer', async () => {
    const badValues = [ [], '', null, undefined ]
    badValues.forEach(async (val) => {
      await expect(clients[0].subscribePeer(val)).rejects.toBeDefined()
    })
  })

  it('should not subscribe to an empty list of peers', async () => {
    await clients[0].subscribePeers()
    expect(Object.keys(clients[0].channels).length).toEqual(0)
  })

  it('should subscribe to other peers', async () => {
    clients.forEach(async (client) => {
      await client.subscribePeers(peers[client.ID])
      expect(Object.keys(client.channels).length).toEqual(nrPeers - 1)

      peers[client.ID].forEach((peer) => {
        expect(client.channels[peer]).not.toBeUndefined()
        expect(client.channels[peer].socket.state).toEqual(client.channels[peer].socket.SUBSCRIBED)
      })
    })
  })

  it('should subscribe to new peers on pings', async () => {
    const client = new MasqSync.Client(OPTIONS)
    await client.init()
    await client.subscribePeer(clients[0].ID)

    expect(Object.keys(client.channels).length).toEqual(1)

    // wait a bit for the other clients to sub
    await new Promise(resolve => setTimeout(resolve, 100))

    // check that the new client ID is listed in the previous ones
    expect(Object.keys(clients[0].channels).length).toEqual(3)
    expect(Object.keys(clients[0].channels)).toContain(client.ID)
    // clean2up
    await clients[0].unsubscribePeer(client.ID)
  })

  it('should unsubscribe peer on demand', async () => {
    const ID = 'foo'

    await clients[0].subscribePeer(ID)
    expect(Object.keys(clients[0].channels)).toContain(ID)
    expect(Object.keys(clients[0].channels).length).toEqual(3)

    await clients[0].unsubscribePeer(ID)
    expect(Object.keys(clients[0].channels).length).toEqual(2)
    expect(Object.keys(clients[0].channels)).not.toContain(ID)
  })

  it('should fail to unsubscribe bad peers', async () => {
    const badValues = [ 'foo', '', null, undefined ]
    badValues.forEach(async (val) => {
      await expect(clients[0].unsubscribePeer(val)).rejects.toBeDefined()
      expect(Object.keys(clients[0].channels).length).toEqual(2)
    })
  })
})
