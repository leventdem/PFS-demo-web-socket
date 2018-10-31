import Localforage from './localforage'

class MasqStore {
  constructor (params) {
    this.localforage = new Localforage()
  }
  async addDevice (device) {
    await this.localforage.setItem(device.name, device)
  }

  async getCurrentDevice () {
    const deviceList = await this.localforage.dump()
    for (let key of Object.keys(deviceList)) {
      if (deviceList[key].isCurrentDevice === true) {
        return deviceList[key]
      }
    }
  }

  async addPairedDevice (device) {
    await this.localforage.setItem(device.name, device)
  }

  async listDevices () {
    return this.localforage.dump()
  }
}

module.exports = MasqStore
