/* eslint-disable no-unused-vars */
import fs from 'fs'
import jwt from 'jsonwebtoken'
import { SerialPort } from 'serialport'
import { generateKeyPair } from 'crypto'
import { TypedEmitter } from 'tiny-typed-emitter'
import { ReadlineParser } from '@serialport/parser-readline'
import { InterByteTimeoutParser } from '@serialport/parser-inter-byte-timeout'

import { delay, randomInterval } from './utils'

const MILLISECOND = 1
const SECOND = MILLISECOND * 1000
const MINUTE = SECOND * 60
const HOUR = MINUTE * 60
const SIMPLE_WAIT_TIME = randomInterval(10 * MILLISECOND, 50 * MILLISECOND)
const LONG_WAIT_TIME = randomInterval(15 * SECOND, 30 * SECOND)

export enum SignalQualityRating {
  NONE,
  POOR,
  OK,
  GOOD,
  EXCELLENT,
  RANDOM
}

export enum SignalQuality {
  NONE = 0,
  ONE = 1,
  TWO = 2,
  THREE = 3,
  FOUR = 4,
  FIVE = 5
}

// snake case to match rock7 service provider
export type SBDMessage = {
  momsn: number
  data: string
  serial: number
  'iridium_latitude': number
  'iridium_longitude': number
  'iridium_cep': number
  imei: string
  'device_type': string
  'transmit_time': string
  JWT: string
}

export type JWTSignerDetails = {
  publicKey: string
  privateKey: string
  passphrase: string
}

export enum LogLevel {
  DEBUG = 'DEBUG',
  INFO = 'INFO',
  WARN = 'WARN',
  ERROR = 'ERROR',
  CRITICAL = 'CRITICAL'
}

export type LogEvent = {
  level: LogLevel
  message: string
  datetime: Date
  timeSinceLast: string
}

export interface IridiumEmulatorInterface {
  'log': (event: LogEvent) => void
  'sbd-message': (message: SBDMessage) => void
  'signer-key-generated': (details: JWTSignerDetails) => void
}

export class IridiumEmulator extends TypedEmitter<IridiumEmulatorInterface> {
  /** The virtual serial port connection */
  #port: SerialPort

  get port () {
    return this.#port
  }

  /** Indicates if the inbound command should be echo'd back on the port */
  #echoEnabled = true

  get echoEnabled () {
    return this.#echoEnabled
  }

  /** Indicates if ring alerts is enabled on the emulator */
  #ringAlertsEnabled = false

  get ringAlertsEnabled () {
    return this.#ringAlertsEnabled
  }

  /** The quality of signal the emulator should mock */
  #signalQualityRating: SignalQualityRating = SignalQualityRating.OK

  get signalQualityRating () {
    return this.#signalQualityRating
  }

  /** The current signal quality of the emulator */
  #currentSignalQuality: SignalQuality = SignalQuality.ONE

  get currentSignalQuality () {
    return this.#currentSignalQuality
  }

  /** Indicates if signal quality indicator is enabled on the emulator */
  #signalQualityIndicator = false

  get signalQualityIndicator () {
    return this.#signalQualityIndicator
  }

  /** Indicates if the service availability indicator is enabled on the emulator */
  #serviceAvailabilityIndicator = false

  get serviceAvailabilityIndicator () {
    return this.#serviceAvailabilityIndicator
  }

  /** The current buffer for Mobile Orientated (MO) messages */
  #moBuffer: Buffer

  get moBuffer () {
    return this.#moBuffer
  }

  /* The sequence number for Mobile Orientated (MO) messages */
  #moSequenceNo = 0

  get moSequenceNo () {
    return this.#moSequenceNo
  }

  /** The current buffer for Mobile Terminated (MT) messages */
  #mtBuffer: string

  get mtBuffer () {
    return this.#mtBuffer
  }

  /* The sequence number for Mobile Terminated (MT) messages */
  #mtSequenceNo = 0

  get mtSequenceNo () {
    return this.#mtSequenceNo
  }

  /** Indicates that incoming data is expected to be binary and appended to buffer */
  #binaryMode = false

  get binaryMode () {
    return this.#binaryMode
  }

  /** Buffer containing the inbound binary data */
  #binaryBuffer: Buffer | null

  get binaryBuffer () {
    return this.#binaryBuffer
  }

  /** The expected length of the inbound binary data */
  #binaryBufferLength: number

  get binaryBufferLength () {
    return this.#binaryBufferLength
  }

  /** Timeout function to invoke when binary data is not received */
  #binaryBufferTimeout: NodeJS.Timeout | null

  get binaryBufferTimeout () {
    return this.#binaryBufferTimeout
  }

  /** The JWT signer key which is used to sign outbound messages */
  #jwtSignerKey: string

  /** The passphrase required to unencrypt the jwtSignerKey */
  #jwtSignerKeyPassphrase: string

  /** Serial port parser to read input based on new line delimeter */
  #readlineParser: ReadlineParser

  /** Serial port parser to read input based on binary */
  #binaryParser: InterByteTimeoutParser

  constructor ({
    portPath,
    baudRate = 19200,
    signalQualityRating = SignalQualityRating.OK,
    jwtSignerKey,
    jwtSignerKeyPassphrase
  }: {
    portPath: string,
    baudRate?: number,
    signalQualityRating: SignalQualityRating,
    jwtSignerKey?: string,
    jwtSignerKeyPassphrase?: string
  }) {
    super()

    this.#port = new SerialPort({
      path: portPath,
      baudRate: baudRate
    })

    this.#port.on('open', () => {
      this.#logger.info('Serial port open')
    })

    this.#readlineParser = new ReadlineParser({ delimiter: '\r\n' })
    this.#readlineParser.on('data', async (data: string) => {
      await this.#handleData(data)
    })

    this.#binaryParser = new InterByteTimeoutParser({ interval: 30 })
    this.#binaryParser.on('data', async (data) => {
      await this.#handleData(data)
    })

    this.#port.pipe(this.#readlineParser)

    this.#moBuffer = Buffer.alloc(340)
    this.#mtBuffer = '' // TODO: COnvert to buffer
    this.#binaryBuffer = null
    this.#binaryBufferLength = 0
    this.#binaryBufferTimeout = null

    if (jwtSignerKey) {
      this.#jwtSignerKey = fs.readFileSync(jwtSignerKey).toString()

      if (jwtSignerKeyPassphrase) this.#jwtSignerKeyPassphrase = jwtSignerKeyPassphrase
    } else {
      // no key provided, generate a public/private key pair with random password
      const passphrase = Math.random().toString(36).slice(-8)

      generateKeyPair('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
          cipher: 'aes-256-cbc',
          passphrase
        }
      }, (error, publicKey, privateKey) => {
        if (error) throw error

        this.#jwtSignerKey = privateKey
        this.#jwtSignerKeyPassphrase = passphrase

        // notify the new public/private key pair
        this.emit('signer-key-generated', {
          publicKey,
          privateKey,
          passphrase
        })
      })
    }

    this.#signalQualityRating = signalQualityRating
    this.#updateSignalQuality()
  }

  #logger = {
    lastLogDateTime: new Date(),
    debug: (message: string) => this.#logger.log(LogLevel.DEBUG, message),
    info: (message: string) => this.#logger.log(LogLevel.INFO, message),
    warn: (message: string) => this.#logger.log(LogLevel.WARN, message),
    error: (message: string) => this.#logger.log(LogLevel.ERROR, message),
    critical: (message: string) => this.#logger.log(LogLevel.CRITICAL, message),
    log: (level: LogLevel, message: string) => {
      const datetime = new Date()

      const difference = new Date().getTime() - this.#logger.lastLogDateTime.getTime()
      let timeSinceLast

      if (difference > HOUR) {
        timeSinceLast = Math.round(difference / HOUR) + 'h'
      } if (difference > MINUTE) {
        timeSinceLast = Math.round(difference / MINUTE) + 'm'
      } else if (difference > SECOND) {
        timeSinceLast = Math.round(difference / SECOND) + 's'
      } else {
        timeSinceLast = difference + 'ms'
      }

      this.emit('log', { level, datetime, message, timeSinceLast })

      this.#logger.lastLogDateTime = datetime
    }
  }

  #write (data: string): void {
    this.#logger.info(`>> ${data}`)
    this.#port.write(data + '\r\n')
  }

  #toggleBinaryMode = (binaryBufferLength?: number): void => {
    if (this.#binaryBufferTimeout !== null) clearTimeout(this.#binaryBufferTimeout)

    this.#binaryMode = !this.#binaryMode
    this.#binaryBufferLength = binaryBufferLength ?? 0
    this.#binaryBuffer = null

    if (this.#binaryMode) {
      this.#binaryBufferTimeout = setTimeout(() => {
        this.#logger.warn('SBD message write timeout. An insufficient number of bytes were transferred to 9602 during the transfer period of 60 seconds')
        this.#write('1')
        this.#toggleBinaryMode()
      }, 60 * SECOND)

      this.#port.unpipe(this.#readlineParser)
      this.#port.pipe(this.#binaryParser)

      this.#write('READY')
    } else {
      this.#port.unpipe(this.#binaryParser)
      this.#port.pipe(this.#readlineParser)
    }
  }

  #handleData = async (data: string | Buffer): Promise<void> => {
    this.#logger.info(`<< ${this.#binaryMode ? data.toString('hex') : data}`)

    if (this.#binaryMode) {
      try {
        this.#binaryBuffer = this.#binaryBuffer ? Buffer.concat([this.#binaryBuffer, Buffer.from(data)]) : Buffer.from(data)
      } catch (error: any) {
        this.#logger.error('Buffer overload. ' + error.message ?? '')
        this.#write('2')
        return this.#toggleBinaryMode()
      }

      if (this.#binaryBuffer.length === this.#binaryBufferLength) {
        // received the expected number of bytes, now we can
        // calculate the checksum against the checksum provided
        // by the client.
        const buffer = this.#binaryBuffer.subarray(0, this.#binaryBuffer.length - 2)
        const checksum = this.#binaryBuffer.subarray(this.#binaryBuffer.length - 2, this.#binaryBuffer.length)

        let sum = 0
        for (let i = 0; i < buffer.length; i++) sum += buffer[i]

        const calculatedChecksum = Buffer.alloc(2)

        // set the least significant byte of the message summation
        calculatedChecksum[1] = sum & 0xff

        // drop the least significant byte
        sum >>= 8

        // set the (second) least significant byte of the message summation
        calculatedChecksum[0] = sum & 0xff

        this.#logger.debug(`Client provided checksum was '${checksum.toString('hex')}', calculated checksum was '${calculatedChecksum.toString('hex')}'`)

        if (checksum.equals(calculatedChecksum)) {
          buffer.copy(this.#moBuffer)
          this.#write('0')
        } else {
          this.#logger.warn('SBD message checksum sent from DTE does not match the checksum calculated by the 9602.')
          this.#write('2')
        }

        this.#toggleBinaryMode()
      } else if (this.#binaryBuffer.length > this.#binaryBufferLength) {
        this.#logger.warn(`Received more binary data (${this.#binaryBuffer.length}) than expected (${this.#binaryBufferLength})`)
        this.#write('2')

        this.#toggleBinaryMode()
      }

      return
    }

    if (data instanceof Buffer) {
      this.#write('ERROR')
      return
    }

    let command, detail

    if (data.includes('=')) {
      command = data.substring(0, data.indexOf('=') + 1)
      detail = data.substring(data.indexOf('=') + 1, data.length)
    } else {
      command = data
    }

    if (this.#echoEnabled) {
      await delay(SIMPLE_WAIT_TIME)
      this.#write(data)
    }

    await delay(SIMPLE_WAIT_TIME)

    switch (command) {
      /** Flow Control */
      case 'AT&K0': // Disable
      case 'AT&K3': // Enable
        this.#write('OK')
        break

      /** Disable DTE Echo */
      case 'ATE0':
        this.#echoEnabled = false
        this.#write('OK')
        break

      /** Enable DTE Echo */
      case 'ATE1':
        this.#echoEnabled = true
        this.#write('OK')
        break

      /** Indicator Event Reporting */
      case 'AT+CIER=':
        switch (detail) {
          case '0,0,0,0': // Disable
          case '0,1,0,0': // Disable
          case '0,0,1,0': // Disable
          case '1,0,0,0': // Disable
            this.#serviceAvailabilityIndicator = false
            this.#signalQualityIndicator = false
            break
          case '1,1,0,0': // Enable Signal
            this.#signalQualityIndicator = true
            this.#serviceAvailabilityIndicator = false
            break
          case '1,0,1,0': // Enable Service
            this.#signalQualityIndicator = false
            this.#serviceAvailabilityIndicator = true
            break
          case '1,1,1,0': // Enable Signal & Service
            this.#signalQualityIndicator = true
            this.#serviceAvailabilityIndicator = true
            break
          default:
            this.#write('ERROR')
            return
        }

        this.#write('OK')

        if (this.#signalQualityIndicator) this.#write(`+CIEV:0,${this.#currentSignalQuality}`)
        if (this.#serviceAvailabilityIndicator) this.#write(`+CIEV:1,${this.#currentSignalQuality >= 1 ? 1 : 0}`)

        break

      /** Short Burst Data: Clear SBD Message Buffer(s) */
      case 'AT+SBDD0':
        this.#moBuffer.fill(0)
        this.#write('OK')
        break
      case 'AT+SBDD1':
        this.#mtBuffer = ''
        this.#write('OK')
        break
      case 'AT+SBDD2':
        this.#moBuffer.fill(0)
        this.#mtBuffer = ''
        this.#write('OK')
        break

      /** Short Burst Data: Automatic Registration */
      case 'AT+SBDAREG=':
        switch (detail) {
          case '0': // Disable Automatic SBD Network Registration (default)
          case '1': // Set the Automatic SBD Network Registration mode to "Automatic"
          case '2': // Set the Automatic SBD Network Registration mode to "Ask"
            this.#write('OK')
            break
          default:
            this.#write('ERROR')
        }
        break

      /** Short Burst Data: Mobile-Terminated Alert */
      case 'AT+SBDMTA=':
        switch (detail) {
          case '0': // Disable SBD Ring Alert indication
            this.#ringAlertsEnabled = false
            this.#write('OK')
            break
          case '1': // Enable SBD Ring Alert indication (default)
            this.#ringAlertsEnabled = true
            this.#write('OK')
            break
          default:
            this.#write('ERROR')
        }
        break

      /* Short Burst Data: Write Binary Data to the ISU */
      case 'AT+SBDWB=': {
        let length = 0
        try {
          // attempt to parse expected binary length as integer
          length = parseInt(detail ?? '')
        } catch (error) {
          this.#write('ERROR')
          break
        }

        if (length < 1 || length > 340) {
          this.#logger.warn('SBD message size is not correct. The maximum mobile originated SBD message length is 340 bytes. The minimum mobile originated SBD message length is 1 byte')
          this.#write('3')
          break
        }

        this.#toggleBinaryMode(length + 2)
        break
      }

      /* Short Burst Data: Initiate an SBD Session Extended */
      case 'AT+SBDIX':
      case 'AT+SBDIXA': {
        const waitTime = LONG_WAIT_TIME

        this.#logger.debug(`Initiating simulated SBD session. Waiting ${Math.round(waitTime / SECOND)} seconds...`)

        await delay(LONG_WAIT_TIME)

        // the connection was successful if we still have 2 or more
        // bars of signal. if we have 1 bar of signal then it should
        // be a success 20% of the time.
        const success = this.#currentSignalQuality >= 2 ||
          (this.#currentSignalQuality === 1 && randomInterval(5, 10) % 10)

        if (success) {
          this.#moSequenceNo++
          this.#mtSequenceNo++

          // match the rock7 service provider datetime format
          const rbDateFormat = new Date().toISOString()
            .substring(2) // drop century
            .replace('T', ' ') // drop time indicator
            .replace('Z', '') // drop UTC timezone
            .substring(-4) // drop milliseconds

          this.#logger.debug('Emitting sbd-message event with message details')
          const claims = {
            momsn: this.#moSequenceNo,
            data: this.moBuffer.slice(0, this.moBuffer.indexOf(0x00)).toString('hex'),
            serial: 206899,
            iridium_latitude: 50.2563,
            iridium_longitude: 82.2532,
            iridium_cep: 122,
            imei: '300534062390910',
            device_type: 'ROCKBLOCK',
            transmit_time: rbDateFormat
          }

          // sign the claims and send the message
          const token = jwt.sign(claims, {
            key: this.#jwtSignerKey,
            ...this.#jwtSignerKeyPassphrase && {
              passphrase: this.#jwtSignerKeyPassphrase
            }
          }, {
            algorithm: 'RS256',
            issuer: 'Rock7'
          })

          this.emit('sbd-message', {
            ...claims,
            JWT: token
          })
        }

        this.#write(`+SBDIX: ${success ? 0 : 32}, ${this.#moSequenceNo}, ${success ? 0 : 2}, ${this.#mtSequenceNo}, 0, 0`)
        this.#write('OK')

        break
      }
      default:
        this.#logger.error('Command not supported in emulator')
        this.#write('ERROR')
        break
    }
  }

  /**
   * Randomly updates the signal quality depending on
   * the configured network quality rating. The signal
   * quality will be updated at random intervals, as
   * specified in the configuration.
   */
  #updateSignalQuality = (): void => {
    let minSignalQuality, maxSignalQuality

    switch (this.#signalQualityRating) {
      case SignalQualityRating.NONE:
        minSignalQuality = SignalQuality.NONE
        maxSignalQuality = SignalQuality.NONE
        break
      case SignalQualityRating.POOR:
        minSignalQuality = SignalQuality.NONE
        maxSignalQuality = SignalQuality.TWO
        break
      case SignalQualityRating.OK:
        minSignalQuality = SignalQuality.ONE
        maxSignalQuality = SignalQuality.TWO
        break
      case SignalQualityRating.GOOD:
        minSignalQuality = SignalQuality.THREE
        maxSignalQuality = SignalQuality.FOUR
        break
      case SignalQualityRating.EXCELLENT:
        minSignalQuality = SignalQuality.FIVE
        maxSignalQuality = SignalQuality.FIVE
        break
      case SignalQualityRating.RANDOM:
        minSignalQuality = SignalQuality.NONE
        maxSignalQuality = SignalQuality.FIVE
    }

    const current = this.#currentSignalQuality
    const update = randomInterval(minSignalQuality, maxSignalQuality) as SignalQuality

    if (current !== update) {
      this.#currentSignalQuality = update
      this.#logger.debug(`Updated signal quality to '${update}'`)

      if (this.#signalQualityIndicator) this.#write(`+CIEV:0,${update}`)
      if (this.#serviceAvailabilityIndicator) this.#write(`+CIEV:1,${update >= 1 ? 1 : 0}`)
    } else {
      this.#logger.debug(`Signal quality remains as ${current}`)
    }

    const waitTime = randomInterval(15 * SECOND, 1 * MINUTE)
    this.#logger.debug(`Next signal quality update tick is in ${waitTime}ms`)

    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const _this = this

    setTimeout(function () {
      _this.#updateSignalQuality()
    }, waitTime)
  }
}
