import usx from 'unishox2.siara.cc'

/**
 * Compress a string using the Unishox 2 compression algorithm.
 *
 * @param str
 * @returns {Buffer} the compress string as binary
 */
function compress (str: string) {
  const uint8arr = new Uint8Array(str.length + 10)
  const length = usx.unishox2_compress_simple(str, str.length, uint8arr)
  return Buffer.from(uint8arr.subarray(0, length))
}

/**
 * Decompress a buffer encoded with the Unishox 2 compression algorithm.
 *
 * @param buffer
 * @returns {string} the decompressed string
 */
function decompress (buffer: Buffer) {
  return usx.unishox2_decompress_simple(buffer, buffer.length)
}

const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

const randomInterval = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1) + min)

export { compress, decompress, delay, randomInterval }
