import type { Certificate, Key, KeyService } from './api'

export function demoApi(): KeyService {
  const now = new Date()
  const daysAgo = (days: number) => new Date(now.getTime() - days * 86_400_000).toISOString()
  const certificate = (certificateId: string, date: Date): Certificate => ({
    certificateId,
    credentialId: crypto.randomUUID(),
    certificatePem: '',
    chainPem: '',
    notBefore: date.toISOString(),
    notAfter: new Date(date.getTime() + 30 * 86_400_000).toISOString(),
  })
  const sampleKey = (keyId: string, days: number, certificates: Certificate[]): Key => ({
    keyId, keystoreId: 'pkcs12-test', algorithm: 'RSA-2048', publicKey: '',
    createdAt: daysAgo(days), status: 'ACTIVE', certificates,
  })
  let keys = [
    sampleKey('8e42b97c9b4c2f1676ed979c422b41f0', 2, [
      certificate('c84d6517b450f64d6400f56b0a02fdf1', new Date(daysAgo(2))),
    ]),
    sampleKey('32dc0b21b95fcab0892c7df1158a60b3', 5, []),
    sampleKey('f628a08bba78b70d9e0cffbc2da345c8', 9, []),
  ]
  const detail = async (keyId: string) => {
    const key = keys.find(item => item.keyId === keyId)
    if (!key) throw new Error('Chiave non trovata.')
    return key
  }

  return {
    async capabilities() {
      return [{ algorithm: 'RSA-2048', signatureScheme: 'RSASSA-PKCS1-v1_5', hashAlgorithms: [{ algorithm: 'SHA-256', digestBytes: 32 }] }]
    },
    async list() { return keys },
    detail,
    async create(_requestId, _code, algorithm, alias) {
      const key = { ...sampleKey(crypto.randomUUID().replaceAll('-', ''), 0, []), algorithm, alias }
      keys = [key, ...keys]
      return key
    },
    async issue(keyId, _requestId, _code, alias) {
      const key = await detail(keyId)
      const issued = { ...certificate(crypto.randomUUID().replaceAll('-', ''), new Date()), alias }
      keys = keys.map(item => item.keyId === keyId
        ? { ...key, certificates: [issued, ...(key.certificates ?? [])] }
        : item)
      return issued
    },
    async renameKey(keyId, alias) {
      await detail(keyId)
      keys = keys.map(key => key.keyId === keyId ? { ...key, alias } : key)
    },
    async renameCertificate(keyId, certificateId, alias) {
      const key = await detail(keyId)
      keys = keys.map(item => item.keyId === keyId ? {
        ...item, certificates: key.certificates?.map(cert => cert.certificateId === certificateId ? { ...cert, alias } : cert),
      } : item)
    },
  }
}
