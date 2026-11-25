import type { Certificate, Key } from './api'

const dateFormat = new Intl.DateTimeFormat('it-IT', { day: '2-digit', month: 'short', year: 'numeric' })
export const date = (value: string) => dateFormat.format(new Date(value))
const shortId = (value: string) => `${value.slice(0, 8)}…${value.slice(-4)}`

export const keyName = (key: Key) => key.alias || shortId(key.keyId)
export function keyOption(key: Key, keys: Key[]) {
  const duplicate = key.alias && keys.some(item =>
    item.keyId !== key.keyId && item.alias === key.alias && item.algorithm === key.algorithm)
  return `${keyName(key)} · ${key.algorithm}${duplicate ? ` · …${key.keyId.slice(-4)}` : ''}`
}
export const certificateName = (certificate: Certificate) => certificate.alias || shortId(certificate.certificateId)
export const certificateOption = (certificate: Certificate) =>
  `${certificateName(certificate)} · scade il ${date(certificate.notAfter)}${certificate.alias ? ` · …${certificate.certificateId.slice(-4)}` : ''}`
