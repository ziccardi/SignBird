import createClient from 'openapi-fetch'
import type { components, paths } from './api.generated'

export type Key = components['schemas']['Key']
export type KeyCapability = components['schemas']['KeyCapability']
export type KeyAlgorithm = components['schemas']['KeyAlgorithm']
export type DigestInput = components['schemas']['CreateDigestSignatureRequest']
export type Certificate = components['schemas']['Certificate']
export type P7mJob = components['schemas']['P7mJob']

export interface DocumentService {
  list(): Promise<P7mJob[]>
  upload(keyId: string, credentialId: string, file: File): Promise<P7mJob>
  approve(jobId: string, code: string): Promise<P7mJob>
  download(jobId: string): Promise<Blob>
}

export type SignatureRequest = components['schemas']['SignatureRequest']

export interface ActivationService {
  status(): Promise<{ enabled: boolean }>
  enroll(): Promise<{ secret: string }>
  confirm(code: string): Promise<{ enabled: boolean }>
  list(): Promise<SignatureRequest[]>
  create(input: DigestInput, code: string): Promise<SignatureRequest>
  approve(requestId: string, code: string): Promise<SignatureRequest>
}

export interface KeyService {
  activation?: ActivationService
  documents?: DocumentService
  capabilities(): Promise<KeyCapability[]>
  list(): Promise<Key[]>
  detail(keyId: string): Promise<Key>
  create(requestId: string, code: string, algorithm: KeyAlgorithm, alias: string): Promise<Key>
  issue(keyId: string, requestId: string, code: string, alias: string): Promise<Certificate>
  renameKey(keyId: string, alias: string, code: string): Promise<void>
  renameCertificate(keyId: string, certificateId: string, alias: string, code: string): Promise<void>
}

function read<T>(result: { data?: T; error?: { message: string }; response: Response }): T {
  if (result.data !== undefined) return result.data
  if (result.response.status === 401) {
    throw new Error('Unauthorized session. Sign in again and check that the token includes the API audience.')
  }
  if (result.response.status >= 500 && typeof result.error !== 'object') {
    throw new Error('API Service is unreachable. Check that the SignBird services are running.')
  }
  throw new Error(result.error?.message || `Operation failed (HTTP ${result.response.status}).`)
}

export function connectApi(getToken: () => Promise<string>): KeyService {
  const client = createClient<paths>({ redirect: 'error' })
  client.use({
    async onRequest({ request }) {
      request.headers.set('Authorization', `Bearer ${await getToken()}`)
      return request
    },
  })

  return {
    documents: {
      async list() {
        return read(await client.GET('/v1/signatures/p7m'))
      },
      async upload(keyId, credentialId, file) {
        return read(await client.POST('/v1/signatures/p7m', {
          body: { keyId, credentialId, file: file.name },
          bodySerializer(body) {
            const form = new FormData()
            form.append('keyId', body.keyId)
            form.append('credentialId', body.credentialId)
            form.append('file', file)
            return form
          },
        }))
      },
      async approve(jobId, code) {
        return read(await client.POST('/v1/signatures/p7m/{jobId}/approve', {
          params: { path: { jobId } },
          body: { code },
        }))
      },
      async download(jobId) {
        return read(await client.GET('/v1/signatures/p7m/{jobId}/download', {
          params: { path: { jobId } },
          parseAs: 'blob',
        }))
      },
    },
    activation: {
      async status() {
        return read(await client.GET('/v1/activation/totp'))
      },
      async enroll() {
        return read(await client.POST('/v1/activation/totp'))
      },
      async confirm(code) {
        return read(await client.POST('/v1/activation/totp/confirm', { body: { code } }))
      },
      async list() {
        return read(await client.GET('/v1/signatures/digest'))
      },
      async create(input, code) {
        return read(await client.POST('/v1/signatures/digest', {
          params: { header: { 'X-TOTP-Code': code } },
          body: input,
        }))
      },
      async approve(requestId, code) {
        return read(await client.POST('/v1/signatures/digest/{requestId}/approve', {
          params: { path: { requestId } },
          body: { code },
        }))
      },
    },
    async list() {
      return read(await client.GET('/v1/keys'))
    },
    async capabilities() {
      return read(await client.GET('/v1/keys/capabilities'))
    },
    async detail(keyId) {
      return read(await client.GET('/v1/keys/{keyId}', { params: { path: { keyId } } }))
    },
    async create(requestId, code, algorithm, alias) {
      return read(await client.POST('/v1/keys', {
        params: { header: { 'Idempotency-Key': requestId, 'X-TOTP-Code': code } },
        body: { keystoreId: 'pkcs12-test', algorithm, alias },
      }))
    },
    async issue(keyId, requestId, code, alias) {
      return read(await client.POST('/v1/certificates', {
        params: { header: { 'Idempotency-Key': requestId, 'X-TOTP-Code': code } },
        body: { keyId, alias },
      }))
    },
    async renameKey(keyId, alias, code) {
      const result = await client.PATCH('/v1/keys/{keyId}', {
        params: { path: { keyId }, header: { 'X-TOTP-Code': code } },
        body: { alias },
      })
      if (!result.response.ok) read(result)
    },
    async renameCertificate(keyId, certificateId, alias, code) {
      const result = await client.PATCH('/v1/keys/{keyId}/certificates/{certificateId}', {
        params: { path: { keyId, certificateId }, header: { 'X-TOTP-Code': code } },
        body: { alias },
      })
      if (!result.response.ok) read(result)
    },
  }
}
