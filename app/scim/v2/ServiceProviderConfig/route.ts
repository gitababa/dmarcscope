import type { NextRequest } from 'next/server'
import { scim, scimJson } from '@/lib/scim-http'

export const dynamic = 'force-dynamic'

export const GET = (req: NextRequest) =>
  scim(req, async ({ base }) =>
    scimJson({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
      patch: { supported: true },
      bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
      filter: { supported: true, maxResults: 100 },
      changePassword: { supported: false },
      sort: { supported: false },
      etag: { supported: false },
      authenticationSchemes: [{ type: 'oauthbearertoken', name: 'Bearer token', description: 'The SCIM token from API & SCIM in the app.', primary: true }],
      meta: { resourceType: 'ServiceProviderConfig', location: `${base}/scim/v2/ServiceProviderConfig` },
    })
  )
