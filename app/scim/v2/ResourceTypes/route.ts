import type { NextRequest } from 'next/server'
import { GROUP_SCHEMA, LIST_SCHEMA, USER_SCHEMA } from '@/lib/scim'
import { scim, scimJson } from '@/lib/scim-http'

export const dynamic = 'force-dynamic'

export const GET = (req: NextRequest) =>
  scim(req, async ({ base }) => {
    const resources = [
      { schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'], id: 'User', name: 'User', endpoint: '/Users', schema: USER_SCHEMA, meta: { resourceType: 'ResourceType', location: `${base}/scim/v2/ResourceTypes/User` } },
      { schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'], id: 'Group', name: 'Group', endpoint: '/Groups', schema: GROUP_SCHEMA, meta: { resourceType: 'ResourceType', location: `${base}/scim/v2/ResourceTypes/Group` } },
    ]
    return scimJson({ schemas: [LIST_SCHEMA], totalResults: 2, startIndex: 1, itemsPerPage: 2, Resources: resources })
  })
