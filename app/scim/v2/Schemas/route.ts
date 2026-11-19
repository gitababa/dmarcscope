import type { NextRequest } from 'next/server'
import { GROUP_SCHEMA, LIST_SCHEMA, USER_SCHEMA } from '@/lib/scim'
import { scim, scimJson } from '@/lib/scim-http'

export const dynamic = 'force-dynamic'

const attr = (name: string, extra: Record<string, unknown> = {}) => ({ name, type: 'string', multiValued: false, required: false, mutability: 'readWrite', returned: 'default', uniqueness: 'none', ...extra })

export const GET = (req: NextRequest) =>
  scim(req, async () =>
    scimJson({
      schemas: [LIST_SCHEMA],
      totalResults: 2,
      startIndex: 1,
      itemsPerPage: 2,
      Resources: [
        { id: USER_SCHEMA, name: 'User', attributes: [attr('userName', { required: true, mutability: 'immutable', uniqueness: 'server' }), attr('externalId'), attr('displayName'), attr('active', { type: 'boolean' })] },
        { id: GROUP_SCHEMA, name: 'Group', attributes: [attr('displayName', { required: true, uniqueness: 'server' }), attr('externalId'), attr('members', { type: 'complex', multiValued: true })] },
      ],
    })
  )
