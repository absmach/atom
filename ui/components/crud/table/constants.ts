export const TENANTS_QUERY = `
  query CrudTenants {
    tenants(limit: 100, offset: 0) {
      items { id name }
    }
  }
`;

export const TENANT_STATUS_MUTATIONS = {
  enable: `mutation EnableTenant($id: ID!) { enableTenant(id: $id) { id status updatedAt } }`,
  disable: `mutation DisableTenant($id: ID!) { disableTenant(id: $id) { id status updatedAt } }`,
  freeze: `mutation FreezeTenant($id: ID!) { freezeTenant(id: $id) { id status updatedAt } }`,
} as const;

export const ENTITY_STATUS_MUTATIONS = {
  enable: `mutation EnableEntity($id: ID!) { enableEntity(id: $id) { id status updatedAt } }`,
  disable: `mutation DisableEntity($id: ID!) { disableEntity(id: $id) { id status updatedAt } }`,
} as const;

export const PROFILE_STATUS_MUTATION = `
  mutation UpdateProfileStatus($id: ID!, $input: UpdateProfileInput!) {
    updateProfile(id: $id, input: $input) { id status updatedAt }
  }
`;
