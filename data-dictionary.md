# Diccionario de Datos

Generado automáticamente el 2025-10-28T13:56:01.538Z.

## permisos (`Permiso`)

- Fuente del esquema: `src/permisos/schemas/permiso.schema.ts`
- Timestamps automáticos: Sí

| Campo          | Tipo     | Requerido | Único | Referencia | Default    |
| ---            | ---      | ---       | ---   | ---        | ---        |
| codigo         | String   | Sí        | Sí    |            |            |
| nombre         | String   | Sí        | No    |            |            |
| descripcion    | String   | No        | No    |            |            |
| actualizado_en | Date     | No        | No    |            |            |
| _id            | ObjectId | No        | No    |            |defaultId() |
| createdAt      | Date     | No        | No    |            |            |
| updatedAt      | Date     | No        | No    |            |            |

## roles (`Role`)

- Fuente del esquema: `src/roles/schemas/role.schema.ts`
- Timestamps automáticos: Sí

| Campo          | Tipo     | Requerido | Único | Referencia | Default     | 
| ---            | ---      | ---       | ---   | ---        | ---         |
| codigo         | String   | Sí        | Sí    |            |             |
| nombre         | String   | Sí        | No    |            |             |
| descripcion    | String   | No        | No    |            |             |
| actualizado_en | Date     | No        | No    |            |             |
| _id            | ObjectId | No        | No    |            | defaultId() |
| createdAt      | Date     | No        | No    |            |             |
| updatedAt      | Date     | No        | No    |            |             |

## rolepermisos (`RolePermiso`)

- Fuente del esquema: `src/roles-permisos/schemas/role-permiso.schema.ts`
- Timestamps automáticos: Sí

| Campo | Tipo | Requerido | Único | Referencia | Default |
| --- | --- | --- | --- | --- | --- |
| roleId | ObjectId→Role | Sí | No | Role |  |
| permisoId | ObjectId→Permiso | Sí | No | Permiso |  |
| creado_en | Date | No | No |  |  |
| _id | ObjectId | No | No |  | defaultId() |
| createdAt | Date | No | No |  |  |
| updatedAt | Date | No | No |  |  |

## users (`User`)

- Fuente del esquema: `src/users/schemas/user.schema.ts`
- Timestamps automáticos: Sí

| Campo | Tipo | Requerido | Único | Referencia | Default |
| --- | --- | --- | --- | --- | --- |
| name | String | Sí | No |  |  |
| lastName | String | Sí | No |  |  |
| email | String | Sí | Sí |  |  |
| password | String | Sí | No |  |  |
| roles | Array<String> | No | No |  | ["usuario"] |
| permisos | Array<String> | No | No |  | [] |
| isActive | Boolean | No | No |  | true |
| _id | ObjectId | No | No |  | defaultId() |
| createdAt | Date | No | No |  |  |
| updatedAt | Date | No | No |  |  |

## verificacioncorreos (`VerificacionCorreo`)

- Fuente del esquema: `src/verificaciones-correo/schemas/verificacion-correo.schema.ts`
- Timestamps automáticos: Sí

| Campo | Tipo | Requerido | Único | Referencia | Default |
| --- | --- | --- | --- | --- | --- |
| usuarioId | ObjectId→User | Sí | No | User |  |
| token | String | Sí | No |  |  |
| usado | Boolean | No | No |  | false |
| expiracion | Date | No | No |  |  |
| _id | ObjectId | No | No |  | defaultId() |
| createdAt | Date | No | No |  |  |
| updatedAt | Date | No | No |  |  |
