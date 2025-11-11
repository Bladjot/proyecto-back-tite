import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

export type RolePermisoDocument = RolePermiso & Document;

@Schema({ collection: 'roles_permisos', timestamps: true })
export class RolePermiso {
  @Prop({ type: Types.ObjectId, ref: 'Role', required: true })
  roleId: Types.ObjectId;

  @Prop({ type: Types.ObjectId, ref: 'Permiso', required: true })
  permisoId: Types.ObjectId;

  @Prop()
  creado_en?: Date;
}

export const RolePermisoSchema = SchemaFactory.createForClass(RolePermiso);
