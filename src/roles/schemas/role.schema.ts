import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type RoleDocument = Role & Document;

@Schema({ collection: 'roles', timestamps: true })
export class Role {
  @Prop({ required: true, unique: true })
  codigo: string; // Ej: admin, vendedor, cliente

  @Prop({ required: true })
  nombre: string; // Nombre legible del rol

  @Prop()
  descripcion: string;

  @Prop()
  actualizado_en: Date;
}

export const RoleSchema = SchemaFactory.createForClass(Role);
