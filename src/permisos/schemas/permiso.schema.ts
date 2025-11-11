import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type PermisoDocument = Permiso & Document;

@Schema({ collection: 'permisos', timestamps: true })
export class Permiso {
  @Prop({ required: true, unique: true })
  codigo: string; // Ej: crear_producto, ver_dashboard

  @Prop({ required: true })
  nombre: string; // Nombre legible del permiso

  @Prop()
  descripcion: string;

  @Prop()
  actualizado_en: Date;
}

export const PermisoSchema = SchemaFactory.createForClass(Permiso);
