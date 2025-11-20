import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

@Schema({
  collection: 'acreditaciones_vendedores',
  timestamps: true,
})
export class VendorAccreditation extends Document {
  @Prop({ type: Types.ObjectId, ref: 'User', required: false })
  usuario_id?: Types.ObjectId;

  @Prop({ required: true })
  nombre_tienda: string;

  @Prop({ required: true })
  telefono_contacto: string;

  @Prop({ required: false })
  rut_empresa?: string;

  @Prop({
    type: String,
    enum: ['pendiente', 'aprobado', 'rechazado'],
    default: 'pendiente',
  })
  estado: 'pendiente' | 'aprobado' | 'rechazado';
}

export const VendorAccreditationSchema =
  SchemaFactory.createForClass(VendorAccreditation);
