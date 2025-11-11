import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

export type VerificacionCorreoDocument = VerificacionCorreo & Document;

@Schema({ collection: 'verificaciones_correo', timestamps: true })
export class VerificacionCorreo {
  @Prop({ type: Types.ObjectId, ref: 'User', required: true })
  usuarioId: Types.ObjectId;

  @Prop({ required: true })
  token: string; // Token único de verificación

  @Prop({ default: false })
  usado: boolean; // Si ya fue usado

  @Prop()
  expiracion: Date; // Fecha de caducidad
}

export const VerificacionCorreoSchema = SchemaFactory.createForClass(VerificacionCorreo);
