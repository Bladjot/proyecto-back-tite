// ✅ src/users/schemas/user.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({
  collection: 'usuarios',
  timestamps: {
    createdAt: 'creado_en',
    updatedAt: 'actualizado_en',
  },
  toJSON: {
    virtuals: true,
    transform: (_: any, ret: any) => {
      ret.id = ret._id;
      delete ret._id;
      delete ret.__v;
      delete ret.contrasena;
      return ret;
    },
  },
})
export class User extends Document {
  @Prop({ required: true })
  nombre: string;

  @Prop({ required: true })
  apellido: string;

  @Prop({ required: true, unique: true })
  correo: string;

  @Prop({ required: false })
  telefono?: string;

  @Prop({ required: true })
  contrasena: string;

  @Prop({ required: true, unique: true })
  rut: string;

  @Prop({ type: [String], default: ['cliente'] })
  roles: string[];

  @Prop({ type: [String], default: [] })
  permisos: string[];

  @Prop({ default: true })
  activo: boolean;

  @Prop({ required: false })
  foto?: string;

  // Campos opcionales para perfil extendido
  @Prop({ required: false })
  biografia?: string;

  @Prop({ type: Object, required: false, default: {} })
  preferencias?: Record<string, any>;
}

export const UserSchema = SchemaFactory.createForClass(User);
