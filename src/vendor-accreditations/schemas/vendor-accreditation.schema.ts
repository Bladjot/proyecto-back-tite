import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

@Schema({
  timestamps: true,
})
export class VendorAccreditation extends Document {
  @Prop({ type: Types.ObjectId, ref: 'User', required: false })
  userId?: Types.ObjectId;

  @Prop({ required: true })
  storeName: string;

  @Prop({ required: true })
  contactNumber: string;

  @Prop({ required: true })
  companyRut: string;

  @Prop({
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending',
  })
  status: 'pending' | 'approved' | 'rejected';
}

export const VendorAccreditationSchema =
  SchemaFactory.createForClass(VendorAccreditation);
