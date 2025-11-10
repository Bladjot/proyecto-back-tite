import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { CreateVendorAccreditationDto } from './dto/create-vendor-accreditation.dto';
import {
  VendorAccreditation,
} from './schemas/vendor-accreditation.schema';

@Injectable()
export class VendorAccreditationsService {
  constructor(
    @InjectModel(VendorAccreditation.name)
    private readonly vendorAccreditationModel: Model<VendorAccreditation>,
  ) {}

  create(
    dto: CreateVendorAccreditationDto,
    userId?: string,
  ): Promise<VendorAccreditation> {
    const payload = {
      ...dto,
      usuario_id: userId ? new Types.ObjectId(userId) : undefined,
    };
    const doc = new this.vendorAccreditationModel(payload);
    return doc.save();
  }

  findAll(): Promise<VendorAccreditation[]> {
    return this.vendorAccreditationModel.find().sort({ createdAt: -1 }).exec();
  }

  async remove(id: string): Promise<{ message: string }> {
    const deleted = await this.vendorAccreditationModel
      .findByIdAndDelete(id)
      .exec();

    if (!deleted) {
      throw new NotFoundException('Solicitud no encontrada');
    }

    return { message: 'Solicitud eliminada correctamente' };
  }
}
