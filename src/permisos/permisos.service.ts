import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Permiso, PermisoDocument } from './schemas/permiso.schema';
import { CreatePermisoDto } from './dto/create-permiso.dto';
import { UpdatePermisoDto } from './dto/update-permiso.dto';

@Injectable()
export class PermisosService {
  constructor(
    @InjectModel(Permiso.name) private permisoModel: Model<PermisoDocument>,
  ) {}

  async create(createPermisoDto: CreatePermisoDto): Promise<Permiso> {
    const permiso = new this.permisoModel(createPermisoDto);
    return permiso.save();
  }

  async findAll(): Promise<Permiso[]> {
    return this.permisoModel.find().exec();
  }

  async findOne(id: string): Promise<Permiso> {
    const permiso = await this.permisoModel.findById(id).exec();
    if (!permiso) throw new NotFoundException('Permiso no encontrado');
    return permiso;
  }

  async update(id: string, updatePermisoDto: UpdatePermisoDto): Promise<Permiso> {
    const permiso = await this.permisoModel
      .findByIdAndUpdate(id, updatePermisoDto, { new: true })
      .exec();
    if (!permiso) throw new NotFoundException('Permiso no encontrado');
    return permiso;
  }

  async remove(id: string): Promise<void> {
    const result = await this.permisoModel.findByIdAndDelete(id).exec();
    if (!result) throw new NotFoundException('Permiso no encontrado');
  }
}
