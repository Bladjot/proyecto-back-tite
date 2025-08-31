import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { RolePermiso, RolePermisoDocument } from './schemas/role-permiso.schema';
import { CreateRolePermisoDto } from './dto/create-role-permiso.dto';
import { UpdateRolePermisoDto } from './dto/update-role-permiso.dto';

@Injectable()
export class RolesPermisosService {
  constructor(
    @InjectModel(RolePermiso.name) private rolePermisoModel: Model<RolePermisoDocument>,
  ) {}

  async create(dto: CreateRolePermisoDto): Promise<RolePermiso> {
    const relation = new this.rolePermisoModel(dto);
    return relation.save();
  }

  async findAll(): Promise<RolePermiso[]> {
    return this.rolePermisoModel
      .find()
      .populate('roleId')
      .populate('permisoId')
      .exec();
  }

  async findOne(id: string): Promise<RolePermiso> {
    const relation = await this.rolePermisoModel
      .findById(id)
      .populate('roleId')
      .populate('permisoId')
      .exec();
    if (!relation) throw new NotFoundException('Relación rol-permiso no encontrada');
    return relation;
  }

  async update(id: string, dto: UpdateRolePermisoDto): Promise<RolePermiso> {
    const relation = await this.rolePermisoModel
      .findByIdAndUpdate(id, dto, { new: true })
      .populate('roleId')
      .populate('permisoId')
      .exec();
    if (!relation) throw new NotFoundException('Relación rol-permiso no encontrada');
    return relation;
  }

  async remove(id: string): Promise<void> {
    const result = await this.rolePermisoModel.findByIdAndDelete(id).exec();
    if (!result) throw new NotFoundException('Relación rol-permiso no encontrada');
  }
}
