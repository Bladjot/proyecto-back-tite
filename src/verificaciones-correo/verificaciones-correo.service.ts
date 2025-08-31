import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { VerificacionCorreo, VerificacionCorreoDocument } from './schemas/verificacion-correo.schema';
import { CreateVerificacionCorreoDto } from './dto/create-verificacion-correo.dto';
import { UpdateVerificacionCorreoDto } from './dto/update-verificacion-correo.dto';

@Injectable()
export class VerificacionesCorreoService {
  constructor(
    @InjectModel(VerificacionCorreo.name) private verificacionModel: Model<VerificacionCorreoDocument>,
  ) {}

  async create(dto: CreateVerificacionCorreoDto): Promise<VerificacionCorreo> {
    const verificacion = new this.verificacionModel(dto);
    return verificacion.save();
  }

  async findAll(): Promise<VerificacionCorreo[]> {
    return this.verificacionModel.find().populate('usuarioId').exec();
  }

  async findOne(id: string): Promise<VerificacionCorreo> {
    const verificacion = await this.verificacionModel.findById(id).populate('usuarioId').exec();
    if (!verificacion) throw new NotFoundException('Verificación no encontrada');
    return verificacion;
  }

  async update(id: string, dto: UpdateVerificacionCorreoDto): Promise<VerificacionCorreo> {
    const verificacion = await this.verificacionModel
      .findByIdAndUpdate(id, dto, { new: true })
      .populate('usuarioId')
      .exec();
    if (!verificacion) throw new NotFoundException('Verificación no encontrada');
    return verificacion;
  }

  async remove(id: string): Promise<void> {
    const result = await this.verificacionModel.findByIdAndDelete(id).exec();
    if (!result) throw new NotFoundException('Verificación no encontrada');
  }
}
