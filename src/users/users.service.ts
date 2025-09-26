import {
  Injectable,
  ConflictException,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import * as bcrypt from 'bcryptjs';

import { User, UserDocument } from './schemas/user.schema';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  // 🟢 Crear usuario
  async create(createUserDto: CreateUserDto): Promise<UserDocument> {
    const existingUser = await this.userModel.findOne({
      email: createUserDto.email,
    });
    if (existingUser) {
      throw new ConflictException('El correo electrónico ya está registrado');
    }

    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(createUserDto.password, salt);

    const newUser = new this.userModel({
      ...createUserDto,
      password: hashedPassword,
    });

    return newUser.save();
  }

  // 🟢 Listar usuarios (sin password)
  async findAll(): Promise<User[]> {
    return this.userModel.find().select('-password').exec();
  }

  // 🟢 Buscar usuario por ID (sin password)
  async findOne(id: string | Types.ObjectId): Promise<User> {
    const user = await this.userModel
      .findById(id)
      .select('-password')
      .exec();
    if (!user) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }
    return user;
  }

  // 🟢 Buscar usuario por email (incluye password, para login)
  async findByEmail(email: string): Promise<UserDocument | null> {
    return this.userModel.findOne({ email }).exec();
  }

  // 🟢 Actualizar usuario (con hash si cambia la contraseña)
  async update(
    id: string | Types.ObjectId,
    updateUserDto: Partial<UpdateUserDto>,
  ): Promise<User> {
    if (updateUserDto.password) {
      const salt = await bcrypt.genSalt();
      updateUserDto.password = await bcrypt.hash(updateUserDto.password, salt);
    }

    const updatedUser = await this.userModel
      .findByIdAndUpdate(id, updateUserDto, { new: true })
      .select('-password')
      .exec();

    if (!updatedUser) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }

    return updatedUser;
  }

  // 🟢 Eliminar usuario
  async remove(id: string | Types.ObjectId): Promise<void> {
    const result = await this.userModel.findByIdAndDelete(id).exec();
    if (!result) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }
  }
}
