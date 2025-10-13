// ✅ src/users/users.service.ts
import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private readonly userModel: Model<User>) {}

  /**
   * 🧩 Crear un nuevo usuario
   */
  async create(createUserDto: CreateUserDto): Promise<User> {
    const newUser = new this.userModel(createUserDto);
    return await newUser.save();
  }

  /**
   * 🔍 Buscar todos los usuarios
   */
  async findAll(): Promise<User[]> {
    return await this.userModel.find().exec();
  }

  /**
   * 🔍 Buscar usuario por ID
   */
  async findOne(id: string): Promise<User> {
    const user = await this.userModel.findById(id).exec();
    if (!user) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }
    return user;
  }

  /**
   * 🔍 Buscar usuario por correo (usado por AuthService)
   */
  async findByEmail(email: string): Promise<User | null> {
    return await this.userModel.findOne({ email }).exec();
  }

  /**
   * ✏️ Actualizar un usuario
   */
  async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    const updatedUser = await this.userModel
      .findByIdAndUpdate(id, updateUserDto, { new: true })
      .exec();

    if (!updatedUser) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }

    return updatedUser;
  }

  /**
   * 🗑️ Eliminar usuario (Admin y Moderador)
   * - Admin puede eliminar cualquier usuario.
   * - Moderador puede eliminar usuarios normales o moderadores,
   *   pero NO puede eliminar a un administrador.
   */
  async remove(id: string, currentUser?: any): Promise<{ message: string }> {
    const userToDelete = await this.userModel.findById(id).exec();
    if (!userToDelete) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }

    const currentRoles = currentUser?.roles || [];
    const targetRoles = userToDelete.roles || [];

    if (currentRoles.includes('moderador') && targetRoles.includes('admin')) {
      throw new ForbiddenException(
        'Un moderador no puede eliminar a un administrador',
      );
    }

    await this.userModel.findByIdAndDelete(id).exec();
    return { message: 'Usuario eliminado correctamente' };
  }
}
