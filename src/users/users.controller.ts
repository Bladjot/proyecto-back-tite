import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { PermisosGuard } from 'src/common/guards/permisos.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Permisos } from 'src/common/decorators/permisos.decorator';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // Crear usuario (puede ser público o restringido, depende de tu lógica)
  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  // Solo los admin pueden ver todos los usuarios
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  @Get()
  findAll() {
    return this.usersService.findAll();
  }

  // Solo usuarios con permiso "ver_usuario" pueden ver un usuario específico
  @UseGuards(JwtAuthGuard, PermisosGuard)
  @Permisos('ver_usuario')
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }

  // Solo usuarios con permiso "editar_usuario" pueden actualizar
  @UseGuards(JwtAuthGuard, PermisosGuard)
  @Permisos('editar_usuario')
  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(id, updateUserDto);
  }

  // Solo admin puede borrar
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.usersService.remove(id);
  }
}
