// src/users/users.controller.ts
import { 
  Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request 
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PublicUserProfileDto } from './dto/public-user-profile.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { PermisosGuard } from 'src/common/guards/permisos.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Permisos } from 'src/common/decorators/permisos.decorator';

@ApiTags('Users') // 👈 agrupa los endpoints en Swagger
@ApiBearerAuth()  // 👈 indica que usan JWT
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // 🧩 Crear usuario (público o según tu lógica)
  @Post()
  @ApiOperation({ summary: 'Crear un nuevo usuario' })
  @ApiResponse({ status: 201, description: 'Usuario creado exitosamente' })
  @ApiResponse({ status: 400, description: 'Datos inválidos' })
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  // 🌐 Perfil público sin datos sensibles
  @Get('public/:id')
  @ApiOperation({ summary: 'Obtener perfil público de un usuario' })
  @ApiResponse({ status: 200, description: 'Perfil público retornado' })
  @ApiResponse({ status: 404, description: 'Usuario no encontrado' })
  findPublic(@Param('id') id: string): Promise<PublicUserProfileDto> {
    return this.usersService.findPublicProfile(id);
  }

  // 👑 Solo admin puede ver todos los usuarios
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  @Get()
  @ApiOperation({ summary: 'Obtener todos los usuarios (solo admin)' })
  @ApiResponse({ status: 200, description: 'Lista de usuarios retornada' })
  @ApiResponse({ status: 403, description: 'No autorizado' })
  findAll() {
    return this.usersService.findAll();
  }

  // 👁️ Ver usuario (requiere permiso específico)
  @UseGuards(JwtAuthGuard, PermisosGuard)
  @Permisos('ver_usuario')
  @Get(':id')
  @ApiOperation({ summary: 'Obtener un usuario por ID (permiso: ver_usuario)' })
  @ApiResponse({ status: 200, description: 'Usuario encontrado' })
  @ApiResponse({ status: 404, description: 'Usuario no encontrado' })
  findOne(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }

  // ✏️ Editar usuario (requiere permiso)
  @UseGuards(JwtAuthGuard, PermisosGuard)
  @Permisos('editar_usuario')
  @Patch(':id')
  @ApiOperation({ summary: 'Actualizar un usuario (permiso: editar_usuario)' })
  @ApiResponse({ status: 200, description: 'Usuario actualizado' })
  @ApiResponse({ status: 404, description: 'Usuario no encontrado' })
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(id, updateUserDto);
  }

  // 🗑️ Eliminar usuario (admin y moderador, pero moderador no puede eliminar admin)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin', 'moderador')
  @Delete(':id')
  @ApiOperation({ 
    summary: 'Eliminar un usuario (admin o moderador, pero moderador no puede eliminar admin)' 
  })
  @ApiResponse({ status: 200, description: 'Usuario eliminado correctamente' })
  @ApiResponse({ status: 403, description: 'No autorizado o acción no permitida' })
  @ApiResponse({ status: 404, description: 'Usuario no encontrado' })
  async remove(@Param('id') id: string, @Request() req) {
    const currentUser = req.user;
    return this.usersService.remove(id, currentUser);
  }
}
