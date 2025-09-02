import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { RolesPermisosService } from './roles-permisos.service';
import { CreateRolePermisoDto } from './dto/create-role-permiso.dto';
import { UpdateRolePermisoDto } from './dto/update-role-permiso.dto';

@ApiTags('Roles-Permisos')
@Controller('roles-permisos')
export class RolesPermisosController {
  constructor(private readonly rolesPermisosService: RolesPermisosService) {}

  @ApiOperation({ summary: 'Asignar un permiso a un rol' })
  @ApiResponse({ status: 201, description: 'Permiso asignado al rol' })
  @Post()
  create(@Body() dto: CreateRolePermisoDto) {
    return this.rolesPermisosService.create(dto);
  }

  @ApiOperation({ summary: 'Listar todas las asignaciones de roles-permisos' })
  @Get()
  findAll() {
    return this.rolesPermisosService.findAll();
  }

  @ApiOperation({ summary: 'Obtener una asignación de rol-permiso por ID' })
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.rolesPermisosService.findOne(id);
  }

  @ApiOperation({ summary: 'Actualizar una asignación de rol-permiso' })
  @Patch(':id')
  update(@Param('id') id: string, @Body() dto: UpdateRolePermisoDto) {
    return this.rolesPermisosService.update(id, dto);
  }

  @ApiOperation({ summary: 'Eliminar una asignación de rol-permiso' })
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.rolesPermisosService.remove(id);
  }
}
