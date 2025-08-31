import { Controller, Get, Post, Body, Param, Delete, Patch } from '@nestjs/common';
import { RolesPermisosService } from './roles-permisos.service';
import { CreateRolePermisoDto } from './dto/create-role-permiso.dto';
import { UpdateRolePermisoDto } from './dto/update-role-permiso.dto';

@Controller('roles-permisos')
export class RolesPermisosController {
  constructor(private readonly rolesPermisosService: RolesPermisosService) {}

  @Post()
  create(@Body() dto: CreateRolePermisoDto) {
    return this.rolesPermisosService.create(dto);
  }

  @Get()
  findAll() {
    return this.rolesPermisosService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.rolesPermisosService.findOne(id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() dto: UpdateRolePermisoDto) {
    return this.rolesPermisosService.update(id, dto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.rolesPermisosService.remove(id);
  }
}
