import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { PermisosService } from './permisos.service';
import { CreatePermisoDto } from './dto/create-permiso.dto';
import { UpdatePermisoDto } from './dto/update-permiso.dto';

@ApiTags('Permisos')
@Controller('permisos')
export class PermisosController {
  constructor(private readonly permisosService: PermisosService) {}

  @ApiOperation({ summary: 'Crear un nuevo permiso' })
  @Post()
  create(@Body() dto: CreatePermisoDto) {
    return this.permisosService.create(dto);
  }

  @ApiOperation({ summary: 'Listar permisos' })
  @Get()
  findAll() {
    return this.permisosService.findAll();
  }

  @ApiOperation({ summary: 'Obtener permiso por ID' })
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.permisosService.findOne(id);
  }

  @ApiOperation({ summary: 'Actualizar un permiso' })
  @Patch(':id')
  update(@Param('id') id: string, @Body() dto: UpdatePermisoDto) {
    return this.permisosService.update(id, dto);
  }

  @ApiOperation({ summary: 'Eliminar un permiso' })
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.permisosService.remove(id);
  }
}
