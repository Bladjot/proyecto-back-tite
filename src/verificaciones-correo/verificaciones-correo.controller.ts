import { Controller, Get, Post, Body, Param, Delete, Patch } from '@nestjs/common';
import { VerificacionesCorreoService } from './verificaciones-correo.service';
import { CreateVerificacionCorreoDto } from './dto/create-verificacion-correo.dto';
import { UpdateVerificacionCorreoDto } from './dto/update-verificacion-correo.dto';

@Controller('verificaciones-correo')
export class VerificacionesCorreoController {
  constructor(private readonly verificacionesService: VerificacionesCorreoService) {}

  @Post()
  create(@Body() dto: CreateVerificacionCorreoDto) {
    return this.verificacionesService.create(dto);
  }

  @Get()
  findAll() {
    return this.verificacionesService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.verificacionesService.findOne(id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() dto: UpdateVerificacionCorreoDto) {
    return this.verificacionesService.update(id, dto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.verificacionesService.remove(id);
  }
}
