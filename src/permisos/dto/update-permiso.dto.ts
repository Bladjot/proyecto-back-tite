import { PartialType } from '@nestjs/mapped-types';
import { CreatePermisoDto } from './create-permiso.dto';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdatePermisoDto extends PartialType(CreatePermisoDto) {
  @ApiPropertyOptional({ description: 'Código único del permiso' })
  codigo?: string;

  @ApiPropertyOptional({ description: 'Nombre del permiso' })
  nombre?: string;

  @ApiPropertyOptional({ description: 'Descripción del permiso' })
  descripcion?: string;
}
