import { PartialType } from '@nestjs/mapped-types';
import { CreateRolePermisoDto } from './create-role-permiso.dto';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateRolePermisoDto extends PartialType(CreateRolePermisoDto) {
  @ApiPropertyOptional({ description: 'ID del rol relacionado' })
  rolId?: string;

  @ApiPropertyOptional({ description: 'ID del permiso relacionado' })
  permisoId?: string;
}
