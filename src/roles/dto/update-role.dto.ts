import { PartialType } from '@nestjs/mapped-types';
import { CreateRoleDto } from './create-role.dto';
import { CreateRolePermisoDto } from 'src/roles-permisos/dto/create-role-permiso.dto';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateRolePermisoDto extends PartialType(CreateRolePermisoDto) {
  @ApiPropertyOptional({ description: 'ID del rol relacionado' })
  rolId?: string;

  @ApiPropertyOptional({ description: 'ID del permiso relacionado' })
  permisoId?: string;
}

export class UpdateRoleDto extends PartialType(CreateRoleDto) {}
