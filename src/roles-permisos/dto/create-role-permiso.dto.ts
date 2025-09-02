import { IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateRolePermisoDto {
  @ApiProperty({ description: 'ID del rol relacionado' })
  @IsNotEmpty()
  @IsString()
  rolId: string;

  @ApiProperty({ description: 'ID del permiso relacionado' })
  @IsNotEmpty()
  @IsString()
  permisoId: string;
}
