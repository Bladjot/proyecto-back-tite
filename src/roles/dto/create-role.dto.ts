import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class CreateRoleDto {
  @ApiProperty({ example: 'admin', description: 'Código único del rol' })
  @IsNotEmpty()
  @IsString()
  codigo: string;

  @ApiProperty({ example: 'Administrador', description: 'Nombre visible del rol' })
  @IsNotEmpty()
  @IsString()
  nombre: string;

  @ApiProperty({ example: 'Acceso completo al sistema', description: 'Descripción del rol' })
  @IsString()
  descripcion?: string;
}
