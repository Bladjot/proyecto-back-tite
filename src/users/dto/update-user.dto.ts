import { PartialType } from '@nestjs/mapped-types';
import { CreateUserDto } from './create-user.dto';
import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsBoolean, IsOptional, IsString, Matches, MinLength } from 'class-validator';

export class UpdateUserDto extends PartialType(CreateUserDto) {
  @ApiPropertyOptional({
    example: 'Juan actualizado',
    description: 'Nuevo nombre del usuario',
  })
  @IsOptional()
  @IsString()
  @Matches(/^[A-Za-zÁÉÍÓÚáéíóúÑñÜü\s]+$/, {
    message: 'El nombre solo puede contener letras y espacios.',
  })
  nombre?: string;

  @ApiPropertyOptional({
    example: 'Pérez modificado',
    description: 'Nuevo apellido del usuario',
  })
  @IsOptional()
  @IsString()
  @Matches(/^[A-Za-zÁÉÍÓÚáéíóúÑñÜü\s]+$/, {
    message: 'El apellido solo puede contener letras y espacios.',
  })
  apellido?: string;

  @ApiPropertyOptional({
    example: '12345678-5',
    description: 'Nuevo RUT del usuario',
  })
  @IsOptional()
  @IsString()
  rut?: string;

  @ApiPropertyOptional({
    example: '1234567',
    description: 'Nueva contraseña (mínimo 6 caracteres)',
    minLength: 6,
  })
  @IsOptional()
  @IsString()
  @MinLength(6)
  contrasena?: string;

  @ApiPropertyOptional({
    example: 'admin',
    description: 'Nuevo rol del usuario',
  })
  @IsOptional()
  @IsString()
  rol?: string;

  @ApiPropertyOptional({
    example: false,
    description: 'Cambia el estado del usuario a inactivo',
  })
  @IsOptional()
  @IsBoolean()
  activo?: boolean;
}
