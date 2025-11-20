// src/users/dto/create-user.dto.ts
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MinLength,
  IsArray,
  IsOptional,
  IsBoolean,
  Matches,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {
  @ApiProperty({ example: 'Juan', description: 'Nombre del usuario' })
  @IsNotEmpty()
  @IsString()
  @Matches(/^[A-Za-zÁÉÍÓÚáéíóúÑñÜü\s]+$/, {
    message: 'El nombre solo puede contener letras y espacios.',
  })
  nombre: string;

  @ApiProperty({ example: 'Pérez', description: 'Apellido del usuario' })
  @IsNotEmpty()
  @IsString()
  @Matches(/^[A-Za-zÁÉÍÓÚáéíóúÑñÜü\s]+$/, {
    message: 'El apellido solo puede contener letras y espacios.',
  })
  apellido: string;

  @ApiProperty({
    example: '12345678-5',
    description: 'RUT chileno del usuario',
  })
  @IsNotEmpty()
  @IsString()
  rut: string;

  @ApiProperty({ example: 'juan@example.com', description: 'Correo electrónico único' })
  @IsNotEmpty()
  @IsEmail()
  correo: string;

  @ApiProperty({ example: 'password123', description: 'Contraseña del usuario (mínimo 6 caracteres)' })
  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  contrasena: string;

  @ApiProperty({
    example: ['cliente'],
    description: 'Lista de roles asignados al usuario',
    required: false,
    isArray: true,
  })
  @IsOptional()
  @IsArray()
  roles?: string[];

  @ApiProperty({
    example: ['crear_producto', 'ver_pedidos'],
    description: 'Lista de permisos explícitos asignados',
    required: false,
    isArray: true,
  })
  @IsOptional()
  @IsArray()
  permisos?: string[];

  @ApiProperty({
    example: true,
    description: 'Indica si la cuenta está activa',
    required: false,
  })
  @IsOptional()
  @IsBoolean()
  activo?: boolean;
}
