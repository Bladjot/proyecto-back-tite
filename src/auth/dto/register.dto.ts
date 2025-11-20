import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, Matches, MinLength } from 'class-validator';

export class RegisterDto {
  @ApiProperty({
    example: 'Juan',
    description: 'Nombre del usuario',
  })
  @IsNotEmpty()
  @IsString()
  @Matches(/^[A-Za-zÁÉÍÓÚáéíóúÑñÜü\s]+$/, {
    message: 'El nombre solo puede contener letras y espacios.',
  })
  nombre: string;

  @ApiProperty({
    example: 'Pérez',
    description: 'Apellido del usuario',
  })
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

  @ApiProperty({
    example: 'juan@example.com',
    description: 'Correo electrónico único',
  })
  @IsNotEmpty()
  @IsEmail()
  correo: string;

  @ApiProperty({
    example: '123456',
    description: 'Contraseña (mínimo 6 caracteres)',
    minLength: 6,
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  contrasena: string;

  @ApiProperty({ description: 'Token de Google reCAPTCHA v2' })
  @IsNotEmpty()
  @IsString()
  recaptchaToken: string;
}
