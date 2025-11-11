import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class LoginDto {
  @ApiProperty({
    example: 'juan@example.com',
    description: 'Correo electrónico del usuario',
  })
  @IsNotEmpty()
  @IsEmail()
  correo: string;

  @ApiProperty({
    example: '123456',
    description: 'Contraseña del usuario',
  })
  @IsNotEmpty()
  @IsString()
  contrasena: string;

  @ApiProperty({ description: 'Token de Google reCAPTCHA v2' })
  @IsNotEmpty()
  @IsString()
  recaptchaToken: string;
}
