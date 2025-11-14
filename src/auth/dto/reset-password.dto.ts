import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEmail, IsOptional, IsString, MinLength } from 'class-validator';

export class ResetPasswordDto {
  @ApiPropertyOptional({
    description: 'Token enviado por correo para validar el cambio',
  })
  @IsString()
  @IsOptional()
  token?: string;

  @ApiPropertyOptional({
    description: 'Correo del usuario (solo se usa si no hay token)',
  })
  @IsEmail()
  @IsOptional()
  correo?: string;

  @ApiProperty({
    description: 'Nueva contraseña',
    minLength: 6,
  })
  @IsString()
  @MinLength(6)
  nuevaContrasena: string;
}
