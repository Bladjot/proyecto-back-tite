import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsEmail, IsOptional, IsString, Matches, MinLength } from 'class-validator';

export class UpdateProfileDetailsDto {
  @ApiPropertyOptional({ description: 'Nombre del usuario', example: 'María' })
  @IsOptional()
  @IsString()
  @Matches(/^[A-Za-zÁÉÍÓÚáéíóúÑñÜü\s]+$/, {
    message: 'El nombre solo puede contener letras y espacios.',
  })
  nombre?: string;

  @ApiPropertyOptional({ description: 'Apellido del usuario', example: 'García' })
  @IsOptional()
  @IsString()
  @Matches(/^[A-Za-zÁÉÍÓÚáéíóúÑñÜü\s]+$/, {
    message: 'El apellido solo puede contener letras y espacios.',
  })
  apellido?: string;

  @ApiPropertyOptional({ description: 'Biografía del usuario' })
  @IsOptional()
  @IsString()
  biografia?: string;

  @ApiPropertyOptional({ description: 'Correo electrónico del usuario' })
  @IsOptional()
  @IsEmail()
  correo?: string;

  @ApiPropertyOptional({ description: 'Teléfono de contacto del usuario' })
  @IsOptional()
  @IsString()
  telefono?: string;

  @ApiPropertyOptional({
    description: 'Preferencias del usuario (JSON string cuando se usa multipart/form-data)',
    example: '{"notificaciones": true}',
  })
  @IsOptional()
  @IsString()
  preferencias?: string;

  @ApiPropertyOptional({
    description: 'Contraseña actual (obligatoria si se envía newPassword)',
  })
  @IsOptional()
  @IsString()
  contrasenaActual?: string;

  @ApiPropertyOptional({
    description: 'Nueva contraseña (mínimo 6 caracteres)',
  })
  @IsOptional()
  @MinLength(6)
  @IsString()
  nuevaContrasena?: string;
}

export class UpdateProfileDetailsWithPhotoDto extends UpdateProfileDetailsDto {
  @ApiPropertyOptional({
    description: 'Foto de perfil (JPG, PNG o WEBP)',
    type: 'string',
    format: 'binary',
    required: false,
  })
  foto?: any;
}
