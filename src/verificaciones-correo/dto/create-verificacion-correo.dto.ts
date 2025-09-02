import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class CreateVerificacionCorreoDto {
  @ApiProperty({ example: 'juan@example.com', description: 'Correo a verificar' })
  @IsEmail()
  correo: string;

  @ApiProperty({ example: 'abc123', description: 'Token de verificación enviado al correo' })
  @IsNotEmpty()
  @IsString()
  token: string;

  @ApiProperty({ example: false, description: 'Si el correo ya fue verificado' })
  verificado?: boolean;
}
