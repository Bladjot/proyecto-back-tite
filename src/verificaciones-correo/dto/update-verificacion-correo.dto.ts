import { PartialType } from '@nestjs/mapped-types';
import { CreateVerificacionCorreoDto } from './create-verificacion-correo.dto';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateVerificacionCorreoDto extends PartialType(CreateVerificacionCorreoDto) {
  @ApiPropertyOptional({ description: 'Correo del usuario asociado' })
  correo?: string;

  @ApiPropertyOptional({ description: 'Token de verificación de correo' })
  token?: string;

  @ApiPropertyOptional({ description: 'Indica si el correo ya fue verificado' })
  verificado?: boolean;
}
