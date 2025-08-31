import { IsNotEmpty, IsString } from 'class-validator';

export class CreateVerificacionCorreoDto {
  @IsNotEmpty()
  @IsString()
  usuarioId: string;

  @IsNotEmpty()
  @IsString()
  token: string;

  expiracion?: Date;
}
